//! Bounded operator-side Beacon REST acquisition.
//!
//! The checkpoint is supplied when this client is constructed. REST responses
//! can advance from it, but no response field can replace or install it.

use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue,
};
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::provider::{HttpEndpointPolicy, HttpTransportFailure, OperatorAuthorization, UnixClock};
use crate::{
    GatewayBuildError, SepoliaGatewayBuilder, UntrustedConsensusRpcInput,
    UntrustedExecutionHeaderRpcInput, encode_consensus_bootstrap,
};
use ratspeak_eth_verifier::{
    BeaconCheckpointRoot, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK,
    SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD, VerifiedExecutionHeader, Verifier,
    encode_manual_checkpoint_file, manual_checkpoint_file_fingerprint,
    sepolia_consensus_update_slot, sepolia_slot_at_unix, split_and_tag_beacon_json_updates,
    tag_beacon_json_payload,
};

const ACCEPT_SSZ: &str = "application/octet-stream";
const ACCEPT_JSON: &str = "application/json";
const ACCEPT_BEACON: &str = "application/octet-stream, application/json;q=0.9";
const SEPOLIA_SLOTS_PER_EPOCH: u64 = 32;
const ETH_CONSENSUS_VERSION: HeaderName = HeaderName::from_static("eth-consensus-version");
const SEPOLIA_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
    0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
];

/// The result of fetching one Beacon bootstrap for an operator-supplied
/// checkpoint.  The card is an untrusted file candidate: a field node must
/// still stage it and obtain native approval before installing the checkpoint.
pub struct BeaconCheckpointCard {
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    bytes: Vec<u8>,
    fingerprint: [u8; 32],
}

impl BeaconCheckpointCard {
    pub fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Domain-separated fingerprint of the exact card bytes. This is an
    /// integrity/provenance identifier, not publisher authentication or
    /// independent checkpoint authority.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

impl std::fmt::Debug for BeaconCheckpointCard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BeaconCheckpointCard")
            .field("checkpoint_epoch", &self.checkpoint_epoch)
            .field("checkpoint_root", &self.checkpoint_root)
            .field("card_bytes", &self.bytes.len())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// Consumer-side bounds for one consensus acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconHttpPolicy {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub maximum_bootstrap_bytes: usize,
    pub maximum_update_response_bytes: usize,
    pub maximum_finality_update_bytes: usize,
    pub maximum_total_bytes: usize,
    pub maximum_updates: usize,
    pub maximum_updates_per_request: usize,
    pub maximum_finalized_age: Duration,
    pub maximum_acquisition_duration: Duration,
    pub maximum_requests: usize,
}

impl BeaconHttpPolicy {
    pub fn conservative() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            maximum_bootstrap_bytes: 1024 * 1024,
            maximum_update_response_bytes: 1024 * 1024,
            maximum_finality_update_bytes: 512 * 1024,
            maximum_total_bytes: 2 * 1024 * 1024,
            maximum_updates: 128,
            maximum_updates_per_request: 16,
            // A light-client finality update can legitimately trail the
            // ordinary finalized head by another sync-committee update. Four
            // Sepolia epochs plus a small transport margin remain bounded at
            // 30 minutes while avoiding false rejection during normal finality.
            maximum_finalized_age: Duration::from_secs(30 * 60),
            maximum_acquisition_duration: Duration::from_secs(2 * 60),
            maximum_requests: 16,
        }
    }

    fn validate(self) -> Result<Self, BeaconClientError> {
        if self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(60)
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(120)
            || self.maximum_bootstrap_bytes == 0
            || self.maximum_bootstrap_bytes > 1024 * 1024
            || self.maximum_update_response_bytes == 0
            || self.maximum_update_response_bytes > 2 * 1024 * 1024
            || self.maximum_finality_update_bytes == 0
            || self.maximum_finality_update_bytes > 512 * 1024
            || self.maximum_total_bytes == 0
            || self.maximum_total_bytes > 2 * 1024 * 1024
            || self.maximum_updates == 0
            || self.maximum_updates > 128
            || self.maximum_updates_per_request == 0
            || self.maximum_updates_per_request > 128
            || self.maximum_finalized_age.is_zero()
            || self.maximum_finalized_age > Duration::from_secs(24 * 60 * 60)
            || self.maximum_acquisition_duration.is_zero()
            || self.maximum_acquisition_duration > Duration::from_secs(10 * 60)
            || self.maximum_requests < 3
            || self.maximum_requests > 130
        {
            return Err(BeaconClientError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// A bounded Beacon response with only the headers needed for strict protocol checks.
#[derive(Clone, PartialEq, Eq)]
pub struct BeaconHttpResponse {
    status: u16,
    content_type: Option<String>,
    consensus_version: Option<String>,
    content_encoding: Option<String>,
    body: Vec<u8>,
}

impl BeaconHttpResponse {
    pub fn new(
        status: u16,
        content_type: Option<&str>,
        consensus_version: Option<&str>,
        content_encoding: Option<&str>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            content_type: content_type.map(str::to_owned),
            consensus_version: consensus_version.map(str::to_owned),
            content_encoding: content_encoding.map(str::to_owned),
            body,
        }
    }
}

impl std::fmt::Debug for BeaconHttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BeaconHttpResponse")
            .field("status", &self.status)
            .field("content_type_present", &self.content_type.is_some())
            .field(
                "consensus_version_present",
                &self.consensus_version.is_some(),
            )
            .field("content_encoding_present", &self.content_encoding.is_some())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Injected seam for deterministic tests and daemon-owned I/O.
pub trait BeaconHttpTransport {
    fn get_ssz(
        &mut self,
        path_and_query: &str,
        maximum_response_bytes: usize,
        timeout: Duration,
    ) -> Result<BeaconHttpResponse, HttpTransportFailure>;
}

/// Redacted alias retained separately in this API to make ownership explicit.
pub type BeaconOperatorAuthorization = OperatorAuthorization;

/// Blocking transport for a dedicated gateway worker thread.
pub struct ReqwestBeaconHttpTransport {
    client: Client,
    endpoint: Url,
}

impl std::fmt::Debug for ReqwestBeaconHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReqwestBeaconHttpTransport")
            .field("endpoint", &"[REDACTED]")
            .finish()
    }
}

impl ReqwestBeaconHttpTransport {
    pub fn new(
        endpoint: &str,
        authorization: Option<BeaconOperatorAuthorization>,
        endpoint_policy: HttpEndpointPolicy,
        policy: BeaconHttpPolicy,
    ) -> Result<Self, BeaconClientError> {
        let policy = policy.validate()?;
        let endpoint = validate_beacon_endpoint(endpoint, endpoint_policy)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_BEACON));
        if let Some(authorization) = authorization {
            headers.insert(AUTHORIZATION, authorization.0);
        }
        let client = Client::builder()
            .connect_timeout(policy.connect_timeout)
            .timeout(policy.request_timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .build()
            .map_err(|_| BeaconClientError::InvalidConfiguration)?;
        Ok(Self { client, endpoint })
    }
}

impl BeaconHttpTransport for ReqwestBeaconHttpTransport {
    fn get_ssz(
        &mut self,
        path_and_query: &str,
        maximum_response_bytes: usize,
        timeout: Duration,
    ) -> Result<BeaconHttpResponse, HttpTransportFailure> {
        if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
            return Err(HttpTransportFailure::Permanent);
        }
        let mut target = self.endpoint.clone();
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
        target.set_path(path);
        target.set_query(query);
        let response = self
            .client
            .get(target)
            .timeout(timeout)
            .send()
            .map_err(|error| {
                if error.is_timeout() || error.is_connect() {
                    HttpTransportFailure::Transient
                } else {
                    HttpTransportFailure::Permanent
                }
            })?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > maximum_response_bytes as u64)
        {
            return Err(HttpTransportFailure::Oversized);
        }
        let content_type = header_text(response.headers(), CONTENT_TYPE);
        let consensus_version = header_text(response.headers(), ETH_CONSENSUS_VERSION);
        let content_encoding = header_text(response.headers(), CONTENT_ENCODING);
        let limit = u64::try_from(maximum_response_bytes)
            .map_err(|_| HttpTransportFailure::Oversized)?
            .saturating_add(1);
        let mut body = Vec::with_capacity(maximum_response_bytes.min(64 * 1024));
        response
            .take(limit)
            .read_to_end(&mut body)
            .map_err(|_| HttpTransportFailure::Transient)?;
        if body.len() > maximum_response_bytes {
            return Err(HttpTransportFailure::Oversized);
        }
        Ok(BeaconHttpResponse {
            status,
            content_type,
            consensus_version,
            content_encoding,
            body,
        })
    }
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn validate_beacon_endpoint(
    endpoint: &str,
    policy: HttpEndpointPolicy,
) -> Result<Url, BeaconClientError> {
    let mut endpoint = Url::parse(endpoint).map_err(|_| BeaconClientError::InvalidConfiguration)?;
    if endpoint.cannot_be_a_base()
        || endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(BeaconClientError::InvalidConfiguration);
    }
    match endpoint.scheme() {
        "https" => {}
        "http"
            if policy == HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
                && endpoint.host().is_some_and(is_loopback_host) => {}
        "http" => return Err(BeaconClientError::InsecureEndpoint),
        _ => return Err(BeaconClientError::InvalidConfiguration),
    }
    endpoint.set_path("");
    Ok(endpoint)
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(_) => false,
        Host::Ipv4(address) => IpAddr::V4(address).is_loopback(),
        Host::Ipv6(address) => IpAddr::V6(address).is_loopback(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BeaconClientError {
    #[error("invalid Beacon provider configuration")]
    InvalidConfiguration,
    #[error("Beacon provider endpoint requires HTTPS")]
    InsecureEndpoint,
    #[error("Beacon provider is temporarily unavailable")]
    Transient,
    #[error("Beacon provider returned invalid protocol data")]
    InvalidResponse,
    #[error("Beacon provider response exceeded a local bound")]
    SizeLimit,
    #[error("Beacon acquisition exhausted its local request or time budget")]
    AcquisitionLimit,
    #[error("Beacon consensus did not verify from the configured checkpoint")]
    VerificationFailed,
    #[error("Beacon bootstrap epoch does not match the operator-supplied epoch")]
    CheckpointEpochMismatch,
    #[error("Beacon consensus would roll back locally verified state")]
    Rollback,
    #[error("Beacon consensus conflicts with locally verified state")]
    Conflict,
    #[error("Beacon finalized state is stale or ahead of the trusted clock")]
    ClockPolicy,
    #[error("execution header did not match Beacon-verified consensus")]
    ExecutionMismatch,
}

/// Consensus bytes proven from the constructor-supplied checkpoint.
pub struct VerifiedBeaconConsensus {
    input: UntrustedConsensusRpcInput,
    verified: VerifiedExecutionHeader,
}

impl VerifiedBeaconConsensus {
    pub fn finalized_slot(&self) -> u64 {
        self.verified.finalized_slot()
    }

    pub fn execution_block_hash(&self) -> [u8; 32] {
        self.verified.execution_block_hash()
    }

    pub fn consensus_input(&self) -> &UntrustedConsensusRpcInput {
        &self.input
    }
}

impl std::fmt::Debug for VerifiedBeaconConsensus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedBeaconConsensus")
            .field("finalized_slot", &self.finalized_slot())
            .field("updates_count", &self.input.updates_ssz.len())
            .finish_non_exhaustive()
    }
}

/// Stateful client which rejects rollback and same-slot conflicts.
pub struct BeaconConsensusClient<T, C> {
    checkpoint: BeaconCheckpointRoot,
    transport: T,
    clock: C,
    policy: BeaconHttpPolicy,
    last_verified: Option<(u64, [u8; 32])>,
}

impl<T, C> std::fmt::Debug for BeaconConsensusClient<T, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BeaconConsensusClient")
            .field("policy", &self.policy)
            .field(
                "last_verified_slot",
                &self.last_verified.map(|value| value.0),
            )
            .finish_non_exhaustive()
    }
}

impl<T, C> BeaconConsensusClient<T, C>
where
    T: BeaconHttpTransport,
    C: UnixClock,
{
    pub fn new(
        checkpoint: BeaconCheckpointRoot,
        transport: T,
        clock: C,
        policy: BeaconHttpPolicy,
    ) -> Result<Self, BeaconClientError> {
        Ok(Self {
            checkpoint,
            transport,
            clock,
            policy: policy.validate()?,
            last_verified: None,
        })
    }

    /// Restores a locally persisted monotonicity floor produced by an earlier
    /// instance of this same checkpoint-pinned client.
    pub(crate) fn restore_monotonic_floor(
        &mut self,
        finalized_slot: u64,
        execution_block_hash: [u8; 32],
    ) -> Result<(), BeaconClientError> {
        if finalized_slot == 0 || execution_block_hash == [0; 32] || self.last_verified.is_some() {
            return Err(BeaconClientError::InvalidConfiguration);
        }
        self.last_verified = Some((finalized_slot, execution_block_hash));
        Ok(())
    }

    pub fn acquire_consensus(&mut self) -> Result<VerifiedBeaconConsensus, BeaconClientError> {
        let now_unix = self
            .clock
            .now_unix()
            .map_err(|_| BeaconClientError::ClockPolicy)?;
        let started_at_unix = now_unix;
        let mut request_count = 0_usize;
        let current_slot =
            sepolia_slot_at_unix(now_unix).map_err(|_| BeaconClientError::ClockPolicy)?;
        let root = hex_root(self.checkpoint.beacon_block_root());
        let bootstrap = self.fetch(
            &format!("/eth/v1/beacon/light_client/bootstrap/{root}"),
            self.policy.maximum_bootstrap_bytes,
            true,
            started_at_unix,
            &mut request_count,
        )?;
        let bootstrap_encoding =
            response_encoding(&bootstrap).ok_or(BeaconClientError::InvalidResponse)?;
        let bootstrap_version = if bootstrap_encoding == BeaconResponseEncoding::Ssz {
            Some(one_version(&bootstrap)?.to_owned())
        } else {
            None
        };
        let mut total_bytes = bootstrap.body.len();
        let bootstrap_body =
            consensus_response_payload(bootstrap, self.policy.maximum_bootstrap_bytes)?;
        let bootstrap_input = UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: now_unix,
            bootstrap_ssz: bootstrap_body.clone(),
            updates_ssz: Vec::new(),
            finality_update_ssz: None,
        };
        let bootstrap_wire = encode_consensus_bootstrap(&bootstrap_input)
            .map_err(|_| BeaconClientError::VerificationFailed)?;
        let bootstrap_verified = Verifier::sepolia()
            .verify_consensus_bootstrap_at_unix(&bootstrap_wire, &self.checkpoint, now_unix)
            .map_err(|_| {
                tracing::warn!(
                    stage = "checkpoint_bootstrap_verification",
                    "Ethereum Beacon consensus verification failed"
                );
                BeaconClientError::VerificationFailed
            })?;
        if bootstrap_version
            .as_deref()
            .is_some_and(|version| version != fork_for_slot(bootstrap_verified.finalized_slot()))
        {
            return Err(BeaconClientError::InvalidResponse);
        }

        let start_period =
            bootstrap_verified.finalized_slot() / SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        let current_period = current_slot / SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        let requested_periods = current_period
            .checked_sub(start_period)
            .and_then(|value| value.checked_add(1))
            .ok_or(BeaconClientError::ClockPolicy)?;
        if requested_periods > self.policy.maximum_updates as u64 {
            return Err(BeaconClientError::SizeLimit);
        }
        let mut updates = Vec::new();
        let mut period = start_period;
        let mut remaining = requested_periods as usize;
        while remaining > 0 {
            let count = remaining.min(self.policy.maximum_updates_per_request);
            let response = self.fetch(
                &format!("/eth/v1/beacon/light_client/updates?start_period={period}&count={count}"),
                self.policy.maximum_update_response_bytes,
                false,
                started_at_unix,
                &mut request_count,
            )?;
            let raw_response_len = response.body.len();
            let mut batch = split_update_response(&response, period, count)?;
            if batch.len() > count || updates.len() + batch.len() > self.policy.maximum_updates {
                return Err(BeaconClientError::InvalidResponse);
            }
            total_bytes = checked_total(
                total_bytes,
                raw_response_len,
                self.policy.maximum_total_bytes,
            )?;
            let advanced = batch.len();
            updates.append(&mut batch);
            period = period
                .checked_add(advanced as u64)
                .ok_or(BeaconClientError::SizeLimit)?;
            remaining -= advanced;
        }

        let finality = self.fetch(
            "/eth/v1/beacon/light_client/finality_update",
            self.policy.maximum_finality_update_bytes,
            true,
            started_at_unix,
            &mut request_count,
        )?;
        let finality_encoding =
            response_encoding(&finality).ok_or(BeaconClientError::InvalidResponse)?;
        let finality_version = if finality_encoding == BeaconResponseEncoding::Ssz {
            Some(one_version(&finality)?.to_owned())
        } else {
            None
        };
        total_bytes = checked_total(
            total_bytes,
            finality.body.len(),
            self.policy.maximum_total_bytes,
        )?;
        let _ = total_bytes;
        let finality_body =
            consensus_response_payload(finality, self.policy.maximum_finality_update_bytes)?;
        let input = UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: now_unix,
            bootstrap_ssz: bootstrap_body,
            updates_ssz: updates,
            finality_update_ssz: Some(finality_body),
        };
        let wire = encode_consensus_bootstrap(&input)
            .map_err(|_| BeaconClientError::VerificationFailed)?;
        let verified = Verifier::sepolia()
            .verify_consensus_bootstrap_at_unix(&wire, &self.checkpoint, now_unix)
            .map_err(|_| {
                tracing::warn!(
                    stage = "consensus_update_verification",
                    "Ethereum Beacon consensus verification failed"
                );
                BeaconClientError::VerificationFailed
            })?;
        if finality_version
            .as_deref()
            .is_some_and(|version| version != fork_for_slot(verified.finalized_slot()))
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        let finalized_at = verified
            .finalized_at_unix()
            .map_err(|_| BeaconClientError::ClockPolicy)?;
        validate_finalized_clock(now_unix, finalized_at, self.policy.maximum_finalized_age)?;
        self.admit_monotonic(verified.finalized_slot(), verified.execution_block_hash())?;
        Ok(VerifiedBeaconConsensus { input, verified })
    }

    /// Fetches only the bounded Beacon bootstrap and emits an RSETHCF1 card.
    /// The checkpoint root and expected epoch are constructor/caller inputs;
    /// neither can be selected by the HTTP response. The returned card remains
    /// an untrusted manual candidate until a field node's native approval flow
    /// installs it.
    pub fn acquire_checkpoint_card(
        &mut self,
        expected_epoch: u64,
    ) -> Result<BeaconCheckpointCard, BeaconClientError> {
        if expected_epoch == 0 {
            return Err(BeaconClientError::InvalidConfiguration);
        }
        let now_unix = self
            .clock
            .now_unix()
            .map_err(|_| BeaconClientError::ClockPolicy)?;
        let mut request_count = 0_usize;
        let root = hex_root(self.checkpoint.beacon_block_root());
        let response = self.fetch(
            &format!("/eth/v1/beacon/light_client/bootstrap/{root}"),
            self.policy.maximum_bootstrap_bytes,
            true,
            now_unix,
            &mut request_count,
        )?;
        let encoding = response_encoding(&response).ok_or(BeaconClientError::InvalidResponse)?;
        let version = if encoding == BeaconResponseEncoding::Ssz {
            Some(one_version(&response)?.to_owned())
        } else {
            None
        };
        let payload = consensus_response_payload(response, self.policy.maximum_bootstrap_bytes)?;
        let input = UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: now_unix,
            bootstrap_ssz: payload,
            updates_ssz: Vec::new(),
            finality_update_ssz: None,
        };
        let bootstrap_bundle = encode_consensus_bootstrap(&input)
            .map_err(|_| BeaconClientError::VerificationFailed)?;
        let verified = Verifier::sepolia()
            .verify_consensus_bootstrap_at_unix(&bootstrap_bundle, &self.checkpoint, now_unix)
            .map_err(|_| BeaconClientError::VerificationFailed)?;
        if version
            .as_deref()
            .is_some_and(|value| value != fork_for_slot(verified.finalized_slot()))
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        let epoch = verified.finalized_slot() / SEPOLIA_SLOTS_PER_EPOCH;
        if epoch != expected_epoch {
            return Err(BeaconClientError::CheckpointEpochMismatch);
        }
        let bytes = encode_manual_checkpoint_file(
            expected_epoch,
            self.checkpoint.beacon_block_root(),
            &bootstrap_bundle,
        )
        .map_err(|_| BeaconClientError::VerificationFailed)?;
        let fingerprint = manual_checkpoint_file_fingerprint(&bytes);
        Ok(BeaconCheckpointCard {
            checkpoint_epoch: expected_epoch,
            checkpoint_root: self.checkpoint.beacon_block_root(),
            bytes,
            fingerprint,
        })
    }

    pub fn acquire_builder(
        &mut self,
        execution: &UntrustedExecutionHeaderRpcInput,
    ) -> Result<SepoliaGatewayBuilder, BeaconClientError> {
        let consensus = self.acquire_consensus()?;
        SepoliaGatewayBuilder::from_untrusted_rpc_at_unix(
            &self.checkpoint,
            consensus.consensus_input(),
            execution,
            consensus.input.captured_at_unix,
        )
        .map_err(|error| match error {
            GatewayBuildError::LocalVerificationFailed => BeaconClientError::ExecutionMismatch,
            _ => BeaconClientError::InvalidResponse,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn fetch(
        &mut self,
        path: &str,
        cap: usize,
        require_consensus_version: bool,
        started_at_unix: u64,
        request_count: &mut usize,
    ) -> Result<BeaconHttpResponse, BeaconClientError> {
        if *request_count >= self.policy.maximum_requests {
            return Err(BeaconClientError::AcquisitionLimit);
        }
        let now_unix = self
            .clock
            .now_unix()
            .map_err(|_| BeaconClientError::ClockPolicy)?;
        let elapsed = now_unix
            .checked_sub(started_at_unix)
            .ok_or(BeaconClientError::ClockPolicy)?;
        let remaining = self
            .policy
            .maximum_acquisition_duration
            .checked_sub(Duration::from_secs(elapsed))
            .filter(|duration| !duration.is_zero())
            .ok_or(BeaconClientError::AcquisitionLimit)?;
        let timeout = self.policy.request_timeout.min(remaining);
        *request_count += 1;
        let response =
            self.transport
                .get_ssz(path, cap, timeout)
                .map_err(|failure| match failure {
                    HttpTransportFailure::Transient => BeaconClientError::Transient,
                    HttpTransportFailure::Permanent => BeaconClientError::InvalidResponse,
                    HttpTransportFailure::Oversized => BeaconClientError::SizeLimit,
                })?;
        if response.body.len() > cap {
            return Err(BeaconClientError::SizeLimit);
        }
        if response.status != 200
            || response.content_encoding.is_some()
            || response_encoding(&response).is_none()
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        if response_encoding(&response) == Some(BeaconResponseEncoding::Ssz)
            && require_consensus_version
            && response.consensus_version.is_none()
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        if response
            .content_type
            .as_ref()
            .is_some_and(|value| value.len() > 64)
            || response
                .consensus_version
                .as_ref()
                .is_some_and(|value| value.len() > 32)
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        if let Some(version) = response.consensus_version.as_deref() {
            let mut versions = version.split(',');
            versions
                .next()
                .filter(|value| matches!(*value, "electra" | "fulu"))
                .ok_or(BeaconClientError::InvalidResponse)?;
            let mut count = 1_usize;
            for value in versions {
                if !matches!(value, "electra" | "fulu") {
                    return Err(BeaconClientError::InvalidResponse);
                }
                count = count.checked_add(1).ok_or(BeaconClientError::SizeLimit)?;
            }
            if require_consensus_version && count != 1
                || count > self.policy.maximum_updates_per_request
            {
                return Err(BeaconClientError::InvalidResponse);
            }
        }
        Ok(response)
    }

    fn admit_monotonic(
        &mut self,
        slot: u64,
        block_hash: [u8; 32],
    ) -> Result<(), BeaconClientError> {
        if let Some((previous_slot, previous_hash)) = self.last_verified {
            if slot < previous_slot {
                return Err(BeaconClientError::Rollback);
            }
            if slot == previous_slot && block_hash != previous_hash {
                return Err(BeaconClientError::Conflict);
            }
        }
        self.last_verified = Some((slot, block_hash));
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeaconResponseEncoding {
    Ssz,
    Json,
}

fn response_encoding(response: &BeaconHttpResponse) -> Option<BeaconResponseEncoding> {
    match response.content_type.as_deref()? {
        ACCEPT_SSZ => Some(BeaconResponseEncoding::Ssz),
        ACCEPT_JSON | "application/json; charset=utf-8" => Some(BeaconResponseEncoding::Json),
        _ => None,
    }
}

fn consensus_response_payload(
    response: BeaconHttpResponse,
    maximum_payload_bytes: usize,
) -> Result<Vec<u8>, BeaconClientError> {
    let encoded = match response_encoding(&response) {
        Some(BeaconResponseEncoding::Ssz) => response.body,
        Some(BeaconResponseEncoding::Json) => {
            tag_beacon_json_payload(&response.body).map_err(|error| match error {
                ratspeak_eth_verifier::VerifyError::ConsensusJsonLimit => {
                    BeaconClientError::SizeLimit
                }
                _ => BeaconClientError::InvalidResponse,
            })?
        }
        None => return Err(BeaconClientError::InvalidResponse),
    };
    if encoded.len() > maximum_payload_bytes {
        return Err(BeaconClientError::SizeLimit);
    }
    Ok(encoded)
}

fn checked_total(current: usize, added: usize, cap: usize) -> Result<usize, BeaconClientError> {
    let total = current
        .checked_add(added)
        .ok_or(BeaconClientError::SizeLimit)?;
    if total > cap {
        return Err(BeaconClientError::SizeLimit);
    }
    Ok(total)
}

fn validate_finalized_clock(
    now_unix: u64,
    finalized_at_unix: u64,
    maximum_age: Duration,
) -> Result<(), BeaconClientError> {
    let age = now_unix.checked_sub(finalized_at_unix).ok_or_else(|| {
        tracing::warn!(
            stage = "finalized_clock_future",
            now_unix,
            finalized_at_unix,
            "Ethereum Beacon consensus clock policy failed"
        );
        BeaconClientError::ClockPolicy
    })?;
    if age > maximum_age.as_secs() {
        tracing::warn!(
            stage = "finalized_clock_stale",
            age_seconds = age,
            maximum_age_seconds = maximum_age.as_secs(),
            "Ethereum Beacon consensus clock policy failed"
        );
        return Err(BeaconClientError::ClockPolicy);
    }
    Ok(())
}

fn one_version(response: &BeaconHttpResponse) -> Result<&str, BeaconClientError> {
    let version = response
        .consensus_version
        .as_deref()
        .ok_or(BeaconClientError::InvalidResponse)?;
    if version.contains(',') || !matches!(version, "electra" | "fulu") {
        return Err(BeaconClientError::InvalidResponse);
    }
    Ok(version)
}

fn split_update_response(
    response: &BeaconHttpResponse,
    expected_first_period: u64,
    maximum_updates: usize,
) -> Result<Vec<Vec<u8>>, BeaconClientError> {
    if response_encoding(response) == Some(BeaconResponseEncoding::Json) {
        let updates = split_and_tag_beacon_json_updates(&response.body, maximum_updates).map_err(
            |error| match error {
                ratspeak_eth_verifier::VerifyError::ConsensusJsonLimit => {
                    BeaconClientError::SizeLimit
                }
                _ => BeaconClientError::InvalidResponse,
            },
        )?;
        validate_update_periods(&updates, expected_first_period)?;
        return Ok(updates);
    }
    let mut cursor = response.body.as_slice();
    let mut updates = Vec::new();
    let mut expected_period = expected_first_period;
    while !cursor.is_empty() {
        let length_bytes: [u8; 8] = cursor
            .get(..8)
            .ok_or(BeaconClientError::InvalidResponse)?
            .try_into()
            .map_err(|_| BeaconClientError::InvalidResponse)?;
        cursor = &cursor[8..];
        let length = usize::try_from(u64::from_le_bytes(length_bytes))
            .map_err(|_| BeaconClientError::SizeLimit)?;
        if length <= 4 || length > cursor.len() {
            return Err(BeaconClientError::InvalidResponse);
        }
        let chunk = &cursor[..length];
        let payload = &chunk[4..];
        let attested_slot = sepolia_consensus_update_slot(payload)
            .map_err(|_| BeaconClientError::InvalidResponse)?;
        let period = attested_slot / SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        if chunk[..4] != expected_sepolia_fork_digest(attested_slot / 32)
            || period != expected_period
        {
            return Err(BeaconClientError::InvalidResponse);
        }
        updates.push(payload.to_vec());
        cursor = &cursor[length..];
        expected_period = expected_period
            .checked_add(1)
            .ok_or(BeaconClientError::SizeLimit)?;
    }
    if updates.is_empty() {
        return Err(BeaconClientError::InvalidResponse);
    }
    if let Some(versions) = response.consensus_version.as_deref() {
        let versions = versions.split(',').collect::<Vec<_>>();
        if versions.len() != updates.len()
            || versions.iter().zip(&updates).any(|(version, update)| {
                sepolia_consensus_update_slot(update)
                    .map(|slot| *version != fork_for_slot(slot))
                    .unwrap_or(true)
            })
        {
            return Err(BeaconClientError::InvalidResponse);
        }
    }
    Ok(updates)
}

fn validate_update_periods(
    updates: &[Vec<u8>],
    expected_first_period: u64,
) -> Result<(), BeaconClientError> {
    let mut expected_period = expected_first_period;
    for update in updates {
        let slot = sepolia_consensus_update_slot(update)
            .map_err(|_| BeaconClientError::InvalidResponse)?;
        if slot / SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD != expected_period {
            return Err(BeaconClientError::InvalidResponse);
        }
        expected_period = expected_period
            .checked_add(1)
            .ok_or(BeaconClientError::SizeLimit)?;
    }
    Ok(())
}

fn expected_sepolia_fork_digest(epoch: u64) -> [u8; 4] {
    let version = match epoch {
        0..50 => [0x90, 0, 0, 0x69],
        50..100 => [0x90, 0, 0, 0x70],
        100..56_832 => [0x90, 0, 0, 0x71],
        56_832..132_608 => [0x90, 0, 0, 0x72],
        132_608..222_464 => [0x90, 0, 0, 0x73],
        222_464..272_640 => [0x90, 0, 0, 0x74],
        _ => [0x90, 0, 0, 0x75],
    };
    let mut fork_data = [0_u8; 64];
    fork_data[..4].copy_from_slice(&version);
    fork_data[32..].copy_from_slice(&SEPOLIA_GENESIS_VALIDATORS_ROOT);
    let mut digest: [u8; 32] = Sha256::digest(fork_data).into();
    if epoch >= 272_640 {
        let (blob_epoch, maximum_blobs) = match epoch {
            0..274_176 => (222_464_u64, 9_u64),
            274_176..275_712 => (274_176, 15),
            _ => (275_712, 21),
        };
        let mut parameters = [0_u8; 16];
        parameters[..8].copy_from_slice(&blob_epoch.to_le_bytes());
        parameters[8..].copy_from_slice(&maximum_blobs.to_le_bytes());
        let parameter_hash = Sha256::digest(parameters);
        for (byte, mask) in digest.iter_mut().zip(parameter_hash) {
            *byte ^= mask;
        }
    }
    digest[..4].try_into().expect("four-byte prefix")
}

fn fork_for_slot(slot: u64) -> &'static str {
    let epoch = slot / 32;
    if epoch >= 272_640 { "fulu" } else { "electra" }
}

fn hex_root(root: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for byte in root {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use base64::Engine;

    use super::*;
    use crate::GatewayProviderFailure;

    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];
    const CAPTURED_AT_UNIX: u64 = 1_788_034_160;

    fn decode(value: &str) -> Vec<u8> {
        let compact: String = value
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .unwrap()
    }

    fn bootstrap() -> Vec<u8> {
        decode(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-bootstrap-343888.ssz.b64"
        ))
    }

    fn finality() -> Vec<u8> {
        decode(include_str!(
            "../tests/fixtures/sepolia-finality-2026-08-29.ssz.b64"
        ))
    }

    fn updates_1343_1344() -> Vec<u8> {
        include_bytes!("../tests/fixtures/sepolia-updates-1343-1344.ssz").to_vec()
    }

    fn update_1345() -> Vec<u8> {
        include_bytes!("../tests/fixtures/sepolia-update-1345.ssz").to_vec()
    }

    fn response(version: &str, body: Vec<u8>) -> BeaconHttpResponse {
        BeaconHttpResponse::new(200, Some(ACCEPT_SSZ), Some(version), None, body)
    }

    fn update_response(body: Vec<u8>) -> BeaconHttpResponse {
        BeaconHttpResponse::new(200, Some(ACCEPT_SSZ), None, None, body)
    }

    fn json_response(body: &[u8]) -> BeaconHttpResponse {
        BeaconHttpResponse::new(200, Some(ACCEPT_JSON), None, None, body.to_vec())
    }

    #[derive(Debug)]
    struct ScriptedTransport {
        replies: VecDeque<Result<BeaconHttpResponse, HttpTransportFailure>>,
        requests: Vec<String>,
        ignore_consumer_cap: bool,
    }

    impl ScriptedTransport {
        fn new(replies: impl IntoIterator<Item = BeaconHttpResponse>) -> Self {
            Self {
                replies: replies.into_iter().map(Ok).collect(),
                requests: Vec::new(),
                ignore_consumer_cap: false,
            }
        }
    }

    impl BeaconHttpTransport for ScriptedTransport {
        fn get_ssz(
            &mut self,
            path_and_query: &str,
            maximum_response_bytes: usize,
            _timeout: Duration,
        ) -> Result<BeaconHttpResponse, HttpTransportFailure> {
            self.requests.push(path_and_query.to_owned());
            let response = self
                .replies
                .pop_front()
                .unwrap_or(Err(HttpTransportFailure::Permanent))?;
            if !self.ignore_consumer_cap && response.body.len() > maximum_response_bytes {
                return Err(HttpTransportFailure::Oversized);
            }
            Ok(response)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(u64);

    impl UnixClock for FixedClock {
        fn now_unix(&self) -> Result<u64, GatewayProviderFailure> {
            Ok(self.0)
        }
    }

    fn client_with(
        replies: impl IntoIterator<Item = BeaconHttpResponse>,
    ) -> BeaconConsensusClient<ScriptedTransport, FixedClock> {
        let mut policy = BeaconHttpPolicy::conservative();
        // The captured public Sepolia provider was 17 minutes behind its wall
        // clock; admit it only under this explicit test policy.
        policy.maximum_finalized_age = Duration::from_secs(20 * 60);
        BeaconConsensusClient::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            ScriptedTransport::new(replies),
            FixedClock(CAPTURED_AT_UNIX),
            policy,
        )
        .unwrap()
    }

    fn successful_responses() -> [BeaconHttpResponse; 4] {
        [
            response("fulu", bootstrap()),
            response("fulu,fulu", updates_1343_1344()),
            response("fulu", update_1345()),
            response("fulu", finality()),
        ]
    }

    #[test]
    fn update_version_list_is_exactly_bound_to_framed_updates() {
        let accepted = response("fulu,fulu", updates_1343_1344());
        assert_eq!(split_update_response(&accepted, 1343, 2).unwrap().len(), 2);

        for version in ["fulu", "fulu,electra", "fulu,fulu,fulu"] {
            let rejected = response(version, updates_1343_1344());
            assert_eq!(
                split_update_response(&rejected, 1343, 2),
                Err(BeaconClientError::InvalidResponse)
            );
        }
    }

    #[test]
    fn captured_bootstrap_updates_and_finality_verify_from_configured_root() {
        let mut client = client_with(successful_responses());
        let consensus = client.acquire_consensus().unwrap();
        assert_eq!(consensus.finalized_slot(), 11_024_959);
        assert_ne!(consensus.execution_block_hash(), [0; 32]);
        let transport = client.into_transport();
        assert_eq!(transport.requests.len(), 4);
        assert!(transport.requests[0].ends_with(&hex_root(CHECKPOINT_ROOT)));
        assert_eq!(
            transport.requests[1],
            "/eth/v1/beacon/light_client/updates?start_period=1343&count=3"
        );
        assert_eq!(
            transport.requests[2],
            "/eth/v1/beacon/light_client/updates?start_period=1345&count=1"
        );
        assert_eq!(
            transport.requests[3],
            "/eth/v1/beacon/light_client/finality_update"
        );
    }

    #[test]
    fn checkpoint_card_fetches_only_bootstrap_and_is_byte_stable() {
        let mut client = client_with([response("fulu", bootstrap())]);
        let card = client.acquire_checkpoint_card(343_888).unwrap();
        assert_eq!(card.checkpoint_epoch(), 343_888);
        assert_eq!(card.checkpoint_root(), CHECKPOINT_ROOT);
        let expected_fingerprint =
            ratspeak_eth_verifier::manual_checkpoint_file_fingerprint(card.bytes());
        assert_eq!(card.fingerprint(), expected_fingerprint);
        let parsed = ratspeak_eth_verifier::ManualCheckpointFile::parse(card.bytes()).unwrap();
        assert_eq!(parsed.checkpoint_epoch(), card.checkpoint_epoch());
        assert_eq!(parsed.checkpoint_root(), card.checkpoint_root());
        assert_eq!(parsed.encode(), card.bytes());
        let transport = client.into_transport();
        assert_eq!(transport.requests.len(), 1);
        assert!(transport.requests[0].ends_with(&hex_root(CHECKPOINT_ROOT)));
    }

    #[test]
    fn checkpoint_card_requires_operator_epoch_and_root() {
        let mut wrong_epoch = client_with([response("fulu", bootstrap())]);
        assert_eq!(
            wrong_epoch.acquire_checkpoint_card(343_889).unwrap_err(),
            BeaconClientError::CheckpointEpochMismatch
        );

        let mut zero_epoch = client_with([response("fulu", bootstrap())]);
        assert_eq!(
            zero_epoch.acquire_checkpoint_card(0).unwrap_err(),
            BeaconClientError::InvalidConfiguration
        );

        let mut wrong_root = BeaconConsensusClient::new(
            BeaconCheckpointRoot::sepolia([0x55; 32]),
            ScriptedTransport::new([response("fulu", bootstrap())]),
            FixedClock(CAPTURED_AT_UNIX),
            BeaconHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            wrong_root.acquire_checkpoint_card(343_888).unwrap_err(),
            BeaconClientError::VerificationFailed
        );
    }

    #[test]
    fn checkpoint_card_reuses_hardened_response_contracts() {
        for response in [
            BeaconHttpResponse::new(302, Some(ACCEPT_SSZ), Some("fulu"), None, bootstrap()),
            BeaconHttpResponse::new(
                200,
                Some(ACCEPT_SSZ),
                Some("fulu"),
                Some("gzip"),
                bootstrap(),
            ),
        ] {
            let mut client = client_with([response]);
            assert!(matches!(
                client.acquire_checkpoint_card(343_888),
                Err(BeaconClientError::InvalidResponse | BeaconClientError::VerificationFailed)
            ));
        }
    }

    #[test]
    fn downloaded_bootstrap_cannot_replace_wrong_configured_root() {
        let mut client = BeaconConsensusClient::new(
            BeaconCheckpointRoot::sepolia([0x55; 32]),
            ScriptedTransport::new(successful_responses()),
            FixedClock(CAPTURED_AT_UNIX),
            BeaconHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            client.acquire_consensus().unwrap_err(),
            BeaconClientError::VerificationFailed
        );
    }

    #[test]
    fn protocol_headers_status_redirects_and_content_encoding_fail_closed() {
        let cases = [
            BeaconHttpResponse::new(302, Some(ACCEPT_SSZ), Some("fulu"), None, bootstrap()),
            BeaconHttpResponse::new(
                200,
                Some("application/json"),
                Some("fulu"),
                None,
                bootstrap(),
            ),
            BeaconHttpResponse::new(200, Some(ACCEPT_SSZ), Some("deneb"), None, bootstrap()),
            BeaconHttpResponse::new(
                200,
                Some(ACCEPT_SSZ),
                Some("fulu"),
                Some("gzip"),
                bootstrap(),
            ),
        ];
        for bad_bootstrap in cases {
            let mut client = client_with([bad_bootstrap]);
            assert!(matches!(
                client.acquire_consensus(),
                Err(BeaconClientError::InvalidResponse | BeaconClientError::VerificationFailed)
            ));
        }
    }

    #[test]
    fn json_transport_is_explicitly_tagged_and_structurally_bounded() {
        let mut client = client_with([json_response(br#"{"version":"fulu","data":{}}"#)]);
        let mut request_count = 0;
        let response = client
            .fetch(
                "/eth/v1/beacon/light_client/bootstrap/ignored",
                1024,
                true,
                CAPTURED_AT_UNIX,
                &mut request_count,
            )
            .unwrap();
        let tagged = consensus_response_payload(response, 1024).unwrap();
        assert!(tagged.starts_with(b"RSJSON1\0"));

        let duplicate = json_response(br#"{"version":"fulu","version":"electra","data":{}}"#);
        assert_eq!(
            consensus_response_payload(duplicate, 1024).unwrap_err(),
            BeaconClientError::InvalidResponse
        );

        let too_many =
            json_response(br#"[{"version":"fulu","data":{}},{"version":"fulu","data":{}}]"#);
        assert_eq!(
            split_update_response(&too_many, 1343, 1).unwrap_err(),
            BeaconClientError::SizeLimit
        );
    }

    #[test]
    #[ignore = "operator opt-in: requires RSETH_CONSENSUS_RPC_URL and RSETH_CHECKPOINT_ROOT"]
    fn live_sepolia_beacon_json_verifies_from_operator_checkpoint() {
        use crate::provider::SystemUnixClock;

        let endpoint = std::env::var("RSETH_CONSENSUS_RPC_URL")
            .expect("RSETH_CONSENSUS_RPC_URL must be set for this ignored test");
        let encoded_root = std::env::var("RSETH_CHECKPOINT_ROOT")
            .expect("RSETH_CHECKPOINT_ROOT must be set for this ignored test");
        let encoded_root = encoded_root
            .strip_prefix("0x")
            .expect("checkpoint root must use the 0x prefix");
        assert_eq!(
            encoded_root.len(),
            64,
            "checkpoint root must contain 32 bytes"
        );
        let mut root = [0_u8; 32];
        for (index, byte) in root.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded_root[index * 2..index * 2 + 2], 16)
                .expect("checkpoint root must be lowercase or uppercase hexadecimal");
        }
        let mut policy = BeaconHttpPolicy::conservative();
        // The operator opted into this endpoint check. Some public providers
        // trail wall-clock finality by slightly more than the production
        // default, so the test makes its 20-minute freshness policy explicit.
        policy.maximum_finalized_age = Duration::from_secs(20 * 60);
        let mut bootstrap_transport =
            ReqwestBeaconHttpTransport::new(&endpoint, None, HttpEndpointPolicy::HttpsOnly, policy)
                .unwrap();
        let checkpoint = BeaconCheckpointRoot::sepolia(root);
        let bootstrap_response = bootstrap_transport
            .get_ssz(
                &format!(
                    "/eth/v1/beacon/light_client/bootstrap/{}",
                    hex_root(checkpoint.beacon_block_root())
                ),
                policy.maximum_bootstrap_bytes,
                policy.request_timeout,
            )
            .unwrap();
        let bootstrap_payload =
            consensus_response_payload(bootstrap_response, policy.maximum_bootstrap_bytes).unwrap();
        let now = SystemUnixClock.now_unix().unwrap();
        let bootstrap_wire = encode_consensus_bootstrap(&UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: now,
            bootstrap_ssz: bootstrap_payload,
            updates_ssz: Vec::new(),
            finality_update_ssz: None,
        })
        .unwrap();
        Verifier::sepolia()
            .verify_consensus_bootstrap_at_unix(&bootstrap_wire, &checkpoint, now)
            .expect("live JSON bootstrap must verify from the operator checkpoint");

        let transport =
            ReqwestBeaconHttpTransport::new(&endpoint, None, HttpEndpointPolicy::HttpsOnly, policy)
                .unwrap();
        let mut client =
            BeaconConsensusClient::new(checkpoint, transport, SystemUnixClock, policy).unwrap();
        let verified = client.acquire_consensus().unwrap();
        assert_ne!(verified.execution_block_hash(), [0; 32]);
    }

    #[test]
    fn consumer_rechecks_caps_even_if_injected_transport_does_not() {
        let mut policy = BeaconHttpPolicy::conservative();
        policy.maximum_bootstrap_bytes = 32;
        let mut transport = ScriptedTransport::new([response("fulu", bootstrap())]);
        transport.ignore_consumer_cap = true;
        let mut client = BeaconConsensusClient::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            transport,
            FixedClock(CAPTURED_AT_UNIX),
            policy,
        )
        .unwrap();
        assert_eq!(
            client.acquire_consensus().unwrap_err(),
            BeaconClientError::SizeLimit
        );
    }

    #[test]
    fn truncated_finality_and_update_framing_fail_closed() {
        let mut truncated_finality = finality();
        truncated_finality.truncate(truncated_finality.len() - 1);
        let mut client = client_with([
            response("fulu", bootstrap()),
            update_response(updates_1343_1344()),
            update_response(update_1345()),
            response("fulu", truncated_finality),
        ]);
        assert_eq!(
            client.acquire_consensus().unwrap_err(),
            BeaconClientError::VerificationFailed
        );

        let malformed = update_response(vec![8, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            split_update_response(&malformed, 1343, 16).unwrap_err(),
            BeaconClientError::InvalidResponse
        );
    }

    #[test]
    fn stale_and_future_clock_samples_fail_closed() {
        assert_eq!(
            validate_finalized_clock(10_000, 9_000, Duration::from_secs(999)),
            Err(BeaconClientError::ClockPolicy)
        );
        assert_eq!(
            validate_finalized_clock(9_000, 10_000, Duration::from_secs(999)),
            Err(BeaconClientError::ClockPolicy)
        );

        let mut future = client_with(successful_responses());
        future.clock = FixedClock(1_787_786_000);
        assert_eq!(
            future.acquire_consensus().unwrap_err(),
            BeaconClientError::VerificationFailed
        );
    }

    #[test]
    fn rollback_and_same_slot_conflict_are_rejected() {
        let mut client = client_with([]);
        client.admit_monotonic(20, [1; 32]).unwrap();
        assert_eq!(
            client.admit_monotonic(19, [1; 32]),
            Err(BeaconClientError::Rollback)
        );
        assert_eq!(
            client.admit_monotonic(20, [2; 32]),
            Err(BeaconClientError::Conflict)
        );
        client.admit_monotonic(20, [1; 32]).unwrap();
        client.admit_monotonic(21, [3; 32]).unwrap();
    }

    #[test]
    fn bounded_update_sequence_requires_exact_fork_digest_and_periods() {
        let response = update_response(updates_1343_1344());
        assert_eq!(split_update_response(&response, 1343, 16).unwrap().len(), 2);
        assert_eq!(
            expected_sepolia_fork_digest(344_000),
            [0x74, 0xd0, 0x14, 0x59]
        );

        let mut wrong_digest = response.clone();
        wrong_digest.body[8] ^= 1;
        assert_eq!(
            split_update_response(&wrong_digest, 1343, 16),
            Err(BeaconClientError::InvalidResponse)
        );
        assert_eq!(
            split_update_response(&response, 1344, 16),
            Err(BeaconClientError::InvalidResponse)
        );
    }

    #[test]
    fn acquisition_has_one_total_request_and_time_budget() {
        let mut policy = BeaconHttpPolicy::conservative();
        policy.maximum_requests = 3;
        let mut client = BeaconConsensusClient::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            ScriptedTransport::new(successful_responses()),
            FixedClock(CAPTURED_AT_UNIX),
            policy,
        )
        .unwrap();
        assert!(matches!(
            client.acquire_consensus(),
            Err(BeaconClientError::AcquisitionLimit)
        ));

        let mut client = client_with([response("fulu", bootstrap())]);
        let mut count = 0;
        assert_eq!(
            client.fetch(
                "/eth/v1/beacon/light_client/bootstrap/ignored",
                1024 * 1024,
                true,
                CAPTURED_AT_UNIX - 120,
                &mut count,
            ),
            Err(BeaconClientError::AcquisitionLimit)
        );
    }

    #[test]
    fn endpoint_policy_has_no_ambient_hostname_http_exception() {
        let policy = BeaconHttpPolicy::conservative();
        assert_eq!(
            ReqwestBeaconHttpTransport::new(
                "http://localhost:5052",
                None,
                HttpEndpointPolicy::AllowLoopbackHttpForDevelopment,
                policy,
            )
            .unwrap_err(),
            BeaconClientError::InsecureEndpoint
        );
        ReqwestBeaconHttpTransport::new(
            "http://127.0.0.1:5052",
            None,
            HttpEndpointPolicy::AllowLoopbackHttpForDevelopment,
            policy,
        )
        .unwrap();
        assert!(
            ReqwestBeaconHttpTransport::new(
                "https://user:secret@example.invalid",
                None,
                HttpEndpointPolicy::HttpsOnly,
                policy,
            )
            .is_err()
        );
    }
}
