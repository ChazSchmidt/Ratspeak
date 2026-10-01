//! Native, fail-closed host boundary for the standalone Ethereum gateway.
//!
//! Rathole may supervise this process, but it is not an ingress, discovery, or
//! authorization authority. The daemon is silent while no request or retained
//! work is ready.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use lxmf_core::message_api::{DeliveryMethod, LxMessage};
use lxmf_core::router::{LxmRouter, RouterConfig, RouterConfigExt};
use ratspeak_eth_gateway::{
    BeaconHttpPolicy, BeaconOperatorAuthorization, CompleteBlockReceiptProofBackend,
    GatewayAdmissionError, GatewayExecutionPolicy, GatewayExecutionProvider,
    GatewayLxmfOutboundIntent, GatewayLxmfService, GatewayLxmfServiceError,
    GatewayLxmfServiceOutcome, GatewayProviderFailure, GatewayRateLimit, HttpEndpointPolicy,
    LiveSepoliaGatewayProvider, OperatorAuthorization, ProviderHttpPolicy,
    ReqwestBeaconHttpTransport, ReqwestGatewayHttpTransport, SystemUnixClock,
    VerifiedConsensusFloor, VerifiedConsensusFloorSink,
};
use ratspeak_eth_verifier::BeaconCheckpointRoot;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use serde::Deserialize;
use zeroize::Zeroizing;

pub mod checkpoint_card;
pub mod propagation;

const LXMF_DELIVERY_ASPECT: &str = "lxmf.delivery";
const LXMF_PROPAGATION_ASPECT: &str = "lxmf.propagation";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const CONSENSUS_FLOOR_MAGIC: &[u8; 8] = b"RSETHF1\0";
const CONSENSUS_FLOOR_PAYLOAD_BYTES: usize = 8 + 32 + 8 + 32;
const CONSENSUS_FLOOR_BYTES: u64 = (CONSENSUS_FLOOR_PAYLOAD_BYTES + 32) as u64;
const MIN_SCHEDULER_INTERVAL_MS: u64 = 250;
const MAX_SCHEDULER_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DaemonError {
    #[error("gateway daemon configuration is invalid")]
    InvalidConfiguration,
    #[error("gateway daemon filesystem boundary is invalid")]
    InvalidFilesystemBoundary,
    #[error("another gateway daemon owns the configured instance")]
    AlreadyRunning,
    #[error("gateway daemon identity is unavailable")]
    IdentityUnavailable,
    #[error("gateway provider initialization failed")]
    ProviderUnavailable,
    #[error("gateway service initialization failed")]
    ServiceUnavailable,
    #[error("gateway LXMF message was rejected")]
    MessageRejected,
    #[error("gateway transport is unavailable")]
    TransportUnavailable,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayDaemonConfig {
    pub rns_config_dir: PathBuf,
    pub service_identity_path: PathBuf,
    pub durable_gateway_db: PathBuf,
    pub instance_lock_path: PathBuf,
    pub requesters: Vec<RequesterConfig>,
    pub provider: ProviderConfig,
    #[serde(default)]
    pub propagation: Option<PropagationConfig>,
    #[serde(default)]
    pub policy: DaemonPolicyConfig,
}

impl std::fmt::Debug for GatewayDaemonConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayDaemonConfig")
            .field("requester_count", &self.requesters.len())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterConfig {
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub ed25519_public_key: String,
    /// Full `X25519 || Ed25519` RNS public key. Required only when outbound
    /// propagation fallback is enabled.
    #[serde(default)]
    pub rns_public_key: Option<String>,
    /// Operator-supplied Ratspeak RSCP1 authorization card. It is public
    /// identity material, but the referenced file must remain private to stop
    /// another local user from replacing the gateway's requester authority.
    #[serde(default)]
    pub contact_card_path: Option<PathBuf>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropagationConfig {
    pub node_destination_hash: String,
    pub node_rns_public_key: String,
    pub poll_interval_seconds: u64,
    pub delivery_limit_kb: u32,
    pub maximum_messages_per_poll: usize,
    #[serde(default)]
    pub outbound_fallback: bool,
    pub node_transfer_limit_kb: u32,
    pub node_stamp_cost: u8,
}

impl std::fmt::Debug for PropagationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PropagationConfig")
            .field("poll_interval_seconds", &self.poll_interval_seconds)
            .field("delivery_limit_kb", &self.delivery_limit_kb)
            .field("maximum_messages_per_poll", &self.maximum_messages_per_poll)
            .field("outbound_fallback", &self.outbound_fallback)
            .field("node_transfer_limit_kb", &self.node_transfer_limit_kb)
            .field("node_stamp_cost", &self.node_stamp_cost)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct ValidatedPropagationConfig {
    pub node_destination_hash: [u8; 16],
    pub node_rns_public_key: [u8; 64],
    pub poll_interval: Duration,
    pub delivery_limit_kb: u32,
    pub maximum_messages_per_poll: usize,
    pub outbound_fallback: bool,
    pub node_transfer_limit_kb: u32,
    pub node_stamp_cost: u8,
}

impl std::fmt::Debug for ValidatedPropagationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedPropagationConfig")
            .field("poll_interval", &self.poll_interval)
            .field("outbound_fallback", &self.outbound_fallback)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RequesterConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequesterConfig([REDACTED])")
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Operator-approved checkpoint obtained outside the configured providers.
    pub checkpoint_root: String,
    /// Beacon epoch for the exact operator-approved checkpoint root.
    pub checkpoint_epoch: u64,
    pub consensus_floor_path: PathBuf,
    pub beacon_rpc_endpoint: String,
    pub execution_rpc_endpoint: String,
    pub beacon_authorization_path: Option<PathBuf>,
    pub execution_authorization_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_loopback_http_for_development: bool,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderConfig([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonPolicyConfig {
    pub scheduler_interval_ms: u64,
    pub window_seconds: u64,
    pub maximum_requests: u32,
    pub maximum_requested_bytes: u64,
    pub lease_seconds: u64,
    pub retry_seconds: u64,
    pub maximum_outbound_attempts: u8,
    pub outbound_retry_delay_ms: u64,
}

impl Default for DaemonPolicyConfig {
    fn default() -> Self {
        let rate = GatewayRateLimit::conservative();
        let execution = GatewayExecutionPolicy::conservative();
        Self {
            scheduler_interval_ms: 1_000,
            window_seconds: rate.window_seconds,
            maximum_requests: rate.maximum_requests,
            maximum_requested_bytes: rate.maximum_requested_bytes,
            lease_seconds: execution.lease_seconds,
            retry_seconds: execution.retry_seconds,
            maximum_outbound_attempts: 3,
            outbound_retry_delay_ms: 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundRoute {
    Opportunistic,
    Direct,
    Propagated,
}

/// Whether a propagated relay copy may be deleted after this handling attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagatedMessageDisposition {
    /// The message was durably admitted or was invalid and safe to discard.
    Resolved,
    /// Durable state may be unavailable or ambiguous; retain and retry.
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundHandlingError {
    SafeReject,
    Service(GatewayLxmfServiceError),
}

fn classify_propagated_service_error(
    error: GatewayLxmfServiceError,
) -> PropagatedMessageDisposition {
    match error {
        // Admission is the first durable write. Storage or state failure here
        // cannot establish whether the request was committed, so retain it.
        GatewayLxmfServiceError::Admission(
            GatewayAdmissionError::Storage | GatewayAdmissionError::InvalidState,
        ) => PropagatedMessageDisposition::Retry,
        // Execution begins only after admission returned a durable outcome.
        // Later failures are recoverable from retained work. Authentication,
        // malformed input, rate limits, and replay conflicts are safe rejects.
        _ => PropagatedMessageDisposition::Resolved,
    }
}

impl InboundRoute {
    fn method(self) -> DeliveryMethod {
        match self {
            Self::Opportunistic => DeliveryMethod::Opportunistic,
            Self::Direct => DeliveryMethod::Direct,
            Self::Propagated => DeliveryMethod::Propagated,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedOutboundLxmf {
    destination_hash: [u8; 16],
    packed_message: Vec<u8>,
    propagation_fallback: Option<Box<SealedOutboundLxmf>>,
}

impl std::fmt::Debug for SealedOutboundLxmf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedOutboundLxmf")
            .field("packed_len", &self.packed_message.len())
            .finish()
    }
}

impl SealedOutboundLxmf {
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }

    pub fn packed_message(&self) -> &[u8] {
        &self.packed_message
    }

    pub fn propagation_fallback(&self) -> Option<&SealedOutboundLxmf> {
        self.propagation_fallback.as_deref()
    }
}

/// A transport acknowledgement is deliberately not Ethereum evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportObservation {
    AcceptedForDelivery,
    Rejected,
    LyingAcknowledgementForTest,
}

pub trait OutboundLxmfTransport {
    fn send(&mut self, message: SealedOutboundLxmf) -> Result<TransportObservation, DaemonError>;
}

pub struct GatewayDaemon<P> {
    service: GatewayLxmfService,
    provider: P,
    router: LxmRouter,
    _database_anchor: File,
    signing_key: Ed25519PrivateKey,
    requester_keys: HashMap<[u8; 16], Ed25519PublicKey>,
    requester_rns_keys: HashMap<[u8; 16], [u8; 64]>,
    propagation: Option<ValidatedPropagationConfig>,
    scheduler_interval: Duration,
}

impl<P> std::fmt::Debug for GatewayDaemon<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayDaemon")
            .field("requester_count", &self.requester_keys.len())
            .field("scheduler_interval", &self.scheduler_interval)
            .finish_non_exhaustive()
    }
}

impl<P: GatewayExecutionProvider> GatewayDaemon<P> {
    pub fn open(
        config: &GatewayDaemonConfig,
        identity: &Identity,
        provider: P,
    ) -> Result<Self, DaemonError> {
        config.validate()?;
        ensure_private_parent(&config.durable_gateway_db)?;
        let database_anchor = if config.durable_gateway_db.exists() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&config.durable_gateway_db)
                .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
            validate_opened_private_file(&file)?;
            file
        } else {
            open_private_rw_create(&config.durable_gateway_db)?
        };
        let requesters = config.requester_keys()?;
        let requester_rns_keys = config.requester_rns_keys()?;
        let propagation = config.validated_propagation()?;
        let service_hash =
            Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
        let private = identity
            .get_private_key()
            .ok_or(DaemonError::IdentityUnavailable)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&private[32..]);
        // SQLite needs the real private pathname so WAL can create its
        // same-directory sidecars. DurableGatewayAdmission also applies
        // SQLITE_OPEN_NOFOLLOW. Keep the validated descriptor anchored and
        // recheck that the pathname still names the same inode after SQLite
        // opens it.
        let service = GatewayLxmfService::open(
            &config.durable_gateway_db,
            service_hash,
            requesters.iter().map(|(hash, key)| (*hash, key.to_bytes())),
            config.rate_limit(),
            config.execution_policy(),
        )
        .map_err(|error| {
            tracing::error!(%error, class = ?error, "Ethereum gateway durable service could not open");
            DaemonError::ServiceUnavailable
        })?;
        let anchored = validate_opened_private_file(&database_anchor)?;
        let reopened = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&config.durable_gateway_db)
            .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
        let current = validate_opened_private_file(&reopened)?;
        if anchored.dev() != current.dev() || anchored.ino() != current.ino() {
            return Err(DaemonError::InvalidFilesystemBoundary);
        }
        let router_config = RouterConfig {
            propagation_enabled: false,
            autopeer: false,
            max_peers: 0,
            ext: RouterConfigExt {
                processing_limit: Some(2),
                ..RouterConfigExt::default()
            },
            ..RouterConfig::default()
        };
        Ok(Self {
            service,
            provider,
            router: LxmRouter::new(router_config),
            _database_anchor: database_anchor,
            signing_key: Ed25519PrivateKey::from_bytes(&seed),
            requester_keys: requesters,
            requester_rns_keys,
            propagation,
            scheduler_interval: Duration::from_millis(config.policy.scheduler_interval_ms),
        })
    }

    pub fn scheduler_interval(&self) -> Duration {
        self.scheduler_interval
    }

    pub fn handle_packed<T: OutboundLxmfTransport>(
        &mut self,
        packed: &[u8],
        route: InboundRoute,
        now_unix: u64,
        transport: &mut T,
    ) -> Result<usize, DaemonError> {
        let outcome = self
            .handle_inbound(packed, route, now_unix)
            .map_err(|_| DaemonError::MessageRejected)?;
        self.dispatch(outcome, transport)
    }

    /// Handle one relay-delivered message without allowing relay deletion on
    /// an ambiguous durable-store failure. Transport failure after admission
    /// remains resolved because retained gateway work owns response recovery.
    pub fn handle_propagated_packed<T: OutboundLxmfTransport>(
        &mut self,
        packed: &[u8],
        now_unix: u64,
        transport: &mut T,
    ) -> PropagatedMessageDisposition {
        match self.handle_inbound(packed, InboundRoute::Propagated, now_unix) {
            Ok(outcome) => {
                let _ = self.dispatch(outcome, transport);
                PropagatedMessageDisposition::Resolved
            }
            Err(InboundHandlingError::SafeReject) => PropagatedMessageDisposition::Resolved,
            Err(InboundHandlingError::Service(error)) => classify_propagated_service_error(error),
        }
    }

    fn handle_inbound(
        &mut self,
        packed: &[u8],
        route: InboundRoute,
        now_unix: u64,
    ) -> Result<GatewayLxmfServiceOutcome, InboundHandlingError> {
        let mut message =
            LxMessage::unpack(packed).map_err(|_| InboundHandlingError::SafeReject)?;
        message.incoming = true;
        message.method = route.method();
        let key = self
            .requester_keys
            .get(&message.source_hash)
            .ok_or(InboundHandlingError::SafeReject)?;
        if !message.verify(key) {
            return Err(InboundHandlingError::SafeReject);
        }
        // Keep LXMF-owned ticket/dedup semantics in lxmf-core. Durable gateway
        // admission remains the authoritative duplicate/replay boundary, so a
        // duplicate still reaches the service's durable release budget.
        if !self.router.deliver_inbound(&message, true) {
            return Err(InboundHandlingError::SafeReject);
        }
        self.service
            .handle_inbound(&message, &mut self.provider, now_unix)
            .map_err(InboundHandlingError::Service)
    }

    /// Run at most one retained job. Calling this while idle emits no traffic.
    pub fn resume_once<T: OutboundLxmfTransport>(
        &mut self,
        now_unix: u64,
        transport: &mut T,
    ) -> Result<usize, DaemonError> {
        let outcome = self
            .service
            .resume_next(&mut self.provider, now_unix)
            .map_err(|error| {
                tracing::error!(%error, class = ?error, "Ethereum gateway durable work could not resume");
                DaemonError::ServiceUnavailable
            })?;
        self.dispatch(outcome, transport)
    }

    fn dispatch<T: OutboundLxmfTransport>(
        &mut self,
        outcome: GatewayLxmfServiceOutcome,
        transport: &mut T,
    ) -> Result<usize, DaemonError> {
        let GatewayLxmfServiceOutcome::Outbound(intents) = outcome else {
            return Ok(0);
        };
        let release_token = intents
            .first()
            .map(GatewayLxmfOutboundIntent::release_token)
            .ok_or(DaemonError::ServiceUnavailable)?;
        if intents
            .iter()
            .any(|intent| intent.release_token() != release_token)
        {
            return Err(DaemonError::ServiceUnavailable);
        }
        let mut sent = 0;
        for intent in intents {
            let message = self.seal(intent)?;
            // Receipts and acknowledgements intentionally do not feed back into
            // Ethereum state. Local router acceptance only closes this bounded
            // output release so a retained inbound cannot amplify traffic.
            if matches!(transport.send(message)?, TransportObservation::Rejected) {
                return Err(DaemonError::TransportUnavailable);
            }
            sent += 1;
        }
        self.service
            .acknowledge_outbound_release(release_token)
            .map_err(|_| DaemonError::ServiceUnavailable)?;
        Ok(sent)
    }

    fn seal(
        &mut self,
        intent: GatewayLxmfOutboundIntent,
    ) -> Result<SealedOutboundLxmf, DaemonError> {
        let mut message = LxMessage::new(
            intent.destination_hash(),
            intent.source_hash(),
            "",
            "",
            DeliveryMethod::Direct,
        );
        message
            .set_file_attachment_field(intent.attachment_name(), intent.attachment())
            .map_err(|_| DaemonError::MessageRejected)?;
        self.router
            .prepare_outbound(&mut message)
            .map_err(|_| DaemonError::MessageRejected)?;
        message
            .sign(&self.signing_key)
            .map_err(|_| DaemonError::IdentityUnavailable)?;
        let packed_message = message.pack().map_err(|_| DaemonError::MessageRejected)?;
        let propagation_fallback = self.prepare_propagation_fallback(&mut message)?;
        Ok(SealedOutboundLxmf {
            destination_hash: intent.destination_hash(),
            packed_message,
            propagation_fallback: propagation_fallback.map(Box::new),
        })
    }

    fn prepare_propagation_fallback(
        &self,
        message: &mut LxMessage,
    ) -> Result<Option<SealedOutboundLxmf>, DaemonError> {
        let Some(config) = self
            .propagation
            .as_ref()
            .filter(|config| config.outbound_fallback)
        else {
            return Ok(None);
        };
        let public_key = self
            .requester_rns_keys
            .get(&message.destination_hash)
            .ok_or(DaemonError::InvalidConfiguration)?;
        let requester =
            Identity::from_public_key(public_key).map_err(|_| DaemonError::InvalidConfiguration)?;
        message.method = DeliveryMethod::Propagated;
        let (packed, _, _) = message
            .pack_propagated_encrypted_with_stamp(
                |plaintext| {
                    requester.encrypt(plaintext, None).map_err(|_| {
                        lxmf_core::message_api::MessageError::PackFailed(
                            "recipient encryption failed".into(),
                        )
                    })
                },
                config.node_stamp_cost,
            )
            .map_err(|_| DaemonError::MessageRejected)?;
        if packed.len() > config.node_transfer_limit_kb as usize * 1024 {
            return Err(DaemonError::MessageRejected);
        }
        Ok(Some(SealedOutboundLxmf {
            destination_hash: config.node_destination_hash,
            packed_message: packed,
            propagation_fallback: None,
        }))
    }
}

impl GatewayDaemonConfig {
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let bytes = read_private_regular_file(path, MAX_CONFIG_BYTES)?;
        let mut config: Self =
            serde_json::from_slice(&bytes).map_err(|_| DaemonError::InvalidConfiguration)?;
        config.normalize_contact_cards()?;
        config.validate()?;
        Ok(config)
    }

    fn normalize_contact_cards(&mut self) -> Result<(), DaemonError> {
        let floor_lock = consensus_floor_lock_path(&self.provider.consensus_floor_path);
        for requester in &mut self.requesters {
            let Some(path) = requester.contact_card_path.as_deref() else {
                continue;
            };
            if !requester.source_hash.is_empty()
                || !requester.ed25519_public_key.is_empty()
                || requester.rns_public_key.is_some()
            {
                return Err(DaemonError::InvalidConfiguration);
            }
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfiguration);
            }
            if [
                &self.service_identity_path,
                &self.durable_gateway_db,
                &self.instance_lock_path,
                &self.provider.consensus_floor_path,
                &floor_lock,
            ]
            .into_iter()
            .chain(self.provider.beacon_authorization_path.iter())
            .chain(self.provider.execution_authorization_path.iter())
            .any(|private| path == private)
            {
                return Err(DaemonError::InvalidConfiguration);
            }
            let material = parse_rscp1_contact_card(&read_private_regular_file(
                path,
                MAX_CONTACT_CARD_BYTES,
            )?)?;
            requester.source_hash = hex::encode(material.source_hash);
            requester.ed25519_public_key = hex::encode(material.ed25519_public_key);
            requester.rns_public_key = material.rns_public_key.map(hex::encode);
            requester.contact_card_path = None;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), DaemonError> {
        for path in [
            &self.rns_config_dir,
            &self.service_identity_path,
            &self.durable_gateway_db,
            &self.instance_lock_path,
            &self.provider.consensus_floor_path,
        ] {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfiguration);
            }
        }
        for path in self
            .provider
            .beacon_authorization_path
            .iter()
            .chain(self.provider.execution_authorization_path.iter())
        {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfiguration);
            }
        }
        for requester in &self.requesters {
            if requester
                .contact_card_path
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                return Err(DaemonError::InvalidConfiguration);
            }
        }
        if self.requesters.is_empty()
            || self.requesters.len() > 256
            || self.policy.scheduler_interval_ms < MIN_SCHEDULER_INTERVAL_MS
            || self.policy.scheduler_interval_ms > MAX_SCHEDULER_INTERVAL_MS
            || self.policy.maximum_outbound_attempts == 0
            || self.policy.maximum_outbound_attempts > 8
            || self.policy.outbound_retry_delay_ms > 60_000
            || self.provider.beacon_rpc_endpoint.is_empty()
            || self.provider.beacon_rpc_endpoint.len() > 8 * 1024
            || self.provider.execution_rpc_endpoint.is_empty()
            || self.provider.execution_rpc_endpoint.len() > 8 * 1024
        {
            return Err(DaemonError::InvalidConfiguration);
        }
        let floor_lock_path = consensus_floor_lock_path(&self.provider.consensus_floor_path);
        if [
            &self.service_identity_path,
            &self.durable_gateway_db,
            &self.instance_lock_path,
        ]
        .iter()
        .any(|path| **path == self.provider.consensus_floor_path || **path == floor_lock_path)
            || self
                .provider
                .beacon_authorization_path
                .iter()
                .chain(self.provider.execution_authorization_path.iter())
                .any(|path| path == &self.provider.consensus_floor_path || path == &floor_lock_path)
        {
            return Err(DaemonError::InvalidConfiguration);
        }
        for requester in &self.requesters {
            if let Some(card) = requester.contact_card_path.as_ref() {
                let aliases_private_state = [
                    &self.service_identity_path,
                    &self.durable_gateway_db,
                    &self.instance_lock_path,
                    &self.provider.consensus_floor_path,
                    &floor_lock_path,
                ]
                .into_iter()
                .chain(self.provider.beacon_authorization_path.iter())
                .chain(self.provider.execution_authorization_path.iter())
                .any(|private| card == private);
                if aliases_private_state {
                    return Err(DaemonError::InvalidConfiguration);
                }
            }
        }
        self.requester_keys()?;
        self.validated_propagation()?;
        if self.provider.checkpoint_epoch == 0
            || parse_hex::<32>(&self.provider.checkpoint_root)? == [0; 32]
        {
            return Err(DaemonError::InvalidConfiguration);
        }
        Ok(())
    }

    fn requester_keys(&self) -> Result<HashMap<[u8; 16], Ed25519PublicKey>, DaemonError> {
        let mut result = HashMap::new();
        for requester in &self.requesters {
            let material = requester_public_material(requester)?;
            let source = material.source_hash;
            let key_bytes = material.ed25519_public_key;
            let key = Ed25519PublicKey::from_bytes(&key_bytes)
                .map_err(|_| DaemonError::InvalidConfiguration)?;
            if source == [0; 16] || result.insert(source, key).is_some() {
                return Err(DaemonError::InvalidConfiguration);
            }
        }
        Ok(result)
    }

    fn requester_rns_keys(&self) -> Result<HashMap<[u8; 16], [u8; 64]>, DaemonError> {
        let propagation_fallback = self
            .propagation
            .as_ref()
            .is_some_and(|config| config.outbound_fallback);
        let mut result = HashMap::new();
        for requester in &self.requesters {
            let material = requester_public_material(requester)?;
            let source = material.source_hash;
            let ed25519 = material.ed25519_public_key;
            let public_key = material.rns_public_key;
            let Some(public_key) = public_key else {
                if propagation_fallback {
                    return Err(DaemonError::InvalidConfiguration);
                }
                continue;
            };
            let identity = Identity::from_public_key(&public_key)
                .map_err(|_| DaemonError::InvalidConfiguration)?;
            let derived = Destination::hash_from_name_and_identity(
                LXMF_DELIVERY_ASPECT,
                Some(&identity.hash),
            );
            if derived != source || public_key[32..] != ed25519 {
                return Err(DaemonError::InvalidConfiguration);
            }
            result.insert(source, public_key);
        }
        Ok(result)
    }

    pub fn validated_propagation(&self) -> Result<Option<ValidatedPropagationConfig>, DaemonError> {
        let Some(config) = &self.propagation else {
            return Ok(None);
        };
        if !(5..=86_400).contains(&config.poll_interval_seconds)
            || !(1..=64).contains(&config.delivery_limit_kb)
            || !(1..=16).contains(&config.maximum_messages_per_poll)
            || !(1..=256).contains(&config.node_transfer_limit_kb)
            || config.node_stamp_cost > 24
        {
            return Err(DaemonError::InvalidConfiguration);
        }
        let node_destination_hash = parse_hex::<16>(&config.node_destination_hash)?;
        let node_rns_public_key = parse_hex::<64>(&config.node_rns_public_key)?;
        let identity = Identity::from_public_key(&node_rns_public_key)
            .map_err(|_| DaemonError::InvalidConfiguration)?;
        if node_destination_hash
            != Destination::hash_from_name_and_identity(
                LXMF_PROPAGATION_ASPECT,
                Some(&identity.hash),
            )
        {
            return Err(DaemonError::InvalidConfiguration);
        }
        self.requester_rns_keys()?;
        Ok(Some(ValidatedPropagationConfig {
            node_destination_hash,
            node_rns_public_key,
            poll_interval: Duration::from_secs(config.poll_interval_seconds),
            delivery_limit_kb: config.delivery_limit_kb,
            maximum_messages_per_poll: config.maximum_messages_per_poll,
            outbound_fallback: config.outbound_fallback,
            node_transfer_limit_kb: config.node_transfer_limit_kb,
            node_stamp_cost: config.node_stamp_cost,
        }))
    }

    fn rate_limit(&self) -> GatewayRateLimit {
        GatewayRateLimit {
            window_seconds: self.policy.window_seconds,
            maximum_requests: self.policy.maximum_requests,
            maximum_requested_bytes: self.policy.maximum_requested_bytes,
        }
    }

    fn execution_policy(&self) -> GatewayExecutionPolicy {
        GatewayExecutionPolicy {
            lease_seconds: self.policy.lease_seconds,
            retry_seconds: self.policy.retry_seconds,
        }
    }
}

const MAX_CONTACT_CARD_BYTES: u64 = 1024;

struct RequesterPublicMaterial {
    source_hash: [u8; 16],
    ed25519_public_key: [u8; 32],
    rns_public_key: Option<[u8; 64]>,
}

fn requester_public_material(
    requester: &RequesterConfig,
) -> Result<RequesterPublicMaterial, DaemonError> {
    match (
        requester.contact_card_path.as_deref(),
        (!requester.source_hash.is_empty()).then_some(requester.source_hash.as_str()),
        (!requester.ed25519_public_key.is_empty()).then_some(requester.ed25519_public_key.as_str()),
        requester.rns_public_key.as_deref(),
    ) {
        (None, Some(source), Some(ed25519), rns) => Ok(RequesterPublicMaterial {
            source_hash: parse_hex::<16>(source)?,
            ed25519_public_key: parse_hex::<32>(ed25519)?,
            rns_public_key: rns.map(parse_hex::<64>).transpose()?,
        }),
        _ => Err(DaemonError::InvalidConfiguration),
    }
}

fn parse_rscp1_contact_card(bytes: &[u8]) -> Result<RequesterPublicMaterial, DaemonError> {
    use base64::Engine;
    let payload = std::str::from_utf8(bytes)
        .map_err(|_| DaemonError::InvalidConfiguration)?
        .trim();
    let fields: Vec<_> = payload
        .strip_prefix("RSCP1:")
        .ok_or(DaemonError::InvalidConfiguration)?
        .split(':')
        .collect();
    if fields.len() != 4 {
        return Err(DaemonError::InvalidConfiguration);
    }
    let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(fields[0])
        .map_err(|_| DaemonError::InvalidConfiguration)?;
    let name = std::str::from_utf8(&name).map_err(|_| DaemonError::InvalidConfiguration)?;
    // Match Ratspeak's RSCP1 importer even though the display name is not
    // authorization material and is intentionally discarded here.
    let _sanitized_name = sanitize_contact_card_name(name);
    let source = parse_card_hex16(fields[1])?;
    let identity_hash = parse_card_hex16(fields[2])?;
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(fields[3])
        .map_err(|_| DaemonError::InvalidConfiguration)?;
    let public: [u8; 64] = public
        .try_into()
        .map_err(|_| DaemonError::InvalidConfiguration)?;
    let identity =
        Identity::from_public_key(&public).map_err(|_| DaemonError::InvalidConfiguration)?;
    if identity.hash != identity_hash
        || Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash))
            != source
    {
        return Err(DaemonError::InvalidConfiguration);
    }
    let mut ed25519 = [0; 32];
    ed25519.copy_from_slice(&public[32..]);
    Ok(RequesterPublicMaterial {
        source_hash: source,
        ed25519_public_key: ed25519,
        rns_public_key: Some(public),
    })
}

fn sanitize_contact_card_name(value: &str) -> String {
    value
        .chars()
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

fn parse_card_hex16(value: &str) -> Result<[u8; 16], DaemonError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DaemonError::InvalidConfiguration);
    }
    parse_hex::<16>(value)
}

pub type NativeSepoliaProvider = LiveSepoliaGatewayProvider<
    ReqwestBeaconHttpTransport,
    ReqwestGatewayHttpTransport,
    SystemUnixClock,
    CompleteBlockReceiptProofBackend<ReqwestGatewayHttpTransport>,
>;

pub fn load_native_provider(config: &ProviderConfig) -> Result<NativeSepoliaProvider, DaemonError> {
    let checkpoint_root = parse_hex::<32>(&config.checkpoint_root)?;
    if checkpoint_root == [0; 32] || config.checkpoint_epoch == 0 {
        return Err(DaemonError::InvalidConfiguration);
    }
    let checkpoint = BeaconCheckpointRoot::sepolia(checkpoint_root);
    let (floor_sink, floor) =
        ConsensusFloorFile::open(config.consensus_floor_path.clone(), checkpoint_root)?;
    let endpoint_policy = if config.allow_loopback_http_for_development {
        HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
    } else {
        HttpEndpointPolicy::HttpsOnly
    };
    let beacon_policy = BeaconHttpPolicy::conservative();
    let http_policy = ProviderHttpPolicy::conservative();
    let beacon_authorization =
        load_beacon_authorization(config.beacon_authorization_path.as_deref())?;
    let beacon_transport = ReqwestBeaconHttpTransport::new(
        &config.beacon_rpc_endpoint,
        beacon_authorization,
        endpoint_policy,
        beacon_policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?;
    let authorization =
        load_operator_authorization(config.execution_authorization_path.as_deref())?;
    let transport = ReqwestGatewayHttpTransport::new(
        &config.execution_rpc_endpoint,
        authorization,
        endpoint_policy,
        http_policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?;
    // Receipt reconstruction may issue one exact receipt request per block
    // transaction. Give it an independently hardened client rather than
    // sharing mutable request correlation or authorization state.
    let receipt_authorization =
        load_operator_authorization(config.execution_authorization_path.as_deref())?;
    let receipt_transport = ReqwestGatewayHttpTransport::new(
        &config.execution_rpc_endpoint,
        receipt_authorization,
        endpoint_policy,
        http_policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?;
    let receipt_backend = CompleteBlockReceiptProofBackend::new(receipt_transport, http_policy)
        .map_err(|_| DaemonError::ProviderUnavailable)?;
    LiveSepoliaGatewayProvider::new(
        checkpoint,
        config.checkpoint_epoch,
        beacon_transport,
        transport,
        SystemUnixClock,
        receipt_backend,
        beacon_policy,
        http_policy,
    )
    .map_err(|_| DaemonError::ProviderUnavailable)?
    .with_durable_consensus_floor(floor, Box::new(floor_sink))
    .map_err(|_| DaemonError::ProviderUnavailable)
}

struct ConsensusFloorFile {
    path: PathBuf,
    checkpoint_root: [u8; 32],
    current: Option<VerifiedConsensusFloor>,
    _path_lock: File,
}

impl ConsensusFloorFile {
    fn open(
        path: PathBuf,
        checkpoint_root: [u8; 32],
    ) -> Result<(Self, Option<VerifiedConsensusFloor>), DaemonError> {
        let lock_path = consensus_floor_lock_path(&path);
        ensure_private_parent(&lock_path)?;
        let path_lock = open_private_rw_create(&lock_path)?;
        let result = unsafe { libc::flock(path_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(DaemonError::AlreadyRunning);
        }
        let current = load_consensus_floor(&path, checkpoint_root)?;
        Ok((
            Self {
                path,
                checkpoint_root,
                current,
                _path_lock: path_lock,
            },
            current,
        ))
    }
}

impl VerifiedConsensusFloorSink for ConsensusFloorFile {
    fn commit(&mut self, floor: VerifiedConsensusFloor) -> Result<(), GatewayProviderFailure> {
        if floor.checkpoint_root() != self.checkpoint_root {
            return Err(GatewayProviderFailure::Permanent);
        }
        let on_disk = load_consensus_floor(&self.path, self.checkpoint_root)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        if on_disk != self.current
            || on_disk.is_some_and(|current| !floor_advances_or_repeats(floor, current))
        {
            return Err(GatewayProviderFailure::Permanent);
        }
        if on_disk == Some(floor) {
            self.current = Some(floor);
            return Ok(());
        }
        persist_consensus_floor(&self.path, floor)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        self.current = Some(floor);
        Ok(())
    }
}

fn floor_advances_or_repeats(
    candidate: VerifiedConsensusFloor,
    current: VerifiedConsensusFloor,
) -> bool {
    candidate.finalized_slot() > current.finalized_slot()
        || (candidate.finalized_slot() == current.finalized_slot()
            && candidate.execution_block_hash() == current.execution_block_hash())
}

fn consensus_floor_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn load_consensus_floor(
    path: &Path,
    checkpoint_root: [u8; 32],
) -> Result<Option<VerifiedConsensusFloor>, DaemonError> {
    ensure_private_parent(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DaemonError::InvalidFilesystemBoundary),
    }
    let bytes = read_private_regular_file(path, CONSENSUS_FLOOR_BYTES)?;
    if bytes.len() as u64 != CONSENSUS_FLOOR_BYTES || &bytes[..8] != CONSENSUS_FLOOR_MAGIC {
        return Err(DaemonError::ProviderUnavailable);
    }
    let expected_checksum = rns_crypto::sha::sha256(&bytes[..CONSENSUS_FLOOR_PAYLOAD_BYTES]);
    if bytes[CONSENSUS_FLOOR_PAYLOAD_BYTES..] != expected_checksum {
        return Err(DaemonError::ProviderUnavailable);
    }
    let stored_root: [u8; 32] = bytes[8..40]
        .try_into()
        .map_err(|_| DaemonError::ProviderUnavailable)?;
    if stored_root != checkpoint_root {
        return Err(DaemonError::ProviderUnavailable);
    }
    let slot = u64::from_le_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| DaemonError::ProviderUnavailable)?,
    );
    let execution_hash: [u8; 32] = bytes[48..80]
        .try_into()
        .map_err(|_| DaemonError::ProviderUnavailable)?;
    VerifiedConsensusFloor::new(stored_root, slot, execution_hash)
        .map(Some)
        .map_err(|_| DaemonError::ProviderUnavailable)
}

fn persist_consensus_floor(path: &Path, floor: VerifiedConsensusFloor) -> Result<(), DaemonError> {
    ensure_private_parent(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let _ = read_private_regular_file(path, CONSENSUS_FLOOR_BYTES)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(DaemonError::InvalidFilesystemBoundary),
    }
    let parent = path
        .parent()
        .ok_or(DaemonError::InvalidFilesystemBoundary)?;
    let temp = parent.join(format!(
        ".gateway-consensus-floor-{}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let mut bytes = Vec::with_capacity(CONSENSUS_FLOOR_BYTES as usize);
    bytes.extend_from_slice(CONSENSUS_FLOOR_MAGIC);
    bytes.extend_from_slice(&floor.checkpoint_root());
    bytes.extend_from_slice(&floor.finalized_slot().to_le_bytes());
    bytes.extend_from_slice(&floor.execution_block_hash());
    let checksum = rns_crypto::sha::sha256(&bytes);
    bytes.extend_from_slice(&checksum);
    let result = file.write_all(&bytes).and_then(|_| file.sync_all());
    drop(file);
    if result.is_err() || std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let _ = read_private_regular_file(path, CONSENSUS_FLOOR_BYTES)?;
    Ok(())
}

fn load_beacon_authorization(
    path: Option<&Path>,
) -> Result<Option<BeaconOperatorAuthorization>, DaemonError> {
    load_operator_authorization(path)
}

fn load_operator_authorization(
    path: Option<&Path>,
) -> Result<Option<OperatorAuthorization>, DaemonError> {
    path.map(|path| {
        let bytes = Zeroizing::new(read_private_regular_file(path, 16 * 1024)?);
        let value = std::str::from_utf8(&bytes).map_err(|_| DaemonError::ProviderUnavailable)?;
        OperatorAuthorization::parse(value.trim()).map_err(|_| DaemonError::ProviderUnavailable)
    })
    .transpose()
}

/// Advisory process lock held for the daemon lifetime.
pub struct InstanceLock(File);

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InstanceLock")
    }
}

impl InstanceLock {
    pub fn acquire(path: &Path) -> Result<Self, DaemonError> {
        ensure_private_parent(path)?;
        let file = open_private_rw_create(path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(DaemonError::AlreadyRunning);
        }
        Ok(Self(file))
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn load_service_identity(path: &Path) -> Result<Identity, DaemonError> {
    ensure_private_parent(path)?;
    let bytes = Zeroizing::new(read_private_regular_file(path, 1024)?);
    if bytes.len() != 64 {
        return Err(DaemonError::IdentityUnavailable);
    }
    Identity::from_private_key(&bytes).map_err(|_| DaemonError::IdentityUnavailable)
}

pub fn load_or_create_service_identity(path: &Path) -> Result<Identity, DaemonError> {
    ensure_private_parent(path)?;
    if path.exists() {
        return load_service_identity(path);
    }
    let identity = Identity::new();
    let private = identity
        .get_private_key()
        .ok_or(DaemonError::IdentityUnavailable)?;
    let parent = path
        .parent()
        .ok_or(DaemonError::InvalidFilesystemBoundary)?;
    let temp = parent.join(format!(".gateway-identity-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| DaemonError::IdentityUnavailable)?;
    let result = file
        .write_all(private.as_ref())
        .and_then(|_| file.sync_all());
    drop(file);
    if result.is_err() || std::fs::hard_link(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(DaemonError::IdentityUnavailable);
    }
    let _ = std::fs::remove_file(&temp);
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
    drop(Zeroizing::new(read_private_regular_file(path, 1024)?));
    Ok(identity)
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], DaemonError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|_| DaemonError::InvalidConfiguration)?;
    bytes
        .try_into()
        .map_err(|_| DaemonError::InvalidConfiguration)
}

fn ensure_private_parent(path: &Path) -> Result<(), DaemonError> {
    let parent = path
        .parent()
        .ok_or(DaemonError::InvalidFilesystemBoundary)?;
    if parent
        .canonicalize()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?
        != parent
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    let metadata =
        std::fs::symlink_metadata(parent).map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(())
}

fn validate_opened_private_file(file: &File) -> Result<std::fs::Metadata, DaemonError> {
    let metadata = file
        .metadata()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(metadata)
}

fn read_private_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DaemonError> {
    ensure_private_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    let before = validate_opened_private_file(&file)?;
    if before.len() > maximum {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if bytes.len() as u64 > maximum {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    let after = file
        .metadata()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(bytes)
}

/// Restrict any SQLite sidecars and runtime files created by this dedicated
/// process. Call before opening the durable store or Reticulum runtime.
pub fn install_private_process_umask() {
    unsafe {
        libc::umask(0o077);
    }
}

pub fn validate_private_directory(path: &Path) -> Result<(), DaemonError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    if path
        .canonicalize()
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?
        != path
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(DaemonError::InvalidFilesystemBoundary);
    }
    Ok(())
}

fn open_private_rw_create(path: &Path) -> Result<File, DaemonError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::InvalidFilesystemBoundary)?;
    validate_opened_private_file(&file)?;
    Ok(file)
}

#[cfg(test)]
mod tests;
