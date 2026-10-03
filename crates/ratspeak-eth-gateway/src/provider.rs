//! Bounded operator-side Sepolia provider.
//!
//! Endpoint and authorization values are constructor inputs for the standalone
//! daemon. They are deliberately absent from gateway messages and durable
//! state, and all public diagnostics are redacted. RPC observations remain
//! non-authoritative. Evidence is exposed only after `SepoliaGatewayBuilder`
//! verifies it against its independently supplied checkpoint anchor.

use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{TxKind, U256, keccak256};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use url::{Host, Url};

use crate::{
    AcceptedEvidenceRequest, AcceptedSignedRelay, AcceptedTransactionStatusRequest,
    EvmAnchorGatewayBuilder, GatewayBundle, GatewayExecutionProvider, GatewayProviderFailure,
    MessagingEvidenceKind, RelayProviderObservation, RelayProviderStatus, SepoliaGatewayBuilder,
    TransactionStatusObservation, UntrustedAccountProofRpcInput, UntrustedStorageProofRpcInput,
    UntrustedTxReceiptProofRpcInput,
};
use ratspeak_eth_verifier::{
    MAX_PROOF_NODE_BYTES, MAX_PROOF_NODES, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, chain_definition,
};

const MAX_SIGNED_TRANSACTION_BYTES: usize = 256;
const NATIVE_TRANSFER_GAS_LIMIT: u64 = 21_000;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_VALUES: usize = 8_192;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
const MAX_RPC_ERROR_MESSAGE_BYTES: usize = 512;

/// Fixed HTTP limits controlled by the operator, never by an incoming request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderHttpPolicy {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub maximum_json_response_bytes: usize,
}

impl ProviderHttpPolicy {
    pub fn conservative() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            maximum_json_response_bytes: 2 * 1024 * 1024,
        }
    }

    pub(crate) fn validate(self) -> Result<Self, ProviderConfigurationError> {
        if self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(60)
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(120)
            || self.maximum_json_response_bytes == 0
            || self.maximum_json_response_bytes > 4 * 1024 * 1024
        {
            return Err(ProviderConfigurationError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// Plain HTTP is only available for an explicitly selected loopback-only
/// development service. Production configuration should use `HttpsOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpEndpointPolicy {
    HttpsOnly,
    AllowLoopbackHttpForDevelopment,
}

/// Authorization material with deliberately redacted formatting.
pub struct OperatorAuthorization(pub(crate) HeaderValue);

impl OperatorAuthorization {
    pub fn parse(value: &str) -> Result<Self, ProviderConfigurationError> {
        let mut header = HeaderValue::from_str(value)
            .map_err(|_| ProviderConfigurationError::InvalidAuthorization)?;
        header.set_sensitive(true);
        Ok(Self(header))
    }
}

impl std::fmt::Debug for OperatorAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OperatorAuthorization([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderConfigurationError {
    #[error("invalid gateway provider endpoint")]
    InvalidEndpoint,
    #[error("gateway provider endpoint requires HTTPS")]
    InsecureEndpoint,
    #[error("invalid gateway provider authorization")]
    InvalidAuthorization,
    #[error("invalid gateway provider HTTP policy")]
    InvalidPolicy,
    #[error("gateway provider HTTP client could not be created")]
    ClientCreation,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GatewayHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl GatewayHttpResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl std::fmt::Debug for GatewayHttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpTransportFailure {
    #[error("gateway provider transport is temporarily unavailable")]
    Transient,
    #[error("gateway provider transport permanently rejected the request")]
    Permanent,
    #[error("gateway provider response exceeds its configured limit")]
    Oversized,
}

/// Injected HTTP seam for deterministic tests and daemon-specific transports.
/// Implementations must not log request or response bodies.
pub trait GatewayHttpTransport {
    fn post_json(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
        timeout: Duration,
    ) -> Result<GatewayHttpResponse, HttpTransportFailure>;
}

/// Concrete blocking client intended for a dedicated gateway worker thread.
pub struct ReqwestGatewayHttpTransport {
    client: Client,
    endpoint: Url,
}

impl std::fmt::Debug for ReqwestGatewayHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReqwestGatewayHttpTransport")
            .field("endpoint", &"[REDACTED]")
            .finish()
    }
}

impl ReqwestGatewayHttpTransport {
    pub fn new(
        endpoint: &str,
        authorization: Option<OperatorAuthorization>,
        endpoint_policy: HttpEndpointPolicy,
        policy: ProviderHttpPolicy,
    ) -> Result<Self, ProviderConfigurationError> {
        let policy = policy.validate()?;
        let endpoint = validate_endpoint(endpoint, endpoint_policy)?;
        // `reqwest` is built without its large default AWS-LC provider. Keep
        // the provider explicit; if the daemon installed another rustls
        // provider first, rustls will retain that operator choice.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(authorization) = authorization {
            headers.insert(AUTHORIZATION, authorization.0);
        }
        let client = Client::builder()
            .connect_timeout(policy.connect_timeout)
            .timeout(policy.request_timeout)
            // Provider credentials and raw transactions must never follow an
            // ambient HTTP(S)_PROXY selected outside daemon configuration.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .build()
            .map_err(|_| ProviderConfigurationError::ClientCreation)?;
        Ok(Self { client, endpoint })
    }
}

impl GatewayHttpTransport for ReqwestGatewayHttpTransport {
    fn post_json(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
        timeout: Duration,
    ) -> Result<GatewayHttpResponse, HttpTransportFailure> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .timeout(timeout)
            .body(body.to_vec())
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
        Ok(GatewayHttpResponse::new(status, body))
    }
}

fn validate_endpoint(
    endpoint: &str,
    policy: HttpEndpointPolicy,
) -> Result<Url, ProviderConfigurationError> {
    let endpoint = Url::parse(endpoint).map_err(|_| ProviderConfigurationError::InvalidEndpoint)?;
    if endpoint.cannot_be_a_base()
        || endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ProviderConfigurationError::InvalidEndpoint);
    }
    match endpoint.scheme() {
        "https" => Ok(endpoint),
        "http"
            if policy == HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
                && endpoint.host().is_some_and(is_loopback_host) =>
        {
            Ok(endpoint)
        }
        "http" => Err(ProviderConfigurationError::InsecureEndpoint),
        _ => Err(ProviderConfigurationError::InvalidEndpoint),
    }
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        // A hostname can be redirected through local resolver configuration;
        // the development exception is deliberately literal loopback only.
        Host::Domain(_) => false,
        Host::Ipv4(address) => IpAddr::V4(address).is_loopback(),
        Host::Ipv6(address) => IpAddr::V6(address).is_loopback(),
    }
}

pub trait UnixClock {
    fn now_unix(&self) -> Result<u64, GatewayProviderFailure>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUnixClock;

impl UnixClock for SystemUnixClock {
    fn now_unix(&self) -> Result<u64, GatewayProviderFailure> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| GatewayProviderFailure::Permanent)
    }
}

/// Optional seam for an operator backend capable of constructing exact
/// transaction and receipt MPT proofs. Ordinary execution JSON-RPC does not
/// provide those proof nodes, so the default backend is fail-closed.
pub trait ExactReceiptProofBackend {
    /// Returns only an untrusted location hint. Finality and canonicality are
    /// established later through the consensus-authenticated parent chain.
    fn fetch_receipt_location(
        &mut self,
        _tx_hash: [u8; 32],
        _captured_at_unix: u64,
    ) -> Result<UntrustedReceiptLocation, GatewayProviderFailure> {
        Err(GatewayProviderFailure::Permanent)
    }

    fn fetch_exact_receipt_proof(
        &mut self,
        tx_hash: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        captured_at_unix: u64,
    ) -> Result<UntrustedTxReceiptProofRpcInput, GatewayProviderFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedReceiptLocation {
    pub block_number: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedReceiptProofBackend;

impl ExactReceiptProofBackend for UnsupportedReceiptProofBackend {
    fn fetch_exact_receipt_proof(
        &mut self,
        _tx_hash: [u8; 32],
        _execution_block_number: u64,
        _execution_block_hash: [u8; 32],
        _captured_at_unix: u64,
    ) -> Result<UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
        Err(GatewayProviderFailure::Permanent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStorageEvidenceBundles {
    pub account: GatewayBundle,
    pub storage: GatewayBundle,
}

/// Execution provider pinned to one already verified EVM anchor.
///
/// One instance is bound to one chain. The app may keep one configured agent
/// contact per installed chain and route a signed relay by the chain ID decoded
/// from its EIP-1559 envelope. RPC data remains untrusted and is locally
/// reverified against the anchor before evidence is emitted.
pub struct EvmAnchorRpcProvider<T, C = SystemUnixClock, R = UnsupportedReceiptProofBackend> {
    builder: EvmAnchorGatewayBuilder,
    transport: T,
    clock: C,
    receipt_backend: R,
    policy: ProviderHttpPolicy,
    next_rpc_id: u64,
}

impl<T, C, R> std::fmt::Debug for EvmAnchorRpcProvider<T, C, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvmAnchorRpcProvider")
            .field("chain_id", &self.builder.anchor().chain_id())
            .field("block_number", &self.builder.anchor().block_number())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<T, C> EvmAnchorRpcProvider<T, C, UnsupportedReceiptProofBackend> {
    pub fn new(
        builder: EvmAnchorGatewayBuilder,
        transport: T,
        clock: C,
        policy: ProviderHttpPolicy,
    ) -> Result<Self, ProviderConfigurationError> {
        Ok(Self {
            builder,
            transport,
            clock,
            receipt_backend: UnsupportedReceiptProofBackend,
            policy: policy.validate()?,
            next_rpc_id: 1,
        })
    }
}

impl<T, C, R> EvmAnchorRpcProvider<T, C, R> {
    pub fn with_receipt_backend<R2>(
        self,
        receipt_backend: R2,
    ) -> EvmAnchorRpcProvider<T, C, R2> {
        EvmAnchorRpcProvider {
            builder: self.builder,
            transport: self.transport,
            clock: self.clock,
            receipt_backend,
            policy: self.policy,
            next_rpc_id: self.next_rpc_id,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T, C, R> GatewayExecutionProvider for EvmAnchorRpcProvider<T, C, R>
where
    T: GatewayHttpTransport,
    C: UnixClock,
    R: ExactReceiptProofBackend,
{
    fn submit_signed_relay(
        &mut self,
        relay: &AcceptedSignedRelay,
    ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
        prevalidate_relay(relay)?;
        if relay.chain_id() != self.builder.anchor().chain_id() {
            return Err(GatewayProviderFailure::Permanent);
        }

        let expected_hash = relay.tx_hash();
        let reply = self.rpc_call(
            RpcMethod::SendRawTransaction,
            json!([canonical_data_hex(relay.raw_transaction())]),
        )?;
        match reply {
            RpcReply::Result(value) => {
                if parse_fixed_hex::<32>(&value)? != expected_hash {
                    return Err(GatewayProviderFailure::Permanent);
                }
                Ok(RelayProviderObservation::new(
                    expected_hash,
                    RelayProviderStatus::Accepted,
                ))
            }
            RpcReply::Rejected { .. } => Ok(RelayProviderObservation::new(
                expected_hash,
                RelayProviderStatus::Rejected,
            )),
        }
    }

    fn fetch_verified_evidence(
        &mut self,
        request: &AcceptedEvidenceRequest,
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        match request.evidence_kind() {
            MessagingEvidenceKind::AccountProof => {
                self.fetch_account_evidence(request.subject())
            }
            MessagingEvidenceKind::ReceiptProof => {
                let captured_at_unix = self.clock.now_unix()?;
                let anchor = self.builder.anchor();
                let mut input = self.receipt_backend.fetch_exact_receipt_proof(
                    request.subject(),
                    anchor.block_number(),
                    anchor.block_hash(),
                    captured_at_unix,
                )?;
                input.captured_at_unix = captured_at_unix;
                if input.chain_id != anchor.chain_id()
                    || input.network != anchor.network()
                    || input.tx_hash != request.subject()
                    || input.block_number != anchor.block_number()
                    || input.block_hash != anchor.block_hash()
                    || input.transactions_root != anchor.transactions_root()
                    || input.receipts_root != anchor.receipts_root()
                {
                    return Err(GatewayProviderFailure::Permanent);
                }
                self.builder
                    .build_tx_receipt_proof(&input)
                    .map_err(|_| GatewayProviderFailure::Permanent)
            }
            // Stack-anchor and aggregate-package transport remain distinct from
            // the shared EVM proof layer. The phone verifies those inputs before
            // constructing this provider.
            MessagingEvidenceKind::Consensus
            | MessagingEvidenceKind::ExecutionHeader
            | MessagingEvidenceKind::AccountStatePackage
            | MessagingEvidenceKind::FinalizedReceiptPackage => {
                Err(GatewayProviderFailure::Permanent)
            }
        }
    }

    fn observe_transaction_status(
        &mut self,
        _request: &AcceptedTransactionStatusRequest,
    ) -> Result<TransactionStatusObservation, GatewayProviderFailure> {
        Err(GatewayProviderFailure::Permanent)
    }
}

impl<T, C, R> EvmAnchorRpcProvider<T, C, R>
where
    T: GatewayHttpTransport,
    C: UnixClock,
{
    /// Fetches and locally verifies the contract account proof and one storage
    /// slot proof at the exact authenticated anchor. This is the primitive used
    /// by balance-proof definitions; the user never configures the RPC call.
    pub fn fetch_verified_storage_evidence(
        &mut self,
        account_address: [u8; 20],
        storage_key: [u8; 32],
    ) -> Result<VerifiedStorageEvidenceBundles, GatewayProviderFailure> {
        let (chain_id, network, block_number, block_hash, state_root) = {
            let anchor = self.builder.anchor();
            (
                anchor.chain_id(),
                anchor.network().to_owned(),
                anchor.block_number(),
                anchor.block_hash(),
                anchor.state_root(),
            )
        };

        let block = self.rpc_call(
            RpcMethod::GetBlockByHash,
            json!([canonical_data_hex(&block_hash), false]),
        )?;
        let RpcReply::Result(block) = block else {
            return Err(GatewayProviderFailure::Permanent);
        };
        validate_anchor_block(&block, self.builder.anchor())?;

        let selector = json!({
            "blockHash": canonical_data_hex(&block_hash),
            "requireCanonical": true
        });
        let params = json!([
            canonical_data_hex(&account_address),
            [canonical_data_hex(&storage_key)],
            selector
        ]);
        let reply = self.rpc_call(RpcMethod::GetProof, params)?;
        let proof = match reply {
            RpcReply::Result(proof) => proof,
            RpcReply::Rejected { code: -32602 } => match self.rpc_call(
                RpcMethod::GetProof,
                json!([
                    canonical_data_hex(&account_address),
                    [canonical_data_hex(&storage_key)],
                    format!("0x{block_number:x}")
                ]),
            )? {
                RpcReply::Result(proof) => proof,
                RpcReply::Rejected { .. } => return Err(GatewayProviderFailure::Permanent),
            },
            RpcReply::Rejected { .. } => return Err(GatewayProviderFailure::Permanent),
        };

        let (account_input, storage_input) = parse_account_and_storage_proof_result(
            &proof,
            chain_id,
            &network,
            self.clock.now_unix()?,
            block_number,
            block_hash,
            state_root,
            account_address,
            storage_key,
        )?;

        let verified_account = self
            .builder
            .verify_account(&account_input)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        let account = self
            .builder
            .build_account_proof(&account_input)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        let storage = self
            .builder
            .build_storage_proof(&verified_account, &storage_input)
            .map_err(|_| GatewayProviderFailure::Permanent)?;

        Ok(VerifiedStorageEvidenceBundles { account, storage })
    }

    fn fetch_account_evidence(
        &mut self,
        subject: [u8; 32],
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        if subject[..12] != [0; 12] {
            return Err(GatewayProviderFailure::Permanent);
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&subject[12..]);

        let (chain_id, network, block_number, block_hash, state_root) = {
            let anchor = self.builder.anchor();
            (
                anchor.chain_id(),
                anchor.network().to_owned(),
                anchor.block_number(),
                anchor.block_hash(),
                anchor.state_root(),
            )
        };

        let block = self.rpc_call(
            RpcMethod::GetBlockByHash,
            json!([canonical_data_hex(&block_hash), false]),
        )?;
        let RpcReply::Result(block) = block else {
            return Err(GatewayProviderFailure::Permanent);
        };
        validate_anchor_block(&block, self.builder.anchor())?;

        let selector = json!({
            "blockHash": canonical_data_hex(&block_hash),
            "requireCanonical": true
        });
        let proof_reply = self.rpc_call(
            RpcMethod::GetProof,
            json!([canonical_data_hex(&address), [], selector]),
        )?;
        let proof = match proof_reply {
            RpcReply::Result(proof) => proof,
            RpcReply::Rejected { code: -32602 } => match self.rpc_call(
                RpcMethod::GetProof,
                json!([
                    canonical_data_hex(&address),
                    [],
                    format!("0x{block_number:x}")
                ]),
            )? {
                RpcReply::Result(proof) => proof,
                RpcReply::Rejected { .. } => return Err(GatewayProviderFailure::Permanent),
            },
            RpcReply::Rejected { .. } => return Err(GatewayProviderFailure::Permanent),
        };

        let input = parse_account_proof_result(
            &proof,
            chain_id,
            &network,
            self.clock.now_unix()?,
            block_number,
            block_hash,
            state_root,
            address,
        )?;
        self.builder
            .build_account_proof(&input)
            .map_err(|_| GatewayProviderFailure::Permanent)
    }

    fn rpc_call(
        &mut self,
        method: RpcMethod,
        params: Value,
    ) -> Result<RpcReply, GatewayProviderFailure> {
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(1);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method.as_str(),
            "params": params,
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .transport
            .post_json(
                &body,
                self.policy.maximum_json_response_bytes,
                self.policy.request_timeout,
            )
            .map_err(map_transport_failure)?;
        if response.body().len() > self.policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        match response.status() {
            200..=299 => parse_rpc_reply(response.body(), id),
            408 | 425 | 429 | 500..=599 => Err(GatewayProviderFailure::Transient),
            _ => Err(GatewayProviderFailure::Permanent),
        }
    }
}

/// Live Sepolia execution provider pinned to one locally verified builder.
pub struct SepoliaRpcProvider<T, C = SystemUnixClock, R = UnsupportedReceiptProofBackend> {
    builder: SepoliaGatewayBuilder,
    transport: T,
    clock: C,
    receipt_backend: R,
    policy: ProviderHttpPolicy,
    next_rpc_id: u64,
}

impl<T, C, R> std::fmt::Debug for SepoliaRpcProvider<T, C, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SepoliaRpcProvider")
            .field(
                "execution_block_number",
                &self.builder.execution_block_number(),
            )
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<T, C> SepoliaRpcProvider<T, C, UnsupportedReceiptProofBackend> {
    pub fn new(
        builder: SepoliaGatewayBuilder,
        transport: T,
        clock: C,
        policy: ProviderHttpPolicy,
    ) -> Result<Self, ProviderConfigurationError> {
        Ok(Self {
            builder,
            transport,
            clock,
            receipt_backend: UnsupportedReceiptProofBackend,
            policy: policy.validate()?,
            next_rpc_id: 1,
        })
    }
}

impl<T, C, R> SepoliaRpcProvider<T, C, R> {
    pub fn with_receipt_backend<R2>(self, receipt_backend: R2) -> SepoliaRpcProvider<T, C, R2> {
        SepoliaRpcProvider {
            builder: self.builder,
            transport: self.transport,
            clock: self.clock,
            receipt_backend,
            policy: self.policy,
            next_rpc_id: self.next_rpc_id,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T, C, R> GatewayExecutionProvider for SepoliaRpcProvider<T, C, R>
where
    T: GatewayHttpTransport,
    C: UnixClock,
    R: ExactReceiptProofBackend,
{
    fn submit_signed_relay(
        &mut self,
        relay: &AcceptedSignedRelay,
    ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
        prevalidate_relay(relay)?;
        let expected_hash = relay.tx_hash();
        let raw = canonical_data_hex(relay.raw_transaction());
        let reply = self.rpc_call(RpcMethod::SendRawTransaction, json!([raw]))?;
        match reply {
            RpcReply::Result(value) => {
                let returned = parse_fixed_hex::<32>(&value)?;
                if returned != expected_hash {
                    return Err(GatewayProviderFailure::Permanent);
                }
                Ok(RelayProviderObservation::new(
                    expected_hash,
                    RelayProviderStatus::Accepted,
                ))
            }
            RpcReply::Rejected { .. } => Ok(RelayProviderObservation::new(
                expected_hash,
                RelayProviderStatus::Rejected,
            )),
        }
    }

    fn observe_transaction_status(
        &mut self,
        _request: &AcceptedTransactionStatusRequest,
    ) -> Result<TransactionStatusObservation, GatewayProviderFailure> {
        // This provider is anchored to a caller-supplied historic execution
        // header for evidence construction. Only the live provider owns the
        // fixed latest/safe/finalized sampling surface.
        Err(GatewayProviderFailure::Permanent)
    }

    fn fetch_verified_evidence(
        &mut self,
        request: &AcceptedEvidenceRequest,
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        match request.evidence_kind() {
            MessagingEvidenceKind::Consensus => {
                if request.subject() != self.builder.checkpoint_root() {
                    return Err(GatewayProviderFailure::Permanent);
                }
                Ok(self.builder.consensus_bundle().clone())
            }
            MessagingEvidenceKind::ExecutionHeader => {
                if request.subject() != self.builder.execution_block_hash() {
                    return Err(GatewayProviderFailure::Permanent);
                }
                Ok(self.builder.execution_bundle().clone())
            }
            MessagingEvidenceKind::AccountProof => {
                self.fetch_account_evidence(request.subject(), false)
            }
            MessagingEvidenceKind::AccountStatePackage => {
                self.fetch_account_evidence(request.subject(), true)
            }
            MessagingEvidenceKind::ReceiptProof => {
                let captured_at_unix = self.clock.now_unix()?;
                let mut input = self.receipt_backend.fetch_exact_receipt_proof(
                    request.subject(),
                    self.builder.execution_block_number(),
                    self.builder.execution_block_hash(),
                    captured_at_unix,
                )?;
                // Proof backends supply untrusted chain material, not the
                // operator process's observation time.
                input.captured_at_unix = captured_at_unix;
                if input.tx_hash != request.subject()
                    || input.block_number != self.builder.execution_block_number()
                    || input.block_hash != self.builder.execution_block_hash()
                    || input.transactions_root != self.builder.execution_transactions_root()
                    || input.receipts_root != self.builder.execution_receipts_root()
                {
                    return Err(GatewayProviderFailure::Permanent);
                }
                self.builder
                    .build_tx_receipt_proof(&input)
                    .map_err(|_| GatewayProviderFailure::Permanent)
            }
            MessagingEvidenceKind::FinalizedReceiptPackage => {
                // Historical receipt finality requires ancestry from a freshly
                // verified consensus anchor. The live provider owns that flow.
                Err(GatewayProviderFailure::Permanent)
            }
        }
    }
}

impl<T, C, R> SepoliaRpcProvider<T, C, R>
where
    T: GatewayHttpTransport,
    C: UnixClock,
{
    fn fetch_account_evidence(
        &mut self,
        subject: [u8; 32],
        composite: bool,
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        if subject[..12] != [0; 12] {
            return Err(GatewayProviderFailure::Permanent);
        }
        let mut address = [0_u8; 20];
        address.copy_from_slice(&subject[12..]);
        let block_hash = self.builder.execution_block_hash();
        let block_hash_hex = canonical_data_hex(&block_hash);
        let block = self
            .rpc_call(RpcMethod::GetBlockByHash, json!([block_hash_hex, false]))
            .inspect_err(|failure| {
                tracing::warn!(stage = "account_block_rpc", class = ?failure, "Ethereum account proof failed");
            })?;
        let RpcReply::Result(block) = block else {
            let RpcReply::Rejected { code } = block else {
                unreachable!("RPC replies are result or rejected")
            };
            tracing::warn!(
                stage = "account_block_rpc_rejected",
                rpc_code = code,
                "Ethereum account proof failed"
            );
            return Err(GatewayProviderFailure::Permanent);
        };
        validate_block_anchor(&block, &self.builder).inspect_err(|failure| {
            tracing::warn!(stage = "account_block_anchor", class = ?failure, "Ethereum account proof failed");
        })?;

        let proof_reply = self.rpc_call(
            RpcMethod::GetProof,
            json!([
                canonical_data_hex(&address),
                [],
                {"blockHash": canonical_data_hex(&block_hash), "requireCanonical": true}
            ]),
        )
        .inspect_err(|failure| {
            tracing::warn!(stage = "account_get_proof_rpc", class = ?failure, "Ethereum account proof failed");
        })?;
        let proof = match proof_reply {
            RpcReply::Result(proof) => proof,
            // Some otherwise archive-capable providers do not implement the
            // EIP-1898 object selector. The block was already fetched by the
            // exact Beacon-committed hash and its roots were checked. A proof
            // fetched by that finalized block number is still accepted only
            // if local MPT verification reaches the committed state root.
            RpcReply::Rejected { code: -32602 } => {
                tracing::debug!(
                    stage = "account_get_proof_block_number_fallback",
                    "Ethereum provider requires the finalized block-number selector"
                );
                match self
                    .rpc_call(
                        RpcMethod::GetProof,
                        json!([
                            canonical_data_hex(&address),
                            [],
                            format!("0x{:x}", self.builder.execution_block_number())
                        ]),
                    )
                    .inspect_err(|failure| {
                        tracing::warn!(stage = "account_get_proof_fallback_rpc", class = ?failure, "Ethereum account proof failed");
                    })? {
                    RpcReply::Result(proof) => proof,
                    RpcReply::Rejected { code } => {
                        tracing::warn!(
                            stage = "account_get_proof_fallback_rejected",
                            rpc_code = code,
                            "Ethereum account proof failed"
                        );
                        return Err(GatewayProviderFailure::Permanent);
                    }
                }
            }
            RpcReply::Rejected { code } => {
                tracing::warn!(
                    stage = "account_get_proof_rejected",
                    rpc_code = code,
                    "Ethereum account proof failed"
                );
                return Err(GatewayProviderFailure::Permanent);
            }
        };
        let input = parse_account_proof_result(
            &proof,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            self.clock.now_unix()?,
            self.builder.execution_block_number(),
            block_hash,
            self.builder.execution_state_root(),
            address,
        )
        .inspect_err(|failure| {
            tracing::warn!(stage = "account_proof_parse", class = ?failure, "Ethereum account proof failed");
        })?;
        if composite {
            self.builder.build_account_state_evidence(&input)
        } else {
            self.builder.build_account_proof(&input)
        }
        .map_err(|_| {
            tracing::warn!(
                stage = "account_bundle_verification",
                "Ethereum account proof failed"
            );
            GatewayProviderFailure::Permanent
        })
    }

    fn rpc_call(
        &mut self,
        method: RpcMethod,
        params: Value,
    ) -> Result<RpcReply, GatewayProviderFailure> {
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(1);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method.as_str(),
            "params": params,
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .transport
            .post_json(
                &body,
                self.policy.maximum_json_response_bytes,
                self.policy.request_timeout,
            )
            .map_err(map_transport_failure)?;
        // The public injected transport is not part of the trust boundary.
        // Enforce the cap again before status or JSON processing.
        if response.body().len() > self.policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        match response.status() {
            200..=299 => parse_rpc_reply(response.body(), id),
            408 | 425 | 429 | 500..=599 => Err(GatewayProviderFailure::Transient),
            _ => Err(GatewayProviderFailure::Permanent),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RpcMethod {
    SendRawTransaction,
    GetBlockByHash,
    GetProof,
}

impl RpcMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::SendRawTransaction => "eth_sendRawTransaction",
            Self::GetBlockByHash => "eth_getBlockByHash",
            Self::GetProof => "eth_getProof",
        }
    }
}

enum RpcReply {
    Result(Value),
    Rejected { code: i64 },
}

pub(crate) fn map_transport_failure(failure: HttpTransportFailure) -> GatewayProviderFailure {
    match failure {
        HttpTransportFailure::Transient => GatewayProviderFailure::Transient,
        HttpTransportFailure::Permanent | HttpTransportFailure::Oversized => {
            GatewayProviderFailure::Permanent
        }
    }
}

pub(crate) fn prevalidate_relay(relay: &AcceptedSignedRelay) -> Result<(), GatewayProviderFailure> {
    prevalidate_raw_relay(relay.raw_transaction(), relay.tx_hash(), relay.sender())
}

fn prevalidate_raw_relay(
    raw: &[u8],
    expected_hash: [u8; 32],
    expected_sender: [u8; 20],
) -> Result<(), GatewayProviderFailure> {
    if raw.is_empty() || raw.len() > MAX_SIGNED_TRANSACTION_BYTES {
        return Err(GatewayProviderFailure::Permanent);
    }
    let local_hash = keccak256(raw).0;
    if local_hash != expected_hash {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut remaining = raw;
    let envelope =
        TxEnvelope::decode_2718(&mut remaining).map_err(|_| GatewayProviderFailure::Permanent)?;
    if !remaining.is_empty() {
        return Err(GatewayProviderFailure::Permanent);
    }
    let chain_id = envelope
        .chain_id()
        .ok_or(GatewayProviderFailure::Permanent)?;
    if chain_definition(chain_id).is_none() {
        return Err(GatewayProviderFailure::Permanent);
    }

    // The relay is deliberately semantics-agnostic. Clear-sign policy belongs
    // on the signing device; the gateway only verifies that the exact signed
    // bytes are a supported EIP-1559 call from the claimed sender.
    let TxEnvelope::Eip1559(signed) = &envelope else {
        return Err(GatewayProviderFailure::Permanent);
    };
    let tx = signed.tx();
    if !matches!(tx.to, TxKind::Call(_)) || !tx.access_list.is_empty() {
        return Err(GatewayProviderFailure::Permanent);
    }
    let sender = envelope
        .recover_signer()
        .map_err(|_| GatewayProviderFailure::Permanent)?;
    if sender.0 != expected_sender {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn parse_rpc_reply(bytes: &[u8], expected_id: u64) -> Result<RpcReply, GatewayProviderFailure> {
    parse_rpc_reply_bounded(bytes, expected_id, MAX_JSON_VALUES)
}

fn parse_rpc_reply_bounded(
    bytes: &[u8],
    expected_id: u64,
    maximum_json_values: usize,
) -> Result<RpcReply, GatewayProviderFailure> {
    if bytes.is_empty() {
        return Err(GatewayProviderFailure::Transient);
    }
    let value = serde_json::from_slice::<StrictJsonValue>(bytes)
        .map_err(|_| GatewayProviderFailure::Transient)?
        .0;
    validate_json_limits_bounded(&value, maximum_json_values)?;
    let object = value.as_object().ok_or(GatewayProviderFailure::Transient)?;
    let allowed = ["jsonrpc", "id", "result", "error"];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    match (object.get("result"), object.get("error")) {
        (Some(result), None) => Ok(RpcReply::Result(result.clone())),
        (None, Some(error)) => {
            let code = validate_rpc_error(error)?;
            Ok(RpcReply::Rejected { code })
        }
        _ => Err(GatewayProviderFailure::Permanent),
    }
}

pub(crate) fn parse_rpc_result_bounded(
    bytes: &[u8],
    expected_id: u64,
    maximum_json_values: usize,
) -> Result<Value, GatewayProviderFailure> {
    match parse_rpc_reply_bounded(bytes, expected_id, maximum_json_values)? {
        RpcReply::Result(value) => Ok(value),
        RpcReply::Rejected { .. } => Err(GatewayProviderFailure::Permanent),
    }
}

/// `serde_json::Value` accepts duplicate object names by retaining the last
/// one. JSON-RPC correlation and proof fields must instead have one meaning.
struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object names or floating-point numbers")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point JSON is not accepted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = object.next_entry::<String, StrictJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON object name"));
            }
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

fn validate_rpc_error(value: &Value) -> Result<i64, GatewayProviderFailure> {
    let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
    let code = object
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(GatewayProviderFailure::Permanent)?;
    if object.keys().any(|key| key != "code" && key != "message")
        || object.len() != 2
        || object
            .get("message")
            .and_then(Value::as_str)
            .is_none_or(|message| message.len() > MAX_RPC_ERROR_MESSAGE_BYTES)
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(code)
}

#[cfg(test)]
fn validate_json_limits(value: &Value) -> Result<(), GatewayProviderFailure> {
    validate_json_limits_bounded(value, MAX_JSON_VALUES)
}

fn validate_json_limits_bounded(
    value: &Value,
    maximum_json_values: usize,
) -> Result<(), GatewayProviderFailure> {
    if maximum_json_values == 0 {
        return Err(GatewayProviderFailure::Permanent);
    }
    fn visit(
        value: &Value,
        depth: usize,
        count: &mut usize,
        maximum_json_values: usize,
    ) -> Result<(), GatewayProviderFailure> {
        if depth > MAX_JSON_DEPTH {
            return Err(GatewayProviderFailure::Permanent);
        }
        *count = count
            .checked_add(1)
            .ok_or(GatewayProviderFailure::Permanent)?;
        if *count > maximum_json_values {
            return Err(GatewayProviderFailure::Permanent);
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                Err(GatewayProviderFailure::Permanent)
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, count, maximum_json_values)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if key.len() > 128 {
                        return Err(GatewayProviderFailure::Permanent);
                    }
                    visit(value, depth + 1, count, maximum_json_values)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    visit(value, 0, &mut 0, maximum_json_values)
}

fn validate_anchor_block(
    value: &Value,
    anchor: &ratspeak_eth_verifier::VerifiedEvmAnchor,
) -> Result<(), GatewayProviderFailure> {
    let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
    if parse_field_fixed_hex::<32>(object, "hash")? != anchor.block_hash()
        || parse_field_quantity_u64(object, "number")? != anchor.block_number()
        || parse_field_fixed_hex::<32>(object, "stateRoot")? != anchor.state_root()
        || parse_field_fixed_hex::<32>(object, "transactionsRoot")?
            != anchor.transactions_root()
        || parse_field_fixed_hex::<32>(object, "receiptsRoot")? != anchor.receipts_root()
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn validate_block_anchor(
    value: &Value,
    builder: &SepoliaGatewayBuilder,
) -> Result<(), GatewayProviderFailure> {
    let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
    if parse_field_fixed_hex::<32>(object, "hash")? != builder.execution_block_hash()
        || parse_field_quantity_u64(object, "number")? != builder.execution_block_number()
        || parse_field_fixed_hex::<32>(object, "stateRoot")? != builder.execution_state_root()
        || parse_field_fixed_hex::<32>(object, "transactionsRoot")?
            != builder.execution_transactions_root()
        || parse_field_fixed_hex::<32>(object, "receiptsRoot")? != builder.execution_receipts_root()
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn parse_account_and_storage_proof_result(
    value: &Value,
    chain_id: u64,
    network: &str,
    captured_at_unix: u64,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    expected_address: [u8; 20],
    expected_key: [u8; 32],
) -> Result<
    (UntrustedAccountProofRpcInput, UntrustedStorageProofRpcInput),
    GatewayProviderFailure,
> {
    let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
    let allowed = [
        "address",
        "balance",
        "codeHash",
        "nonce",
        "storageHash",
        "accountProof",
        "storageProof",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || parse_field_fixed_hex::<20>(object, "address")? != expected_address
    {
        return Err(GatewayProviderFailure::Permanent);
    }

    let definition = chain_definition(chain_id).ok_or(GatewayProviderFailure::Permanent)?;
    if definition.network != network {
        return Err(GatewayProviderFailure::Permanent);
    }

    let proof_values = object
        .get("accountProof")
        .and_then(Value::as_array)
        .ok_or(GatewayProviderFailure::Permanent)?;
    if proof_values.is_empty() || proof_values.len() > MAX_PROOF_NODES {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut account_proof = Vec::with_capacity(proof_values.len());
    for node in proof_values {
        let node = parse_data_hex(node, MAX_PROOF_NODE_BYTES)?;
        if node.is_empty() {
            return Err(GatewayProviderFailure::Permanent);
        }
        account_proof.push(node);
    }

    let storage_root = parse_field_fixed_hex(object, "storageHash")?;
    let storage_values = object
        .get("storageProof")
        .and_then(Value::as_array)
        .ok_or(GatewayProviderFailure::Permanent)?;
    if storage_values.len() != 1 {
        return Err(GatewayProviderFailure::Permanent);
    }
    let storage = storage_values[0]
        .as_object()
        .ok_or(GatewayProviderFailure::Permanent)?;
    if storage.keys().any(|key| !["key", "value", "proof"].contains(&key.as_str())) {
        return Err(GatewayProviderFailure::Permanent);
    }
    let key = parse_storage_key(
        storage.get("key").ok_or(GatewayProviderFailure::Permanent)?,
    )?;
    if key != expected_key {
        return Err(GatewayProviderFailure::Permanent);
    }
    let value = parse_quantity_u256(
        storage.get("value").ok_or(GatewayProviderFailure::Permanent)?,
    )?;
    let proof_values = storage
        .get("proof")
        .and_then(Value::as_array)
        .ok_or(GatewayProviderFailure::Permanent)?;
    if proof_values.is_empty() || proof_values.len() > MAX_PROOF_NODES {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut storage_proof = Vec::with_capacity(proof_values.len());
    for node in proof_values {
        let node = parse_data_hex(node, MAX_PROOF_NODE_BYTES)?;
        if node.is_empty() {
            return Err(GatewayProviderFailure::Permanent);
        }
        storage_proof.push(node);
    }

    let account = UntrustedAccountProofRpcInput {
        chain_id,
        network: network.to_owned(),
        captured_at_unix,
        block_number,
        block_hash,
        state_root,
        address: expected_address,
        balance: parse_field_u256(object, "balance")?,
        nonce: parse_field_quantity_u64(object, "nonce")?,
        code_hash: parse_field_fixed_hex(object, "codeHash")?,
        storage_root,
        account_proof,
    };
    let storage = UntrustedStorageProofRpcInput {
        chain_id,
        network: network.to_owned(),
        captured_at_unix,
        block_number,
        block_hash,
        account_address: expected_address,
        storage_root,
        key,
        value,
        proof: storage_proof,
    };
    Ok((account, storage))
}

fn parse_storage_key(value: &Value) -> Result<[u8; 32], GatewayProviderFailure> {
    let value = value.as_str().ok_or(GatewayProviderFailure::Permanent)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(GatewayProviderFailure::Permanent)?;
    if digits.is_empty()
        || digits.len() > 64
        || digits
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut normalized = String::with_capacity(digits.len() + 1);
    if digits.len() % 2 != 0 {
        normalized.push('0');
    }
    normalized.push_str(digits);
    let decoded =
        alloy_primitives::hex::decode(normalized).map_err(|_| GatewayProviderFailure::Permanent)?;
    if decoded.len() > 32 {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut out = [0u8; 32];
    out[32 - decoded.len()..].copy_from_slice(&decoded);
    Ok(out)
}

fn parse_quantity_u256(value: &Value) -> Result<U256, GatewayProviderFailure> {
    let value = value.as_str().ok_or(GatewayProviderFailure::Permanent)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(GatewayProviderFailure::Permanent)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || digits.len() > 64
        || digits
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut padded = String::with_capacity(digits.len() + 1);
    if digits.len() % 2 != 0 {
        padded.push('0');
    }
    padded.push_str(digits);
    let bytes =
        alloy_primitives::hex::decode(padded).map_err(|_| GatewayProviderFailure::Permanent)?;
    Ok(U256::from_be_slice(&bytes))
}

fn parse_account_proof_result(
    value: &Value,
    chain_id: u64,
    network: &str,
    captured_at_unix: u64,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    expected_address: [u8; 20],
) -> Result<UntrustedAccountProofRpcInput, GatewayProviderFailure> {
    let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
    let allowed = [
        "address",
        "balance",
        "codeHash",
        "nonce",
        "storageHash",
        "accountProof",
        "storageProof",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || parse_field_fixed_hex::<20>(object, "address")? != expected_address
        || object
            .get("storageProof")
            .and_then(Value::as_array)
            .is_none_or(|proofs| !proofs.is_empty())
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    let proof_values = object
        .get("accountProof")
        .and_then(Value::as_array)
        .ok_or(GatewayProviderFailure::Permanent)?;
    if proof_values.is_empty() || proof_values.len() > MAX_PROOF_NODES {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut account_proof = Vec::with_capacity(proof_values.len());
    for node in proof_values {
        let node = parse_data_hex(node, MAX_PROOF_NODE_BYTES)?;
        if node.is_empty() {
            return Err(GatewayProviderFailure::Permanent);
        }
        account_proof.push(node);
    }
    let definition = chain_definition(chain_id).ok_or(GatewayProviderFailure::Permanent)?;
    if definition.network != network {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(UntrustedAccountProofRpcInput {
        chain_id,
        network: network.to_owned(),
        captured_at_unix,
        block_number,
        block_hash,
        state_root,
        address: expected_address,
        balance: parse_field_u256(object, "balance")?,
        nonce: parse_field_quantity_u64(object, "nonce")?,
        code_hash: parse_field_fixed_hex(object, "codeHash")?,
        storage_root: parse_field_fixed_hex(object, "storageHash")?,
        account_proof,
    })
}

pub(crate) fn parse_field_fixed_hex<const N: usize>(
    object: &Map<String, Value>,
    field: &str,
) -> Result<[u8; N], GatewayProviderFailure> {
    parse_fixed_hex(object.get(field).ok_or(GatewayProviderFailure::Permanent)?)
}

pub(crate) fn parse_fixed_hex<const N: usize>(
    value: &Value,
) -> Result<[u8; N], GatewayProviderFailure> {
    let bytes = parse_data_hex(value, N)?;
    bytes
        .try_into()
        .map_err(|_| GatewayProviderFailure::Permanent)
}

fn parse_data_hex(value: &Value, maximum_bytes: usize) -> Result<Vec<u8>, GatewayProviderFailure> {
    let value = value.as_str().ok_or(GatewayProviderFailure::Permanent)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(GatewayProviderFailure::Permanent)?;
    if digits.len() % 2 != 0
        || digits.len() > maximum_bytes.saturating_mul(2)
        || digits
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    alloy_primitives::hex::decode(digits).map_err(|_| GatewayProviderFailure::Permanent)
}

pub(crate) fn parse_field_quantity_u64(
    object: &Map<String, Value>,
    field: &str,
) -> Result<u64, GatewayProviderFailure> {
    parse_quantity_u64(object.get(field).ok_or(GatewayProviderFailure::Permanent)?)
}

pub(crate) fn parse_quantity_u64(value: &Value) -> Result<u64, GatewayProviderFailure> {
    let value = value.as_str().ok_or(GatewayProviderFailure::Permanent)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(GatewayProviderFailure::Permanent)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || digits.len() > 16
        || digits
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    u64::from_str_radix(digits, 16).map_err(|_| GatewayProviderFailure::Permanent)
}

fn parse_field_u256(
    object: &Map<String, Value>,
    field: &str,
) -> Result<U256, GatewayProviderFailure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(GatewayProviderFailure::Permanent)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(GatewayProviderFailure::Permanent)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || digits.len() > 64
        || digits
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    let mut padded = String::with_capacity(digits.len() + 1);
    if digits.len() % 2 != 0 {
        padded.push('0');
    }
    padded.push_str(digits);
    let bytes =
        alloy_primitives::hex::decode(padded).map_err(|_| GatewayProviderFailure::Permanent)?;
    Ok(U256::from_be_slice(&bytes))
}

pub(crate) fn canonical_data_hex(bytes: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use alloy_primitives::keccak256;
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount};
    use base64::Engine;
    use ratspeak_eth_verifier::{
        BeaconCheckpointRoot, MemoryAccountStore, PinnedCheckpoint, Verifier,
    };

    use super::*;
    use crate::messaging::{
        AuthenticatedGatewayEnvelope, GatewayMessageOutcome, GatewayRateLimit, GatewayRelayGuard,
        encode_test_evidence_request, encode_test_signed_relay,
    };
    use crate::{UntrustedConsensusRpcInput, UntrustedExecutionHeaderRpcInput};

    const REQUESTER: [u8; 16] = [0x31; 16];
    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    #[derive(Debug, Default)]
    struct ScriptedTransport {
        replies: VecDeque<Result<GatewayHttpResponse, HttpTransportFailure>>,
        requests: Vec<Vec<u8>>,
    }

    impl GatewayHttpTransport for ScriptedTransport {
        fn post_json(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
            _timeout: Duration,
        ) -> Result<GatewayHttpResponse, HttpTransportFailure> {
            self.requests.push(body.to_vec());
            self.replies.pop_front().expect("scripted HTTP reply")
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(u64);

    impl UnixClock for FixedClock {
        fn now_unix(&self) -> Result<u64, GatewayProviderFailure> {
            Ok(self.0)
        }
    }

    fn decode_fixture(value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .unwrap()
    }

    fn builder() -> SepoliaGatewayBuilder {
        let execution_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-execution-header-11574048.rseth.b64"
        ));
        let execution = Verifier::sepolia()
            .parse_execution_header_proof(&execution_bytes)
            .unwrap();
        SepoliaGatewayBuilder::from_untrusted_rpc(
            &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            &UntrustedConsensusRpcInput {
                chain_id: SEPOLIA_CHAIN_ID,
                network: SEPOLIA_NETWORK.to_owned(),
                captured_at_unix: 0,
                bootstrap_ssz: decode_fixture(include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/sepolia-bootstrap-343888.ssz.b64"
                )),
                updates_ssz: Vec::new(),
                finality_update_ssz: None,
            },
            &UntrustedExecutionHeaderRpcInput {
                chain_id: execution.chain_id,
                network: execution.network,
                captured_at_unix: execution.created_at_unix,
                rlp_header: execution.rlp_header,
            },
        )
        .unwrap()
    }

    fn raw_native_transfer() -> Vec<u8> {
        alloy_primitives::hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap()
    }

    fn accepted_relay() -> AcceptedSignedRelay {
        let raw = raw_native_transfer();
        let message = encode_test_signed_relay([0x42; 16], 1_000, &raw);
        let mut guard =
            GatewayRelayGuard::new(REQUESTER, GatewayRateLimit::conservative()).unwrap();
        let GatewayMessageOutcome::SignedRelay(relay) = guard
            .handle_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(REQUESTER, &message),
                1,
            )
            .unwrap()
        else {
            panic!("expected relay")
        };
        relay
    }

    fn accepted_evidence(
        kind: MessagingEvidenceKind,
        subject: [u8; 32],
    ) -> AcceptedEvidenceRequest {
        let message = encode_test_evidence_request(
            [0x43; 16],
            kind,
            subject,
            ratspeak_eth_verifier::MAX_BUNDLE_BYTES as u32,
            true,
            1_000,
        );
        let mut guard =
            GatewayRelayGuard::new(REQUESTER, GatewayRateLimit::conservative()).unwrap();
        let GatewayMessageOutcome::EvidenceRequest(request) = guard
            .handle_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(REQUESTER, &message),
                1,
            )
            .unwrap()
        else {
            panic!("expected evidence request")
        };
        request
    }

    fn response(id: u64, result: Value) -> GatewayHttpResponse {
        GatewayHttpResponse::new(
            200,
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap(),
        )
    }

    #[test]
    fn exact_raw_transaction_submission_is_hash_bound_and_method_fixed() {
        let relay = accepted_relay();
        let mut transport = ScriptedTransport::default();
        transport
            .replies
            .push_back(Ok(response(1, json!(canonical_data_hex(&relay.tx_hash())))));
        let mut provider = SepoliaRpcProvider::new(
            builder(),
            transport,
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let observation = provider.submit_signed_relay(&relay).unwrap();
        assert_eq!(observation.status(), RelayProviderStatus::Accepted);
        let transport = provider.into_transport();
        let request: Value = serde_json::from_slice(&transport.requests[0]).unwrap();
        assert_eq!(request["method"], "eth_sendRawTransaction");
        assert_eq!(
            request["params"][0],
            canonical_data_hex(relay.raw_transaction())
        );
        assert_eq!(request["id"], 1);
    }

    #[test]
    fn relay_rejects_mismatched_id_hash_false_acceptance_and_rpc_shape() {
        for body in [
            json!({"jsonrpc":"2.0","id":2,"result":canonical_data_hex(&accepted_relay().tx_hash())}),
            json!({"jsonrpc":"2.0","id":1,"result":canonical_data_hex(&[0x99; 32])}),
            json!({"jsonrpc":"2.0","id":1,"result":canonical_data_hex(&accepted_relay().tx_hash()),"method":"eth_sendRawTransaction"}),
        ] {
            let mut transport = ScriptedTransport::default();
            transport.replies.push_back(Ok(GatewayHttpResponse::new(
                200,
                serde_json::to_vec(&body).unwrap(),
            )));
            let mut provider = SepoliaRpcProvider::new(
                builder(),
                transport,
                FixedClock(7),
                ProviderHttpPolicy::conservative(),
            )
            .unwrap();
            assert_eq!(
                provider.submit_signed_relay(&accepted_relay()),
                Err(GatewayProviderFailure::Permanent)
            );
        }
    }

    #[test]
    fn valid_rpc_error_is_rejection_not_confirmation() {
        let rejection = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"rejected"}}"#;
        match parse_rpc_reply(rejection, 1).unwrap() {
            RpcReply::Rejected { code } => assert_eq!(code, -32000),
            RpcReply::Result(_) => panic!("RPC rejection was parsed as a result"),
        }
        let mut transport = ScriptedTransport::default();
        transport
            .replies
            .push_back(Ok(GatewayHttpResponse::new(200, rejection.to_vec())));
        let mut provider = SepoliaRpcProvider::new(
            builder(),
            transport,
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let observation = provider.submit_signed_relay(&accepted_relay()).unwrap();
        assert_eq!(observation.status(), RelayProviderStatus::Rejected);
    }

    #[test]
    fn transport_failures_http_status_timeout_and_oversize_are_bounded() {
        for reply in [
            Err(HttpTransportFailure::Transient),
            Err(HttpTransportFailure::Oversized),
            Ok(GatewayHttpResponse::new(429, Vec::new())),
            Ok(GatewayHttpResponse::new(401, Vec::new())),
        ] {
            let expected = match &reply {
                Err(HttpTransportFailure::Transient)
                | Ok(GatewayHttpResponse { status: 429, .. }) => GatewayProviderFailure::Transient,
                _ => GatewayProviderFailure::Permanent,
            };
            let mut transport = ScriptedTransport::default();
            transport.replies.push_back(reply);
            let mut provider = SepoliaRpcProvider::new(
                builder(),
                transport,
                FixedClock(7),
                ProviderHttpPolicy::conservative(),
            )
            .unwrap();
            assert_eq!(
                provider.submit_signed_relay(&accepted_relay()),
                Err(expected)
            );
        }

        let policy = ProviderHttpPolicy {
            maximum_json_response_bytes: 64,
            ..ProviderHttpPolicy::conservative()
        };
        let mut transport = ScriptedTransport::default();
        // A buggy injected transport returns more than the cap it was given.
        transport
            .replies
            .push_back(Ok(GatewayHttpResponse::new(200, vec![b' '; 65])));
        let mut provider =
            SepoliaRpcProvider::new(builder(), transport, FixedClock(7), policy).unwrap();
        assert_eq!(
            provider.submit_signed_relay(&accepted_relay()),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn verified_execution_header_is_served_without_rpc_authority() {
        let builder = builder();
        let block_hash = builder.execution_block_hash();
        let expected = builder.execution_bundle().clone();
        let mut provider = SepoliaRpcProvider::new(
            builder,
            ScriptedTransport::default(),
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let bundle = provider
            .fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::ExecutionHeader,
                block_hash,
            ))
            .unwrap();
        assert_eq!(bundle, expected);
        assert!(provider.into_transport().requests.is_empty());
    }

    #[test]
    fn consensus_is_served_only_for_the_configured_checkpoint_root() {
        let builder = builder();
        let root = builder.checkpoint_root();
        let expected = builder.consensus_bundle().clone();
        let request = accepted_evidence(MessagingEvidenceKind::Consensus, root);
        let encoder = GatewayRelayGuard::new(REQUESTER, GatewayRateLimit::conservative()).unwrap();
        assert!(
            !encoder
                .evidence_manifest(&request, &expected)
                .unwrap()
                .is_empty()
        );
        assert!(
            !encoder
                .evidence_response(&request, &expected)
                .unwrap()
                .is_empty()
        );
        let wrong_request = accepted_evidence(MessagingEvidenceKind::Consensus, [0x55; 32]);
        assert_eq!(
            encoder
                .evidence_response(&wrong_request, &expected)
                .unwrap_err(),
            crate::GatewayMessageError::EvidenceMismatch
        );
        let mut provider = SepoliaRpcProvider::new(
            builder,
            ScriptedTransport::default(),
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            provider
                .fetch_verified_evidence(
                    &accepted_evidence(MessagingEvidenceKind::Consensus, root,)
                )
                .unwrap(),
            expected
        );
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::Consensus,
                [0x55; 32],
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        assert!(provider.into_transport().requests.is_empty());
    }

    #[test]
    fn wrong_execution_subject_and_default_receipt_backend_fail_closed() {
        let mut provider = SepoliaRpcProvider::new(
            builder(),
            ScriptedTransport::default(),
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::ExecutionHeader,
                [0x55; 32]
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::ReceiptProof,
                [0x66; 32]
            )),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn account_rpc_material_is_strict_and_locally_verifiable() {
        let address = [0x11; 20];
        let account = TrieAccount {
            nonce: 7,
            balance: U256::from(123_456_789_u64),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };
        let key = Nibbles::unpack(keccak256(address));
        let mut trie = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([key]));
        trie.add_leaf(key, &alloy_rlp::encode(account));
        let state_root: [u8; 32] = trie.root().into();
        let nodes = trie
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();
        let result = json!({
            "address": canonical_data_hex(&address),
            "balance": "0x75bcd15",
            "codeHash": canonical_data_hex(account.code_hash.as_slice()),
            "nonce": "0x7",
            "storageHash": canonical_data_hex(account.storage_root.as_slice()),
            "accountProof": nodes.iter().map(|node| canonical_data_hex(node)).collect::<Vec<_>>(),
            "storageProof": [],
        });
        let input =
            parse_account_proof_result(
                &result,
                SEPOLIA_CHAIN_ID,
                SEPOLIA_NETWORK,
                77,
                42,
                [0x22; 32],
                state_root,
                address,
            ).unwrap();
        let bytes = crate::encode_account_proof(&input).unwrap();
        Verifier::sepolia()
            .verify_and_import(
                &bytes,
                &PinnedCheckpoint::sepolia(42, [0x22; 32], state_root),
                &mut MemoryAccountStore::default(),
            )
            .unwrap();

        let mut wrong = result;
        wrong["balance"] = json!("0x075bcd15");
        assert_eq!(
            parse_account_proof_result(
                &wrong,
                SEPOLIA_CHAIN_ID,
                SEPOLIA_NETWORK,
                77,
                42,
                [0x22; 32],
                state_root,
                address,
            ),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn block_root_mismatch_is_rejected_before_get_proof() {
        let builder = builder();
        let block = json!({
            "hash": canonical_data_hex(&builder.execution_block_hash()),
            "number": format!("0x{:x}", builder.execution_block_number()),
            "stateRoot": canonical_data_hex(&[0x99; 32]),
            "transactionsRoot": canonical_data_hex(&builder.execution_transactions_root()),
            "receiptsRoot": canonical_data_hex(&builder.execution_receipts_root()),
        });
        let mut transport = ScriptedTransport::default();
        transport.replies.push_back(Ok(response(1, block)));
        let mut provider = SepoliaRpcProvider::new(
            builder,
            transport,
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let mut subject = [0; 32];
        subject[12..].copy_from_slice(&[0x11; 20]);
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::AccountProof,
                subject
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(provider.into_transport().requests.len(), 1);
    }

    #[test]
    fn account_requests_use_only_the_anchored_block_and_eip_1898_selector() {
        let builder = builder();
        let block_hash = builder.execution_block_hash();
        let block = json!({
            "hash": canonical_data_hex(&block_hash),
            "number": format!("0x{:x}", builder.execution_block_number()),
            "stateRoot": canonical_data_hex(&builder.execution_state_root()),
            "transactionsRoot": canonical_data_hex(&builder.execution_transactions_root()),
            "receiptsRoot": canonical_data_hex(&builder.execution_receipts_root()),
        });
        let address = [0x11; 20];
        let invalid_proof = json!({
            "address": canonical_data_hex(&address),
            "balance": "0x0",
            "codeHash": canonical_data_hex(&[0; 32]),
            "nonce": "0x0",
            "storageHash": canonical_data_hex(&[0; 32]),
            "accountProof": ["0x01"],
            "storageProof": [],
        });
        let mut transport = ScriptedTransport::default();
        transport.replies.push_back(Ok(response(1, block)));
        transport.replies.push_back(Ok(response(2, invalid_proof)));
        let mut provider = SepoliaRpcProvider::new(
            builder,
            transport,
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let mut subject = [0; 32];
        subject[12..].copy_from_slice(&address);
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::AccountProof,
                subject
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        let transport = provider.into_transport();
        assert_eq!(transport.requests.len(), 2);
        let block_request: Value = serde_json::from_slice(&transport.requests[0]).unwrap();
        assert_eq!(block_request["method"], "eth_getBlockByHash");
        assert_eq!(
            block_request["params"],
            json!([canonical_data_hex(&block_hash), false])
        );
        let proof_request: Value = serde_json::from_slice(&transport.requests[1]).unwrap();
        assert_eq!(proof_request["method"], "eth_getProof");
        assert_eq!(proof_request["params"][0], canonical_data_hex(&address));
        assert_eq!(proof_request["params"][1], json!([]));
        assert_eq!(
            proof_request["params"][2]["blockHash"],
            canonical_data_hex(&block_hash)
        );
        assert_eq!(proof_request["params"][2]["requireCanonical"], true);
    }

    #[test]
    fn unsupported_eip_1898_selector_falls_back_to_exact_finalized_number() {
        let builder = builder();
        let block_hash = builder.execution_block_hash();
        let block_number = builder.execution_block_number();
        let block = json!({
            "hash": canonical_data_hex(&block_hash),
            "number": format!("0x{block_number:x}"),
            "stateRoot": canonical_data_hex(&builder.execution_state_root()),
            "transactionsRoot": canonical_data_hex(&builder.execution_transactions_root()),
            "receiptsRoot": canonical_data_hex(&builder.execution_receipts_root()),
        });
        let address = [0x11; 20];
        let invalid_proof = json!({
            "address": canonical_data_hex(&address),
            "balance": "0x0",
            "codeHash": canonical_data_hex(&[0; 32]),
            "nonce": "0x0",
            "storageHash": canonical_data_hex(&[0; 32]),
            "accountProof": ["0x01"],
            "storageProof": [],
        });
        let mut transport = ScriptedTransport::default();
        transport.replies.push_back(Ok(response(1, block)));
        transport.replies.push_back(Ok(GatewayHttpResponse::new(
            200,
            br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"unsupported selector"}}"#
                .to_vec(),
        )));
        transport.replies.push_back(Ok(response(3, invalid_proof)));
        let mut provider = SepoliaRpcProvider::new(
            builder,
            transport,
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let mut subject = [0; 32];
        subject[12..].copy_from_slice(&address);
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::AccountProof,
                subject
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        let transport = provider.into_transport();
        assert_eq!(transport.requests.len(), 3);
        let fallback: Value = serde_json::from_slice(&transport.requests[2]).unwrap();
        assert_eq!(fallback["method"], "eth_getProof");
        assert_eq!(fallback["params"][0], canonical_data_hex(&address));
        assert_eq!(fallback["params"][1], json!([]));
        assert_eq!(fallback["params"][2], format!("0x{block_number:x}"));
    }

    #[test]
    fn malformed_account_subject_never_reaches_http() {
        let mut provider = SepoliaRpcProvider::new(
            builder(),
            ScriptedTransport::default(),
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            provider.fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::AccountProof,
                [0x11; 32]
            )),
            Err(GatewayProviderFailure::Permanent)
        );
        assert!(provider.into_transport().requests.is_empty());
    }

    #[test]
    fn endpoint_and_authorization_are_redacted_and_https_is_default() {
        const MARKER: &str = "PRIVATE_PROVIDER_MARKER";
        assert_eq!(
            validate_endpoint("http://example.com", HttpEndpointPolicy::HttpsOnly),
            Err(ProviderConfigurationError::InsecureEndpoint)
        );
        assert!(
            validate_endpoint(
                "http://127.0.0.1:8545",
                HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
            )
            .is_ok()
        );
        assert_eq!(
            validate_endpoint(
                "http://192.0.2.1:8545",
                HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
            ),
            Err(ProviderConfigurationError::InsecureEndpoint)
        );
        assert_eq!(
            validate_endpoint(
                "http://localhost:8545",
                HttpEndpointPolicy::AllowLoopbackHttpForDevelopment
            ),
            Err(ProviderConfigurationError::InsecureEndpoint)
        );
        let auth = OperatorAuthorization::parse(&format!("Bearer {MARKER}")).unwrap();
        assert!(!format!("{auth:?}").contains(MARKER));
        let transport = ReqwestGatewayHttpTransport::new(
            &format!("https://{MARKER}.invalid/rpc"),
            Some(auth),
            HttpEndpointPolicy::HttpsOnly,
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert!(!format!("{transport:?}").contains(MARKER));
        let response = GatewayHttpResponse::new(200, MARKER.as_bytes().to_vec());
        assert!(!format!("{response:?}").contains(MARKER));
    }

    #[test]
    fn json_depth_count_hex_and_error_data_are_rejected() {
        let mut nested = json!(null);
        for _ in 0..=MAX_JSON_DEPTH {
            nested = json!([nested]);
        }
        assert_eq!(
            validate_json_limits(&nested),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            parse_fixed_hex::<1>(&json!("0xAA")),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            parse_quantity_u64(&json!("0x00")),
            Err(GatewayProviderFailure::Permanent)
        );
        let error =
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"no","data":"secret"}}"#;
        assert!(matches!(
            parse_rpc_reply(error, 1),
            Err(GatewayProviderFailure::Permanent)
        ));
        let duplicate = br#"{"jsonrpc":"2.0","id":1,"id":2,"result":"0x00"}"#;
        assert!(matches!(
            parse_rpc_reply(duplicate, 1),
            Err(GatewayProviderFailure::Transient)
        ));
    }

    #[test]
    fn wrong_chain_transaction_is_rejected_before_http() {
        let mut raw = raw_native_transfer();
        // The chain id is part of the signed typed transaction. Any mutation is
        // invalid and must be rejected locally before transport.
        raw[4] ^= 1;
        let mut remaining = raw.as_slice();
        let decoded = TxEnvelope::decode_2718(&mut remaining).unwrap();
        assert_ne!(decoded.chain_id(), Some(SEPOLIA_CHAIN_ID));
        let local_hash = keccak256(&raw).0;
        assert_eq!(
            prevalidate_raw_relay(&raw, local_hash, [2; 20]),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn exact_receipt_backend_output_is_still_locally_verified() {
        #[derive(Debug)]
        struct FixtureReceipt(UntrustedTxReceiptProofRpcInput);
        impl ExactReceiptProofBackend for FixtureReceipt {
            fn fetch_exact_receipt_proof(
                &mut self,
                _tx_hash: [u8; 32],
                _number: u64,
                _block: [u8; 32],
                _at: u64,
            ) -> Result<UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
                Ok(self.0.clone())
            }
        }
        let captured = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(&captured)
            .unwrap();
        let mut input = UntrustedTxReceiptProofRpcInput {
            chain_id: parsed.chain_id,
            network: parsed.network,
            captured_at_unix: parsed.created_at_unix,
            block_number: parsed.block_number,
            block_hash: parsed.block_hash,
            tx_hash: parsed.tx_hash,
            tx_index: parsed.tx_index,
            raw_tx: parsed.raw_tx,
            receipt: parsed.receipt,
            transactions_root: parsed.transactions_root,
            receipts_root: parsed.receipts_root,
            tx_proof: parsed.tx_proof,
            receipt_proof: parsed.receipt_proof,
        };
        let tx_hash = input.tx_hash;
        // The backend is deliberately handed a different timestamp; the
        // provider must replace it with its own clock before bundling.
        input.captured_at_unix = 99;
        let provider = SepoliaRpcProvider::new(
            builder(),
            ScriptedTransport::default(),
            FixedClock(7),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let mut provider = provider.with_receipt_backend(FixtureReceipt(input));
        let bundle = provider
            .fetch_verified_evidence(&accepted_evidence(
                MessagingEvidenceKind::ReceiptProof,
                tx_hash,
            ))
            .unwrap();
        let verified = Verifier::sepolia()
            .parse_tx_receipt_proof(bundle.bytes())
            .unwrap();
        assert_eq!(verified.created_at_unix, 7);
        assert_eq!(verified.tx_hash, tx_hash);
        assert_ne!(bundle.bytes(), captured);
    }
}
