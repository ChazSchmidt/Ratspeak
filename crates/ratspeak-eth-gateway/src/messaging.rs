use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Header, Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{TxKind, U256};
use alloy_rlp::Decodable;
use ratspeak_eth_verifier::{BeaconCheckpointRoot, MAX_BUNDLE_BYTES, SEPOLIA_CHAIN_ID, Verifier};
use sha2::{Digest, Sha256};

use crate::{GatewayBundle, GatewayBundleKind};

pub(crate) mod durable;

pub use durable::{
    DurableGatewayAdmission, DurableGatewayOutcome, GatewayAdmissionError, GatewayJob,
    GatewayJobKind, GatewayJobState, GatewayLease, GatewayResultKind, GatewayStoredResult,
};

const MAGIC: &[u8; 7] = b"RSETHM1";
const VERSION: u8 = 1;
const KIND_EVIDENCE_REQUEST: u8 = 1;
const KIND_EVIDENCE_MANIFEST: u8 = 2;
const KIND_EVIDENCE_RESPONSE: u8 = 3;
const KIND_SIGNED_RELAY: u8 = 4;
const KIND_RELAY_OBSERVATION: u8 = 5;
const KIND_BULK_APPROVAL: u8 = 6;
const KIND_SERVICE_FAILURE: u8 = 7;
/// Fixed, authenticated request for a non-authoritative transaction presence
/// observation. This is intentionally distinct from receipt proof delivery.
const KIND_TRANSACTION_STATUS_REQUEST: u8 = 8;
/// Fixed response to `KIND_TRANSACTION_STATUS_REQUEST`.
const KIND_TRANSACTION_STATUS_OBSERVATION: u8 = 9;
const MAX_CONTROL_BYTES: usize = 4 * 1024;
const MAX_SIGNED_TRANSACTION_BYTES: usize = 256;
const NATIVE_TRANSFER_GAS_LIMIT: u64 = 21_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingEvidenceKind {
    ExecutionHeader,
    AccountProof,
    ReceiptProof,
    Consensus,
    AccountStatePackage,
    FinalizedReceiptPackage,
}

impl MessagingEvidenceKind {
    fn wire(self) -> u8 {
        match self {
            Self::ExecutionHeader => 1,
            Self::AccountProof => 2,
            Self::ReceiptProof => 3,
            Self::Consensus => 4,
            Self::AccountStatePackage => 5,
            Self::FinalizedReceiptPackage => 6,
        }
    }

    fn from_wire(value: u8) -> Result<Self, GatewayMessageError> {
        match value {
            1 => Ok(Self::ExecutionHeader),
            2 => Ok(Self::AccountProof),
            3 => Ok(Self::ReceiptProof),
            4 => Ok(Self::Consensus),
            5 => Ok(Self::AccountStatePackage),
            6 => Ok(Self::FinalizedReceiptPackage),
            _ => Err(GatewayMessageError::UnsupportedKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceCheckpointContext {
    epoch: u64,
    root: [u8; 32],
}

impl EvidenceCheckpointContext {
    pub fn new(epoch: u64, root: [u8; 32]) -> Result<Self, GatewayMessageError> {
        if epoch == 0 || root == [0; 32] {
            return Err(GatewayMessageError::InvalidMessage);
        }
        Ok(Self { epoch, root })
    }

    pub fn epoch(self) -> u64 {
        self.epoch
    }

    pub fn root(self) -> [u8; 32] {
        self.root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayObservation {
    GatewayAccepted,
    RpcAccepted,
    RpcRejected,
}

/// A narrow, non-authoritative provider observation about one exact
/// transaction hash. `Included` is not receipt verification or finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionPresence {
    NotSeen,
    Pending,
    Included,
}

impl TransactionPresence {
    fn wire(self) -> u8 {
        match self {
            Self::NotSeen => 1,
            Self::Pending => 2,
            Self::Included => 3,
        }
    }

    fn from_wire(value: u8) -> Result<Self, GatewayMessageError> {
        match value {
            1 => Ok(Self::NotSeen),
            2 => Ok(Self::Pending),
            3 => Ok(Self::Included),
            _ => Err(GatewayMessageError::InvalidMessage),
        }
    }
}

/// A sampled execution head. These values are provider reports, not trust
/// anchors; the field node must still independently verify receipt evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionStatusHead {
    number: u64,
    hash: [u8; 32],
}

impl TransactionStatusHead {
    pub fn new(number: u64, hash: [u8; 32]) -> Result<Self, GatewayMessageError> {
        if number == 0 || hash == [0; 32] {
            return Err(GatewayMessageError::InvalidMessage);
        }
        Ok(Self { number, hash })
    }

    pub fn number(self) -> u64 {
        self.number
    }
    pub fn hash(self) -> [u8; 32] {
        self.hash
    }
}

/// Typed result produced only by the configured gateway provider boundary.
/// No constructor accepts a caller-selected RPC method or endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionStatusObservation {
    tx_hash: [u8; 32],
    presence: TransactionPresence,
    included_block_number: u64,
    included_block_hash: [u8; 32],
    latest: TransactionStatusHead,
    safe: TransactionStatusHead,
    finalized: TransactionStatusHead,
}

impl TransactionStatusObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_hash: [u8; 32],
        presence: TransactionPresence,
        included_block_number: u64,
        included_block_hash: [u8; 32],
        latest: TransactionStatusHead,
        safe: TransactionStatusHead,
        finalized: TransactionStatusHead,
    ) -> Result<Self, GatewayMessageError> {
        if tx_hash == [0; 32]
            || matches!(presence, TransactionPresence::Included)
                != (included_block_number != 0 && included_block_hash != [0; 32])
            || (!matches!(presence, TransactionPresence::Included)
                && (included_block_number != 0 || included_block_hash != [0; 32]))
        {
            return Err(GatewayMessageError::InvalidMessage);
        }
        Ok(Self {
            tx_hash,
            presence,
            included_block_number,
            included_block_hash,
            latest,
            safe,
            finalized,
        })
    }

    pub fn tx_hash(self) -> [u8; 32] {
        self.tx_hash
    }
    pub fn presence(self) -> TransactionPresence {
        self.presence
    }
    pub fn included_block_number(self) -> u64 {
        self.included_block_number
    }
    pub fn included_block_hash(self) -> [u8; 32] {
        self.included_block_hash
    }
    pub fn latest(self) -> TransactionStatusHead {
        self.latest
    }
    pub fn safe(self) -> TransactionStatusHead {
        self.safe
    }
    pub fn finalized(self) -> TransactionStatusHead {
        self.finalized
    }
}

impl RelayObservation {
    fn wire(self) -> u8 {
        match self {
            Self::GatewayAccepted => 1,
            Self::RpcAccepted => 2,
            Self::RpcRejected => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRateLimit {
    pub window_seconds: u64,
    /// Authenticated attachments accepted for consideration in one window.
    /// Malformed, unsupported, and expired attachments consume an attempt.
    pub maximum_requests: u32,
    /// Declared evidence response budgets and signed transaction bytes accepted
    /// in one window. Invalid messages cannot reserve response capacity.
    pub maximum_requested_bytes: u64,
}

impl GatewayRateLimit {
    pub fn conservative() -> Self {
        Self {
            window_seconds: 60,
            maximum_requests: 8,
            maximum_requested_bytes: 4 * 1024 * 1024 + 64 * 1024,
        }
    }
}

/// Capability produced only by the crate's trusted LXMF adapter boundary.
///
/// Application code cannot turn a caller-provided boolean into this type:
///
/// ```compile_fail
/// use ratspeak_eth_gateway::AuthenticatedGatewayEnvelope;
/// let _ = AuthenticatedGatewayEnvelope::from_verified_lxmf([1; 16], b"request");
/// ```
#[derive(Clone, Copy)]
pub struct AuthenticatedGatewayEnvelope<'a> {
    sender_source_hash: [u8; 16],
    persisted_attachment: &'a [u8],
}

impl std::fmt::Debug for AuthenticatedGatewayEnvelope<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGatewayEnvelope")
            .field("persisted_attachment_len", &self.persisted_attachment.len())
            .finish()
    }
}

impl<'a> AuthenticatedGatewayEnvelope<'a> {
    /// Constructed only by the in-crate LXMF adapter after it validates the
    /// exact delivered message and native attachment field.
    pub(super) fn from_lxmf_adapter(
        sender_source_hash: [u8; 16],
        persisted_attachment: &'a [u8],
    ) -> Self {
        Self {
            sender_source_hash,
            persisted_attachment,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_verified_lxmf(
        sender_source_hash: [u8; 16],
        persisted_attachment: &'a [u8],
    ) -> Self {
        Self::from_lxmf_adapter(sender_source_hash, persisted_attachment)
    }

    pub(super) fn request_id(&self) -> Result<[u8; 16], GatewayMessageError> {
        match decode(self.persisted_attachment)? {
            Message::EvidenceRequest(request) => Ok(request.request_id),
            Message::SignedRelay(relay) => Ok(relay.request_id),
            Message::BulkApproval(approval) => Ok(approval.request_id),
            Message::TransactionStatus(request) => Ok(request.request_id),
            Message::Other => Err(GatewayMessageError::UnsupportedKind),
        }
    }
}

pub struct AcceptedBulkApproval {
    request_id: [u8; 16],
    evidence_kind: MessagingEvidenceKind,
    digest: [u8; 32],
    encoded_size: u32,
    expires_at_unix: u64,
    checkpoint_context: Option<EvidenceCheckpointContext>,
}

impl std::fmt::Debug for AcceptedBulkApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedBulkApproval")
            .field("evidence_kind", &self.evidence_kind)
            .field("encoded_size", &self.encoded_size)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl AcceptedBulkApproval {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn evidence_kind(&self) -> MessagingEvidenceKind {
        self.evidence_kind
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn encoded_size(&self) -> u32 {
        self.encoded_size
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub fn checkpoint_context(&self) -> Option<EvidenceCheckpointContext> {
        self.checkpoint_context
    }
}

pub struct AcceptedEvidenceRequest {
    request_id: [u8; 16],
    evidence_kind: MessagingEvidenceKind,
    subject: [u8; 32],
    maximum_response_bytes: u32,
    bulk_approved: bool,
    expires_at_unix: u64,
    checkpoint_context: Option<EvidenceCheckpointContext>,
}

impl std::fmt::Debug for AcceptedEvidenceRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedEvidenceRequest")
            .field("evidence_kind", &self.evidence_kind)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("bulk_approved", &self.bulk_approved)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl AcceptedEvidenceRequest {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn evidence_kind(&self) -> MessagingEvidenceKind {
        self.evidence_kind
    }
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }
    pub fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }
    pub fn bulk_approved(&self) -> bool {
        self.bulk_approved
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub fn checkpoint_context(&self) -> Option<EvidenceCheckpointContext> {
        self.checkpoint_context
    }
}

pub struct AcceptedSignedRelay {
    request_id: [u8; 16],
    tx_hash: [u8; 32],
    sender: [u8; 20],
    raw_transaction: Vec<u8>,
    expires_at_unix: u64,
}

/// One exact transaction-status request, admitted only after the LXMF edge
/// authenticated its sender and persisted its attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedTransactionStatusRequest {
    request_id: [u8; 16],
    expires_at_unix: u64,
    tx_hash: [u8; 32],
}

impl AcceptedTransactionStatusRequest {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
}

impl std::fmt::Debug for AcceptedSignedRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedSignedRelay")
            .field("raw_transaction_len", &self.raw_transaction.len())
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl AcceptedSignedRelay {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    pub fn sender(&self) -> [u8; 20] {
        self.sender
    }
    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }
}

#[derive(Debug)]
pub enum GatewayMessageOutcome {
    IgnoredUnauthenticated,
    EvidenceRequest(AcceptedEvidenceRequest),
    SignedRelay(AcceptedSignedRelay),
    TransactionStatus(AcceptedTransactionStatusRequest),
    BulkApproval(AcceptedBulkApproval),
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum GatewayMessageError {
    #[error("invalid gateway message")]
    InvalidMessage,
    #[error("unsupported gateway message kind")]
    UnsupportedKind,
    #[error("gateway request expired")]
    Expired,
    #[error("gateway request exceeds its byte budget")]
    BudgetExceeded,
    #[error("bulk evidence was not explicitly approved")]
    BulkApprovalRequired,
    #[error("gateway request was rate limited")]
    RateLimited,
    #[error("gateway evidence does not match the request")]
    EvidenceMismatch,
    #[error("signed relay is not a supported clear-signed EIP-1559 transaction")]
    InvalidSignedRelay,
}

#[derive(Debug)]
/// A process-local guard for one configured LXMF requester identity.
///
/// Callers must retain this guard across requests for the rate limit to have
/// effect. Restart-persistent or distributed limiting is outside this type.
pub struct GatewayRelayGuard {
    expected_requester_source_hash: [u8; 16],
    limit: GatewayRateLimit,
    window_started_unix: Option<u64>,
    requests_in_window: u32,
    requested_bytes_in_window: u64,
}

impl GatewayRelayGuard {
    pub fn new(
        expected_requester_source_hash: [u8; 16],
        limit: GatewayRateLimit,
    ) -> Result<Self, GatewayMessageError> {
        if expected_requester_source_hash == [0; 16]
            || limit.window_seconds == 0
            || limit.maximum_requests == 0
            || limit.maximum_requested_bytes == 0
            || limit.maximum_requested_bytes > 64 * 1024 * 1024
        {
            return Err(GatewayMessageError::InvalidMessage);
        }
        Ok(Self {
            expected_requester_source_hash,
            limit,
            window_started_unix: None,
            requests_in_window: 0,
            requested_bytes_in_window: 0,
        })
    }

    pub fn handle_persisted_attachment(
        &mut self,
        envelope: AuthenticatedGatewayEnvelope<'_>,
        now_unix: u64,
    ) -> Result<GatewayMessageOutcome, GatewayMessageError> {
        if envelope.sender_source_hash != self.expected_requester_source_hash {
            return Ok(GatewayMessageOutcome::IgnoredUnauthenticated);
        }

        // Charge the authenticated attempt before interpreting attacker-controlled
        // protocol or transaction bytes. A valid message reserves its larger
        // declared response/relay byte cost after bounded decoding.
        self.charge_attempt(now_unix)?;
        let message = decode(envelope.persisted_attachment)?;
        match message {
            Message::EvidenceRequest(request) => {
                if now_unix >= request.expires_at_unix {
                    return Err(GatewayMessageError::Expired);
                }
                self.charge_requested_bytes(u64::from(request.maximum_response_bytes))?;
                Ok(GatewayMessageOutcome::EvidenceRequest(request))
            }
            Message::SignedRelay(relay) => {
                if now_unix >= relay.expires_at_unix {
                    return Err(GatewayMessageError::Expired);
                }
                self.charge_requested_bytes(relay.raw_transaction.len() as u64)?;
                Ok(GatewayMessageOutcome::SignedRelay(relay))
            }
            Message::TransactionStatus(request) => {
                if now_unix >= request.expires_at_unix {
                    return Err(GatewayMessageError::Expired);
                }
                self.charge_requested_bytes(226)?;
                Ok(GatewayMessageOutcome::TransactionStatus(request))
            }
            Message::BulkApproval(approval) => {
                if now_unix >= approval.expires_at_unix {
                    return Err(GatewayMessageError::Expired);
                }
                Ok(GatewayMessageOutcome::BulkApproval(approval))
            }
            _ => Err(GatewayMessageError::UnsupportedKind),
        }
    }

    fn charge_attempt(&mut self, now_unix: u64) -> Result<(), GatewayMessageError> {
        if self
            .window_started_unix
            .is_none_or(|started| now_unix.saturating_sub(started) >= self.limit.window_seconds)
        {
            self.window_started_unix = Some(now_unix);
            self.requests_in_window = 0;
            self.requested_bytes_in_window = 0;
        }
        let next_requests = self
            .requests_in_window
            .checked_add(1)
            .ok_or(GatewayMessageError::RateLimited)?;
        if next_requests > self.limit.maximum_requests {
            return Err(GatewayMessageError::RateLimited);
        }
        self.requests_in_window = next_requests;
        Ok(())
    }

    fn charge_requested_bytes(&mut self, bytes: u64) -> Result<(), GatewayMessageError> {
        let next_bytes = self
            .requested_bytes_in_window
            .checked_add(bytes)
            .ok_or(GatewayMessageError::RateLimited)?;
        if next_bytes > self.limit.maximum_requested_bytes {
            return Err(GatewayMessageError::RateLimited);
        }
        self.requested_bytes_in_window = next_bytes;
        Ok(())
    }

    pub fn evidence_manifest(
        &self,
        request: &AcceptedEvidenceRequest,
        bundle: &GatewayBundle,
    ) -> Result<Vec<u8>, GatewayMessageError> {
        validate_bundle_for_request(request, bundle, false)?;
        let digest: [u8; 32] = Sha256::digest(bundle.bytes()).into();
        let size =
            u32::try_from(bundle.bytes().len()).map_err(|_| GatewayMessageError::BudgetExceeded)?;
        Ok(encode_manifest(
            request.request_id,
            request.evidence_kind,
            request.checkpoint_context,
            digest,
            size,
        ))
    }

    pub fn evidence_response(
        &self,
        request: &AcceptedEvidenceRequest,
        bundle: &GatewayBundle,
    ) -> Result<Vec<u8>, GatewayMessageError> {
        validate_bundle_for_request(request, bundle, true)?;
        let digest: [u8; 32] = Sha256::digest(bundle.bytes()).into();
        Ok(encode_evidence(
            request.request_id,
            request.evidence_kind,
            request.checkpoint_context,
            digest,
            bundle.bytes(),
        ))
    }

    pub(crate) fn staged_evidence_response(
        &self,
        request: &AcceptedEvidenceRequest,
        bundle: &GatewayBundle,
    ) -> Result<Vec<u8>, GatewayMessageError> {
        validate_bundle_for_request(request, bundle, false)?;
        let digest: [u8; 32] = Sha256::digest(bundle.bytes()).into();
        Ok(encode_evidence(
            request.request_id,
            request.evidence_kind,
            request.checkpoint_context,
            digest,
            bundle.bytes(),
        ))
    }

    pub fn relay_observation(
        &self,
        relay: &AcceptedSignedRelay,
        observation: RelayObservation,
    ) -> Vec<u8> {
        let mut out = prelude(KIND_RELAY_OBSERVATION);
        out.extend_from_slice(&relay.request_id);
        out.extend_from_slice(&relay.tx_hash);
        out.push(observation.wire());
        out
    }

    pub fn transaction_status_observation(
        &self,
        request: &AcceptedTransactionStatusRequest,
        observation: TransactionStatusObservation,
    ) -> Result<Vec<u8>, GatewayMessageError> {
        if observation.tx_hash() != request.tx_hash() {
            return Err(GatewayMessageError::EvidenceMismatch);
        }
        let mut out = prelude(KIND_TRANSACTION_STATUS_OBSERVATION);
        out.extend_from_slice(&request.request_id);
        out.extend_from_slice(&request.tx_hash);
        out.push(observation.presence.wire());
        out.extend_from_slice(&observation.included_block_number.to_le_bytes());
        out.extend_from_slice(&observation.included_block_hash);
        for head in [observation.latest, observation.safe, observation.finalized] {
            out.extend_from_slice(&head.number.to_le_bytes());
            out.extend_from_slice(&head.hash);
        }
        debug_assert_eq!(out.len(), 226);
        Ok(out)
    }
}

/// A coarse, authenticated transport failure for one exact retained request.
///
/// This notice carries no provider text and makes no statement about Ethereum
/// state. It only lets the requester stop waiting when the gateway has already
/// durably concluded that it cannot complete the request.
pub(crate) fn service_failure(
    request_id: [u8; 16],
    original_attachment_digest: [u8; 32],
) -> Vec<u8> {
    let mut out = prelude(KIND_SERVICE_FAILURE);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&original_attachment_digest);
    out
}

fn validate_bundle_for_request(
    request: &AcceptedEvidenceRequest,
    bundle: &GatewayBundle,
    require_bulk_approval: bool,
) -> Result<(), GatewayMessageError> {
    if bundle.bytes().is_empty()
        || bundle.bytes().len() > MAX_BUNDLE_BYTES
        || bundle.bytes().len() > request.maximum_response_bytes as usize
    {
        return Err(GatewayMessageError::BudgetExceeded);
    }
    if require_bulk_approval && bundle.bytes().len() > MAX_CONTROL_BYTES && !request.bulk_approved {
        return Err(GatewayMessageError::BulkApprovalRequired);
    }
    let subject_matches = match (request.evidence_kind, bundle.kind()) {
        (MessagingEvidenceKind::Consensus, GatewayBundleKind::ConsensusBootstrap) => {
            Verifier::sepolia()
                .reverify_historical_consensus_bootstrap(
                    bundle.bytes(),
                    &BeaconCheckpointRoot::sepolia(request.subject),
                )
                .map(|_| true)
        }
        (MessagingEvidenceKind::ExecutionHeader, GatewayBundleKind::ExecutionHeader) => {
            Verifier::sepolia()
                .parse_execution_header_proof(bundle.bytes())
                .map(|parsed| {
                    let mut rlp = parsed.rlp_header.as_slice();
                    Header::decode(&mut rlp).is_ok_and(|header| {
                        rlp.is_empty() && header.hash_slow().0 == request.subject
                    })
                })
        }
        (MessagingEvidenceKind::AccountProof, GatewayBundleKind::AccountProof) => {
            Verifier::sepolia()
                .parse_account_proof(bundle.bytes())
                .map(|parsed| {
                    request.subject[..12] == [0; 12] && request.subject[12..] == parsed.address
                })
        }
        (MessagingEvidenceKind::ReceiptProof, GatewayBundleKind::TxReceiptProof) => {
            let verifier = Verifier::sepolia();
            verifier
                .parse_tx_receipt_proof(bundle.bytes())
                .map(|parsed| parsed.tx_hash == request.subject)
                .or_else(|_| {
                    verifier
                        .parse_finalized_tx_receipt_proof(bundle.bytes())
                        .map(|parsed| parsed.receipt_proof.tx_hash == request.subject)
                })
        }
        (MessagingEvidenceKind::AccountStatePackage, GatewayBundleKind::AccountStateEvidence) => {
            request
                .checkpoint_context
                .ok_or(ratspeak_eth_verifier::VerifyError::CheckpointMismatch)
                .and_then(|context| {
                    let mut address = [0_u8; 20];
                    if request.subject[..12] != [0; 12] {
                        return Err(ratspeak_eth_verifier::VerifyError::UnexpectedAccount);
                    }
                    address.copy_from_slice(&request.subject[12..]);
                    Verifier::sepolia()
                        .verify_account_state_evidence(
                            bundle.bytes(),
                            &BeaconCheckpointRoot::sepolia(context.root),
                            address,
                        )
                        .map(|_| true)
                })
        }
        (
            MessagingEvidenceKind::FinalizedReceiptPackage,
            GatewayBundleKind::FinalizedReceiptEvidence,
        ) => request
            .checkpoint_context
            .ok_or(ratspeak_eth_verifier::VerifyError::CheckpointMismatch)
            .and_then(|context| {
                Verifier::sepolia()
                    .verify_finalized_receipt_evidence(
                        bundle.bytes(),
                        &BeaconCheckpointRoot::sepolia(context.root),
                        request.subject,
                    )
                    .map(|_| true)
            }),
        _ => return Err(GatewayMessageError::EvidenceMismatch),
    };
    subject_matches
        .map_err(|_| GatewayMessageError::EvidenceMismatch)?
        .then_some(())
        .ok_or(GatewayMessageError::EvidenceMismatch)
}

enum Message {
    EvidenceRequest(AcceptedEvidenceRequest),
    SignedRelay(AcceptedSignedRelay),
    BulkApproval(AcceptedBulkApproval),
    TransactionStatus(AcceptedTransactionStatusRequest),
    Other,
}

fn decode(bytes: &[u8]) -> Result<Message, GatewayMessageError> {
    if bytes.len() > MAX_CONTROL_BYTES || bytes.len() < MAGIC.len() + 1 + 8 + 1 {
        return Err(GatewayMessageError::InvalidMessage);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(7)? != MAGIC || cursor.u8()? != VERSION || cursor.u64()? != SEPOLIA_CHAIN_ID {
        return Err(GatewayMessageError::InvalidMessage);
    }
    match cursor.u8()? {
        KIND_EVIDENCE_REQUEST => {
            let request_id = cursor.array()?;
            let expires_at_unix = cursor.u64()?;
            let evidence_kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
            let subject = cursor.array()?;
            let checkpoint_context = decode_checkpoint_context(&mut cursor, evidence_kind)?;
            let maximum_response_bytes = cursor.u32()?;
            let bulk_approved = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(GatewayMessageError::InvalidMessage),
            };
            cursor.finish()?;
            if request_id == [0; 16]
                || subject == [0; 32]
                || maximum_response_bytes == 0
                || maximum_response_bytes as usize > MAX_BUNDLE_BYTES
                || expires_at_unix == 0
            {
                return Err(GatewayMessageError::InvalidMessage);
            }
            Ok(Message::EvidenceRequest(AcceptedEvidenceRequest {
                request_id,
                evidence_kind,
                subject,
                maximum_response_bytes,
                bulk_approved,
                expires_at_unix,
                checkpoint_context,
            }))
        }
        KIND_SIGNED_RELAY => {
            let request_id = cursor.array()?;
            let expires_at_unix = cursor.u64()?;
            let size = cursor.u32()? as usize;
            if request_id == [0; 16]
                || expires_at_unix == 0
                || size == 0
                || size > MAX_SIGNED_TRANSACTION_BYTES
            {
                return Err(GatewayMessageError::InvalidSignedRelay);
            }
            let raw_transaction = cursor.take(size)?.to_vec();
            cursor.finish()?;
            let (tx_hash, sender) = validate_signed_transaction(&raw_transaction)?;
            Ok(Message::SignedRelay(AcceptedSignedRelay {
                request_id,
                tx_hash,
                sender,
                raw_transaction,
                expires_at_unix,
            }))
        }
        KIND_BULK_APPROVAL => {
            let request_id = cursor.array()?;
            let expires_at_unix = cursor.u64()?;
            let evidence_kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
            let checkpoint_context = decode_checkpoint_context(&mut cursor, evidence_kind)?;
            let digest = cursor.array()?;
            let encoded_size = cursor.u32()?;
            cursor.finish()?;
            if request_id == [0; 16]
                || digest == [0; 32]
                || encoded_size as usize > MAX_BUNDLE_BYTES
                || encoded_size as usize <= MAX_CONTROL_BYTES
                || expires_at_unix == 0
            {
                return Err(GatewayMessageError::InvalidMessage);
            }
            Ok(Message::BulkApproval(AcceptedBulkApproval {
                request_id,
                evidence_kind,
                digest,
                encoded_size,
                expires_at_unix,
                checkpoint_context,
            }))
        }
        KIND_TRANSACTION_STATUS_REQUEST => {
            let request_id = cursor.array()?;
            let expires_at_unix = cursor.u64()?;
            let tx_hash = cursor.array()?;
            cursor.finish()?;
            if request_id == [0; 16] || expires_at_unix == 0 || tx_hash == [0; 32] {
                return Err(GatewayMessageError::InvalidMessage);
            }
            Ok(Message::TransactionStatus(
                AcceptedTransactionStatusRequest {
                    request_id,
                    expires_at_unix,
                    tx_hash,
                },
            ))
        }
        KIND_EVIDENCE_MANIFEST
        | KIND_EVIDENCE_RESPONSE
        | KIND_RELAY_OBSERVATION
        | KIND_TRANSACTION_STATUS_OBSERVATION => Ok(Message::Other),
        _ => Err(GatewayMessageError::UnsupportedKind),
    }
}

fn validate_signed_transaction(raw: &[u8]) -> Result<([u8; 32], [u8; 20]), GatewayMessageError> {
    let mut remaining = raw;
    let envelope = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|_| GatewayMessageError::InvalidSignedRelay)?;
    if !remaining.is_empty() {
        return Err(GatewayMessageError::InvalidSignedRelay);
    }
    let chain_id = envelope
        .chain_id()
        .ok_or(GatewayMessageError::InvalidSignedRelay)?;
    if chain_definition(chain_id).is_none() {
        return Err(GatewayMessageError::InvalidSignedRelay);
    }
    let TxEnvelope::Eip1559(signed) = &envelope else {
        return Err(GatewayMessageError::InvalidSignedRelay);
    };
    let tx = signed.tx();
    if !matches!(tx.to, TxKind::Call(_)) || !tx.access_list.is_empty() {
        return Err(GatewayMessageError::InvalidSignedRelay);
    }
    let sender = envelope
        .recover_signer()
        .map_err(|_| GatewayMessageError::InvalidSignedRelay)?;
    Ok((envelope.tx_hash().0, *sender.0))
}

fn encode_manifest(
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    checkpoint_context: Option<EvidenceCheckpointContext>,
    digest: [u8; 32],
    size: u32,
) -> Vec<u8> {
    let mut out = prelude(KIND_EVIDENCE_MANIFEST);
    out.extend_from_slice(&request_id);
    out.push(kind.wire());
    encode_checkpoint_context(&mut out, kind, checkpoint_context);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&size.to_le_bytes());
    out
}

fn encode_evidence(
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    checkpoint_context: Option<EvidenceCheckpointContext>,
    digest: [u8; 32],
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = prelude(KIND_EVIDENCE_RESPONSE);
    out.extend_from_slice(&request_id);
    out.push(kind.wire());
    encode_checkpoint_context(&mut out, kind, checkpoint_context);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

pub(crate) fn evidence_response_requires_bulk_approval(
    bytes: &[u8],
) -> Result<bool, GatewayMessageError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(MAGIC.len())? != MAGIC
        || cursor.u8()? != VERSION
        || cursor.u64()? != SEPOLIA_CHAIN_ID
        || cursor.u8()? != KIND_EVIDENCE_RESPONSE
    {
        return Err(GatewayMessageError::InvalidMessage);
    }
    let _: [u8; 16] = cursor.array()?;
    let kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
    decode_checkpoint_context(&mut cursor, kind)?;
    let _: [u8; 32] = cursor.array()?;
    let size = cursor.u32()? as usize;
    cursor.take(size)?;
    cursor.finish()?;
    Ok(size > MAX_CONTROL_BYTES)
}

fn kind_requires_checkpoint_context(kind: MessagingEvidenceKind) -> bool {
    matches!(
        kind,
        MessagingEvidenceKind::AccountStatePackage | MessagingEvidenceKind::FinalizedReceiptPackage
    )
}

fn decode_checkpoint_context(
    cursor: &mut Cursor<'_>,
    kind: MessagingEvidenceKind,
) -> Result<Option<EvidenceCheckpointContext>, GatewayMessageError> {
    if !kind_requires_checkpoint_context(kind) {
        return Ok(None);
    }
    EvidenceCheckpointContext::new(cursor.u64()?, cursor.array()?).map(Some)
}

fn encode_checkpoint_context(
    out: &mut Vec<u8>,
    kind: MessagingEvidenceKind,
    context: Option<EvidenceCheckpointContext>,
) {
    if kind_requires_checkpoint_context(kind) {
        let context = context.expect("validated contextual evidence request");
        out.extend_from_slice(&context.epoch.to_le_bytes());
        out.extend_from_slice(&context.root);
    }
}

fn prelude(kind: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
    out.push(kind);
    out
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], GatewayMessageError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(GatewayMessageError::InvalidMessage)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(GatewayMessageError::InvalidMessage)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, GatewayMessageError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, GatewayMessageError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, GatewayMessageError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], GatewayMessageError> {
        self.take(N)?
            .try_into()
            .map_err(|_| GatewayMessageError::InvalidMessage)
    }
    fn finish(self) -> Result<(), GatewayMessageError> {
        (self.offset == self.bytes.len())
            .then_some(())
            .ok_or(GatewayMessageError::InvalidMessage)
    }
}

#[cfg(test)]
pub(crate) fn encode_test_evidence_request(
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    budget: u32,
    bulk: bool,
    expires: u64,
) -> Vec<u8> {
    let mut out = prelude(KIND_EVIDENCE_REQUEST);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&expires.to_le_bytes());
    out.push(kind.wire());
    out.extend_from_slice(&subject);
    out.extend_from_slice(&budget.to_le_bytes());
    out.push(u8::from(bulk));
    out
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_test_contextual_evidence_request(
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    budget: u32,
    bulk: bool,
    expires: u64,
) -> Vec<u8> {
    assert!(kind_requires_checkpoint_context(kind));
    let mut out = prelude(KIND_EVIDENCE_REQUEST);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&expires.to_le_bytes());
    out.push(kind.wire());
    out.extend_from_slice(&subject);
    encode_checkpoint_context(
        &mut out,
        kind,
        Some(EvidenceCheckpointContext::new(checkpoint_epoch, checkpoint_root).unwrap()),
    );
    out.extend_from_slice(&budget.to_le_bytes());
    out.push(u8::from(bulk));
    out
}

#[cfg(test)]
pub(crate) fn encode_test_signed_relay(request_id: [u8; 16], expires: u64, raw: &[u8]) -> Vec<u8> {
    let mut out = prelude(KIND_SIGNED_RELAY);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&expires.to_le_bytes());
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(raw);
    out
}

#[cfg(test)]
pub(crate) fn encode_test_transaction_status_request(
    request_id: [u8; 16],
    expires: u64,
    tx_hash: [u8; 32],
) -> Vec<u8> {
    let mut out = prelude(KIND_TRANSACTION_STATUS_REQUEST);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&expires.to_le_bytes());
    out.extend_from_slice(&tx_hash);
    debug_assert_eq!(out.len(), 73);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_relay(request_id: [u8; 16], expires: u64, raw: &[u8]) -> Vec<u8> {
        encode_test_signed_relay(request_id, expires, raw)
    }

    fn status_heads() -> [TransactionStatusHead; 3] {
        [
            TransactionStatusHead::new(101, [0x11; 32]).unwrap(),
            TransactionStatusHead::new(100, [0x22; 32]).unwrap(),
            TransactionStatusHead::new(99, [0x33; 32]).unwrap(),
        ]
    }

    #[test]
    fn transaction_status_request_wire_is_fixed_and_strict() {
        let request_id = [0x10; 16];
        let tx_hash = [0x20; 32];
        let wire =
            encode_test_transaction_status_request(request_id, 0x8877_6655_4433_2211, tx_hash);
        assert_eq!(wire.len(), 73);
        assert_eq!(&wire[..7], MAGIC);
        assert_eq!(wire[16], KIND_TRANSACTION_STATUS_REQUEST);
        let Message::TransactionStatus(decoded) = decode(&wire).unwrap() else {
            panic!("wrong frame");
        };
        assert_eq!(decoded.request_id(), request_id);
        assert_eq!(decoded.expires_at_unix(), 0x8877_6655_4433_2211);
        assert_eq!(decoded.tx_hash(), tx_hash);
        for malformed in [
            wire[..72].to_vec(),
            {
                let mut value = wire.clone();
                value.push(0);
                value
            },
            encode_test_transaction_status_request([0; 16], 12, tx_hash),
            encode_test_transaction_status_request(request_id, 0, tx_hash),
            encode_test_transaction_status_request(request_id, 12, [0; 32]),
        ] {
            assert!(decode(&malformed).is_err());
        }
    }

    #[test]
    fn transaction_status_observation_is_fixed_correlated_and_non_authoritative() {
        let request = AcceptedTransactionStatusRequest {
            request_id: [0x41; 16],
            expires_at_unix: 100,
            tx_hash: [0x42; 32],
        };
        let [latest, safe, finalized] = status_heads();
        let observation = TransactionStatusObservation::new(
            request.tx_hash(),
            TransactionPresence::Included,
            98,
            [0x44; 32],
            latest,
            safe,
            finalized,
        )
        .unwrap();
        let guard = GatewayRelayGuard::new([0x55; 16], GatewayRateLimit::conservative()).unwrap();
        let wire = guard
            .transaction_status_observation(&request, observation)
            .unwrap();
        assert_eq!(wire.len(), 226);
        assert_eq!(wire[16], KIND_TRANSACTION_STATUS_OBSERVATION);
        assert_eq!(&wire[17..33], &request.request_id);
        assert_eq!(&wire[33..65], &request.tx_hash());
        assert_eq!(wire[65], 3);
        assert!(
            TransactionStatusObservation::new(
                request.tx_hash(),
                TransactionPresence::Pending,
                98,
                [0x44; 32],
                latest,
                safe,
                finalized,
            )
            .is_err()
        );
        assert!(TransactionStatusHead::new(0, [1; 32]).is_err());
        assert!(
            guard
                .transaction_status_observation(
                    &request,
                    TransactionStatusObservation::new(
                        [0x99; 32],
                        TransactionPresence::NotSeen,
                        0,
                        [0; 32],
                        latest,
                        safe,
                        finalized,
                    )
                    .unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn legacy_request_wire_is_unchanged_and_has_no_checkpoint_context() {
        let wire = encode_test_evidence_request(
            [0x11; 16],
            MessagingEvidenceKind::ReceiptProof,
            [0x22; 32],
            0x0011_2233,
            true,
            0x8877_6655_4433_2211,
        );
        let mut expected = prelude(KIND_EVIDENCE_REQUEST);
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&0x8877_6655_4433_2211_u64.to_le_bytes());
        expected.push(3);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&0x0011_2233_u32.to_le_bytes());
        expected.push(1);
        assert_eq!(wire, expected);
        let Message::EvidenceRequest(decoded) = decode(&wire).unwrap() else {
            panic!("expected evidence request")
        };
        assert_eq!(decoded.checkpoint_context(), None);
    }

    #[test]
    fn composite_request_context_is_exact_and_mutation_fails_closed() {
        let wire = encode_test_contextual_evidence_request(
            [0x12; 16],
            MessagingEvidenceKind::FinalizedReceiptPackage,
            [0x33; 32],
            343_888,
            [0x44; 32],
            MAX_BUNDLE_BYTES as u32,
            false,
            1_000,
        );
        let Message::EvidenceRequest(decoded) = decode(&wire).unwrap() else {
            panic!("expected evidence request")
        };
        assert_eq!(
            decoded.checkpoint_context(),
            Some(EvidenceCheckpointContext::new(343_888, [0x44; 32]).unwrap())
        );

        let context_offset = MAGIC.len() + 1 + 8 + 1 + 16 + 8 + 1 + 32;
        let mut zero_epoch = wire.clone();
        zero_epoch[context_offset..context_offset + 8].fill(0);
        assert!(matches!(
            decode(&zero_epoch),
            Err(GatewayMessageError::InvalidMessage)
        ));

        let mut wrong_root = wire;
        wrong_root[context_offset + 8] ^= 1;
        let Message::EvidenceRequest(decoded) = decode(&wrong_root).unwrap() else {
            panic!("expected evidence request")
        };
        assert_ne!(decoded.checkpoint_context().unwrap().root(), [0x44; 32]);
    }

    #[test]
    fn unconfigured_identity_does_nothing_before_parsing() {
        let expected = [1; 16];
        let mut guard = GatewayRelayGuard::new(expected, GatewayRateLimit::conservative()).unwrap();
        assert!(matches!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf([2; 16], b"garbage"),
                    100,
                )
                .unwrap(),
            GatewayMessageOutcome::IgnoredUnauthenticated
        ));
    }

    #[test]
    fn request_validation_expiry_and_rate_limit_are_bounded() {
        let expected = [1; 16];
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 1,
            maximum_requested_bytes: 100,
        };
        let mut guard = GatewayRelayGuard::new(expected, limit).unwrap();
        let request = encode_test_evidence_request(
            [3; 16],
            MessagingEvidenceKind::ReceiptProof,
            [4; 32],
            100,
            true,
            200,
        );
        assert!(matches!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &request),
                    100
                )
                .unwrap(),
            GatewayMessageOutcome::EvidenceRequest(_)
        ));
        assert_eq!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &request),
                    101
                )
                .unwrap_err(),
            GatewayMessageError::RateLimited
        );
        let mut fresh = GatewayRelayGuard::new(expected, limit).unwrap();
        assert_eq!(
            fresh
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &request),
                    200
                )
                .unwrap_err(),
            GatewayMessageError::Expired
        );
        assert_eq!(
            fresh
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &request),
                    201
                )
                .unwrap_err(),
            GatewayMessageError::RateLimited
        );
    }

    #[test]
    fn malformed_authenticated_attempt_is_rate_limited_before_decode() {
        let expected = [1; 16];
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 1,
            maximum_requested_bytes: 100,
        };
        let mut guard = GatewayRelayGuard::new(expected, limit).unwrap();
        assert_eq!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, b"garbage"),
                    100
                )
                .unwrap_err(),
            GatewayMessageError::InvalidMessage
        );

        let request = encode_test_evidence_request(
            [3; 16],
            MessagingEvidenceKind::ReceiptProof,
            [4; 32],
            100,
            true,
            200,
        );
        assert_eq!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &request),
                    101
                )
                .unwrap_err(),
            GatewayMessageError::RateLimited
        );
    }

    #[test]
    fn unix_epoch_is_a_real_window_start_not_an_uninitialized_sentinel() {
        let expected = [1; 16];
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 1,
            maximum_requested_bytes: 100,
        };
        let mut guard = GatewayRelayGuard::new(expected, limit).unwrap();
        for (index, expected_error) in [
            GatewayMessageError::InvalidMessage,
            GatewayMessageError::RateLimited,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                guard
                    .handle_persisted_attachment(
                        AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, b"garbage"),
                        0
                    )
                    .unwrap_err(),
                expected_error,
                "attempt {index} at timestamp zero"
            );
        }
    }

    #[test]
    fn valid_requests_consume_declared_byte_budget_without_double_counting_attempts() {
        let expected = [1; 16];
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 2,
            maximum_requested_bytes: 100,
        };
        let mut guard = GatewayRelayGuard::new(expected, limit).unwrap();
        let first = encode_test_evidence_request(
            [3; 16],
            MessagingEvidenceKind::ReceiptProof,
            [4; 32],
            60,
            true,
            200,
        );
        let second = encode_test_evidence_request(
            [5; 16],
            MessagingEvidenceKind::ReceiptProof,
            [6; 32],
            40,
            true,
            200,
        );
        assert!(matches!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &first),
                    100
                )
                .unwrap(),
            GatewayMessageOutcome::EvidenceRequest(_)
        ));
        assert!(matches!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &second),
                    101
                )
                .unwrap(),
            GatewayMessageOutcome::EvidenceRequest(_)
        ));
    }

    #[test]
    fn unknown_message_kinds_are_not_representable() {
        assert_eq!(
            MessagingEvidenceKind::from_wire(4).unwrap(),
            MessagingEvidenceKind::Consensus
        );
        assert_eq!(
            MessagingEvidenceKind::from_wire(0).unwrap_err(),
            GatewayMessageError::UnsupportedKind
        );
        let mut bytes = prelude(99);
        bytes.extend_from_slice(&[0; 64]);
        let mut guard = GatewayRelayGuard::new([1; 16], GatewayRateLimit::conservative()).unwrap();
        assert_eq!(
            guard
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf([1; 16], &bytes),
                    100
                )
                .unwrap_err(),
            GatewayMessageError::UnsupportedKind
        );
    }

    #[test]
    fn signed_relay_accepts_only_exact_native_sepolia_envelopes() {
        let raw = alloy_primitives::hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap();
        let expected = [0x91; 16];
        let message = signed_relay([0x92; 16], 200, &raw);
        let mut guard = GatewayRelayGuard::new(expected, GatewayRateLimit::conservative()).unwrap();
        let outcome = guard
            .handle_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &message),
                100,
            )
            .unwrap();
        let rendered = format!("{outcome:?}");
        assert!(rendered.contains("raw_transaction_len"));
        assert!(!rendered.contains(&alloy_primitives::hex::encode(&raw)));
        let GatewayMessageOutcome::SignedRelay(relay) = outcome else {
            panic!("expected signed relay")
        };
        assert_eq!(relay.raw_transaction(), raw);
        assert_ne!(relay.tx_hash(), [0; 32]);

        let mut wrong_kind = raw;
        wrong_kind[0] = 1;
        let invalid = signed_relay([0x93; 16], 200, &wrong_kind);
        let mut fresh = GatewayRelayGuard::new(expected, GatewayRateLimit::conservative()).unwrap();
        assert_eq!(
            fresh
                .handle_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(expected, &invalid),
                    100,
                )
                .unwrap_err(),
            GatewayMessageError::InvalidSignedRelay
        );
    }
}
