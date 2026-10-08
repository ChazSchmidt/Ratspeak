use alloy_consensus::Header;
use alloy_rlp::Decodable;
use ratspeak_eth_verifier::{
    BeaconCheckpointRoot, KIND_TX_RECEIPT_PROOF, MAX_BUNDLE_BYTES, MemoryAccountStore,
    SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, Verifier, VerifyError,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{
    AssuranceEventInput, AssuranceEventKind, AssuranceSubjectKind, record_assurance,
};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, StoredFinalizedHeader,
    StoredSignedTransaction, parse_stored_u64, stored_array,
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
// Transaction-status messages deliberately have their own fixed wire kinds.
// They are progress reports from an authenticated service, never Ethereum
// evidence or a substitute for locally verified receipt confirmation.
const KIND_TRANSACTION_STATUS_REQUEST: u8 = 8;
const KIND_TRANSACTION_STATUS_OBSERVATION: u8 = 9;
const MAX_CONTROL_BYTES: usize = 4 * 1024;
const MAX_SIGNED_TRANSACTION_BYTES: usize = 256;
const TRANSACTION_STATUS_RESPONSE_BYTES: u64 = 226;
/// Reticulum-friendly lower bound for repeated status requests for the same
/// transaction and service. It limits duplicate traffic but makes no claim
/// about block time or confirmation progress.
pub const MIN_TRANSACTION_STATUS_POLL_INTERVAL_SECONDS: u64 = 12;
const MAX_CONSENSUS_REQUEST_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
const MAX_OUTBOUND_LEASE_SECONDS: u64 = 60 * 60;
const MAX_OUTBOUND_QUEUE_ATTEMPTS: i64 = 3;
pub const MAX_PENDING_BULK_EVIDENCE_REVIEWS: usize = 64;
const OUTBOUND_READY: i64 = 0;
const OUTBOUND_LEASED: i64 = 1;
const OUTBOUND_SETTLED: i64 = 2;

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
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::ExecutionHeader => 1,
            Self::AccountProof => 2,
            Self::ReceiptProof => 3,
            Self::Consensus => 4,
            Self::AccountStatePackage => 5,
            Self::FinalizedReceiptPackage => 6,
        }
    }

    pub(crate) fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ExecutionHeader),
            2 => Ok(Self::AccountProof),
            3 => Ok(Self::ReceiptProof),
            4 => Ok(Self::Consensus),
            5 => Ok(Self::AccountStatePackage),
            6 => Ok(Self::FinalizedReceiptPackage),
            _ => Err(NodeStoreError::new(
                "unsupported Ethereum messaging evidence kind",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckpointRequestContext {
    pub(crate) checkpoint_epoch: u64,
    pub(crate) checkpoint_root: [u8; 32],
}

impl CheckpointRequestContext {
    fn is_valid(self) -> bool {
        self.checkpoint_epoch != 0 && self.checkpoint_root != [0; 32]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayObservation {
    GatewayAccepted,
    RpcAccepted,
    RpcRejected,
}

/// A service-reported transaction location. This is deliberately separate
/// from [`crate::TransactionAssurance`]: none of these variants establish
/// Ethereum state or transaction confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    NotSeen,
    Pending,
    Included,
}

impl TransactionStatus {
    fn wire(self) -> u8 {
        match self {
            Self::NotSeen => 1,
            Self::Pending => 2,
            Self::Included => 3,
        }
    }

    fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::NotSeen),
            2 => Ok(Self::Pending),
            3 => Ok(Self::Included),
            _ => Err(NodeStoreError::new(
                "invalid transaction status observation",
            )),
        }
    }
}

/// A locally received, authenticated service report. All source and time
/// fields come from the Ratspeak envelope/host, never the wire payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTransactionStatusObservation {
    tx_hash: [u8; 32],
    source_hash: [u8; 16],
    status: TransactionStatus,
    included_block_number: Option<u64>,
    included_block_hash: Option<[u8; 32]>,
    latest_head_number: u64,
    latest_head_hash: [u8; 32],
    safe_head_number: u64,
    safe_head_hash: [u8; 32],
    finalized_head_number: u64,
    finalized_head_hash: [u8; 32],
    observed_at_unix: u64,
}

/// Durable transport/verification lifecycle for the newest exact receipt
/// package request for one local transaction and selected service. A
/// Completed request is not itself receipt confirmation; callers must read
/// `TransactionAssurance` separately for that conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedReceiptRequestProgress {
    request_id: [u8; 16],
    status: MessageRequestStatus,
    created_at_unix: u64,
    expires_at_unix: u64,
}

impl FinalizedReceiptRequestProgress {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn status(&self) -> MessageRequestStatus {
        self.status
    }

    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Continuity classification for successive authenticated service reports.
/// It describes reported progress only; it has no Ethereum-state authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatusContinuity {
    /// There is no earlier retained report for this transaction.
    FirstObservation,
    /// Two successive reports name the same included block.
    StillIncluded,
    /// A later report names a different included block.
    IncludedMoved,
    /// A prior inclusion disappeared from the newest report.
    AwaitingReinclusion,
    /// An inclusion was reported again after an intervening absence.
    Reincluded,
    /// The newest report changed non-inclusion state without an inclusion.
    StatusChanged,
    /// Successive reports conflict with previously reported finalized-head
    /// progression. The report remains non-authoritative and should be shown
    /// as uncertain rather than interpreted as a transaction outcome.
    Inconsistent,
}

/// A bounded continuity projection for application progress rendering. It
/// exposes only authenticated source hashes, never a user-visible label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionStatusHistoryView {
    latest: StoredTransactionStatusObservation,
    previous_inclusion: Option<StoredTransactionStatusObservation>,
    continuity: TransactionStatusContinuity,
}

impl TransactionStatusHistoryView {
    pub fn latest(&self) -> &StoredTransactionStatusObservation {
        &self.latest
    }

    pub fn continuity(&self) -> TransactionStatusContinuity {
        self.continuity
    }

    /// The nearest earlier Included report from the same authenticated source
    /// as [`Self::latest`], if one exists. It is still only a service report.
    pub fn previous_inclusion(&self) -> Option<&StoredTransactionStatusObservation> {
        self.previous_inclusion.as_ref()
    }
}

impl StoredTransactionStatusObservation {
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    pub fn source_hash(&self) -> [u8; 16] {
        self.source_hash
    }
    pub fn status(&self) -> TransactionStatus {
        self.status
    }
    pub fn included_block_number(&self) -> Option<u64> {
        self.included_block_number
    }
    pub fn included_block_hash(&self) -> Option<[u8; 32]> {
        self.included_block_hash
    }
    pub fn latest_head_number(&self) -> u64 {
        self.latest_head_number
    }
    pub fn latest_head_hash(&self) -> [u8; 32] {
        self.latest_head_hash
    }
    pub fn safe_head_number(&self) -> u64 {
        self.safe_head_number
    }
    pub fn safe_head_hash(&self) -> [u8; 32] {
        self.safe_head_hash
    }
    pub fn finalized_head_number(&self) -> u64 {
        self.finalized_head_number
    }
    pub fn finalized_head_hash(&self) -> [u8; 32] {
        self.finalized_head_hash
    }
    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
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

    fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::GatewayAccepted),
            2 => Ok(Self::RpcAccepted),
            3 => Ok(Self::RpcRejected),
            _ => Err(NodeStoreError::new("invalid relay observation")),
        }
    }
}

/// Adapter-supplied LXMF authority for an already persisted attachment.
///
/// `sender_source_hash` is exactly the 16-byte `LxMessage::source_hash` retained
/// by Ratspeak. The adapter must bind `sig_valid` to this same inbound message.
#[derive(Debug)]
pub(crate) struct AuthenticatedNodeEnvelope<'a> {
    sig_valid: bool,
    sender_source_hash: [u8; 16],
    persisted_attachment: &'a [u8],
}

impl<'a> AuthenticatedNodeEnvelope<'a> {
    #[cfg(test)]
    pub(crate) fn new(
        sig_valid: bool,
        sender_source_hash: [u8; 16],
        persisted_attachment: &'a [u8],
    ) -> Self {
        Self {
            sig_valid,
            sender_source_hash,
            persisted_attachment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRequestStatus {
    Pending,
    AwaitingBulkApproval,
    Ready,
    Completed,
    Cancelled,
    Expired,
    PendingVerification,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OutboundMessageBinding {
    gateway_destination_hash: [u8; 16],
    local_source_hash: [u8; 16],
    identity_session_generation: u64,
}

impl std::fmt::Debug for OutboundMessageBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundMessageBinding")
            .field(
                "identity_session_generation",
                &self.identity_session_generation,
            )
            .finish_non_exhaustive()
    }
}

impl OutboundMessageBinding {
    pub fn new(
        gateway_destination_hash: [u8; 16],
        local_source_hash: [u8; 16],
        identity_session_generation: u64,
    ) -> Result<Self> {
        if gateway_destination_hash == [0; 16]
            || local_source_hash == [0; 16]
            || gateway_destination_hash == local_source_hash
            || identity_session_generation == 0
        {
            return Err(NodeStoreError::new("invalid outbound messaging binding"));
        }
        Ok(Self {
            gateway_destination_hash,
            local_source_hash,
            identity_session_generation,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMessageKind {
    EvidenceRequest,
    BulkApproval,
    SignedTransactionRelay,
    TransactionStatusRequest,
}

impl OutboundMessageKind {
    fn as_i64(self) -> i64 {
        match self {
            Self::EvidenceRequest => 1,
            Self::BulkApproval => 2,
            Self::SignedTransactionRelay => 3,
            Self::TransactionStatusRequest => 4,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::EvidenceRequest),
            2 => Ok(Self::BulkApproval),
            3 => Ok(Self::SignedTransactionRelay),
            4 => Ok(Self::TransactionStatusRequest),
            _ => Err(NodeStoreError::new("invalid outbound message kind")),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OutboundMessageLease {
    request_id: [u8; 16],
    kind: OutboundMessageKind,
    generation: u64,
    destination_hash: [u8; 16],
    source_hash: [u8; 16],
    identity_session_generation: u64,
    attachment: Vec<u8>,
}

impl std::fmt::Debug for OutboundMessageLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundMessageLease")
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .field("attachment_len", &self.attachment.len())
            .finish()
    }
}

impl OutboundMessageLease {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn kind(&self) -> OutboundMessageKind {
        self.kind
    }
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }
    pub fn source_hash(&self) -> [u8; 16] {
        self.source_hash
    }
    pub fn attachment(&self) -> &[u8] {
        &self.attachment
    }
}

impl MessageRequestStatus {
    fn as_i64(self) -> i64 {
        match self {
            Self::Pending => 1,
            Self::AwaitingBulkApproval => 2,
            Self::Ready => 3,
            Self::Completed => 4,
            Self::Cancelled => 5,
            Self::Expired => 6,
            Self::PendingVerification => 7,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::AwaitingBulkApproval),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Completed),
            5 => Ok(Self::Cancelled),
            6 => Ok(Self::Expired),
            7 => Ok(Self::PendingVerification),
            _ => Err(NodeStoreError::new("invalid messaging request status")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceManifest {
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    checkpoint_context: Option<CheckpointRequestContext>,
    digest: [u8; 32],
    encoded_size: u32,
}

impl EvidenceManifest {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn kind(&self) -> MessagingEvidenceKind {
        self.kind
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn encoded_size(&self) -> u32 {
        self.encoded_size
    }
}

/// Native-review snapshot for an authenticated, correlated bulk manifest.
///
/// The fields are deliberately private and `Debug` omits identifiers and
/// digests. A snapshot is only a review input: approval requires a one-shot,
/// transactional comparison with the exact durable request row.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingBulkEvidenceReview {
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    checkpoint_context: Option<CheckpointRequestContext>,
    manifest_digest: [u8; 32],
    encoded_size: u32,
    expires_at_unix: u64,
    binding_digest: [u8; 32],
}

impl std::fmt::Debug for PendingBulkEvidenceReview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingBulkEvidenceReview")
            .field("kind", &self.kind)
            .field("encoded_size", &self.encoded_size)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("has_checkpoint_context", &self.checkpoint_context.is_some())
            .finish_non_exhaustive()
    }
}

impl PendingBulkEvidenceReview {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn expected_gateway_source_hash(&self) -> [u8; 16] {
        self.expected_gateway_source_hash
    }

    pub fn kind(&self) -> MessagingEvidenceKind {
        self.kind
    }

    /// Public evidence subject: an account address padded to 32 bytes, a
    /// transaction hash, or the legacy request subject for older proof kinds.
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }

    pub fn checkpoint_epoch(&self) -> Option<u64> {
        self.checkpoint_context
            .map(|context| context.checkpoint_epoch)
    }

    pub fn checkpoint_root(&self) -> Option<[u8; 32]> {
        self.checkpoint_context
            .map(|context| context.checkpoint_root)
    }

    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub fn encoded_size(&self) -> u32 {
        self.encoded_size
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Domain-separated digest binding every reviewed field to the validated
    /// durable request record. It is not gateway or Ethereum authority.
    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkEvidenceReviewDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkEvidenceReviewResolution {
    Approved,
    Denied,
}

/// Authenticated and correlated evidence bytes that still require verifier
/// processing. In particular, receipt evidence here is not confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedEvidence {
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    checkpoint_context: Option<CheckpointRequestContext>,
    digest: [u8; 32],
    bytes: Vec<u8>,
}

/// Authenticated, correlated bytes durably retained before local verification.
/// This type carries no Ethereum authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMessageEvidence {
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    digest: [u8; 32],
    bytes: Vec<u8>,
    received_at_unix: u64,
}

impl PendingMessageEvidence {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn kind(&self) -> MessagingEvidenceKind {
        self.kind
    }
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn received_at_unix(&self) -> u64 {
        self.received_at_unix
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingEvidenceImportOutcome {
    Imported,
    AlreadyCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundEvidenceRequest {
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    maximum_response_bytes: u32,
    created_at_unix: u64,
    expires_at_unix: u64,
}

/// A bounded query for non-authoritative transaction progress. The subject is
/// accepted only if it is an exact signed transaction already stored locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundTransactionStatusRequest {
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    tx_hash: [u8; 32],
    created_at_unix: u64,
    expires_at_unix: u64,
}

/// A bounded exact-receipt request that may be scheduled only from one
/// completed, authenticated status observation. The observation is a traffic
/// hint: its reported block number/hash are never copied into this request or
/// used as proof authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedStatusReceiptRequest {
    request_id: [u8; 16],
    status_request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    maximum_response_bytes: u32,
    now_unix: u64,
    expires_at_unix: u64,
}

impl OutboundTransactionStatusRequest {
    pub fn new(
        request_id: [u8; 16],
        expected_gateway_source_hash: [u8; 16],
        tx_hash: [u8; 32],
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        Self {
            request_id,
            expected_gateway_source_hash,
            tx_hash,
            created_at_unix,
            expires_at_unix,
        }
    }
}

impl FinalizedStatusReceiptRequest {
    /// `status_request_id` identifies the exact completed status request that
    /// made this receipt request eligible. The caller supplies a new random
    /// `request_id`; the node verifies every other binding durably.
    pub fn new(
        request_id: [u8; 16],
        status_request_id: [u8; 16],
        expected_gateway_source_hash: [u8; 16],
        maximum_response_bytes: u32,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        Self {
            request_id,
            status_request_id,
            expected_gateway_source_hash,
            maximum_response_bytes,
            now_unix,
            expires_at_unix,
        }
    }
}

impl OutboundEvidenceRequest {
    pub fn new(
        request_id: [u8; 16],
        expected_gateway_source_hash: [u8; 16],
        kind: MessagingEvidenceKind,
        subject: [u8; 32],
        maximum_response_bytes: u32,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        Self {
            request_id,
            expected_gateway_source_hash,
            kind,
            subject,
            maximum_response_bytes,
            created_at_unix,
            expires_at_unix,
        }
    }
}

impl CorrelatedEvidence {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn kind(&self) -> MessagingEvidenceKind {
        self.kind
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMessageOutcome {
    IgnoredUnauthenticated,
    ManifestAccepted(EvidenceManifest),
    BulkApprovalRequired(EvidenceManifest),
    EvidencePending(PendingMessageEvidence),
    RelayObserved {
        tx_hash: [u8; 32],
        observation: RelayObservation,
    },
    /// An authenticated service progress report. It is not a receipt,
    /// consensus proof, or transaction confirmation.
    TransactionStatusObserved {
        /// Exact completed local request correlation. The application can pass
        /// this only to `plan_finalized_receipt_after_status`; it cannot
        /// select a transaction/block/checkpoint for receipt verification.
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        status: TransactionStatus,
    },
    /// The authenticated gateway durably stopped this transport request.
    /// This is not evidence about Ethereum state.
    ServiceFailed,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Evidence,
    Relay,
    TransactionStatus,
}

impl OperationKind {
    fn as_i64(self) -> i64 {
        match self {
            Self::Evidence => 1,
            Self::Relay => 2,
            Self::TransactionStatus => 3,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Evidence),
            2 => Ok(Self::Relay),
            3 => Ok(Self::TransactionStatus),
            _ => Err(NodeStoreError::new("invalid messaging operation kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestRecord {
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    operation: OperationKind,
    evidence_kind: Option<MessagingEvidenceKind>,
    subject: [u8; 32],
    checkpoint_context: Option<CheckpointRequestContext>,
    maximum_response_bytes: u64,
    bulk_approved: bool,
    created_at_unix: u64,
    expires_at_unix: u64,
    status: MessageRequestStatus,
    manifest_digest: Option<[u8; 32]>,
    manifest_size: Option<u64>,
    relay_observation: Option<RelayObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransactionStatusWireObservation {
    request_id: [u8; 16],
    tx_hash: [u8; 32],
    status: TransactionStatus,
    included_block_number: u64,
    included_block_hash: [u8; 32],
    latest_head_number: u64,
    latest_head_hash: [u8; 32],
    safe_head_number: u64,
    safe_head_hash: [u8; 32],
    finalized_head_number: u64,
    finalized_head_hash: [u8; 32],
}

impl TransactionStatusWireObservation {
    fn validate(self) -> Result<()> {
        let included = self.included_block_number != 0 && self.included_block_hash != [0; 32];
        if (self.status == TransactionStatus::Included) != included
            || self.latest_head_number == 0
            || self.safe_head_number == 0
            || self.finalized_head_number == 0
            || self.latest_head_hash == [0; 32]
            || self.safe_head_hash == [0; 32]
            || self.finalized_head_hash == [0; 32]
            || self.finalized_head_number > self.safe_head_number
            || self.safe_head_number > self.latest_head_number
            || (self.status == TransactionStatus::Included
                && self.included_block_number > self.latest_head_number)
        {
            return Err(NodeStoreError::new(
                "invalid transaction status observation fields",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccountRequestProgressRecord {
    pub(crate) status: MessageRequestStatus,
    pub(crate) bulk_approved: bool,
    pub(crate) outbox_state: Option<i64>,
}

pub(crate) fn create_schema(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_message_requests (
                request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16),
                expected_gateway_source_hash BLOB NOT NULL
                    CHECK(length(expected_gateway_source_hash) = 16),
                operation_kind INTEGER NOT NULL CHECK(operation_kind IN (1, 2, 3)),
                evidence_kind INTEGER CHECK(evidence_kind IS NULL OR evidence_kind IN (1, 2, 3, 4, 5, 6)),
                subject BLOB NOT NULL CHECK(length(subject) = 32),
                checkpoint_epoch TEXT,
                checkpoint_root BLOB CHECK(checkpoint_root IS NULL OR length(checkpoint_root) = 32),
                maximum_response_bytes TEXT NOT NULL,
                bulk_approved INTEGER NOT NULL CHECK(bulk_approved IN (0, 1)),
                created_at_unix TEXT NOT NULL,
                expires_at_unix TEXT NOT NULL,
                status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 7),
                manifest_digest BLOB CHECK(manifest_digest IS NULL OR length(manifest_digest) = 32),
                manifest_size TEXT,
                relay_observation INTEGER
                    CHECK(relay_observation IS NULL OR relay_observation IN (1, 2, 3)),
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                CHECK((operation_kind = 1 AND evidence_kind IS NOT NULL)
                    OR (operation_kind IN (2, 3) AND evidence_kind IS NULL)),
                CHECK((manifest_digest IS NULL AND manifest_size IS NULL)
                    OR (manifest_digest IS NOT NULL AND manifest_size IS NOT NULL)),
                CHECK(operation_kind = 2
                    OR (operation_kind IN (1, 3) AND relay_observation IS NULL)),
                CHECK((evidence_kind IN (5, 6)
                        AND checkpoint_epoch IS NOT NULL AND checkpoint_root IS NOT NULL)
                    OR ((evidence_kind IS NULL OR evidence_kind NOT IN (5, 6))
                        AND checkpoint_epoch IS NULL AND checkpoint_root IS NULL))
            );
             CREATE TABLE IF NOT EXISTS eth_pending_message_evidence (
                request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16),
                evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (1, 2, 3, 4, 5, 6)),
                subject BLOB NOT NULL CHECK(length(subject) = 32),
                evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
                encoded_size TEXT NOT NULL,
                evidence_blob BLOB NOT NULL CHECK(length(evidence_blob) > 0),
                received_at_unix TEXT NOT NULL,
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                FOREIGN KEY(request_id) REFERENCES eth_message_requests(request_id)
             );
             CREATE TABLE IF NOT EXISTS eth_message_outbox (
                request_id BLOB NOT NULL CHECK(length(request_id) = 16),
                item_kind INTEGER NOT NULL CHECK(item_kind IN (1, 2, 3, 4)),
                gateway_destination_hash BLOB NOT NULL CHECK(length(gateway_destination_hash) = 16),
                local_source_hash BLOB NOT NULL CHECK(length(local_source_hash) = 16),
                identity_session_generation TEXT NOT NULL,
                attachment_digest BLOB NOT NULL CHECK(length(attachment_digest) = 32),
                state INTEGER NOT NULL CHECK(state IN (0, 1, 2)),
                attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 3),
                lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
                lease_until_unix TEXT,
                queued_at_unix TEXT,
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                PRIMARY KEY(request_id, item_kind),
                FOREIGN KEY(request_id) REFERENCES eth_message_requests(request_id),
                CHECK((state = 0 AND lease_until_unix IS NULL AND queued_at_unix IS NULL)
                   OR (state = 1 AND lease_until_unix IS NOT NULL AND queued_at_unix IS NULL)
                   OR (state = 2 AND lease_until_unix IS NULL AND queued_at_unix IS NOT NULL))
             );
             CREATE TABLE IF NOT EXISTS eth_transaction_status_observations (
                observation_key BLOB PRIMARY KEY NOT NULL CHECK(length(observation_key) = 32),
                request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
                tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
                source_hash BLOB NOT NULL CHECK(length(source_hash) = 16),
                status INTEGER NOT NULL CHECK(status IN (1, 2, 3)),
                included_block_number TEXT NOT NULL,
                included_block_hash BLOB NOT NULL CHECK(length(included_block_hash) = 32),
                latest_head_number TEXT NOT NULL,
                latest_head_hash BLOB NOT NULL CHECK(length(latest_head_hash) = 32),
                safe_head_number TEXT NOT NULL,
                safe_head_hash BLOB NOT NULL CHECK(length(safe_head_hash) = 32),
                finalized_head_number TEXT NOT NULL,
                finalized_head_hash BLOB NOT NULL CHECK(length(finalized_head_hash) = 32),
                observed_at_unix TEXT NOT NULL,
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                FOREIGN KEY(request_id) REFERENCES eth_message_requests(request_id),
                CHECK((status = 3 AND included_block_number != '0'
                    AND included_block_hash != zeroblob(32))
                    OR (status IN (1, 2) AND included_block_number = '0'
                    AND included_block_hash = zeroblob(32)))
             );
             CREATE INDEX IF NOT EXISTS eth_transaction_status_by_tx_sequence
                 ON eth_transaction_status_observations(tx_hash, request_id);",
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

pub(crate) fn migrate_v6_to_v7(transaction: &Transaction<'_>) -> Result<()> {
    let has_checkpoint_context = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('eth_message_requests')
                WHERE name = 'checkpoint_epoch'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if has_checkpoint_context {
        transaction
            .execute_batch(
                "ALTER TABLE eth_message_requests RENAME TO eth_message_requests_v6;
                 CREATE TABLE eth_message_requests (
                    request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16),
                    expected_gateway_source_hash BLOB NOT NULL CHECK(length(expected_gateway_source_hash) = 16),
                    operation_kind INTEGER NOT NULL CHECK(operation_kind IN (1, 2)),
                    evidence_kind INTEGER CHECK(evidence_kind IS NULL OR evidence_kind IN (1, 2, 3, 4, 5, 6)),
                    subject BLOB NOT NULL CHECK(length(subject) = 32),
                    checkpoint_epoch TEXT,
                    checkpoint_root BLOB CHECK(checkpoint_root IS NULL OR length(checkpoint_root) = 32),
                    maximum_response_bytes TEXT NOT NULL,
                    bulk_approved INTEGER NOT NULL CHECK(bulk_approved IN (0, 1)),
                    created_at_unix TEXT NOT NULL,
                    expires_at_unix TEXT NOT NULL,
                    status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 7),
                    manifest_digest BLOB CHECK(manifest_digest IS NULL OR length(manifest_digest) = 32),
                    manifest_size TEXT,
                    relay_observation INTEGER CHECK(relay_observation IS NULL OR relay_observation IN (1, 2, 3)),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    CHECK((operation_kind = 1 AND evidence_kind IS NOT NULL) OR (operation_kind = 2 AND evidence_kind IS NULL)),
                    CHECK((manifest_digest IS NULL AND manifest_size IS NULL) OR (manifest_digest IS NOT NULL AND manifest_size IS NOT NULL)),
                    CHECK((operation_kind = 1 AND relay_observation IS NULL) OR operation_kind = 2),
                    CHECK((evidence_kind IN (5, 6) AND checkpoint_epoch IS NOT NULL AND checkpoint_root IS NOT NULL)
                        OR ((evidence_kind IS NULL OR evidence_kind NOT IN (5, 6)) AND checkpoint_epoch IS NULL AND checkpoint_root IS NULL))
                 );
                 INSERT INTO eth_message_requests SELECT * FROM eth_message_requests_v6;
                 DROP TABLE eth_message_requests_v6;",
            )
            .map_err(NodeStoreError::sqlite)?;
    } else {
        transaction.execute_batch(
        "ALTER TABLE eth_message_requests RENAME TO eth_message_requests_v6;
         CREATE TABLE eth_message_requests (
            request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16),
            expected_gateway_source_hash BLOB NOT NULL CHECK(length(expected_gateway_source_hash) = 16),
            operation_kind INTEGER NOT NULL CHECK(operation_kind IN (1, 2)),
            evidence_kind INTEGER CHECK(evidence_kind IS NULL OR evidence_kind IN (1, 2, 3, 4)),
            subject BLOB NOT NULL CHECK(length(subject) = 32),
            maximum_response_bytes TEXT NOT NULL,
            bulk_approved INTEGER NOT NULL CHECK(bulk_approved IN (0, 1)),
            created_at_unix TEXT NOT NULL,
            expires_at_unix TEXT NOT NULL,
            status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 7),
            manifest_digest BLOB CHECK(manifest_digest IS NULL OR length(manifest_digest) = 32),
            manifest_size TEXT,
            relay_observation INTEGER CHECK(relay_observation IS NULL OR relay_observation IN (1, 2, 3)),
            record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
            recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
            CHECK((operation_kind = 1 AND evidence_kind IS NOT NULL) OR (operation_kind = 2 AND evidence_kind IS NULL)),
            CHECK((manifest_digest IS NULL AND manifest_size IS NULL) OR (manifest_digest IS NOT NULL AND manifest_size IS NOT NULL)),
            CHECK((operation_kind = 1 AND relay_observation IS NULL) OR operation_kind = 2)
         );
         INSERT INTO eth_message_requests SELECT * FROM eth_message_requests_v6;
         DROP TABLE eth_message_requests_v6;"
        ).map_err(NodeStoreError::sqlite)?;
    }

    // v6 marked evidence requests Completed before returning their bytes to a
    // caller. There is no durable proof that verification/import happened, so
    // reopen them fail closed and let an exact attachment replay populate v7.
    let request_ids = {
        let mut statement = transaction
            .prepare(
                "SELECT request_id FROM eth_message_requests
             WHERE operation_kind = 1 AND status = 4",
            )
            .map_err(NodeStoreError::sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(NodeStoreError::sqlite)?;
        rows.map(|row| {
            let bytes = row.map_err(NodeStoreError::sqlite)?;
            stored_array(&bytes, "migrated messaging request identifier")
        })
        .collect::<Result<Vec<[u8; 16]>>>()?
    };
    for request_id in request_ids {
        let mut record = read_request(transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("migrated evidence request disappeared"))?;
        record.status = MessageRequestStatus::Ready;
        update_request(transaction, &record)?;
    }
    Ok(())
}

/// v17 adds fixed-width transaction-status requests and a separately durable,
/// non-authoritative observation journal. The request/outbox rebuild widens
/// only their CHECK constraints; all v16 rows and their immutable digests are
/// copied byte-for-byte in the same migration transaction.
pub(crate) fn migrate_v16_to_v17(transaction: &Transaction<'_>) -> Result<()> {
    let request_sql = transaction
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'eth_message_requests'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let outbox_sql = transaction
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'eth_message_outbox'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    if request_sql
        .as_deref()
        .is_some_and(|sql| sql.contains("operation_kind IN (1, 2, 3)"))
        && outbox_sql
            .as_deref()
            .is_some_and(|sql| sql.contains("item_kind IN (1, 2, 3, 4)"))
    {
        return Ok(());
    }
    if request_sql.is_none() || outbox_sql.is_none() {
        return Ok(());
    }

    transaction
        .execute_batch(
            "ALTER TABLE eth_sync_plan_requests RENAME TO eth_sync_plan_requests_v16;
             ALTER TABLE eth_sync_plans RENAME TO eth_sync_plans_v16;
             ALTER TABLE eth_message_outbox RENAME TO eth_message_outbox_v16;
             ALTER TABLE eth_pending_message_evidence
                 RENAME TO eth_pending_message_evidence_v16;
             ALTER TABLE eth_message_requests RENAME TO eth_message_requests_v16;",
        )
        .map_err(NodeStoreError::sqlite)?;
    create_schema(transaction)?;
    crate::workflow::create_schema(transaction)?;
    transaction
        .execute_batch(
            "INSERT INTO eth_message_requests (
                request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, checkpoint_epoch, checkpoint_root,
                maximum_response_bytes, bulk_approved, created_at_unix,
                expires_at_unix, status, manifest_digest, manifest_size,
                relay_observation, record_digest, recorded_at_unix
             )
             SELECT request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, checkpoint_epoch, checkpoint_root,
                maximum_response_bytes, bulk_approved, created_at_unix,
                expires_at_unix, status, manifest_digest, manifest_size,
                relay_observation, record_digest, recorded_at_unix
             FROM eth_message_requests_v16;
             INSERT INTO eth_pending_message_evidence
                 SELECT * FROM eth_pending_message_evidence_v16;
             INSERT INTO eth_message_outbox SELECT * FROM eth_message_outbox_v16;
             INSERT INTO eth_sync_plans SELECT * FROM eth_sync_plans_v16;
             INSERT INTO eth_sync_plan_requests SELECT * FROM eth_sync_plan_requests_v16;
             DROP TABLE eth_sync_plan_requests_v16;
             DROP TABLE eth_sync_plans_v16;
             DROP TABLE eth_message_outbox_v16;
             DROP TABLE eth_pending_message_evidence_v16;
             DROP TABLE eth_message_requests_v16;",
        )
        .map_err(NodeStoreError::sqlite)
}

impl EthereumNodeStore {
    /// Accepts an attachment only after the concrete Ratspeak LXMF adapter has
    /// verified the signature on that exact persisted message and reopened the
    /// same authenticated bytes. This node API cannot establish LXMF signature
    /// validity itself; satisfying that precondition is the adapter's trust
    /// boundary. The expected gateway must come from profile configuration.
    pub fn handle_attachment_from_trusted_lxmf_adapter(
        &mut self,
        configured_gateway_source_hash: [u8; 16],
        sender_source_hash: [u8; 16],
        persisted_attachment: &[u8],
        now_unix: u64,
    ) -> Result<NodeMessageOutcome> {
        if configured_gateway_source_hash == [0; 16] {
            return Err(NodeStoreError::new(
                "configured gateway identity is missing",
            ));
        }
        self.handle_gateway_attachment(
            configured_gateway_source_hash,
            AuthenticatedNodeEnvelope {
                sig_valid: true,
                sender_source_hash,
                persisted_attachment,
            },
            now_unix,
        )
    }

    /// Creates a bounded request for proof material. Consensus requests are
    /// bound to the currently approved local checkpoint; the gateway cannot
    /// supply or select that trust root.
    pub fn create_evidence_request(&mut self, request: OutboundEvidenceRequest) -> Result<Vec<u8>> {
        let now_unix = if request.kind == MessagingEvidenceKind::Consensus {
            crate::bootstrap::trusted_now_unix()
                .map_err(|error| NodeStoreError::new(error.to_string()))?
        } else {
            0
        };
        self.create_evidence_request_at(request, now_unix)
    }

    fn create_evidence_request_at(
        &mut self,
        request: OutboundEvidenceRequest,
        now_unix: u64,
    ) -> Result<Vec<u8>> {
        validate_new_request(
            request.request_id,
            request.expected_gateway_source_hash,
            request.subject,
            request.maximum_response_bytes,
            request.created_at_unix,
            request.expires_at_unix,
        )?;
        if request.kind == MessagingEvidenceKind::Consensus {
            if request.created_at_unix
                > now_unix.saturating_add(MAX_CONSENSUS_REQUEST_CLOCK_SKEW_SECONDS)
                || now_unix.saturating_sub(request.created_at_unix)
                    > MAX_CONSENSUS_REQUEST_CLOCK_SKEW_SECONDS
                || now_unix >= request.expires_at_unix
            {
                return Err(NodeStoreError::new(
                    "consensus request does not match the trusted local clock",
                ));
            }
            crate::bootstrap::ensure_active_checkpoint_at(self, request.subject, now_unix)
                .map_err(|error| NodeStoreError::new(error.to_string()))?;
        }
        if matches!(
            request.kind,
            MessagingEvidenceKind::AccountStatePackage
                | MessagingEvidenceKind::FinalizedReceiptPackage
        ) {
            return Err(NodeStoreError::new(
                "composite evidence requests require the durable sync planner",
            ));
        }
        let record = RequestRecord {
            request_id: request.request_id,
            expected_gateway_source_hash: request.expected_gateway_source_hash,
            operation: OperationKind::Evidence,
            evidence_kind: Some(request.kind),
            subject: request.subject,
            checkpoint_context: None,
            maximum_response_bytes: u64::from(request.maximum_response_bytes),
            bulk_approved: false,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            status: MessageRequestStatus::Pending,
            manifest_digest: None,
            manifest_size: None,
            relay_observation: None,
        };
        insert_request(&self.connection, &record)?;
        Ok(encode_evidence_request(&record))
    }

    /// Creates relay bytes only from an already persisted, locally reviewed
    /// native-transfer record. Gateway/RPC responses cannot confirm it.
    pub fn create_signed_transaction_relay(
        &mut self,
        request_id: [u8; 16],
        expected_gateway_source_hash: [u8; 16],
        transaction: &StoredSignedTransaction,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<Vec<u8>> {
        validate_new_request(
            request_id,
            expected_gateway_source_hash,
            transaction.tx_hash(),
            u32::try_from(transaction.raw_transaction().len())
                .map_err(|_| NodeStoreError::new("signed transaction is oversized"))?,
            created_at_unix,
            expires_at_unix,
        )?;
        if transaction.raw_transaction().is_empty()
            || transaction.raw_transaction().len() > MAX_SIGNED_TRANSACTION_BYTES
            || self
                .signed_transaction(transaction.chain_id(), transaction.tx_hash())?
                .as_ref()
                != Some(transaction)
        {
            return Err(NodeStoreError::new(
                "relay requires an exact locally persisted supported-chain transaction",
            ));
        }
        let record = RequestRecord {
            request_id,
            expected_gateway_source_hash,
            operation: OperationKind::Relay,
            evidence_kind: None,
            subject: transaction.tx_hash(),
            checkpoint_context: None,
            maximum_response_bytes: transaction.raw_transaction().len() as u64,
            bulk_approved: false,
            created_at_unix,
            expires_at_unix,
            status: MessageRequestStatus::Pending,
            manifest_digest: None,
            manifest_size: None,
            relay_observation: None,
        };
        insert_request(&self.connection, &record)?;
        Ok(encode_signed_relay(&record, transaction))
    }

    /// Creates a fixed-size transaction progress request for an exact local
    /// signed transaction. A returned report remains non-authoritative until
    /// the separate receipt-proof verifier records final assurance.
    pub fn create_transaction_status_request(
        &mut self,
        request: OutboundTransactionStatusRequest,
    ) -> Result<Vec<u8>> {
        validate_new_request(
            request.request_id,
            request.expected_gateway_source_hash,
            request.tx_hash,
            u32::try_from(TRANSACTION_STATUS_RESPONSE_BYTES)
                .map_err(|_| NodeStoreError::new("transaction status response bound invalid"))?,
            request.created_at_unix,
            request.expires_at_unix,
        )?;
        if self
            .signed_transaction(SEPOLIA_CHAIN_ID, request.tx_hash)?
            .is_none()
        {
            return Err(NodeStoreError::new(
                "transaction status requires an exact locally persisted transaction",
            ));
        }
        let record = RequestRecord {
            request_id: request.request_id,
            expected_gateway_source_hash: request.expected_gateway_source_hash,
            operation: OperationKind::TransactionStatus,
            evidence_kind: None,
            subject: request.tx_hash,
            checkpoint_context: None,
            maximum_response_bytes: TRANSACTION_STATUS_RESPONSE_BYTES,
            bulk_approved: false,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            status: MessageRequestStatus::Pending,
            manifest_digest: None,
            manifest_size: None,
            relay_observation: None,
        };
        insert_request(&self.connection, &record)?;
        Ok(encode_transaction_status_request(&record))
    }

    /// Creates at most one live status request for an exact transaction and
    /// selected service. A recent locally received report is also enough to
    /// coalesce a poll. Either replay result leaves the durable request/report
    /// available for the transport coordinator to resume; it never means the
    /// transaction is confirmed.
    pub fn plan_transaction_status_poll(
        &mut self,
        request: OutboundTransactionStatusRequest,
    ) -> Result<RecordOutcome> {
        if self.has_active_transaction_status_request(
            request.tx_hash,
            request.expected_gateway_source_hash,
            request.created_at_unix,
        )? {
            return Ok(RecordOutcome::Replay);
        }
        if let Some(observation) = self.latest_transaction_status_observation(request.tx_hash)?
            && observation.source_hash == request.expected_gateway_source_hash
            && request.created_at_unix >= observation.observed_at_unix
            && request.created_at_unix - observation.observed_at_unix
                < MIN_TRANSACTION_STATUS_POLL_INTERVAL_SECONDS
        {
            return Ok(RecordOutcome::Replay);
        }
        self.create_transaction_status_request(request)?;
        Ok(RecordOutcome::Inserted)
    }

    /// Schedules one bounded finalized-receipt package request after an exact,
    /// completed authenticated status report says the transaction's reported
    /// inclusion is no later than that report's finalized head.
    ///
    /// The report is only a scheduling hint. In particular, this method never
    /// copies its included block number/hash into the evidence request, never
    /// installs a checkpoint from it, and never changes transaction assurance.
    /// The resulting package is still bound to the locally approved active
    /// checkpoint and must independently verify before it can record a final
    /// success or failure.
    pub fn plan_finalized_receipt_after_status(
        &mut self,
        request: FinalizedStatusReceiptRequest,
    ) -> Result<RecordOutcome> {
        if request.status_request_id == [0; 16]
            || request.now_unix == 0
            || request.expires_at_unix <= request.now_unix
        {
            return Err(NodeStoreError::new(
                "invalid finalized status receipt request timing",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let status_record =
            read_request(&transaction, request.status_request_id)?.ok_or_else(|| {
                NodeStoreError::new("finalized status receipt request has no status request")
            })?;
        if status_record.operation != OperationKind::TransactionStatus
            || status_record.status != MessageRequestStatus::Completed
            || status_record.expected_gateway_source_hash != request.expected_gateway_source_hash
        {
            return Err(NodeStoreError::new(
                "finalized status receipt request is not bound to a completed service status",
            ));
        }
        let observation =
            read_transaction_status_by_request(&transaction, request.status_request_id)?
                .ok_or_else(|| {
                    NodeStoreError::new(
                        "completed status request has no durable transaction observation",
                    )
                })?;
        if observation.tx_hash != status_record.subject
            || observation.source_hash != request.expected_gateway_source_hash
            || observation.status != TransactionStatus::Included
            || observation.included_block_number.is_none()
            || observation.included_block_hash.is_none()
            || observation.included_block_number > Some(observation.finalized_head_number)
        {
            return Err(NodeStoreError::new(
                "status observation is not eligible to schedule receipt verification",
            ));
        }
        if crate::transaction::read_signed_transaction(
            &transaction,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            observation.tx_hash,
        )?
        .is_none()
        {
            return Err(NodeStoreError::new(
                "finalized status receipt request has no exact local transaction",
            ));
        }
        if crate::receipt::read_receipt_by_tx_hash(
            &transaction,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            observation.tx_hash,
        )?
        .is_some()
        {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok(RecordOutcome::Replay);
        }
        if supersede_settled_pending_finalized_receipt_request(
            &transaction,
            observation.tx_hash,
            request.expected_gateway_source_hash,
            request.now_unix,
        )? {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok(RecordOutcome::Replay);
        }
        let checkpoint = crate::checkpoint::latest_checkpoint_approval(&transaction)?
            .ok_or_else(|| NodeStoreError::new("no locally approved checkpoint for receipt"))?;
        let checkpoint_context = CheckpointRequestContext {
            checkpoint_epoch: checkpoint.checkpoint_epoch(),
            checkpoint_root: checkpoint.checkpoint_root(),
        };
        // This repeats the policy check inside insert_planned_package_request
        // before that helper persists any request, keeping the selected root
        // entirely local and current at this transaction's trusted time.
        crate::bootstrap::ensure_active_checkpoint_at_connection(
            &transaction,
            checkpoint_context.checkpoint_root,
            request.now_unix,
        )
        .map_err(|error| NodeStoreError::new(error.to_string()))?;
        insert_planned_package_request(
            &transaction,
            request.request_id,
            request.expected_gateway_source_hash,
            MessagingEvidenceKind::FinalizedReceiptPackage,
            observation.tx_hash,
            checkpoint_context,
            request.maximum_response_bytes,
            request.now_unix,
            request.expires_at_unix,
            request.now_unix,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(RecordOutcome::Inserted)
    }

    /// Returns whether a live, authenticated-status request for this exact
    /// transaction/service already exists. It validates each durable request
    /// record rather than trusting a raw SQLite predicate.
    pub fn has_active_transaction_status_request(
        &self,
        tx_hash: [u8; 32],
        expected_gateway_source_hash: [u8; 16],
        now_unix: u64,
    ) -> Result<bool> {
        if tx_hash == [0; 32] || expected_gateway_source_hash == [0; 16] || now_unix == 0 {
            return Err(NodeStoreError::new(
                "invalid transaction status request query",
            ));
        }
        if self
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)?
            .is_none()
        {
            return Ok(false);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT request_id FROM eth_message_requests
                  WHERE operation_kind = ?1 AND subject = ?2
                    AND expected_gateway_source_hash = ?3 AND status = ?4
                    AND CAST(expires_at_unix AS INTEGER) > ?5
                  ORDER BY recorded_at_unix, rowid
                  LIMIT 1",
            )
            .map_err(NodeStoreError::sqlite)?;
        let identifier = statement
            .query_row(
                rusqlite::params![
                    OperationKind::TransactionStatus.as_i64(),
                    tx_hash.as_slice(),
                    expected_gateway_source_hash.as_slice(),
                    MessageRequestStatus::Pending.as_i64(),
                    now_unix.to_string(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?;
        drop(statement);
        if let Some(identifier) = identifier {
            let record = read_request(
                &self.connection,
                stored_array(&identifier, "transaction status request identifier")?,
            )?
            .ok_or_else(|| NodeStoreError::new("transaction status request disappeared"))?;
            if record.operation != OperationKind::TransactionStatus
                || record.subject != tx_hash
                || record.expected_gateway_source_hash != expected_gateway_source_hash
                || record.status != MessageRequestStatus::Pending
                || record.expires_at_unix <= now_unix
            {
                return Err(NodeStoreError::new(
                    "transaction status request changed during active query",
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Reads the newest durable exact-receipt request for an exact local
    /// transaction and selected service. This exposes request lifecycle only;
    /// callers must not present `Completed` as Ethereum confirmation without
    /// separately checking verified transaction assurance.
    pub fn latest_finalized_receipt_request_progress(
        &self,
        tx_hash: [u8; 32],
        expected_gateway_source_hash: [u8; 16],
    ) -> Result<Option<FinalizedReceiptRequestProgress>> {
        if tx_hash == [0; 32] || expected_gateway_source_hash == [0; 16] {
            return Err(NodeStoreError::new(
                "invalid finalized receipt progress query",
            ));
        }
        if self
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)?
            .is_none()
        {
            return Ok(None);
        }
        let request_id = self
            .connection
            .query_row(
                "SELECT request_id FROM eth_message_requests
                  WHERE operation_kind = ?1 AND evidence_kind = ?2
                    AND subject = ?3 AND expected_gateway_source_hash = ?4
                  ORDER BY rowid DESC LIMIT 1",
                rusqlite::params![
                    OperationKind::Evidence.as_i64(),
                    MessagingEvidenceKind::FinalizedReceiptPackage.wire(),
                    tx_hash.as_slice(),
                    expected_gateway_source_hash.as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?
            .map(|bytes| stored_array(&bytes, "latest finalized receipt request identifier"))
            .transpose()?;
        let Some(request_id) = request_id else {
            return Ok(None);
        };
        let record = read_request(&self.connection, request_id)?
            .ok_or_else(|| NodeStoreError::new("latest finalized receipt request disappeared"))?;
        if record.operation != OperationKind::Evidence
            || record.evidence_kind != Some(MessagingEvidenceKind::FinalizedReceiptPackage)
            || record.subject != tx_hash
            || record.expected_gateway_source_hash != expected_gateway_source_hash
            || record.checkpoint_context.is_none()
        {
            return Err(NodeStoreError::new(
                "latest finalized receipt request changed during progress query",
            ));
        }
        Ok(Some(FinalizedReceiptRequestProgress {
            request_id,
            status: record.status,
            created_at_unix: record.created_at_unix,
            expires_at_unix: record.expires_at_unix,
        }))
    }

    /// Returns the newest intact, locally received service report for this
    /// exact locally signed transaction. It is intentionally not converted to
    /// [`crate::TransactionAssurance`].
    pub fn latest_transaction_status_observation(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<StoredTransactionStatusObservation>> {
        if self
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)?
            .is_none()
        {
            return Ok(None);
        }
        read_latest_transaction_status_observation(&self.connection, tx_hash)
    }

    /// Returns the newest non-authoritative service report plus a bounded
    /// continuity classification derived from intact durable history.
    pub fn transaction_status_history_view(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<TransactionStatusHistoryView>> {
        if self
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)?
            .is_none()
        {
            return Ok(None);
        }
        read_transaction_status_history_view(&self.connection, tx_hash)
    }

    pub fn message_request_status(
        &self,
        request_id: [u8; 16],
    ) -> Result<Option<MessageRequestStatus>> {
        Ok(read_request(&self.connection, request_id)?.map(|record| record.status))
    }

    /// Re-arms the newest account evidence request after a user-authorized
    /// retry. Only a pending, unexpired request with a validated settled
    /// EvidenceRequest row is eligible; no request is created or deleted.
    pub fn rearm_latest_account_sync(
        &mut self,
        binding: OutboundMessageBinding,
        now_unix: u64,
    ) -> Result<()> {
        if now_unix == 0 {
            return Err(NodeStoreError::new("invalid account retry clock"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let Some((request_id, trigger)) =
            crate::workflow::latest_account_sync_request(&transaction)?
        else {
            return Err(NodeStoreError::new("no account sync request to retry"));
        };
        if trigger.expires_at_unix() <= now_unix {
            return Err(NodeStoreError::new("account sync request has expired"));
        }
        let request = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("account sync request disappeared"))?;
        if request.status != MessageRequestStatus::Pending
            || request.operation != OperationKind::Evidence
            || request.evidence_kind != Some(MessagingEvidenceKind::AccountStatePackage)
            || request.expected_gateway_source_hash != binding.gateway_destination_hash
        {
            return Err(NodeStoreError::new("account sync request is not retryable"));
        }
        let kind = OutboundMessageKind::EvidenceRequest;
        let row = read_outbox_row(&transaction, request_id, kind)?
            .ok_or_else(|| NodeStoreError::new("account sync request has no outbox item"))?;
        let attachment = reconstruct_outbound_attachment_exact(&transaction, &request, kind)?;
        let attachment_digest: [u8; 32] = Sha256::digest(&attachment).into();
        let row_binding = OutboundMessageBinding::new(
            row.gateway_destination_hash,
            row.local_source_hash,
            row.identity_session_generation,
        )?;
        if row_binding != binding {
            return Err(NodeStoreError::new("account retry binding changed"));
        }
        validate_outbox_row(&row, request_id, kind, &binding, attachment_digest)?;
        if row.state != OUTBOUND_SETTLED {
            return Err(NodeStoreError::new("account request outbox is not settled"));
        }
        if !(1..=MAX_OUTBOUND_QUEUE_ATTEMPTS).contains(&row.attempts)
            || row.attempts >= MAX_OUTBOUND_QUEUE_ATTEMPTS
        {
            return Err(NodeStoreError::new("account retry attempt cap exceeded"));
        }
        let digest = outbox_digest(
            request_id,
            kind,
            binding,
            attachment_digest,
            OUTBOUND_READY,
            row.attempts,
            row.lease_generation,
            None,
            None,
        );
        let changed = transaction
            .execute(
                "UPDATE eth_message_outbox
                    SET state = ?1, lease_until_unix = NULL, queued_at_unix = NULL,
                        record_digest = ?2
                  WHERE request_id = ?3 AND item_kind = ?4 AND state = ?5
                    AND attempts = ?6 AND lease_generation = ?7",
                rusqlite::params![
                    OUTBOUND_READY,
                    digest.as_slice(),
                    request_id.as_slice(),
                    kind.as_i64(),
                    OUTBOUND_SETTLED,
                    row.attempts,
                    row.lease_generation,
                ],
            )
            .map_err(NodeStoreError::sqlite)?;
        if changed != 1 {
            return Err(NodeStoreError::new("account retry outbox changed"));
        }
        transaction.commit().map_err(NodeStoreError::sqlite)
    }

    /// Cancels only a settled account request after an explicit user retry.
    /// The caller may then create a new request identifier; late replies to
    /// the cancelled request remain harmless and cannot update account state.
    pub fn cancel_settled_account_sync_for_retry(
        &mut self,
        binding: OutboundMessageBinding,
        now_unix: u64,
    ) -> Result<bool> {
        if now_unix == 0 {
            return Err(NodeStoreError::new("invalid account retry clock"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let Some((request_id, trigger)) =
            crate::workflow::latest_account_sync_request(&transaction)?
        else {
            return Ok(false);
        };
        if trigger.expires_at_unix() <= now_unix {
            return Ok(false);
        }
        let mut request = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("account sync request disappeared"))?;
        if request.status != MessageRequestStatus::Pending
            || request.operation != OperationKind::Evidence
            || request.evidence_kind != Some(MessagingEvidenceKind::AccountStatePackage)
            || request.expected_gateway_source_hash != binding.gateway_destination_hash
        {
            return Ok(false);
        }
        let kind = OutboundMessageKind::EvidenceRequest;
        let row = read_outbox_row(&transaction, request_id, kind)?
            .ok_or_else(|| NodeStoreError::new("account sync request has no outbox item"))?;
        let attachment = reconstruct_outbound_attachment_exact(&transaction, &request, kind)?;
        let attachment_digest: [u8; 32] = Sha256::digest(&attachment).into();
        let row_binding = OutboundMessageBinding::new(
            row.gateway_destination_hash,
            row.local_source_hash,
            row.identity_session_generation,
        )?;
        validate_outbox_row(&row, request_id, kind, &row_binding, attachment_digest)?;
        if row_binding != binding
            || row.state != OUTBOUND_SETTLED
            || !(1..=MAX_OUTBOUND_QUEUE_ATTEMPTS).contains(&row.attempts)
        {
            return Ok(false);
        }
        request.status = MessageRequestStatus::Cancelled;
        update_request(&transaction, &request)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(true)
    }

    /// Fails closed unless every request bound to a different gateway is
    /// terminal. Expired requests no longer retain transport work, while
    /// locally pending verification remains active regardless of expiry.
    pub fn ensure_gateway_replacement_allowed(
        &mut self,
        replacement_gateway: [u8; 16],
        now_unix: u64,
    ) -> Result<()> {
        if replacement_gateway == [0; 16] || now_unix == 0 {
            return Err(NodeStoreError::new("invalid gateway replacement context"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut statement = transaction
            .prepare("SELECT request_id FROM eth_message_requests ORDER BY rowid")
            .map_err(NodeStoreError::sqlite)?;
        let identifiers = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(NodeStoreError::sqlite)?
            .map(|row| {
                stored_array(
                    &row.map_err(NodeStoreError::sqlite)?,
                    "gateway replacement request identifier",
                )
            })
            .collect::<Result<Vec<[u8; 16]>>>()?;
        drop(statement);
        for identifier in identifiers {
            let request = read_request(&transaction, identifier)?
                .ok_or_else(|| NodeStoreError::new("messaging request disappeared"))?;
            let active = match request.status {
                MessageRequestStatus::PendingVerification => true,
                MessageRequestStatus::Pending
                | MessageRequestStatus::AwaitingBulkApproval
                | MessageRequestStatus::Ready => request.expires_at_unix > now_unix,
                MessageRequestStatus::Completed
                | MessageRequestStatus::Expired
                | MessageRequestStatus::Cancelled => false,
            };
            if active && request.expected_gateway_source_hash != replacement_gateway {
                return Err(NodeStoreError::new(
                    "active messaging work is bound to another gateway",
                ));
            }
        }
        let pending_ids = {
            let mut statement = transaction
                .prepare("SELECT request_id FROM eth_pending_message_evidence ORDER BY rowid")
                .map_err(NodeStoreError::sqlite)?;
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(NodeStoreError::sqlite)?
                .map(|row| {
                    stored_array(
                        &row.map_err(NodeStoreError::sqlite)?,
                        "gateway replacement pending evidence identifier",
                    )
                })
                .collect::<Result<Vec<[u8; 16]>>>()?
        };
        if let Some(identifier) = pending_ids.into_iter().next() {
            read_pending_evidence(&transaction, identifier)?
                .ok_or_else(|| NodeStoreError::new("pending evidence disappeared"))?;
            return Err(NodeStoreError::new(
                "pending evidence blocks gateway replacement",
            ));
        }
        let outbox_rows = {
            let mut statement = transaction
                .prepare("SELECT request_id, item_kind FROM eth_message_outbox ORDER BY rowid")
                .map_err(NodeStoreError::sqlite)?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(NodeStoreError::sqlite)?
                .map(|row| {
                    let (request, kind) = row.map_err(NodeStoreError::sqlite)?;
                    Ok((
                        stored_array(&request, "gateway replacement outbox request")?,
                        OutboundMessageKind::from_i64(kind)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?
        };
        for (request_id, kind) in outbox_rows {
            let request = read_request(&transaction, request_id)?
                .ok_or_else(|| NodeStoreError::new("outbox parent request disappeared"))?;
            let row = read_outbox_row(&transaction, request_id, kind)?
                .ok_or_else(|| NodeStoreError::new("outbox row disappeared"))?;
            if row.gateway_destination_hash != request.expected_gateway_source_hash {
                return Err(NodeStoreError::new(
                    "outbound message gateway does not match its parent request",
                ));
            }
            let attachment = reconstruct_outbound_attachment_exact(&transaction, &request, kind)?;
            let attachment_digest = Sha256::digest(&attachment).into();
            let binding = OutboundMessageBinding::new(
                row.gateway_destination_hash,
                row.local_source_hash,
                row.identity_session_generation,
            )?;
            validate_outbox_row(&row, request_id, kind, &binding, attachment_digest)?;
            if row.state == OUTBOUND_LEASED && row.gateway_destination_hash != replacement_gateway {
                return Err(NodeStoreError::new(
                    "leased outbound work blocks gateway replacement",
                ));
            }
        }
        crate::field_node::ensure_no_pending_field_operations(&transaction)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(())
    }

    /// Durably consumes one bounded local-queue attempt before returning exact
    /// attachment bytes. This is transport work only and cannot change any
    /// Ethereum assurance state.
    pub fn lease_next_outbound_message(
        &mut self,
        binding: OutboundMessageBinding,
        now_unix: u64,
        lease_seconds: u64,
    ) -> Result<Option<OutboundMessageLease>> {
        if now_unix == 0 || lease_seconds == 0 || lease_seconds > MAX_OUTBOUND_LEASE_SECONDS {
            return Err(NodeStoreError::new("invalid outbound message lease"));
        }
        let lease_until = now_unix
            .checked_add(lease_seconds)
            .ok_or_else(|| NodeStoreError::new("invalid outbound message lease"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;

        let binding_conflict = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM eth_message_outbox o
                    JOIN eth_message_requests r ON r.request_id = o.request_id
                    WHERE r.expected_gateway_source_hash = ?1
                      AND o.state != ?2
                      AND (o.gateway_destination_hash != ?1
                        OR o.local_source_hash != ?3
                        OR o.identity_session_generation != ?4)
                      AND CAST(r.expires_at_unix AS INTEGER) > ?5
                      AND r.status NOT IN (5, 6)
                 )",
                rusqlite::params![
                    binding.gateway_destination_hash.as_slice(),
                    OUTBOUND_SETTLED,
                    binding.local_source_hash.as_slice(),
                    binding.identity_session_generation.to_string(),
                    now_unix.to_string(),
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(NodeStoreError::sqlite)?;
        if binding_conflict {
            return Err(NodeStoreError::new(
                "outbound messaging identity binding changed",
            ));
        }

        let candidate = transaction
            .query_row(
                "SELECT r.request_id,
                    CASE
                      WHEN r.operation_kind = 2 THEN 3
                      WHEN r.operation_kind = 3 THEN 4
                      WHEN r.status = 3 AND r.bulk_approved = 1 THEN 2
                      ELSE 1
                    END AS item_kind
                 FROM eth_message_requests r
                 LEFT JOIN eth_message_outbox o
                   ON o.request_id = r.request_id
                  AND o.item_kind = CASE
                      WHEN r.operation_kind = 2 THEN 3
                      WHEN r.operation_kind = 3 THEN 4
                      WHEN r.status = 3 AND r.bulk_approved = 1 THEN 2
                      ELSE 1 END
                 WHERE r.expected_gateway_source_hash = ?1
                   AND CAST(r.expires_at_unix AS INTEGER) > ?2
                   AND ((r.operation_kind = 1 AND r.status = 1)
                     OR (r.operation_kind = 1 AND r.status = 3 AND r.bulk_approved = 1)
                     OR (r.operation_kind IN (2, 3) AND r.status = 1))
                   AND (o.request_id IS NULL OR (
                       o.state != ?3 AND o.attempts < ?4
                       AND (o.state = ?5 OR CAST(o.lease_until_unix AS INTEGER) <= ?2)))
                 ORDER BY r.recorded_at_unix, r.rowid, item_kind
                 LIMIT 1",
                rusqlite::params![
                    binding.gateway_destination_hash.as_slice(),
                    now_unix.to_string(),
                    OUTBOUND_SETTLED,
                    MAX_OUTBOUND_QUEUE_ATTEMPTS,
                    OUTBOUND_READY,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?;
        let Some((request_id, item_kind)) = candidate else {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok(None);
        };
        let request_id = stored_array(&request_id, "outbound request identifier")?;
        let record = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("outbound request disappeared"))?;
        let kind = match item_kind {
            1 => OutboundMessageKind::EvidenceRequest,
            2 => OutboundMessageKind::BulkApproval,
            3 => OutboundMessageKind::SignedTransactionRelay,
            4 => OutboundMessageKind::TransactionStatusRequest,
            _ => return Err(NodeStoreError::new("invalid outbound message kind")),
        };
        let attachment = reconstruct_outbound_attachment(&transaction, &record, kind)?;
        let attachment_digest: [u8; 32] = Sha256::digest(&attachment).into();
        let existing = read_outbox_row(&transaction, request_id, kind)?;
        let (attempts, generation) = match existing {
            Some(row) => {
                validate_outbox_row(&row, request_id, kind, &binding, attachment_digest)?;
                (row.attempts, row.lease_generation)
            }
            None => (0, 0),
        };
        let attempts = attempts
            .checked_add(1)
            .ok_or_else(|| NodeStoreError::new("outbound attempt counter exhausted"))?;
        let generation = generation
            .checked_add(1)
            .ok_or_else(|| NodeStoreError::new("outbound lease generation exhausted"))?;
        if attempts > MAX_OUTBOUND_QUEUE_ATTEMPTS {
            return Err(NodeStoreError::new("outbound queue attempt cap exceeded"));
        }
        let digest = outbox_digest(
            request_id,
            kind,
            binding,
            attachment_digest,
            OUTBOUND_LEASED,
            attempts,
            generation,
            Some(lease_until),
            None,
        );
        transaction
            .execute(
                "INSERT INTO eth_message_outbox (
                    request_id, item_kind, gateway_destination_hash, local_source_hash,
                    identity_session_generation, attachment_digest, state, attempts,
                    lease_generation, lease_until_unix, queued_at_unix, record_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)
                 ON CONFLICT(request_id, item_kind) DO UPDATE SET
                    state = excluded.state, attempts = excluded.attempts,
                    lease_generation = excluded.lease_generation,
                    lease_until_unix = excluded.lease_until_unix,
                    queued_at_unix = NULL, record_digest = excluded.record_digest",
                rusqlite::params![
                    request_id.as_slice(),
                    kind.as_i64(),
                    binding.gateway_destination_hash.as_slice(),
                    binding.local_source_hash.as_slice(),
                    binding.identity_session_generation.to_string(),
                    attachment_digest.as_slice(),
                    OUTBOUND_LEASED,
                    attempts,
                    generation,
                    lease_until.to_string(),
                    digest.as_slice(),
                ],
            )
            .map_err(NodeStoreError::sqlite)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(Some(OutboundMessageLease {
            request_id,
            kind,
            generation: u64::try_from(generation)
                .map_err(|_| NodeStoreError::new("invalid outbound lease generation"))?,
            destination_hash: binding.gateway_destination_hash,
            source_hash: binding.local_source_hash,
            identity_session_generation: binding.identity_session_generation,
            attachment,
        }))
    }

    /// Records only that the generic Ratspeak queue durably accepted the exact
    /// attachment. It is not a delivery, RPC, or Ethereum-state observation.
    pub fn settle_outbound_message_queued(
        &mut self,
        binding: OutboundMessageBinding,
        lease: &OutboundMessageLease,
        queued_at_unix: u64,
    ) -> Result<()> {
        transition_outbound_lease(&mut self.connection, binding, lease, queued_at_unix, true)
    }

    /// Releases an ambiguous local handoff for another bounded attempt. The
    /// already charged attempt is never refunded.
    pub fn release_outbound_message(
        &mut self,
        binding: OutboundMessageBinding,
        lease: &OutboundMessageLease,
        now_unix: u64,
    ) -> Result<()> {
        transition_outbound_lease(&mut self.connection, binding, lease, now_unix, false)
    }

    pub fn cancel_message_request(&mut self, request_id: [u8; 16]) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut record = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("unknown messaging request"))?;
        if matches!(
            record.status,
            MessageRequestStatus::Completed | MessageRequestStatus::PendingVerification
        ) {
            return Err(NodeStoreError::new(
                "accepted evidence request cannot be cancelled",
            ));
        }
        record.status = MessageRequestStatus::Cancelled;
        update_request(&transaction, &record)?;
        transaction.commit().map_err(NodeStoreError::sqlite)
    }

    /// Returns a stable, bounded set of exact manifests awaiting native review.
    ///
    /// The configured gateway is supplied by the native adapter. A bounded
    /// stale page is durably expired first, but stale rows never consume the
    /// separately bounded live page. If the result reaches
    /// [`MAX_PENDING_BULK_EVIDENCE_REVIEWS`], resolve those reviews and call
    /// again to drain the next deterministic page.
    pub fn pending_bulk_evidence_reviews(
        &mut self,
        expected_gateway_source_hash: [u8; 16],
        now_unix: u64,
    ) -> Result<Vec<PendingBulkEvidenceReview>> {
        if expected_gateway_source_hash == [0; 16] || now_unix == 0 {
            return Err(NodeStoreError::new("invalid bulk evidence review context"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let expired_request_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT request_id FROM eth_message_requests
                      WHERE expected_gateway_source_hash = ?1 AND status = ?2
                        AND CAST(expires_at_unix AS INTEGER) <= ?3
                      ORDER BY recorded_at_unix, rowid
                      LIMIT ?4",
                )
                .map_err(NodeStoreError::sqlite)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        expected_gateway_source_hash.as_slice(),
                        MessageRequestStatus::AwaitingBulkApproval.as_i64(),
                        now_unix.to_string(),
                        i64::try_from(MAX_PENDING_BULK_EVIDENCE_REVIEWS)
                            .map_err(|_| NodeStoreError::new("invalid bulk review bound"))?,
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(NodeStoreError::sqlite)?;
            rows.map(|row| {
                let bytes = row.map_err(NodeStoreError::sqlite)?;
                stored_array(&bytes, "bulk review request identifier")
            })
            .collect::<Result<Vec<[u8; 16]>>>()?
        };
        for request_id in expired_request_ids {
            let mut record = read_request(&transaction, request_id)?
                .ok_or_else(|| NodeStoreError::new("bulk review request disappeared"))?;
            if record.expected_gateway_source_hash != expected_gateway_source_hash {
                return Err(NodeStoreError::new("bulk review gateway binding changed"));
            }
            if !expire_request_if_needed(&transaction, &mut record, now_unix)? {
                return Err(NodeStoreError::new("bulk review expiry selection changed"));
            }
        }

        let live_request_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT request_id FROM eth_message_requests
                      WHERE expected_gateway_source_hash = ?1 AND status = ?2
                        AND CAST(expires_at_unix AS INTEGER) > ?3
                      ORDER BY recorded_at_unix, rowid
                      LIMIT ?4",
                )
                .map_err(NodeStoreError::sqlite)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        expected_gateway_source_hash.as_slice(),
                        MessageRequestStatus::AwaitingBulkApproval.as_i64(),
                        now_unix.to_string(),
                        i64::try_from(MAX_PENDING_BULK_EVIDENCE_REVIEWS)
                            .map_err(|_| NodeStoreError::new("invalid bulk review bound"))?,
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(NodeStoreError::sqlite)?;
            rows.map(|row| {
                let bytes = row.map_err(NodeStoreError::sqlite)?;
                stored_array(&bytes, "bulk review request identifier")
            })
            .collect::<Result<Vec<[u8; 16]>>>()?
        };

        let mut reviews = Vec::with_capacity(live_request_ids.len());
        for request_id in live_request_ids {
            let record = read_request(&transaction, request_id)?
                .ok_or_else(|| NodeStoreError::new("bulk review request disappeared"))?;
            if record.expected_gateway_source_hash != expected_gateway_source_hash
                || record.expires_at_unix <= now_unix
            {
                return Err(NodeStoreError::new("bulk review live selection changed"));
            }
            reviews.push(pending_bulk_review(&record)?);
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(reviews)
    }

    /// Reports whether a live bulk-evidence review exists without mutating
    /// expiry state. Native review entry points retain the durable cleanup.
    pub fn has_pending_bulk_evidence_review(
        &mut self,
        expected_gateway_source_hash: [u8; 16],
        now_unix: u64,
    ) -> Result<bool> {
        if expected_gateway_source_hash == [0; 16] || now_unix == 0 {
            return Err(NodeStoreError::new("invalid bulk evidence review context"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(NodeStoreError::sqlite)?;
        let request_id = transaction
            .query_row(
                "SELECT request_id FROM eth_message_requests
                 WHERE expected_gateway_source_hash = ?1 AND status = ?2
                   AND CAST(expires_at_unix AS INTEGER) > ?3
                 ORDER BY recorded_at_unix, rowid LIMIT 1",
                rusqlite::params![
                    expected_gateway_source_hash.as_slice(),
                    MessageRequestStatus::AwaitingBulkApproval.as_i64(),
                    now_unix.to_string(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?
            .map(|bytes| stored_array::<16>(&bytes, "bulk review request identifier"))
            .transpose()?;
        if let Some(request_id) = request_id {
            let record = read_request(&transaction, request_id)?
                .ok_or_else(|| NodeStoreError::new("bulk review request disappeared"))?;
            if record.expected_gateway_source_hash != expected_gateway_source_hash
                || record.expires_at_unix <= now_unix
            {
                return Err(NodeStoreError::new("bulk review live selection changed"));
            }
            pending_bulk_review(&record)?;
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(request_id.is_some())
    }

    /// Applies one native decision to the exact durable review snapshot.
    ///
    /// Approval authorizes only the digest-and-size-bound kind-6 attachment;
    /// denial cancels the request. Neither transition changes Ethereum
    /// assurance, transport delivery, RPC acceptance, or receipt state.
    pub fn resolve_bulk_evidence_review(
        &mut self,
        review: &PendingBulkEvidenceReview,
        decision: BulkEvidenceReviewDecision,
        now_unix: u64,
    ) -> Result<BulkEvidenceReviewResolution> {
        if now_unix == 0 {
            return Err(NodeStoreError::new("invalid bulk evidence review time"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut record = read_request(&transaction, review.request_id)?
            .ok_or_else(|| NodeStoreError::new("unknown bulk evidence review"))?;
        if expire_request_if_needed(&transaction, &mut record, now_unix)? {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Err(NodeStoreError::new("bulk evidence review expired"));
        }
        let durable_review = pending_bulk_review(&record)?;
        if durable_review != *review {
            return Err(NodeStoreError::new(
                "bulk evidence review no longer matches durable request",
            ));
        }

        let resolution = match decision {
            BulkEvidenceReviewDecision::Approve => {
                if read_outbox_row(
                    &transaction,
                    record.request_id,
                    OutboundMessageKind::BulkApproval,
                )?
                .is_some()
                {
                    return Err(NodeStoreError::new(
                        "bulk approval outbox unexpectedly already exists",
                    ));
                }
                record.bulk_approved = true;
                record.status = MessageRequestStatus::Ready;
                BulkEvidenceReviewResolution::Approved
            }
            BulkEvidenceReviewDecision::Deny => {
                record.status = MessageRequestStatus::Cancelled;
                BulkEvidenceReviewResolution::Denied
            }
        };
        update_request(&transaction, &record)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(resolution)
    }

    /// Approves a previously advertised bulk response and returns an explicit
    /// digest-and-size-bound approval attachment for the gateway.
    #[cfg(test)]
    pub(crate) fn approve_bulk_evidence(
        &mut self,
        request_id: [u8; 16],
        manifest_digest: [u8; 32],
        encoded_size: u32,
        now_unix: u64,
    ) -> Result<Vec<u8>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut record = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("unknown messaging request"))?;
        if matches!(record.status, MessageRequestStatus::Cancelled) {
            return Err(NodeStoreError::new("messaging request was cancelled"));
        }
        if expire_request_if_needed(&transaction, &mut record, now_unix)? {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Err(NodeStoreError::new("messaging request expired"));
        }
        let exact_manifest = record.operation == OperationKind::Evidence
            && record.manifest_digest == Some(manifest_digest)
            && record.manifest_size == Some(u64::from(encoded_size));
        if record.status == MessageRequestStatus::Ready && record.bulk_approved && exact_manifest {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok(encode_bulk_approval(&record, manifest_digest, encoded_size));
        }
        if record.status != MessageRequestStatus::AwaitingBulkApproval || !exact_manifest {
            return Err(NodeStoreError::new(
                "bulk approval does not match the manifest",
            ));
        }
        record.bulk_approved = true;
        record.status = MessageRequestStatus::Ready;
        update_request(&transaction, &record)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(encode_bulk_approval(&record, manifest_digest, encoded_size))
    }

    /// Handles bytes from a generic persisted LXMF attachment/resource.
    /// Authentication is rejected before parsing. `configured_gateway_source_hash`
    /// must be resolved by the adapter from profile configuration, not the payload.
    pub(crate) fn handle_gateway_attachment(
        &mut self,
        configured_gateway_source_hash: [u8; 16],
        envelope: AuthenticatedNodeEnvelope<'_>,
        now_unix: u64,
    ) -> Result<NodeMessageOutcome> {
        if configured_gateway_source_hash == [0; 16]
            || !envelope.sig_valid
            || envelope.sender_source_hash != configured_gateway_source_hash
        {
            return Ok(NodeMessageOutcome::IgnoredUnauthenticated);
        }
        let message = decode_gateway_message(envelope.persisted_attachment)?;
        let message_evidence_hash: [u8; 32] = Sha256::digest(envelope.persisted_attachment).into();
        let request_id = message.request_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let Some(mut record) = read_request(&transaction, request_id)? else {
            return Ok(NodeMessageOutcome::IgnoredUnauthenticated);
        };
        if record.expected_gateway_source_hash != configured_gateway_source_hash {
            return Ok(NodeMessageOutcome::IgnoredUnauthenticated);
        }
        if matches!(record.status, MessageRequestStatus::Cancelled)
            && !matches!(&message, GatewayMessage::ServiceFailure { .. })
        {
            return Err(NodeStoreError::new("messaging request was cancelled"));
        }
        if expire_request_if_needed(&transaction, &mut record, now_unix)? {
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Err(NodeStoreError::new("messaging request expired"));
        }
        let outcome = match message {
            GatewayMessage::Manifest(manifest) => {
                handle_manifest(&transaction, &mut record, manifest)?
            }
            GatewayMessage::Evidence(evidence) => {
                handle_evidence(&transaction, &mut record, evidence, now_unix)?
            }
            GatewayMessage::RelayObservation {
                request_id: _,
                tx_hash,
                observation,
            } => {
                if record.operation != OperationKind::Relay || record.subject != tx_hash {
                    return Err(NodeStoreError::new(
                        "relay observation does not match request",
                    ));
                }
                if record.status == MessageRequestStatus::Completed {
                    if record.relay_observation != Some(observation) {
                        return Err(NodeStoreError::new("conflicting relay observation"));
                    }
                    NodeMessageOutcome::Duplicate
                } else if record.status != MessageRequestStatus::Pending {
                    return Err(NodeStoreError::new("relay request is not pending"));
                } else {
                    let signed = crate::transaction::read_signed_transaction_by_hash(
                        &transaction,
                        tx_hash,
                    )?
                    .ok_or_else(|| {
                        NodeStoreError::new("relay observation has no exact local transaction")
                    })?;
                    record.status = MessageRequestStatus::Completed;
                    record.relay_observation = Some(observation);
                    update_request(&transaction, &record)?;
                    let event_kind = match observation {
                        RelayObservation::GatewayAccepted => {
                            Some(AssuranceEventKind::GatewayAcknowledged)
                        }
                        RelayObservation::RpcAccepted => Some(AssuranceEventKind::RpcAccepted),
                        RelayObservation::RpcRejected => None,
                    };
                    if let Some(event_kind) = event_kind {
                        record_assurance(
                            &transaction,
                            AssuranceEventInput {
                                chain_id: signed.chain_id(),
                                network: signed.network(),
                                subject_kind: AssuranceSubjectKind::Transaction,
                                subject_key: tx_hash,
                                event_kind,
                                evidence_hash: message_evidence_hash,
                                observed_at_unix: now_unix,
                            },
                        )?;
                    }
                    NodeMessageOutcome::RelayObserved {
                        tx_hash,
                        observation,
                    }
                }
            }
            GatewayMessage::TransactionStatus(observation) => {
                observation.validate()?;
                if record.operation != OperationKind::TransactionStatus
                    || record.subject != observation.tx_hash
                {
                    return Err(NodeStoreError::new(
                        "transaction status observation does not match request",
                    ));
                }
                if crate::transaction::read_signed_transaction(
                    &transaction,
                    SEPOLIA_CHAIN_ID,
                    SEPOLIA_NETWORK,
                    observation.tx_hash,
                )?
                .is_none()
                {
                    return Err(NodeStoreError::new(
                        "transaction status observation has no local transaction",
                    ));
                }
                if record.status == MessageRequestStatus::Completed {
                    let stored =
                        read_transaction_status_by_request(&transaction, observation.request_id)?
                            .ok_or_else(|| {
                            NodeStoreError::new(
                                "completed transaction status request has no observation",
                            )
                        })?;
                    if !transaction_status_matches_wire(
                        &stored,
                        configured_gateway_source_hash,
                        observation,
                    ) {
                        return Err(NodeStoreError::new(
                            "conflicting transaction status observation",
                        ));
                    }
                    NodeMessageOutcome::Duplicate
                } else if record.status != MessageRequestStatus::Pending {
                    return Err(NodeStoreError::new(
                        "transaction status request is not pending",
                    ));
                } else {
                    let stored = StoredTransactionStatusObservation {
                        tx_hash: observation.tx_hash,
                        source_hash: envelope.sender_source_hash,
                        status: observation.status,
                        included_block_number: (observation.status == TransactionStatus::Included)
                            .then_some(observation.included_block_number),
                        included_block_hash: (observation.status == TransactionStatus::Included)
                            .then_some(observation.included_block_hash),
                        latest_head_number: observation.latest_head_number,
                        latest_head_hash: observation.latest_head_hash,
                        safe_head_number: observation.safe_head_number,
                        safe_head_hash: observation.safe_head_hash,
                        finalized_head_number: observation.finalized_head_number,
                        finalized_head_hash: observation.finalized_head_hash,
                        observed_at_unix: now_unix,
                    };
                    insert_transaction_status_observation(
                        &transaction,
                        observation.request_id,
                        &stored,
                    )?;
                    record.status = MessageRequestStatus::Completed;
                    update_request(&transaction, &record)?;
                    NodeMessageOutcome::TransactionStatusObserved {
                        request_id: observation.request_id,
                        tx_hash: observation.tx_hash,
                        status: observation.status,
                    }
                }
            }
            GatewayMessage::ServiceFailure {
                request_id: _,
                original_attachment_digest,
            } => {
                validate_service_failure_binding(
                    &transaction,
                    &record,
                    original_attachment_digest,
                )?;
                // A service cannot retract evidence already retained for local
                // verification, nor can it alter completed Ethereum state.
                if matches!(
                    record.status,
                    MessageRequestStatus::Completed
                        | MessageRequestStatus::PendingVerification
                        | MessageRequestStatus::Cancelled
                ) {
                    NodeMessageOutcome::Duplicate
                } else if record.status == MessageRequestStatus::Pending {
                    // Cancelled is the existing durable terminal transport
                    // state. The authenticated notice does not assert that an
                    // Ethereum transaction failed or that any state is valid.
                    record.status = MessageRequestStatus::Cancelled;
                    update_request(&transaction, &record)?;
                    NodeMessageOutcome::ServiceFailed
                } else {
                    return Err(NodeStoreError::new(
                        "service failure cannot retract accepted gateway data",
                    ));
                }
            }
        };
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn pending_message_evidence(
        &self,
        request_id: [u8; 16],
    ) -> Result<Option<PendingMessageEvidence>> {
        read_pending_evidence(&self.connection, request_id)
    }

    pub fn pending_message_evidence_ids(&self) -> Result<Vec<[u8; 16]>> {
        let mut statement = self
            .connection
            .prepare("SELECT request_id FROM eth_pending_message_evidence ORDER BY rowid")
            .map_err(NodeStoreError::sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(NodeStoreError::sqlite)?;
        rows.map(|row| {
            let bytes = row.map_err(NodeStoreError::sqlite)?;
            stored_array(&bytes, "pending evidence request identifier")
        })
        .collect()
    }

    /// Re-verifies one durable response through the locally installed
    /// checkpoint and canonical consensus/execution records. Completion is
    /// unreachable through transport parsing alone.
    pub fn process_pending_message_evidence(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<PendingEvidenceImportOutcome> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        self.process_pending_message_evidence_at(request_id, now_unix)
    }

    pub(crate) fn process_pending_message_evidence_at(
        &mut self,
        request_id: [u8; 16],
        now_unix: u64,
    ) -> Result<PendingEvidenceImportOutcome> {
        let Some(pending) = read_pending_evidence(&self.connection, request_id)? else {
            return match read_request(&self.connection, request_id)?.map(|r| r.status) {
                Some(MessageRequestStatus::Completed) => {
                    Ok(PendingEvidenceImportOutcome::AlreadyCompleted)
                }
                _ => Err(NodeStoreError::new(
                    "pending Ethereum evidence was not found",
                )),
            };
        };
        validate_evidence_subject(pending.kind, pending.subject, &pending.bytes)?;
        if matches!(
            pending.kind,
            MessagingEvidenceKind::AccountStatePackage
                | MessagingEvidenceKind::FinalizedReceiptPackage
        ) {
            self.verify_import_and_complete_composite(&pending, now_unix)?;
            return Ok(PendingEvidenceImportOutcome::Imported);
        }
        self.verify_and_import_pending(&pending, now_unix)?;
        complete_pending_evidence(&mut self.connection, &pending)?;
        Ok(PendingEvidenceImportOutcome::Imported)
    }

    pub fn process_all_pending_message_evidence(&mut self) -> Result<usize> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let ids = self.pending_message_evidence_ids()?;
        let (completed, failures) = retry_to_fixed_point(ids, |request_id| {
            self.process_pending_message_evidence_at(request_id, now_unix)
                .map(|_| ())
        });
        if let Some((_, error)) = failures.into_iter().next() {
            return Err(error);
        }
        Ok(completed)
    }

    /// Explicitly discards an unverifiable pending response without creating
    /// any Ethereum assurance. An already expired request becomes Expired;
    /// an operator discard before expiry becomes Cancelled.
    pub fn discard_pending_message_evidence(&mut self, request_id: [u8; 16]) -> Result<()> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        self.discard_pending_message_evidence_at(request_id, now_unix)
    }

    pub(crate) fn discard_pending_message_evidence_at(
        &mut self,
        request_id: [u8; 16],
        now_unix: u64,
    ) -> Result<()> {
        if now_unix == 0 {
            return Err(NodeStoreError::new("invalid pending evidence discard time"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut request = read_request(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("unknown pending evidence request"))?;
        if request.status != MessageRequestStatus::PendingVerification
            || read_pending_evidence(&transaction, request_id)?.is_none()
        {
            return Err(NodeStoreError::new(
                "request has no discardable pending evidence",
            ));
        }
        let deleted = transaction
            .execute(
                "DELETE FROM eth_pending_message_evidence WHERE request_id = ?1",
                [request_id.as_slice()],
            )
            .map_err(NodeStoreError::sqlite)?;
        if deleted != 1 {
            return Err(NodeStoreError::new("pending evidence discard was lost"));
        }
        request.status = if now_unix >= request.expires_at_unix {
            MessageRequestStatus::Expired
        } else {
            MessageRequestStatus::Cancelled
        };
        update_request(&transaction, &request)?;
        transaction.commit().map_err(NodeStoreError::sqlite)
    }

    fn verify_and_import_pending(
        &mut self,
        pending: &PendingMessageEvidence,
        now_unix: u64,
    ) -> Result<()> {
        let verifier = Verifier::sepolia();
        match pending.kind {
            MessagingEvidenceKind::Consensus => {
                crate::bootstrap::ensure_active_checkpoint_at(self, pending.subject, now_unix)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                let header = verifier
                    .verify_consensus_bootstrap_at_unix(
                        &pending.bytes,
                        &BeaconCheckpointRoot::sepolia(pending.subject),
                        now_unix,
                    )
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                if header.checkpoint_root() != pending.subject {
                    return Err(NodeStoreError::new(
                        "verified consensus checkpoint mismatch",
                    ));
                }
                self.record_verified_finalized_header(&header, &pending.bytes)?;
            }
            MessagingEvidenceKind::ExecutionHeader => {
                let consensus = crate::consensus::read_finalized_header_by_execution_hash(
                    &self.connection,
                    SEPOLIA_CHAIN_ID,
                    SEPOLIA_NETWORK,
                    pending.subject,
                )?
                .ok_or_else(|| {
                    NodeStoreError::new("execution evidence has no canonical consensus record")
                })?;
                let verified_consensus = reverify_consensus(self, &verifier, &consensus, now_unix)?;
                let block = verifier
                    .verify_execution_header(&pending.bytes, &verified_consensus)
                    .map_err(|e| NodeStoreError::new(e.to_string()))?;
                self.record_verified_execution_block(&block, &pending.bytes)?;
            }
            MessagingEvidenceKind::AccountProof => {
                let parsed = verifier
                    .parse_account_proof(&pending.bytes)
                    .map_err(|e| NodeStoreError::new(e.to_string()))?;
                let consensus = crate::consensus::read_finalized_header_by_execution_hash(
                    &self.connection,
                    SEPOLIA_CHAIN_ID,
                    SEPOLIA_NETWORK,
                    parsed.block_hash,
                )?
                .ok_or_else(|| {
                    NodeStoreError::new("account evidence has no canonical consensus record")
                })?;
                let verified_consensus = reverify_consensus(self, &verifier, &consensus, now_unix)?;
                let stored_block = self
                    .execution_block(SEPOLIA_CHAIN_ID, parsed.block_hash)?
                    .ok_or_else(|| {
                        NodeStoreError::new("account evidence has no canonical execution record")
                    })?;
                let verified_block = verifier
                    .verify_execution_header(stored_block.canonical_bundle(), &verified_consensus)
                    .map_err(|e| NodeStoreError::new(e.to_string()))?;
                self.record_verified_execution_block(
                    &verified_block,
                    stored_block.canonical_bundle(),
                )?;
                let mut memory = MemoryAccountStore::default();
                let account = verifier
                    .verify_account_from_consensus(&pending.bytes, &verified_consensus, &mut memory)
                    .map_err(|e| NodeStoreError::new(e.to_string()))?;
                if pending.subject[..12] != [0; 12] || pending.subject[12..] != account.address() {
                    return Err(NodeStoreError::new("verified account subject mismatch"));
                }
                self.record_verified_account(&account, &pending.bytes)?;
            }
            MessagingEvidenceKind::ReceiptProof => {
                if self
                    .signed_transaction(SEPOLIA_CHAIN_ID, pending.subject)?
                    .is_none()
                {
                    return Err(NodeStoreError::new(
                        "receipt evidence has no exact persisted transaction",
                    ));
                }
                match verifier.parse_finalized_tx_receipt_proof(&pending.bytes) {
                    Ok(parsed) => {
                        let anchor = self
                            .execution_block(SEPOLIA_CHAIN_ID, parsed.anchor_block_hash)?
                            .ok_or_else(|| {
                                NodeStoreError::new(
                                    "receipt ancestry has no canonical finalized anchor",
                                )
                            })?;
                        let consensus = crate::consensus::read_finalized_header_by_proof_hash(
                            &self.connection,
                            SEPOLIA_CHAIN_ID,
                            SEPOLIA_NETWORK,
                            anchor.consensus_bundle_hash(),
                        )?
                        .ok_or_else(|| {
                            NodeStoreError::new(
                                "receipt ancestry has no canonical consensus record",
                            )
                        })?;
                        let verified_consensus =
                            reverify_historical_consensus(self, &verifier, &consensus, now_unix)?;
                        let verified_anchor = verifier
                            .verify_execution_header(anchor.canonical_bundle(), &verified_consensus)
                            .map_err(|e| NodeStoreError::new(e.to_string()))?;
                        let verified = verifier
                            .verify_finalized_tx_receipt(&pending.bytes, &verified_anchor)
                            .map_err(|e| NodeStoreError::new(e.to_string()))?;
                        if verified.receipt().tx_hash() != pending.subject {
                            return Err(NodeStoreError::new(
                                "verified receipt transaction mismatch",
                            ));
                        }
                        self.record_verified_finalized_receipt(
                            &verified,
                            &pending.bytes,
                            now_unix,
                        )?;
                    }
                    Err(VerifyError::UnsupportedKind(KIND_TX_RECEIPT_PROOF)) => {
                        let parsed = verifier
                            .parse_tx_receipt_proof(&pending.bytes)
                            .map_err(|e| NodeStoreError::new(e.to_string()))?;
                        let stored_block = self
                            .execution_block(SEPOLIA_CHAIN_ID, parsed.block_hash)?
                            .ok_or_else(|| {
                                NodeStoreError::new(
                                    "receipt evidence has no canonical execution record",
                                )
                            })?;
                        let consensus = crate::consensus::read_finalized_header_by_proof_hash(
                            &self.connection,
                            SEPOLIA_CHAIN_ID,
                            SEPOLIA_NETWORK,
                            stored_block.consensus_bundle_hash(),
                        )?
                        .ok_or_else(|| {
                            NodeStoreError::new(
                                "receipt evidence has no canonical consensus record",
                            )
                        })?;
                        let verified_consensus =
                            reverify_historical_consensus(self, &verifier, &consensus, now_unix)?;
                        let verified_block = verifier
                            .verify_execution_header(
                                stored_block.canonical_bundle(),
                                &verified_consensus,
                            )
                            .map_err(|e| NodeStoreError::new(e.to_string()))?;
                        self.record_verified_execution_block(
                            &verified_block,
                            stored_block.canonical_bundle(),
                        )?;
                        let receipt = verifier
                            .verify_tx_receipt(&pending.bytes, &verified_block)
                            .map_err(|e| NodeStoreError::new(e.to_string()))?;
                        if receipt.tx_hash() != pending.subject {
                            return Err(NodeStoreError::new(
                                "verified receipt transaction mismatch",
                            ));
                        }
                        self.record_verified_receipt(&receipt, &pending.bytes, now_unix)?;
                    }
                    Err(error) => return Err(NodeStoreError::new(error.to_string())),
                }
            }
            MessagingEvidenceKind::AccountStatePackage
            | MessagingEvidenceKind::FinalizedReceiptPackage => {
                return Err(NodeStoreError::new(
                    "composite evidence import routing failed",
                ));
            }
        }
        Ok(())
    }

    fn verify_import_and_complete_composite(
        &mut self,
        pending: &PendingMessageEvidence,
        now_unix: u64,
    ) -> Result<()> {
        let request = read_request(&self.connection, pending.request_id)?
            .ok_or_else(|| NodeStoreError::new("composite request disappeared"))?;
        validate_pending_composite_request(&request, pending)?;
        let context = request
            .checkpoint_context
            .ok_or_else(|| NodeStoreError::new("composite request lost checkpoint context"))?;
        let checkpoint = BeaconCheckpointRoot::sepolia(context.checkpoint_root);
        let verifier = Verifier::sepolia();

        enum VerifiedComposite {
            Account {
                package: Box<ratspeak_eth_verifier::AccountStateEvidencePackage>,
                verified: Box<ratspeak_eth_verifier::VerifiedAccountStateEvidence>,
            },
            Receipt {
                package: Box<ratspeak_eth_verifier::FinalizedReceiptEvidencePackage>,
                verified: Box<ratspeak_eth_verifier::VerifiedFinalizedReceiptEvidence>,
            },
        }

        // Verify every untrusted byte before opening the authoritative write
        // transaction. The transaction below re-reads every local binding and
        // policy row so concurrent revocation or profile changes fail closed.
        let verified = match pending.kind {
            MessagingEvidenceKind::AccountStatePackage => {
                if pending.subject[..12] != [0; 12] {
                    return Err(NodeStoreError::new("invalid account package subject"));
                }
                let wallet = self.wallet_account()?.ok_or_else(|| {
                    NodeStoreError::new("account package has no locally installed wallet")
                })?;
                let address = *wallet.address().0;
                if pending.subject[12..] != address {
                    return Err(NodeStoreError::new(
                        "account package does not target the local wallet",
                    ));
                }
                let package = verifier
                    .parse_account_state_evidence(&pending.bytes)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                let verified = verifier
                    .verify_account_state_evidence(&pending.bytes, &checkpoint, address)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                VerifiedComposite::Account {
                    package: Box::new(package),
                    verified: Box::new(verified),
                }
            }
            MessagingEvidenceKind::FinalizedReceiptPackage => {
                let package = verifier
                    .parse_finalized_receipt_evidence(&pending.bytes)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                let verified = verifier
                    .verify_finalized_receipt_evidence(&pending.bytes, &checkpoint, pending.subject)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                VerifiedComposite::Receipt {
                    package: Box::new(package),
                    verified: Box::new(verified),
                }
            }
            _ => return Err(NodeStoreError::new("not a composite evidence request")),
        };

        match &verified {
            VerifiedComposite::Account { package, verified } => {
                require_canonical_composite_inner(
                    package.consensus_bundle_bytes(),
                    verified.consensus().proof_bundle_hash(),
                    "consensus",
                )?;
                require_canonical_composite_inner(
                    package.execution_header_bytes(),
                    verified.execution_block().proof_bundle_hash(),
                    "execution header",
                )?;
                require_canonical_composite_inner(
                    package.account_proof_bytes(),
                    verified.account().proof_bundle_hash(),
                    "account proof",
                )?;
            }
            VerifiedComposite::Receipt { package, verified } => {
                require_canonical_composite_inner(
                    package.consensus_bundle_bytes(),
                    verified.consensus().proof_bundle_hash(),
                    "consensus",
                )?;
                require_canonical_composite_inner(
                    package.execution_header_bytes(),
                    verified.anchor().proof_bundle_hash(),
                    "execution header",
                )?;
                require_canonical_composite_inner(
                    package.finalized_receipt_bytes(),
                    verified.finalized_receipt().receipt().proof_bundle_hash(),
                    "finalized receipt",
                )?;
            }
        }

        let finalized_slot = match &verified {
            VerifiedComposite::Account { verified, .. } => verified.consensus().finalized_slot(),
            VerifiedComposite::Receipt { verified, .. } => verified.consensus().finalized_slot(),
        };
        let finalized_at_unix = ratspeak_eth_verifier::sepolia_slot_start_unix(finalized_slot)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        crate::bootstrap::ensure_checkpoint_approved_for_finalized_evidence_at(
            self,
            context.checkpoint_root,
            finalized_at_unix,
            now_unix,
        )
        .map_err(|error| NodeStoreError::new(error.to_string()))?;
        if matches!(verified, VerifiedComposite::Receipt { .. })
            && self
                .signed_transaction(SEPOLIA_CHAIN_ID, pending.subject)?
                .is_none()
        {
            return Err(NodeStoreError::new(
                "receipt package has no exact locally persisted transaction",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let stored_pending = read_pending_evidence(&transaction, pending.request_id)?
            .ok_or_else(|| NodeStoreError::new("composite evidence disappeared"))?;
        let mut stored_request = read_request(&transaction, pending.request_id)?
            .ok_or_else(|| NodeStoreError::new("composite request disappeared"))?;
        if stored_pending != *pending {
            return Err(NodeStoreError::new(
                "composite evidence changed before authoritative import",
            ));
        }
        validate_pending_composite_request(&stored_request, &stored_pending)?;
        if stored_request.checkpoint_context != Some(context) {
            return Err(NodeStoreError::new(
                "composite checkpoint context changed before import",
            ));
        }
        crate::bootstrap::ensure_checkpoint_approved_for_finalized_evidence_at_connection(
            &transaction,
            context.checkpoint_root,
            finalized_at_unix,
            now_unix,
        )
        .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let approval = crate::checkpoint::read_checkpoint(
            &transaction,
            SEPOLIA_CHAIN_ID,
            context.checkpoint_root,
        )?
        .ok_or_else(|| NodeStoreError::new("composite checkpoint approval disappeared"))?;
        if approval.checkpoint_epoch() != context.checkpoint_epoch {
            return Err(NodeStoreError::new(
                "composite checkpoint epoch no longer matches its local approval",
            ));
        }

        match verified {
            VerifiedComposite::Account { package, verified } => {
                let wallet = crate::read_wallet_account(&transaction)?.ok_or_else(|| {
                    NodeStoreError::new("account package lost its local wallet binding")
                })?;
                if *wallet.address().0 != verified.account().address()
                    || stored_pending.subject[12..] != verified.account().address()
                {
                    return Err(NodeStoreError::new(
                        "account package local wallet binding changed",
                    ));
                }
                let (consensus, execution, account) = (*verified).into_parts();
                crate::consensus::record_finalized_header_values_in(
                    &transaction,
                    crate::consensus::FinalizedHeaderValues::from_verified(
                        &consensus,
                        package.consensus_bundle_bytes(),
                    )?,
                    true,
                )?;
                crate::consensus::record_execution_block_values_in(
                    &transaction,
                    crate::consensus::ExecutionBlockValues::from_verified(
                        &execution,
                        package.execution_header_bytes(),
                    )?,
                )?;
                crate::record_verified_account_in(
                    &transaction,
                    &account,
                    package.account_proof_bytes(),
                )?;
            }
            VerifiedComposite::Receipt { package, verified } => {
                if crate::transaction::read_signed_transaction(
                    &transaction,
                    SEPOLIA_CHAIN_ID,
                    SEPOLIA_NETWORK,
                    stored_pending.subject,
                )?
                .is_none()
                {
                    return Err(NodeStoreError::new(
                        "receipt package lost its exact local transaction binding",
                    ));
                }
                let (consensus, anchor, receipt) = (*verified).into_parts();
                crate::consensus::record_finalized_header_values_in(
                    &transaction,
                    crate::consensus::FinalizedHeaderValues::from_verified(
                        &consensus,
                        package.consensus_bundle_bytes(),
                    )?,
                    true,
                )?;
                crate::consensus::record_execution_block_values_in(
                    &transaction,
                    crate::consensus::ExecutionBlockValues::from_verified(
                        &anchor,
                        package.execution_header_bytes(),
                    )?,
                )?;
                crate::receipt::record_verified_finalized_receipt_in(
                    &transaction,
                    &receipt,
                    package.finalized_receipt_bytes(),
                    now_unix,
                )?;
            }
        }
        delete_pending_and_complete_request(&transaction, &stored_pending, &mut stored_request)?;
        transaction.commit().map_err(NodeStoreError::sqlite)
    }
}

fn require_canonical_composite_inner(
    bytes: &[u8],
    canonical_hash: [u8; 32],
    name: &'static str,
) -> Result<()> {
    if Sha256::digest(bytes).as_slice() != canonical_hash {
        return Err(NodeStoreError::new(format!(
            "compressed composite {name} must be supplied in canonical uncompressed form"
        )));
    }
    Ok(())
}

fn validate_pending_composite_request(
    request: &RequestRecord,
    pending: &PendingMessageEvidence,
) -> Result<()> {
    if request.operation != OperationKind::Evidence
        || request.status != MessageRequestStatus::PendingVerification
        || request.request_id != pending.request_id
        || request.evidence_kind != Some(pending.kind)
        || request.subject != pending.subject
        || request.manifest_digest != Some(pending.digest)
        || request.manifest_size != Some(pending.bytes.len() as u64)
        || !matches!(
            pending.kind,
            MessagingEvidenceKind::AccountStatePackage
                | MessagingEvidenceKind::FinalizedReceiptPackage
        )
        || request.checkpoint_context.is_none()
    {
        return Err(NodeStoreError::new(
            "pending composite evidence no longer matches its request",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_planned_package_request(
    transaction: &Transaction<'_>,
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    checkpoint_context: CheckpointRequestContext,
    maximum_response_bytes: u32,
    created_at_unix: u64,
    expires_at_unix: u64,
    policy_now_unix: u64,
) -> Result<Vec<u8>> {
    if !matches!(
        kind,
        MessagingEvidenceKind::AccountStatePackage | MessagingEvidenceKind::FinalizedReceiptPackage
    ) || !checkpoint_context.is_valid()
    {
        return Err(NodeStoreError::new("invalid planned evidence package"));
    }
    validate_new_request(
        request_id,
        expected_gateway_source_hash,
        subject,
        maximum_response_bytes,
        created_at_unix,
        expires_at_unix,
    )?;
    crate::bootstrap::ensure_active_checkpoint_at_connection(
        transaction,
        checkpoint_context.checkpoint_root,
        policy_now_unix,
    )
    .map_err(|error| NodeStoreError::new(error.to_string()))?;
    let record = RequestRecord {
        request_id,
        expected_gateway_source_hash,
        operation: OperationKind::Evidence,
        evidence_kind: Some(kind),
        subject,
        checkpoint_context: Some(checkpoint_context),
        maximum_response_bytes: u64::from(maximum_response_bytes),
        bulk_approved: false,
        created_at_unix,
        expires_at_unix,
        status: MessageRequestStatus::Pending,
        manifest_digest: None,
        manifest_size: None,
        relay_observation: None,
    };
    insert_request(transaction, &record)?;
    Ok(encode_evidence_request(&record))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_planned_package_request(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    checkpoint_context: CheckpointRequestContext,
    maximum_response_bytes: u32,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    let record = read_request(connection, request_id)?
        .ok_or_else(|| NodeStoreError::new("planned evidence request disappeared"))?;
    if record.expected_gateway_source_hash != expected_gateway_source_hash
        || record.operation != OperationKind::Evidence
        || record.evidence_kind != Some(kind)
        || record.subject != subject
        || record.checkpoint_context != Some(checkpoint_context)
        || record.maximum_response_bytes != u64::from(maximum_response_bytes)
        || record.created_at_unix != created_at_unix
        || record.expires_at_unix != expires_at_unix
    {
        return Err(NodeStoreError::new("planned evidence request changed"));
    }
    Ok(encode_evidence_request(&record))
}

pub(crate) fn insert_planned_signed_relay(
    transaction: &Transaction<'_>,
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    signed: &StoredSignedTransaction,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    validate_new_request(
        request_id,
        expected_gateway_source_hash,
        signed.tx_hash(),
        u32::try_from(signed.raw_transaction().len())
            .map_err(|_| NodeStoreError::new("signed transaction is oversized"))?,
        created_at_unix,
        expires_at_unix,
    )?;
    if signed.raw_transaction().is_empty()
        || signed.raw_transaction().len() > MAX_SIGNED_TRANSACTION_BYTES
        || crate::transaction::read_signed_transaction(
            transaction,
            signed.chain_id(),
            signed.network(),
            signed.tx_hash(),
        )?
        .as_ref()
            != Some(signed)
    {
        return Err(NodeStoreError::new(
            "relay requires an exact locally persisted supported-chain transaction",
        ));
    }
    let record = RequestRecord {
        request_id,
        expected_gateway_source_hash,
        operation: OperationKind::Relay,
        evidence_kind: None,
        subject: signed.tx_hash(),
        checkpoint_context: None,
        maximum_response_bytes: signed.raw_transaction().len() as u64,
        bulk_approved: false,
        created_at_unix,
        expires_at_unix,
        status: MessageRequestStatus::Pending,
        manifest_digest: None,
        manifest_size: None,
        relay_observation: None,
    };
    insert_request(transaction, &record)?;
    Ok(encode_signed_relay(&record, signed))
}

pub(crate) fn validate_planned_signed_relay(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
    expected_gateway_source_hash: [u8; 16],
    signed: &StoredSignedTransaction,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    let record = read_request(connection, request_id)?
        .ok_or_else(|| NodeStoreError::new("planned relay request disappeared"))?;
    if record.expected_gateway_source_hash != expected_gateway_source_hash
        || record.operation != OperationKind::Relay
        || record.evidence_kind.is_some()
        || record.subject != signed.tx_hash()
        || record.checkpoint_context.is_some()
        || record.maximum_response_bytes != signed.raw_transaction().len() as u64
        || record.created_at_unix != created_at_unix
        || record.expires_at_unix != expires_at_unix
        || crate::transaction::read_signed_transaction(
            connection,
            signed.chain_id(),
            signed.network(),
            signed.tx_hash(),
        )?
        .as_ref()
            != Some(signed)
    {
        return Err(NodeStoreError::new("planned relay request changed"));
    }
    Ok(encode_signed_relay(&record, signed))
}

fn retry_to_fixed_point<T: Copy, E>(
    mut pending: Vec<T>,
    mut process: impl FnMut(T) -> std::result::Result<(), E>,
) -> (usize, Vec<(T, E)>) {
    let mut completed = 0;
    loop {
        let previous_len = pending.len();
        let mut failures = Vec::new();
        for item in pending {
            match process(item) {
                Ok(()) => completed += 1,
                Err(error) => failures.push((item, error)),
            }
        }
        if failures.is_empty() || failures.len() == previous_len {
            return (completed, failures);
        }
        pending = failures.into_iter().map(|(item, _)| item).collect();
    }
}

pub(crate) fn reverify_consensus(
    store: &EthereumNodeStore,
    verifier: &Verifier,
    stored: &StoredFinalizedHeader,
    now_unix: u64,
) -> Result<ratspeak_eth_verifier::VerifiedExecutionHeader> {
    crate::bootstrap::ensure_active_checkpoint_at(store, stored.checkpoint_root(), now_unix)
        .map_err(|e| NodeStoreError::new(e.to_string()))?;
    let verified = verifier
        .verify_consensus_bootstrap(
            stored.canonical_bundle(),
            &BeaconCheckpointRoot::sepolia(stored.checkpoint_root()),
        )
        .map_err(|e| NodeStoreError::new(e.to_string()))?;
    if verified.proof_bundle_hash() != stored.proof_bundle_hash()
        || verified.execution_block_hash() != stored.execution_block_hash()
        || verified.finalized_slot() != stored.finalized_slot()
    {
        return Err(NodeStoreError::new(
            "canonical consensus re-verification mismatch",
        ));
    }
    Ok(verified)
}

pub(crate) fn reverify_historical_consensus(
    store: &EthereumNodeStore,
    verifier: &Verifier,
    stored: &StoredFinalizedHeader,
    now_unix: u64,
) -> Result<ratspeak_eth_verifier::VerifiedExecutionHeader> {
    let finalized_at_unix = ratspeak_eth_verifier::sepolia_slot_start_unix(stored.finalized_slot())
        .map_err(|e| NodeStoreError::new(e.to_string()))?;
    crate::bootstrap::ensure_checkpoint_approved_for_finalized_evidence_at(
        store,
        stored.checkpoint_root(),
        finalized_at_unix,
        now_unix,
    )
    .map_err(|e| NodeStoreError::new(e.to_string()))?;
    let verified = verifier
        .reverify_historical_consensus_bootstrap(
            stored.canonical_bundle(),
            &BeaconCheckpointRoot::sepolia(stored.checkpoint_root()),
        )
        .map_err(|e| NodeStoreError::new(e.to_string()))?;
    if verified.proof_bundle_hash() != stored.proof_bundle_hash()
        || verified.execution_block_hash() != stored.execution_block_hash()
        || verified.finalized_slot() != stored.finalized_slot()
    {
        return Err(NodeStoreError::new(
            "canonical historical consensus re-verification mismatch",
        ));
    }
    Ok(verified)
}

fn validate_new_request(
    request_id: [u8; 16],
    gateway: [u8; 16],
    subject: [u8; 32],
    maximum_response_bytes: u32,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<()> {
    if request_id == [0; 16]
        || gateway == [0; 16]
        || subject == [0; 32]
        || maximum_response_bytes == 0
        || maximum_response_bytes as usize > MAX_BUNDLE_BYTES
        || created_at_unix == 0
        || expires_at_unix <= created_at_unix
    {
        return Err(NodeStoreError::new("invalid bounded messaging request"));
    }
    Ok(())
}

fn expire_request_if_needed(
    transaction: &Transaction<'_>,
    record: &mut RequestRecord,
    now_unix: u64,
) -> Result<bool> {
    if matches!(record.status, MessageRequestStatus::Expired) {
        return Ok(true);
    }
    if record.status == MessageRequestStatus::PendingVerification {
        return Ok(false);
    }
    if now_unix >= record.expires_at_unix {
        record.status = MessageRequestStatus::Expired;
        update_request(transaction, record)?;
        return Ok(true);
    }
    Ok(false)
}

fn pending_bulk_review(record: &RequestRecord) -> Result<PendingBulkEvidenceReview> {
    let kind = record
        .evidence_kind
        .ok_or_else(|| NodeStoreError::new("bulk review is missing an evidence kind"))?;
    let manifest_digest = record
        .manifest_digest
        .ok_or_else(|| NodeStoreError::new("bulk review is missing a manifest digest"))?;
    let encoded_size = u32::try_from(
        record
            .manifest_size
            .ok_or_else(|| NodeStoreError::new("bulk review is missing a manifest size"))?,
    )
    .map_err(|_| NodeStoreError::new("bulk review manifest size is invalid"))?;
    if record.operation != OperationKind::Evidence
        || record.status != MessageRequestStatus::AwaitingBulkApproval
        || record.bulk_approved
        || manifest_digest == [0; 32]
        || encoded_size as usize <= MAX_CONTROL_BYTES
        || encoded_size as usize > MAX_BUNDLE_BYTES
        || u64::from(encoded_size) > record.maximum_response_bytes
        || !request_checkpoint_context_is_valid(record)
    {
        return Err(NodeStoreError::new(
            "stored bulk evidence review failed validation",
        ));
    }
    let binding_digest = bulk_review_binding_digest(record, kind, manifest_digest, encoded_size);
    Ok(PendingBulkEvidenceReview {
        request_id: record.request_id,
        expected_gateway_source_hash: record.expected_gateway_source_hash,
        kind,
        subject: record.subject,
        checkpoint_context: record.checkpoint_context,
        manifest_digest,
        encoded_size,
        expires_at_unix: record.expires_at_unix,
        binding_digest,
    })
}

fn bulk_review_binding_digest(
    record: &RequestRecord,
    kind: MessagingEvidenceKind,
    manifest_digest: [u8; 32],
    encoded_size: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-bulk-evidence-review-v1");
    hasher.update(request_digest(record));
    hasher.update(record.request_id);
    hasher.update(record.expected_gateway_source_hash);
    hasher.update([kind.wire()]);
    hasher.update(record.subject);
    match record.checkpoint_context {
        Some(context) => {
            hasher.update([1]);
            hasher.update(context.checkpoint_epoch.to_le_bytes());
            hasher.update(context.checkpoint_root);
        }
        None => hasher.update([0]),
    }
    hasher.update(manifest_digest);
    hasher.update(encoded_size.to_le_bytes());
    hasher.update(record.expires_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn handle_manifest(
    transaction: &Transaction<'_>,
    record: &mut RequestRecord,
    manifest: EvidenceManifest,
) -> Result<NodeMessageOutcome> {
    if record.operation != OperationKind::Evidence
        || record.evidence_kind != Some(manifest.kind)
        || record.checkpoint_context != manifest.checkpoint_context
        || manifest.digest == [0; 32]
        || manifest.encoded_size == 0
        || u64::from(manifest.encoded_size) > record.maximum_response_bytes
        || manifest.encoded_size as usize > MAX_BUNDLE_BYTES
    {
        return Err(NodeStoreError::new(
            "evidence manifest does not match request",
        ));
    }
    if let Some(existing) = record.manifest_digest {
        if existing != manifest.digest
            || record.manifest_size != Some(u64::from(manifest.encoded_size))
        {
            return Err(NodeStoreError::new("conflicting evidence manifest"));
        }
        return Ok(NodeMessageOutcome::Duplicate);
    }
    record.manifest_digest = Some(manifest.digest);
    record.manifest_size = Some(u64::from(manifest.encoded_size));
    if manifest.encoded_size as usize > MAX_CONTROL_BYTES && !record.bulk_approved {
        record.status = MessageRequestStatus::AwaitingBulkApproval;
        update_request(transaction, record)?;
        Ok(NodeMessageOutcome::BulkApprovalRequired(manifest))
    } else {
        record.status = MessageRequestStatus::Ready;
        update_request(transaction, record)?;
        Ok(NodeMessageOutcome::ManifestAccepted(manifest))
    }
}

fn handle_evidence(
    transaction: &Transaction<'_>,
    record: &mut RequestRecord,
    evidence: CorrelatedEvidence,
    received_at_unix: u64,
) -> Result<NodeMessageOutcome> {
    if record.operation != OperationKind::Evidence
        || !matches!(
            record.status,
            MessageRequestStatus::Ready
                | MessageRequestStatus::PendingVerification
                | MessageRequestStatus::Completed
        )
        || record.evidence_kind != Some(evidence.kind)
        || record.checkpoint_context != evidence.checkpoint_context
        || record.manifest_digest != Some(evidence.digest)
        || record.manifest_size != Some(evidence.bytes.len() as u64)
        || evidence.bytes.len() as u64 > record.maximum_response_bytes
        || (evidence.bytes.len() > MAX_CONTROL_BYTES && !record.bulk_approved)
        || Sha256::digest(&evidence.bytes).as_slice() != evidence.digest
    {
        return Err(NodeStoreError::new(
            "evidence response does not match approved manifest",
        ));
    }
    validate_evidence_subject(evidence.kind, record.subject, &evidence.bytes)?;
    if record.status == MessageRequestStatus::Completed {
        return Ok(NodeMessageOutcome::Duplicate);
    }
    let pending = PendingMessageEvidence {
        request_id: evidence.request_id,
        kind: evidence.kind,
        subject: record.subject,
        digest: evidence.digest,
        bytes: evidence.bytes,
        received_at_unix,
    };
    if record.status == MessageRequestStatus::PendingVerification {
        let stored = read_pending_evidence(transaction, record.request_id)?
            .ok_or_else(|| NodeStoreError::new("pending request lost its evidence bytes"))?;
        if stored.request_id != pending.request_id
            || stored.kind != pending.kind
            || stored.subject != pending.subject
            || stored.digest != pending.digest
            || stored.bytes != pending.bytes
        {
            return Err(NodeStoreError::new("conflicting pending Ethereum evidence"));
        }
        // Return the durable row so an authenticated retransmission also
        // retries local verification after dependencies/checkpoint recover.
        return Ok(NodeMessageOutcome::EvidencePending(stored));
    }
    insert_pending_evidence(transaction, &pending)?;
    record.status = MessageRequestStatus::PendingVerification;
    update_request(transaction, record)?;
    Ok(NodeMessageOutcome::EvidencePending(pending))
}

fn insert_pending_evidence(
    transaction: &Transaction<'_>,
    pending: &PendingMessageEvidence,
) -> Result<()> {
    let digest = pending_evidence_digest(pending);
    transaction
        .execute(
            "INSERT INTO eth_pending_message_evidence (
            request_id, evidence_kind, subject, evidence_digest, encoded_size,
            evidence_blob, received_at_unix, record_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                pending.request_id.as_slice(),
                pending.kind.wire(),
                pending.subject.as_slice(),
                pending.digest.as_slice(),
                pending.bytes.len().to_string(),
                pending.bytes,
                pending.received_at_unix.to_string(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn read_pending_evidence(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
) -> Result<Option<PendingMessageEvidence>> {
    let row = connection
        .query_row(
            "SELECT evidence_kind, subject, evidence_digest, encoded_size,
                evidence_blob, received_at_unix, record_digest
         FROM eth_pending_message_evidence WHERE request_id = ?1",
            [request_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let encoded_size = parse_stored_u64(&row.3, "pending evidence size")?;
    let pending = PendingMessageEvidence {
        request_id,
        kind: MessagingEvidenceKind::from_wire(row.0)?,
        subject: stored_array(&row.1, "pending evidence subject")?,
        digest: stored_array(&row.2, "pending evidence digest")?,
        bytes: row.4,
        received_at_unix: parse_stored_u64(&row.5, "pending evidence receipt time")?,
    };
    let request = read_request(connection, request_id)?
        .ok_or_else(|| NodeStoreError::new("pending evidence lost its request"))?;
    if encoded_size != pending.bytes.len() as u64
        || pending.bytes.is_empty()
        || pending.bytes.len() > MAX_BUNDLE_BYTES
        || pending.received_at_unix == 0
        || pending.digest.as_slice() != Sha256::digest(&pending.bytes).as_slice()
        || request.status != MessageRequestStatus::PendingVerification
        || request.operation != OperationKind::Evidence
        || request.evidence_kind != Some(pending.kind)
        || request.subject != pending.subject
        || request.manifest_digest != Some(pending.digest)
        || request.manifest_size != Some(encoded_size)
        || stored_array::<32>(&row.6, "pending evidence record digest")?
            != pending_evidence_digest(&pending)
    {
        return Err(NodeStoreError::new(
            "stored pending Ethereum evidence failed validation",
        ));
    }
    Ok(Some(pending))
}

fn complete_pending_evidence(
    connection: &mut rusqlite::Connection,
    pending: &PendingMessageEvidence,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(NodeStoreError::sqlite)?;
    let mut request = read_request(&transaction, pending.request_id)?
        .ok_or_else(|| NodeStoreError::new("pending evidence lost its request"))?;
    let stored = read_pending_evidence(&transaction, pending.request_id)?
        .ok_or_else(|| NodeStoreError::new("pending evidence disappeared before completion"))?;
    delete_pending_and_complete_request(&transaction, &stored, &mut request)?;
    transaction.commit().map_err(NodeStoreError::sqlite)
}

fn delete_pending_and_complete_request(
    transaction: &Transaction<'_>,
    pending: &PendingMessageEvidence,
    request: &mut RequestRecord,
) -> Result<()> {
    let stored = read_pending_evidence(transaction, pending.request_id)?
        .ok_or_else(|| NodeStoreError::new("pending evidence disappeared before completion"))?;
    if stored != *pending || request.status != MessageRequestStatus::PendingVerification {
        return Err(NodeStoreError::new(
            "pending evidence changed before completion",
        ));
    }
    let deleted = transaction
        .execute(
            "DELETE FROM eth_pending_message_evidence WHERE request_id = ?1",
            [pending.request_id.as_slice()],
        )
        .map_err(NodeStoreError::sqlite)?;
    if deleted != 1 {
        return Err(NodeStoreError::new("pending evidence completion was lost"));
    }
    request.status = MessageRequestStatus::Completed;
    update_request(transaction, request)
}

fn pending_evidence_digest(pending: &PendingMessageEvidence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-pending-message-evidence-v1");
    hasher.update(pending.request_id);
    hasher.update([pending.kind.wire()]);
    hasher.update(pending.subject);
    hasher.update(pending.digest);
    hasher.update((pending.bytes.len() as u64).to_le_bytes());
    hasher.update(&pending.bytes);
    hasher.update(pending.received_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn validate_evidence_subject(
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    bytes: &[u8],
) -> Result<()> {
    let verifier = Verifier::sepolia();
    let matches = match kind {
        MessagingEvidenceKind::Consensus => verifier.parse_consensus_bootstrap(bytes).map(|_| true),
        MessagingEvidenceKind::ExecutionHeader => {
            verifier.parse_execution_header_proof(bytes).map(|parsed| {
                let mut rlp = parsed.rlp_header.as_slice();
                Header::decode(&mut rlp)
                    .is_ok_and(|header| rlp.is_empty() && header.hash_slow().0 == subject)
            })
        }
        MessagingEvidenceKind::AccountProof => verifier
            .parse_account_proof(bytes)
            .map(|parsed| subject[..12] == [0; 12] && subject[12..] == parsed.address),
        MessagingEvidenceKind::ReceiptProof => {
            match verifier.parse_finalized_tx_receipt_proof(bytes) {
                Ok(parsed) => Ok(parsed.receipt_proof.tx_hash == subject),
                Err(VerifyError::UnsupportedKind(KIND_TX_RECEIPT_PROOF)) => verifier
                    .parse_tx_receipt_proof(bytes)
                    .map(|parsed| parsed.tx_hash == subject),
                Err(error) => Err(error),
            }
        }
        MessagingEvidenceKind::AccountStatePackage => {
            verifier.parse_account_state_evidence(bytes).map(|package| {
                subject[..12] == [0; 12] && subject[12..] == package.account_proof().address
            })
        }
        MessagingEvidenceKind::FinalizedReceiptPackage => verifier
            .parse_finalized_receipt_evidence(bytes)
            .map(|package| package.finalized_receipt().receipt_proof.tx_hash == subject),
    }
    .map_err(|_| NodeStoreError::new("malformed Ethereum evidence response"))?;
    if !matches {
        return Err(NodeStoreError::new("Ethereum evidence subject mismatch"));
    }
    Ok(())
}

enum GatewayMessage {
    Manifest(EvidenceManifest),
    Evidence(CorrelatedEvidence),
    RelayObservation {
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        observation: RelayObservation,
    },
    TransactionStatus(TransactionStatusWireObservation),
    ServiceFailure {
        request_id: [u8; 16],
        original_attachment_digest: [u8; 32],
    },
}

impl GatewayMessage {
    fn request_id(&self) -> [u8; 16] {
        match self {
            Self::Manifest(value) => value.request_id,
            Self::Evidence(value) => value.request_id,
            Self::RelayObservation { request_id, .. } => *request_id,
            Self::TransactionStatus(value) => value.request_id,
            Self::ServiceFailure { request_id, .. } => *request_id,
        }
    }
}

fn decode_gateway_message(bytes: &[u8]) -> Result<GatewayMessage> {
    if bytes.len() < MAGIC.len() + 1 + 8 + 1 || bytes.len() > MAX_BUNDLE_BYTES.saturating_add(128) {
        return Err(NodeStoreError::new("invalid Ethereum gateway message size"));
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(MAGIC.len())? != MAGIC
        || cursor.u8()? != VERSION
        || cursor.u64()? != SEPOLIA_CHAIN_ID
    {
        return Err(NodeStoreError::new(
            "invalid Ethereum gateway message prelude",
        ));
    }
    match cursor.u8()? {
        KIND_EVIDENCE_MANIFEST => {
            let request_id = cursor.array()?;
            let kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
            let checkpoint_context = decode_checkpoint_context(&mut cursor, kind)?;
            let digest = cursor.array()?;
            let encoded_size = cursor.u32()?;
            cursor.finish()?;
            Ok(GatewayMessage::Manifest(EvidenceManifest {
                request_id,
                kind,
                checkpoint_context,
                digest,
                encoded_size,
            }))
        }
        KIND_EVIDENCE_RESPONSE => {
            let request_id = cursor.array()?;
            let kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
            let checkpoint_context = decode_checkpoint_context(&mut cursor, kind)?;
            let digest = cursor.array()?;
            let size = cursor.u32()? as usize;
            if size == 0 || size > MAX_BUNDLE_BYTES {
                return Err(NodeStoreError::new("invalid Ethereum evidence size"));
            }
            let evidence = cursor.take(size)?.to_vec();
            cursor.finish()?;
            Ok(GatewayMessage::Evidence(CorrelatedEvidence {
                request_id,
                kind,
                checkpoint_context,
                digest,
                bytes: evidence,
            }))
        }
        KIND_RELAY_OBSERVATION => {
            let request_id = cursor.array()?;
            let tx_hash = cursor.array()?;
            let observation = RelayObservation::from_wire(cursor.u8()?)?;
            cursor.finish()?;
            Ok(GatewayMessage::RelayObservation {
                request_id,
                tx_hash,
                observation,
            })
        }
        KIND_TRANSACTION_STATUS_OBSERVATION => {
            let observation = TransactionStatusWireObservation {
                request_id: cursor.array()?,
                tx_hash: cursor.array()?,
                status: TransactionStatus::from_wire(cursor.u8()?)?,
                included_block_number: cursor.u64()?,
                included_block_hash: cursor.array()?,
                latest_head_number: cursor.u64()?,
                latest_head_hash: cursor.array()?,
                safe_head_number: cursor.u64()?,
                safe_head_hash: cursor.array()?,
                finalized_head_number: cursor.u64()?,
                finalized_head_hash: cursor.array()?,
            };
            cursor.finish()?;
            observation.validate()?;
            Ok(GatewayMessage::TransactionStatus(observation))
        }
        KIND_SERVICE_FAILURE => {
            let request_id = cursor.array()?;
            let original_attachment_digest = cursor.array()?;
            cursor.finish()?;
            Ok(GatewayMessage::ServiceFailure {
                request_id,
                original_attachment_digest,
            })
        }
        KIND_EVIDENCE_REQUEST
        | KIND_SIGNED_RELAY
        | KIND_BULK_APPROVAL
        | KIND_TRANSACTION_STATUS_REQUEST => {
            Err(NodeStoreError::new("unexpected gateway message direction"))
        }
        _ => Err(NodeStoreError::new(
            "unsupported Ethereum gateway message kind",
        )),
    }
}

fn encode_evidence_request(record: &RequestRecord) -> Vec<u8> {
    let mut out = prelude(KIND_EVIDENCE_REQUEST);
    out.extend_from_slice(&record.request_id);
    out.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    let kind = record.evidence_kind.expect("evidence request kind");
    out.push(kind.wire());
    out.extend_from_slice(&record.subject);
    encode_checkpoint_context(&mut out, kind, record.checkpoint_context);
    out.extend_from_slice(&(record.maximum_response_bytes as u32).to_le_bytes());
    out.push(u8::from(record.bulk_approved));
    out
}

#[derive(Debug)]
struct StoredOutboxRow {
    gateway_destination_hash: [u8; 16],
    local_source_hash: [u8; 16],
    identity_session_generation: u64,
    attachment_digest: [u8; 32],
    state: i64,
    attempts: i64,
    lease_generation: i64,
    lease_until_unix: Option<u64>,
    queued_at_unix: Option<u64>,
    record_digest: [u8; 32],
}

fn reconstruct_outbound_attachment(
    connection: &rusqlite::Connection,
    record: &RequestRecord,
    kind: OutboundMessageKind,
) -> Result<Vec<u8>> {
    let sendable = match kind {
        OutboundMessageKind::EvidenceRequest => {
            record.status == MessageRequestStatus::Pending && !record.bulk_approved
        }
        OutboundMessageKind::BulkApproval => {
            record.status == MessageRequestStatus::Ready && record.bulk_approved
        }
        OutboundMessageKind::SignedTransactionRelay => {
            record.status == MessageRequestStatus::Pending
        }
        OutboundMessageKind::TransactionStatusRequest => {
            record.status == MessageRequestStatus::Pending
        }
    };
    if !sendable {
        return Err(NodeStoreError::new(
            "outbound message state is not sendable",
        ));
    }
    reconstruct_outbound_attachment_exact(connection, record, kind)
}

fn validate_service_failure_binding(
    connection: &rusqlite::Connection,
    record: &RequestRecord,
    original_attachment_digest: [u8; 32],
) -> Result<()> {
    let kind = match record.operation {
        OperationKind::Evidence => OutboundMessageKind::EvidenceRequest,
        OperationKind::Relay => OutboundMessageKind::SignedTransactionRelay,
        OperationKind::TransactionStatus => OutboundMessageKind::TransactionStatusRequest,
    };
    let row = read_outbox_row(connection, record.request_id, kind)?
        .ok_or_else(|| NodeStoreError::new("service failure has no matching outbound request"))?;
    if row.gateway_destination_hash != record.expected_gateway_source_hash {
        return Err(NodeStoreError::new(
            "service failure gateway binding does not match request",
        ));
    }
    let binding = OutboundMessageBinding::new(
        row.gateway_destination_hash,
        row.local_source_hash,
        row.identity_session_generation,
    )?;
    let exact_attachment = reconstruct_outbound_attachment_exact(connection, record, kind)?;
    let exact_digest: [u8; 32] = Sha256::digest(&exact_attachment).into();
    validate_outbox_row(&row, record.request_id, kind, &binding, exact_digest)?;
    if original_attachment_digest != exact_digest {
        return Err(NodeStoreError::new(
            "service failure does not match the outbound request bytes",
        ));
    }
    Ok(())
}

fn reconstruct_outbound_attachment_exact(
    connection: &rusqlite::Connection,
    record: &RequestRecord,
    kind: OutboundMessageKind,
) -> Result<Vec<u8>> {
    match kind {
        OutboundMessageKind::EvidenceRequest if record.operation == OperationKind::Evidence => {
            let mut original = record.clone();
            original.bulk_approved = false;
            Ok(encode_evidence_request(&original))
        }
        OutboundMessageKind::BulkApproval
            if record.operation == OperationKind::Evidence && record.bulk_approved =>
        {
            let digest = record
                .manifest_digest
                .ok_or_else(|| NodeStoreError::new("approved bulk manifest is missing"))?;
            let size = u32::try_from(
                record
                    .manifest_size
                    .ok_or_else(|| NodeStoreError::new("approved bulk size is missing"))?,
            )
            .map_err(|_| NodeStoreError::new("approved bulk size is invalid"))?;
            Ok(encode_bulk_approval(record, digest, size))
        }
        OutboundMessageKind::SignedTransactionRelay if record.operation == OperationKind::Relay => {
            let transaction = crate::transaction::read_signed_transaction_by_hash(
                connection,
                record.subject,
            )?
            .ok_or_else(|| NodeStoreError::new("relay lost its signed transaction"))?;
            Ok(encode_signed_relay(record, &transaction))
        }
        OutboundMessageKind::TransactionStatusRequest
            if record.operation == OperationKind::TransactionStatus =>
        {
            if crate::transaction::read_signed_transaction(
                connection,
                SEPOLIA_CHAIN_ID,
                ratspeak_eth_verifier::SEPOLIA_NETWORK,
                record.subject,
            )?
            .is_none()
            {
                return Err(NodeStoreError::new(
                    "transaction status request lost its exact local transaction",
                ));
            }
            Ok(encode_transaction_status_request(record))
        }
        _ => Err(NodeStoreError::new(
            "outbound message state is not sendable",
        )),
    }
}

fn read_outbox_row(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
    kind: OutboundMessageKind,
) -> Result<Option<StoredOutboxRow>> {
    connection
        .query_row(
            "SELECT gateway_destination_hash, local_source_hash,
                    identity_session_generation, attachment_digest, state, attempts,
                    lease_generation, lease_until_unix, queued_at_unix, record_digest
               FROM eth_message_outbox
              WHERE request_id = ?1 AND item_kind = ?2",
            rusqlite::params![request_id.as_slice(), kind.as_i64()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .map(|row| {
            Ok(StoredOutboxRow {
                gateway_destination_hash: stored_array(&row.0, "outbox gateway")?,
                local_source_hash: stored_array(&row.1, "outbox source")?,
                identity_session_generation: parse_stored_u64(
                    &row.2,
                    "outbox identity generation",
                )?,
                attachment_digest: stored_array(&row.3, "outbox attachment digest")?,
                state: row.4,
                attempts: row.5,
                lease_generation: row.6,
                lease_until_unix: row
                    .7
                    .map(|value| parse_stored_u64(&value, "outbox lease expiry"))
                    .transpose()?,
                queued_at_unix: row
                    .8
                    .map(|value| parse_stored_u64(&value, "outbox queue time"))
                    .transpose()?,
                record_digest: stored_array(&row.9, "outbox record digest")?,
            })
        })
        .transpose()
}

fn validate_outbox_row(
    row: &StoredOutboxRow,
    request_id: [u8; 16],
    kind: OutboundMessageKind,
    binding: &OutboundMessageBinding,
    attachment_digest: [u8; 32],
) -> Result<()> {
    let expected = outbox_digest(
        request_id,
        kind,
        *binding,
        row.attachment_digest,
        row.state,
        row.attempts,
        row.lease_generation,
        row.lease_until_unix,
        row.queued_at_unix,
    );
    let state_shape_valid = match row.state {
        OUTBOUND_READY => row.lease_until_unix.is_none() && row.queued_at_unix.is_none(),
        OUTBOUND_LEASED => row.lease_until_unix.is_some() && row.queued_at_unix.is_none(),
        OUTBOUND_SETTLED => row.lease_until_unix.is_none() && row.queued_at_unix.is_some(),
        _ => false,
    };
    if !state_shape_valid
        || !(1..=MAX_OUTBOUND_QUEUE_ATTEMPTS).contains(&row.attempts)
        || row.lease_generation < 1
        || row.gateway_destination_hash == [0; 16]
        || row.local_source_hash == [0; 16]
        || row.gateway_destination_hash == row.local_source_hash
        || row.identity_session_generation == 0
        || row.gateway_destination_hash != binding.gateway_destination_hash
        || row.local_source_hash != binding.local_source_hash
        || row.identity_session_generation != binding.identity_session_generation
        || row.attachment_digest != attachment_digest
        || expected != row.record_digest
    {
        return Err(NodeStoreError::new("outbound message ledger is invalid"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn outbox_digest(
    request_id: [u8; 16],
    kind: OutboundMessageKind,
    binding: OutboundMessageBinding,
    attachment_digest: [u8; 32],
    state: i64,
    attempts: i64,
    lease_generation: i64,
    lease_until_unix: Option<u64>,
    queued_at_unix: Option<u64>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.message-outbox.v1");
    hasher.update(request_id);
    hasher.update(kind.as_i64().to_le_bytes());
    hasher.update(binding.gateway_destination_hash);
    hasher.update(binding.local_source_hash);
    hasher.update(binding.identity_session_generation.to_le_bytes());
    hasher.update(attachment_digest);
    hasher.update(state.to_le_bytes());
    hasher.update(attempts.to_le_bytes());
    hasher.update(lease_generation.to_le_bytes());
    hasher.update(lease_until_unix.unwrap_or_default().to_le_bytes());
    hasher.update(queued_at_unix.unwrap_or_default().to_le_bytes());
    hasher.finalize().into()
}

fn transition_outbound_lease(
    connection: &mut rusqlite::Connection,
    binding: OutboundMessageBinding,
    lease: &OutboundMessageLease,
    now_unix: u64,
    settle: bool,
) -> Result<()> {
    if now_unix == 0 {
        return Err(NodeStoreError::new("invalid outbound transition time"));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(NodeStoreError::sqlite)?;
    let row = read_outbox_row(&transaction, lease.request_id, lease.kind)?
        .ok_or_else(|| NodeStoreError::new("unknown outbound message lease"))?;
    if binding.gateway_destination_hash != lease.destination_hash
        || binding.local_source_hash != lease.source_hash
        || binding.identity_session_generation != lease.identity_session_generation
    {
        return Err(NodeStoreError::new(
            "outbound messaging identity binding changed",
        ));
    }
    let attachment_digest: [u8; 32] = Sha256::digest(&lease.attachment).into();
    validate_outbox_row(
        &row,
        lease.request_id,
        lease.kind,
        &binding,
        attachment_digest,
    )?;
    if row.state != OUTBOUND_LEASED
        || row.lease_generation
            != i64::try_from(lease.generation)
                .map_err(|_| NodeStoreError::new("invalid outbound lease generation"))?
    {
        return Err(NodeStoreError::new("stale outbound message lease"));
    }
    let request = read_request(&transaction, lease.request_id)?
        .ok_or_else(|| NodeStoreError::new("outbound request disappeared"))?;
    if request.expected_gateway_source_hash != lease.destination_hash
        || request.status == MessageRequestStatus::Cancelled
        || request.status == MessageRequestStatus::Expired
        || now_unix >= request.expires_at_unix
    {
        return Err(NodeStoreError::new("outbound request is no longer valid"));
    }
    let state = if settle {
        OUTBOUND_SETTLED
    } else {
        OUTBOUND_READY
    };
    let queued_at = settle.then_some(now_unix);
    let digest = outbox_digest(
        lease.request_id,
        lease.kind,
        binding,
        attachment_digest,
        state,
        row.attempts,
        row.lease_generation,
        None,
        queued_at,
    );
    let changed = transaction
        .execute(
            "UPDATE eth_message_outbox
                SET state = ?1, lease_until_unix = NULL, queued_at_unix = ?2,
                    record_digest = ?3
              WHERE request_id = ?4 AND item_kind = ?5 AND state = ?6
                AND lease_generation = ?7",
            rusqlite::params![
                state,
                queued_at.map(|value| value.to_string()),
                digest.as_slice(),
                lease.request_id.as_slice(),
                lease.kind.as_i64(),
                OUTBOUND_LEASED,
                row.lease_generation,
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed != 1 {
        return Err(NodeStoreError::new("outbound lease transition was lost"));
    }
    transaction.commit().map_err(NodeStoreError::sqlite)
}

fn encode_signed_relay(
    record: &RequestRecord,
    transaction: &StoredSignedTransaction,
) -> Vec<u8> {
    let mut out = prelude_for_chain(transaction.chain_id(), KIND_SIGNED_RELAY);
    out.extend_from_slice(&record.request_id);
    out.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    out.extend_from_slice(&(transaction.raw_transaction().len() as u32).to_le_bytes());
    out.extend_from_slice(transaction.raw_transaction());
    out
}

/// Fixed-width kind-8 request: prelude (17), request id (16), expiry (8),
/// exact transaction hash (32). It contains no authority or service-supplied
/// source field.
fn encode_transaction_status_request(record: &RequestRecord) -> Vec<u8> {
    let mut out = prelude(KIND_TRANSACTION_STATUS_REQUEST);
    out.extend_from_slice(&record.request_id);
    out.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    out.extend_from_slice(&record.subject);
    out
}

fn encode_bulk_approval(
    record: &RequestRecord,
    manifest_digest: [u8; 32],
    encoded_size: u32,
) -> Vec<u8> {
    let mut out = prelude(KIND_BULK_APPROVAL);
    out.extend_from_slice(&record.request_id);
    out.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    let kind = record.evidence_kind.expect("evidence request kind");
    out.push(kind.wire());
    encode_checkpoint_context(&mut out, kind, record.checkpoint_context);
    out.extend_from_slice(&manifest_digest);
    out.extend_from_slice(&encoded_size.to_le_bytes());
    out
}

fn prelude(kind: u8) -> Vec<u8> {
    prelude_for_chain(SEPOLIA_CHAIN_ID, kind)
}

fn prelude_for_chain(chain_id: u64, kind: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.push(kind);
    out
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
) -> Result<Option<CheckpointRequestContext>> {
    if !kind_requires_checkpoint_context(kind) {
        return Ok(None);
    }
    let context = CheckpointRequestContext {
        checkpoint_epoch: cursor.u64()?,
        checkpoint_root: cursor.array()?,
    };
    context
        .is_valid()
        .then_some(Some(context))
        .ok_or_else(|| NodeStoreError::new("invalid Ethereum checkpoint context"))
}

fn encode_checkpoint_context(
    out: &mut Vec<u8>,
    kind: MessagingEvidenceKind,
    context: Option<CheckpointRequestContext>,
) {
    if kind_requires_checkpoint_context(kind) {
        let context = context.expect("validated contextual evidence request");
        out.extend_from_slice(&context.checkpoint_epoch.to_le_bytes());
        out.extend_from_slice(&context.checkpoint_root);
    }
}

fn insert_request(connection: &rusqlite::Connection, record: &RequestRecord) -> Result<()> {
    let digest = request_digest(record);
    connection
        .execute(
            "INSERT INTO eth_message_requests (
                request_id, expected_gateway_source_hash, operation_kind, evidence_kind,
                subject, checkpoint_epoch, checkpoint_root, maximum_response_bytes,
                bulk_approved, created_at_unix,
                expires_at_unix, status, manifest_digest, manifest_size,
                relay_observation, record_digest
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
             )",
            rusqlite::params![
                record.request_id.as_slice(),
                record.expected_gateway_source_hash.as_slice(),
                record.operation.as_i64(),
                record.evidence_kind.map(MessagingEvidenceKind::wire),
                record.subject.as_slice(),
                record
                    .checkpoint_context
                    .map(|context| context.checkpoint_epoch.to_string()),
                record
                    .checkpoint_context
                    .as_ref()
                    .map(|context| context.checkpoint_root.as_slice()),
                record.maximum_response_bytes.to_string(),
                i64::from(record.bulk_approved),
                record.created_at_unix.to_string(),
                record.expires_at_unix.to_string(),
                record.status.as_i64(),
                record
                    .manifest_digest
                    .as_ref()
                    .map(|value| value.as_slice()),
                record.manifest_size.map(|value| value.to_string()),
                record.relay_observation.map(RelayObservation::wire),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn update_request(transaction: &Transaction<'_>, record: &RequestRecord) -> Result<()> {
    let digest = request_digest(record);
    let changed = transaction
        .execute(
            "UPDATE eth_message_requests SET
                bulk_approved = ?2, status = ?3, manifest_digest = ?4,
                manifest_size = ?5, relay_observation = ?6, record_digest = ?7
             WHERE request_id = ?1",
            rusqlite::params![
                record.request_id.as_slice(),
                i64::from(record.bulk_approved),
                record.status.as_i64(),
                record
                    .manifest_digest
                    .as_ref()
                    .map(|value| value.as_slice()),
                record.manifest_size.map(|value| value.to_string()),
                record.relay_observation.map(RelayObservation::wire),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed != 1 {
        return Err(NodeStoreError::new("messaging request update was lost"));
    }
    Ok(())
}

fn read_request(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
) -> Result<Option<RequestRecord>> {
    let row = connection
        .query_row(
            "SELECT expected_gateway_source_hash, operation_kind, evidence_kind,
                    subject, checkpoint_epoch, checkpoint_root, maximum_response_bytes,
                    bulk_approved, created_at_unix, expires_at_unix, status,
                    manifest_digest, manifest_size, relay_observation, record_digest
             FROM eth_message_requests WHERE request_id = ?1",
            [request_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<u8>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((
        gateway,
        operation,
        evidence_kind,
        subject,
        checkpoint_epoch,
        checkpoint_root,
        maximum,
        bulk,
        created,
        expires,
        status,
        manifest_digest,
        manifest_size,
        relay_observation,
        digest,
    )) = row
    else {
        return Ok(None);
    };
    let record = RequestRecord {
        request_id,
        expected_gateway_source_hash: stored_array(&gateway, "gateway source hash")?,
        operation: OperationKind::from_i64(operation)?,
        evidence_kind: evidence_kind
            .map(MessagingEvidenceKind::from_wire)
            .transpose()?,
        subject: stored_array(&subject, "messaging subject")?,
        checkpoint_context: match (checkpoint_epoch.as_deref(), checkpoint_root.as_deref()) {
            (Some(epoch), Some(root)) => Some(CheckpointRequestContext {
                checkpoint_epoch: parse_stored_u64(epoch, "request checkpoint epoch")?,
                checkpoint_root: stored_array(root, "request checkpoint root")?,
            }),
            (None, None) => None,
            _ => {
                return Err(NodeStoreError::new(
                    "stored messaging checkpoint context is incomplete",
                ));
            }
        },
        maximum_response_bytes: parse_stored_u64(&maximum, "maximum response bytes")?,
        bulk_approved: match bulk {
            0 => false,
            1 => true,
            _ => return Err(NodeStoreError::new("invalid stored bulk approval")),
        },
        created_at_unix: parse_stored_u64(&created, "message creation time")?,
        expires_at_unix: parse_stored_u64(&expires, "message expiry time")?,
        status: MessageRequestStatus::from_i64(status)?,
        manifest_digest: manifest_digest
            .as_deref()
            .map(|value| stored_array(value, "manifest digest"))
            .transpose()?,
        manifest_size: manifest_size
            .as_deref()
            .map(|value| parse_stored_u64(value, "manifest size"))
            .transpose()?,
        relay_observation: relay_observation
            .map(RelayObservation::from_wire)
            .transpose()?,
    };
    let stored_digest: [u8; 32] = stored_array(&digest, "message request digest")?;
    if stored_digest != request_digest(&record)
        || record.request_id == [0; 16]
        || record.expected_gateway_source_hash == [0; 16]
        || record.subject == [0; 32]
        || record.maximum_response_bytes == 0
        || record.maximum_response_bytes as usize > MAX_BUNDLE_BYTES
        || record.created_at_unix == 0
        || record.expires_at_unix <= record.created_at_unix
        || (record.operation == OperationKind::Evidence) != record.evidence_kind.is_some()
        || record.manifest_digest.is_some() != record.manifest_size.is_some()
        || (record.operation != OperationKind::Relay && record.relay_observation.is_some())
        || !request_checkpoint_context_is_valid(&record)
    {
        return Err(NodeStoreError::new(
            "stored messaging request failed validation",
        ));
    }
    Ok(Some(record))
}

/// Returns authenticated, transaction-exact relay reports retained in the
/// durable request journal. These reports remain non-authoritative: they are
/// useful for progress only and can never produce a finalized assurance.
pub(crate) fn stored_relay_observations(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
) -> Result<Vec<RelayObservation>> {
    let mut statement = connection
        .prepare(
            "SELECT request_id
             FROM eth_message_requests
             WHERE operation_kind = ?1 AND subject = ?2 AND status = ?3
                   AND relay_observation IS NOT NULL
             ORDER BY created_at_unix, request_id",
        )
        .map_err(NodeStoreError::sqlite)?;
    let request_ids = statement
        .query_map(
            rusqlite::params![
                OperationKind::Relay.as_i64(),
                tx_hash.as_slice(),
                MessageRequestStatus::Completed.as_i64()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(NodeStoreError::sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(NodeStoreError::sqlite)?;
    drop(statement);

    request_ids
        .into_iter()
        .map(|request_id| {
            let request_id = stored_array(&request_id, "relay request id")?;
            let record = read_request(connection, request_id)?
                .ok_or_else(|| NodeStoreError::new("stored relay request disappeared"))?;
            if record.operation != OperationKind::Relay
                || record.subject != tx_hash
                || record.status != MessageRequestStatus::Completed
            {
                return Err(NodeStoreError::new(
                    "stored relay observation lost its transaction binding",
                ));
            }
            record
                .relay_observation
                .ok_or_else(|| NodeStoreError::new("stored relay observation is missing"))
        })
        .collect()
}

pub(crate) fn read_account_request_progress(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
) -> Result<Option<AccountRequestProgressRecord>> {
    let Some(record) = read_request(connection, request_id)? else {
        return Ok(None);
    };
    if record.operation != OperationKind::Evidence {
        return Err(NodeStoreError::new(
            "account sync progress request is not evidence",
        ));
    }

    let mut evidence_state = None;
    let mut approval_state = None;
    for kind in [
        OutboundMessageKind::EvidenceRequest,
        OutboundMessageKind::BulkApproval,
    ] {
        let Some(row) = read_outbox_row(connection, request_id, kind)? else {
            continue;
        };
        if row.gateway_destination_hash != record.expected_gateway_source_hash {
            return Err(NodeStoreError::new(
                "account sync outbox gateway does not match request",
            ));
        }
        let attachment = reconstruct_outbound_attachment_exact(connection, &record, kind)?;
        let attachment_digest = Sha256::digest(&attachment).into();
        let binding = OutboundMessageBinding::new(
            row.gateway_destination_hash,
            row.local_source_hash,
            row.identity_session_generation,
        )?;
        validate_outbox_row(&row, request_id, kind, &binding, attachment_digest)?;
        match kind {
            OutboundMessageKind::EvidenceRequest => evidence_state = Some(row.state),
            OutboundMessageKind::BulkApproval => approval_state = Some(row.state),
            OutboundMessageKind::SignedTransactionRelay
            | OutboundMessageKind::TransactionStatusRequest => unreachable!(),
        }
    }

    let outbox_state = if record.status == MessageRequestStatus::Ready && record.bulk_approved {
        approval_state
    } else {
        evidence_state
    };
    Ok(Some(AccountRequestProgressRecord {
        status: record.status,
        bulk_approved: record.bulk_approved,
        outbox_state,
    }))
}

fn request_digest(record: &RequestRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-message-request-v1");
    hasher.update(record.request_id);
    hasher.update(record.expected_gateway_source_hash);
    hasher.update(record.operation.as_i64().to_le_bytes());
    hasher.update([record
        .evidence_kind
        .map(MessagingEvidenceKind::wire)
        .unwrap_or(0)]);
    hasher.update(record.subject);
    hasher.update(record.maximum_response_bytes.to_le_bytes());
    hasher.update([u8::from(record.bulk_approved)]);
    hasher.update(record.created_at_unix.to_le_bytes());
    hasher.update(record.expires_at_unix.to_le_bytes());
    hasher.update(record.status.as_i64().to_le_bytes());
    hasher.update(record.manifest_digest.unwrap_or([0; 32]));
    hasher.update(record.manifest_size.unwrap_or(0).to_le_bytes());
    hasher.update([record
        .relay_observation
        .map(RelayObservation::wire)
        .unwrap_or(0)]);
    // Preserve the v1 digest for pre-v13 requests while binding every byte of
    // the authority context on composite requests.
    if let Some(context) = record.checkpoint_context {
        hasher.update(context.checkpoint_epoch.to_le_bytes());
        hasher.update(context.checkpoint_root);
    }
    hasher.finalize().into()
}

fn insert_transaction_status_observation(
    transaction: &Transaction<'_>,
    request_id: [u8; 16],
    observation: &StoredTransactionStatusObservation,
) -> Result<()> {
    validate_stored_transaction_status_observation(observation)?;
    let observation_key = transaction_status_observation_key(request_id, observation);
    let record_digest = transaction_status_observation_digest(observation_key, observation);
    transaction
        .execute(
            "INSERT INTO eth_transaction_status_observations (
                observation_key, request_id, tx_hash, source_hash, status,
                included_block_number, included_block_hash,
                latest_head_number, latest_head_hash, safe_head_number, safe_head_hash,
                finalized_head_number, finalized_head_hash, observed_at_unix, record_digest
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             )",
            rusqlite::params![
                observation_key.as_slice(),
                request_id.as_slice(),
                observation.tx_hash.as_slice(),
                observation.source_hash.as_slice(),
                observation.status.wire(),
                observation.included_block_number.unwrap_or(0).to_string(),
                observation
                    .included_block_hash
                    .unwrap_or([0; 32])
                    .as_slice(),
                observation.latest_head_number.to_string(),
                observation.latest_head_hash.as_slice(),
                observation.safe_head_number.to_string(),
                observation.safe_head_hash.as_slice(),
                observation.finalized_head_number.to_string(),
                observation.finalized_head_hash.as_slice(),
                observation.observed_at_unix.to_string(),
                record_digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

pub(crate) fn read_latest_transaction_status_observation(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
) -> Result<Option<StoredTransactionStatusObservation>> {
    connection
        .query_row(
            "SELECT request_id, tx_hash, source_hash, status,
                    included_block_number, included_block_hash,
                    latest_head_number, latest_head_hash, safe_head_number, safe_head_hash,
                    finalized_head_number, finalized_head_hash, observed_at_unix,
                    observation_key, record_digest
               FROM eth_transaction_status_observations
              WHERE tx_hash = ?1
              -- rowid is the durable receive sequence. `observed_at_unix` is
              -- intentionally host supplied for display and can move when a
              -- device clock is corrected, so it cannot choose the latest.
              ORDER BY rowid DESC
              LIMIT 1",
            [tx_hash.as_slice()],
            read_transaction_status_row,
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .map(validate_transaction_status_row)
        .transpose()
}

/// Returns whether active exact-receipt work still prevents scheduling a new
/// request. A previously settled, still-pending request has no manifest or
/// retained proof bytes, so a newer eligible finalized-status report can
/// retire it and issue a new bounded request. This covers a receipt request
/// that reached the service before the transaction was final without treating
/// its old transport acknowledgement as a confirmation.
fn supersede_settled_pending_finalized_receipt_request(
    connection: &Transaction<'_>,
    tx_hash: [u8; 32],
    expected_gateway_source_hash: [u8; 16],
    now_unix: u64,
) -> Result<bool> {
    let mut statement = connection
        .prepare(
            "SELECT request_id FROM eth_message_requests
              WHERE operation_kind = ?1 AND evidence_kind = ?2
                AND subject = ?3 AND expected_gateway_source_hash = ?4
                AND status IN (?5, ?6, ?7, ?8)
              ORDER BY rowid",
        )
        .map_err(NodeStoreError::sqlite)?;
    let identifiers = statement
        .query_map(
            rusqlite::params![
                OperationKind::Evidence.as_i64(),
                MessagingEvidenceKind::FinalizedReceiptPackage.wire(),
                tx_hash.as_slice(),
                expected_gateway_source_hash.as_slice(),
                MessageRequestStatus::Pending.as_i64(),
                MessageRequestStatus::AwaitingBulkApproval.as_i64(),
                MessageRequestStatus::Ready.as_i64(),
                MessageRequestStatus::PendingVerification.as_i64(),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(NodeStoreError::sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(NodeStoreError::sqlite)?;
    drop(statement);
    for identifier in identifiers {
        let record = read_request(
            connection,
            stored_array(&identifier, "active finalized receipt request identifier")?,
        )?
        .ok_or_else(|| NodeStoreError::new("active finalized receipt request disappeared"))?;
        if record.operation != OperationKind::Evidence
            || record.evidence_kind != Some(MessagingEvidenceKind::FinalizedReceiptPackage)
            || record.subject != tx_hash
            || record.expected_gateway_source_hash != expected_gateway_source_hash
        {
            return Err(NodeStoreError::new(
                "active finalized receipt request changed during query",
            ));
        }
        match record.status {
            MessageRequestStatus::PendingVerification => return Ok(true),
            MessageRequestStatus::Pending if record.expires_at_unix > now_unix => {
                if record.manifest_digest.is_some() || record.manifest_size.is_some() {
                    return Err(NodeStoreError::new(
                        "pending finalized receipt request has a manifest",
                    ));
                }
                let kind = OutboundMessageKind::EvidenceRequest;
                let Some(row) = read_outbox_row(connection, record.request_id, kind)? else {
                    // It has not reached the local outbound ledger yet, so it
                    // is still fresh work rather than a stale service handoff.
                    return Ok(true);
                };
                let attachment = reconstruct_outbound_attachment_exact(connection, &record, kind)?;
                let attachment_digest: [u8; 32] = Sha256::digest(&attachment).into();
                let binding = OutboundMessageBinding::new(
                    row.gateway_destination_hash,
                    row.local_source_hash,
                    row.identity_session_generation,
                )?;
                validate_outbox_row(&row, record.request_id, kind, &binding, attachment_digest)?;
                if row.state == OUTBOUND_SETTLED {
                    let mut cancelled = record;
                    cancelled.status = MessageRequestStatus::Cancelled;
                    update_request(connection, &cancelled)?;
                    continue;
                }
                return Ok(true);
            }
            MessageRequestStatus::AwaitingBulkApproval | MessageRequestStatus::Ready
                if record.expires_at_unix > now_unix =>
            {
                return Ok(true);
            }
            MessageRequestStatus::Pending
            | MessageRequestStatus::AwaitingBulkApproval
            | MessageRequestStatus::Ready => {}
            _ => {
                return Err(NodeStoreError::new(
                    "active finalized receipt request has an invalid status",
                ));
            }
        }
    }
    Ok(false)
}

fn read_transaction_status_by_request(
    connection: &rusqlite::Connection,
    request_id: [u8; 16],
) -> Result<Option<StoredTransactionStatusObservation>> {
    connection
        .query_row(
            "SELECT request_id, tx_hash, source_hash, status,
                    included_block_number, included_block_hash,
                    latest_head_number, latest_head_hash, safe_head_number, safe_head_hash,
                    finalized_head_number, finalized_head_hash, observed_at_unix,
                    observation_key, record_digest
               FROM eth_transaction_status_observations WHERE request_id = ?1",
            [request_id.as_slice()],
            read_transaction_status_row,
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .map(validate_transaction_status_row)
        .transpose()
}

fn read_transaction_status_history_view(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
) -> Result<Option<TransactionStatusHistoryView>> {
    let identifiers = recent_transaction_status_request_ids(connection, tx_hash, 1)?;
    let Some(latest_id) = identifiers.first().copied() else {
        return Ok(None);
    };
    let latest = read_transaction_status_by_request(connection, latest_id)?
        .ok_or_else(|| NodeStoreError::new("latest transaction status observation disappeared"))?;
    if latest.tx_hash != tx_hash {
        return Err(NodeStoreError::new(
            "latest transaction status observation transaction changed",
        ));
    }
    // Reports from different authenticated services must not be compared as
    // one continuous chain. Find the nearest predecessor from this exact
    // source for continuity, and independently retain its nearest inclusion
    // for the application when a report temporarily loses an inclusion.
    let prior_same_source = latest_transaction_status_before_current(
        connection,
        tx_hash,
        latest.source_hash,
        latest_id,
    )?;
    let prior_included =
        latest_included_before_current(connection, tx_hash, latest.source_hash, latest_id)?;
    let continuity =
        transaction_status_continuity(&latest, prior_same_source.as_ref(), prior_included.as_ref());
    Ok(Some(TransactionStatusHistoryView {
        latest,
        previous_inclusion: prior_included,
        continuity,
    }))
}

fn recent_transaction_status_request_ids(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
    limit: i64,
) -> Result<Vec<[u8; 16]>> {
    if limit <= 0 || limit > 2 {
        return Err(NodeStoreError::new(
            "invalid transaction status history bound",
        ));
    }
    let mut statement = connection
        .prepare(
            "SELECT request_id FROM eth_transaction_status_observations
              WHERE tx_hash = ?1 ORDER BY rowid DESC LIMIT ?2",
        )
        .map_err(NodeStoreError::sqlite)?;
    statement
        .query_map(rusqlite::params![tx_hash.as_slice(), limit], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(NodeStoreError::sqlite)?
        .map(|value| {
            stored_array(
                &value.map_err(NodeStoreError::sqlite)?,
                "transaction status history request identifier",
            )
        })
        .collect()
}

fn latest_included_before_current(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
    source_hash: [u8; 16],
    latest_request_id: [u8; 16],
) -> Result<Option<StoredTransactionStatusObservation>> {
    let observation = latest_transaction_status_before_current_with_status(
        connection,
        tx_hash,
        source_hash,
        latest_request_id,
        Some(TransactionStatus::Included),
    )?;
    if observation.as_ref().is_some_and(|value| {
        value.tx_hash != tx_hash
            || value.source_hash != source_hash
            || value.status != TransactionStatus::Included
    }) {
        return Err(NodeStoreError::new(
            "prior included transaction status observation changed",
        ));
    }
    Ok(observation)
}

fn latest_transaction_status_before_current(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
    source_hash: [u8; 16],
    latest_request_id: [u8; 16],
) -> Result<Option<StoredTransactionStatusObservation>> {
    let observation = latest_transaction_status_before_current_with_status(
        connection,
        tx_hash,
        source_hash,
        latest_request_id,
        None,
    )?;
    if observation
        .as_ref()
        .is_some_and(|value| value.tx_hash != tx_hash || value.source_hash != source_hash)
    {
        return Err(NodeStoreError::new(
            "prior transaction status observation changed",
        ));
    }
    Ok(observation)
}

fn latest_transaction_status_before_current_with_status(
    connection: &rusqlite::Connection,
    tx_hash: [u8; 32],
    source_hash: [u8; 16],
    latest_request_id: [u8; 16],
    status: Option<TransactionStatus>,
) -> Result<Option<StoredTransactionStatusObservation>> {
    let status_sql = status.map(TransactionStatus::wire);
    let request_id = connection
        .query_row(
            "SELECT request_id FROM eth_transaction_status_observations
              WHERE tx_hash = ?1 AND source_hash = ?2 AND request_id != ?3
                AND (?4 IS NULL OR status = ?4)
              ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![
                tx_hash.as_slice(),
                source_hash.as_slice(),
                latest_request_id.as_slice(),
                status_sql,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .map(|value| stored_array::<16>(&value, "prior included status request identifier"))
        .transpose()?;
    request_id
        .map(|request_id| {
            read_transaction_status_by_request(connection, request_id)?.ok_or_else(|| {
                NodeStoreError::new("prior transaction status observation disappeared")
            })
        })
        .transpose()
}

fn transaction_status_continuity(
    latest: &StoredTransactionStatusObservation,
    previous: Option<&StoredTransactionStatusObservation>,
    prior_included: Option<&StoredTransactionStatusObservation>,
) -> TransactionStatusContinuity {
    let Some(previous) = previous else {
        return TransactionStatusContinuity::FirstObservation;
    };
    if transaction_status_heads_are_inconsistent(latest, previous) {
        return TransactionStatusContinuity::Inconsistent;
    }
    match latest.status {
        TransactionStatus::Included => match previous.status {
            TransactionStatus::Included
                if latest.included_block_number == previous.included_block_number
                    && latest.included_block_hash == previous.included_block_hash =>
            {
                TransactionStatusContinuity::StillIncluded
            }
            TransactionStatus::Included => TransactionStatusContinuity::IncludedMoved,
            TransactionStatus::NotSeen | TransactionStatus::Pending => {
                if prior_included.is_some() {
                    TransactionStatusContinuity::Reincluded
                } else {
                    TransactionStatusContinuity::StatusChanged
                }
            }
        },
        TransactionStatus::NotSeen | TransactionStatus::Pending => {
            if prior_included.is_some() {
                TransactionStatusContinuity::AwaitingReinclusion
            } else {
                TransactionStatusContinuity::StatusChanged
            }
        }
    }
}

fn transaction_status_heads_are_inconsistent(
    latest: &StoredTransactionStatusObservation,
    previous: &StoredTransactionStatusObservation,
) -> bool {
    latest.finalized_head_number < previous.finalized_head_number
        || (latest.finalized_head_number == previous.finalized_head_number
            && latest.finalized_head_hash != previous.finalized_head_hash)
        || latest.safe_head_number < previous.finalized_head_number
        || latest.latest_head_number < previous.finalized_head_number
}

type TransactionStatusRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    u8,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
);

fn read_transaction_status_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransactionStatusRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
    ))
}

fn validate_transaction_status_row(
    row: TransactionStatusRow,
) -> Result<StoredTransactionStatusObservation> {
    let request_id = stored_array::<16>(&row.0, "transaction status request identifier")?;
    let observation = StoredTransactionStatusObservation {
        tx_hash: stored_array(&row.1, "transaction status transaction hash")?,
        source_hash: stored_array(&row.2, "transaction status source hash")?,
        status: TransactionStatus::from_wire(row.3)?,
        included_block_number: match parse_stored_u64(&row.4, "included block number")? {
            0 => None,
            value => Some(value),
        },
        included_block_hash: match stored_array::<32>(&row.5, "included block hash")? {
            value if value == [0; 32] => None,
            value => Some(value),
        },
        latest_head_number: parse_stored_u64(&row.6, "latest head number")?,
        latest_head_hash: stored_array(&row.7, "latest head hash")?,
        safe_head_number: parse_stored_u64(&row.8, "safe head number")?,
        safe_head_hash: stored_array(&row.9, "safe head hash")?,
        finalized_head_number: parse_stored_u64(&row.10, "finalized head number")?,
        finalized_head_hash: stored_array(&row.11, "finalized head hash")?,
        observed_at_unix: parse_stored_u64(&row.12, "transaction status observation time")?,
    };
    validate_stored_transaction_status_observation(&observation)?;
    let key = stored_array::<32>(&row.13, "transaction status observation key")?;
    let digest = stored_array::<32>(&row.14, "transaction status record digest")?;
    if key != transaction_status_observation_key(request_id, &observation)
        || digest != transaction_status_observation_digest(key, &observation)
    {
        return Err(NodeStoreError::new(
            "stored transaction status observation digest does not match its values",
        ));
    }
    Ok(observation)
}

fn validate_stored_transaction_status_observation(
    observation: &StoredTransactionStatusObservation,
) -> Result<()> {
    let wire = TransactionStatusWireObservation {
        request_id: [1; 16],
        tx_hash: observation.tx_hash,
        status: observation.status,
        included_block_number: observation.included_block_number.unwrap_or(0),
        included_block_hash: observation.included_block_hash.unwrap_or([0; 32]),
        latest_head_number: observation.latest_head_number,
        latest_head_hash: observation.latest_head_hash,
        safe_head_number: observation.safe_head_number,
        safe_head_hash: observation.safe_head_hash,
        finalized_head_number: observation.finalized_head_number,
        finalized_head_hash: observation.finalized_head_hash,
    };
    wire.validate()?;
    if observation.source_hash == [0; 16] || observation.observed_at_unix == 0 {
        return Err(NodeStoreError::new(
            "invalid local transaction status observation",
        ));
    }
    Ok(())
}

fn transaction_status_matches_wire(
    stored: &StoredTransactionStatusObservation,
    source_hash: [u8; 16],
    wire: TransactionStatusWireObservation,
) -> bool {
    stored.tx_hash == wire.tx_hash
        && stored.source_hash == source_hash
        && stored.status == wire.status
        && stored.included_block_number
            == (wire.status == TransactionStatus::Included).then_some(wire.included_block_number)
        && stored.included_block_hash
            == (wire.status == TransactionStatus::Included).then_some(wire.included_block_hash)
        && stored.latest_head_number == wire.latest_head_number
        && stored.latest_head_hash == wire.latest_head_hash
        && stored.safe_head_number == wire.safe_head_number
        && stored.safe_head_hash == wire.safe_head_hash
        && stored.finalized_head_number == wire.finalized_head_number
        && stored.finalized_head_hash == wire.finalized_head_hash
}

fn transaction_status_observation_key(
    request_id: [u8; 16],
    observation: &StoredTransactionStatusObservation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-transaction-status-observation-v1");
    hasher.update(request_id);
    hasher.update(observation.tx_hash);
    hasher.update(observation.source_hash);
    hasher.update([observation.status.wire()]);
    hasher.update(observation.included_block_number.unwrap_or(0).to_le_bytes());
    hasher.update(observation.included_block_hash.unwrap_or([0; 32]));
    hasher.update(observation.latest_head_number.to_le_bytes());
    hasher.update(observation.latest_head_hash);
    hasher.update(observation.safe_head_number.to_le_bytes());
    hasher.update(observation.safe_head_hash);
    hasher.update(observation.finalized_head_number.to_le_bytes());
    hasher.update(observation.finalized_head_hash);
    hasher.finalize().into()
}

fn transaction_status_observation_digest(
    observation_key: [u8; 32],
    observation: &StoredTransactionStatusObservation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-transaction-status-record-v1");
    hasher.update(observation_key);
    hasher.update(observation.observed_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn request_checkpoint_context_is_valid(record: &RequestRecord) -> bool {
    let composite = matches!(
        record.evidence_kind,
        Some(
            MessagingEvidenceKind::AccountStatePackage
                | MessagingEvidenceKind::FinalizedReceiptPackage
        )
    );
    composite == record.checkpoint_context.is_some()
        && record
            .checkpoint_context
            .is_none_or(CheckpointRequestContext::is_valid)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| NodeStoreError::new("invalid Ethereum gateway message"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| NodeStoreError::new("truncated Ethereum gateway message"))?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| NodeStoreError::new("invalid Ethereum gateway field width"))
    }
    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(NodeStoreError::new(
                "trailing Ethereum gateway message bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::TransactionAssurance;
    use crate::transaction::test_support::{
        signed_fixture, signed_fixture_for_chain_with_nonce,
    };

    const REAL_CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];
    const CONSENSUS_CHECKPOINT_ROOT: [u8; 32] = REAL_CHECKPOINT_ROOT;
    const CONSENSUS_NOW: u64 = 1_788_034_160;

    fn real_consensus_bundle() -> Vec<u8> {
        consensus_bundle_at(0)
    }

    fn consensus_bundle() -> Vec<u8> {
        consensus_bundle_at(CONSENSUS_NOW)
    }

    fn consensus_bundle_at(created_at_unix: u64) -> Vec<u8> {
        let bootstrap = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/\
                     sepolia-bootstrap-343888.ssz.b64"
                )
                .trim(),
            )
            .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        bytes.push(ratspeak_eth_verifier::VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(ratspeak_eth_verifier::KIND_PINNED_CONSENSUS_BOOTSTRAP);
        bytes.extend_from_slice(&created_at_unix.to_le_bytes());
        bytes.extend_from_slice(&(bootstrap.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&bootstrap);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.push(0);
        bytes
    }

    fn receipt_bundle() -> (Vec<u8>, [u8; 32]) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/\
                     sepolia-receipt-11574048-0.rseth.b64"
                )
                .trim(),
            )
            .unwrap();
        let parsed = Verifier::sepolia().parse_tx_receipt_proof(&bytes).unwrap();
        (bytes, parsed.tx_hash)
    }

    fn finalized_receipt_bundle_at_anchor() -> (Vec<u8>, [u8; 32]) {
        let (receipt, tx_hash) = receipt_bundle();
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(&receipt)
            .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        bytes.push(ratspeak_eth_verifier::VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(ratspeak_eth_verifier::KIND_FINALIZED_TX_RECEIPT_PROOF);
        bytes.extend_from_slice(&parsed.created_at_unix.to_le_bytes());
        bytes.extend_from_slice(&parsed.block_number.to_le_bytes());
        bytes.extend_from_slice(&parsed.block_hash);
        bytes.extend_from_slice(&parsed.block_number.to_le_bytes());
        bytes.extend_from_slice(&parsed.block_hash);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&(receipt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&receipt);
        (bytes, tx_hash)
    }

    fn finalized_receipt_package() -> (Vec<u8>, Vec<u8>, [u8; 32], u64) {
        let verifier = Verifier::sepolia();
        let consensus = real_consensus_bundle();
        let execution = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/\
                     sepolia-execution-header-11574048.rseth.b64"
                )
                .trim(),
            )
            .unwrap();
        let (finalized, tx_hash) = finalized_receipt_bundle_at_anchor();
        let receipt = verifier
            .parse_finalized_tx_receipt_proof(&finalized)
            .unwrap();
        let package = verifier
            .build_finalized_receipt_evidence(1_800_000_000, &consensus, &execution, &finalized)
            .unwrap();
        let header = verifier
            .reverify_historical_consensus_bootstrap(
                &consensus,
                &BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
            )
            .unwrap();
        let finalized_at =
            ratspeak_eth_verifier::sepolia_slot_start_unix(header.finalized_slot()).unwrap();
        (package, receipt.receipt_proof.raw_tx, tx_hash, finalized_at)
    }

    fn gzip_stored_blocks(inner: &[u8]) -> Vec<u8> {
        let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        let chunks = inner.chunks(u16::MAX as usize).collect::<Vec<_>>();
        for (index, chunk) in chunks.iter().enumerate() {
            gzip.push(u8::from(index + 1 == chunks.len()));
            let len = u16::try_from(chunk.len()).unwrap();
            gzip.extend_from_slice(&len.to_le_bytes());
            gzip.extend_from_slice(&(!len).to_le_bytes());
            gzip.extend_from_slice(chunk);
        }
        let mut crc = 0xffff_ffff_u32;
        for byte in inner {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
        }
        gzip.extend_from_slice(&(!crc).to_le_bytes());
        gzip.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        gzip
    }

    fn compressed_bundle(inner: &[u8]) -> Vec<u8> {
        let compressed = gzip_stored_blocks(inner);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        bytes.push(ratspeak_eth_verifier::VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(11); // canonical compressed-bundle kind
        bytes.extend_from_slice(&1_800_000_001_u64.to_le_bytes());
        bytes.push(1); // gzip
        bytes.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        bytes.extend_from_slice(Sha256::digest(inner).as_slice());
        bytes.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&compressed);
        bytes
    }

    fn synthetic_parseable_account_package(address: [u8; 20]) -> Vec<u8> {
        // Parser-only seam. The deliberately synthetic trie node is never
        // claimed as verified state; this helper exercises the node's exact
        // request/wallet subject rejection before authoritative import.
        let mut account = Vec::new();
        account.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        account.push(ratspeak_eth_verifier::VERSION);
        account.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        account.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        account.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        account.push(3); // canonical account-proof kind
        account.extend_from_slice(&0_u64.to_le_bytes());
        account.extend_from_slice(&1_u64.to_le_bytes());
        account.extend_from_slice(&[0x11; 32]);
        account.extend_from_slice(&[0x22; 32]);
        account.extend_from_slice(&address);
        account.extend_from_slice(&[0; 32]);
        account.extend_from_slice(&0_u64.to_le_bytes());
        account.extend_from_slice(&[0x33; 32]);
        account.extend_from_slice(&[0x44; 32]);
        account.extend_from_slice(&1_u32.to_le_bytes());
        account.extend_from_slice(&1_u32.to_le_bytes());
        account.push(0x80);

        let execution = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/\
                     sepolia-execution-header-11574048.rseth.b64"
                )
                .trim(),
            )
            .unwrap();
        Verifier::sepolia()
            .build_account_state_evidence(
                1_800_000_000,
                &real_consensus_bundle(),
                &execution,
                &account,
            )
            .unwrap()
    }

    fn insert_composite_request(
        store: &mut EthereumNodeStore,
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        subject: [u8; 32],
        maximum_response_bytes: u32,
        now_unix: u64,
    ) -> CheckpointRequestContext {
        let approval = store.latest_checkpoint_approval().unwrap().unwrap();
        let context = CheckpointRequestContext {
            checkpoint_epoch: approval.checkpoint_epoch(),
            checkpoint_root: approval.checkpoint_root(),
        };
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        insert_planned_package_request(
            &transaction,
            request_id,
            [0x44; 16],
            kind,
            subject,
            context,
            maximum_response_bytes,
            now_unix,
            now_unix + 600,
            now_unix,
        )
        .unwrap();
        transaction.commit().unwrap();
        context
    }

    fn contextual_manifest(
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        context: CheckpointRequestContext,
        digest: [u8; 32],
        size: u32,
    ) -> Vec<u8> {
        let mut out = prelude(KIND_EVIDENCE_MANIFEST);
        out.extend_from_slice(&request_id);
        out.push(kind.wire());
        out.extend_from_slice(&context.checkpoint_epoch.to_le_bytes());
        out.extend_from_slice(&context.checkpoint_root);
        out.extend_from_slice(&digest);
        out.extend_from_slice(&size.to_le_bytes());
        out
    }

    fn contextual_evidence(
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        context: CheckpointRequestContext,
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = prelude(KIND_EVIDENCE_RESPONSE);
        out.extend_from_slice(&request_id);
        out.push(kind.wire());
        out.extend_from_slice(&context.checkpoint_epoch.to_le_bytes());
        out.extend_from_slice(&context.checkpoint_root);
        out.extend_from_slice(&digest);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    fn retain_composite_response(
        store: &mut EthereumNodeStore,
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        context: CheckpointRequestContext,
        bytes: &[u8],
        now_unix: u64,
    ) {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let size = u32::try_from(bytes.len()).unwrap();
        let manifest = contextual_manifest(request_id, kind, context, digest, size);
        let outcome = store
            .handle_attachment_from_trusted_lxmf_adapter(
                [0x44; 16], [0x44; 16], &manifest, now_unix,
            )
            .unwrap();
        if matches!(outcome, NodeMessageOutcome::BulkApprovalRequired(_)) {
            store
                .approve_bulk_evidence(request_id, digest, size, now_unix + 1)
                .unwrap();
        }
        let response = contextual_evidence(request_id, kind, context, digest, bytes);
        assert!(matches!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(
                    [0x44; 16],
                    [0x44; 16],
                    &response,
                    now_unix + 2,
                )
                .unwrap(),
            NodeMessageOutcome::EvidencePending(_)
        ));
    }

    #[test]
    fn delayed_receipt_import_reverifies_its_historical_checkpoint_after_advancement() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let verifier = Verifier::sepolia();
        let consensus_bytes = real_consensus_bundle();
        let provisional = verifier
            .reverify_historical_consensus_bootstrap(
                &consensus_bytes,
                &BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
            )
            .unwrap();
        let finalized_at =
            ratspeak_eth_verifier::sepolia_slot_start_unix(provisional.finalized_slot()).unwrap();
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            REAL_CHECKPOINT_ROOT,
            finalized_at,
        );
        let consensus = verifier
            .verify_consensus_bootstrap_at_unix(
                &consensus_bytes,
                &BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
                finalized_at,
            )
            .unwrap();
        store
            .record_verified_finalized_header(&consensus, &consensus_bytes)
            .unwrap();

        let after_advancement = finalized_at + 32 * 12;
        crate::bootstrap::install_test_active_checkpoint(&mut store, [0x72; 32], after_advancement);
        let stored = crate::consensus::read_finalized_header_by_proof_hash(
            &store.connection,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            consensus.proof_bundle_hash(),
        )
        .unwrap()
        .unwrap();
        assert!(reverify_consensus(&store, &verifier, &stored, after_advancement).is_err());
        reverify_historical_consensus(&store, &verifier, &stored, after_advancement).unwrap();
    }

    fn manifest(
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        digest: [u8; 32],
        size: u32,
    ) -> Vec<u8> {
        let mut out = prelude(KIND_EVIDENCE_MANIFEST);
        out.extend_from_slice(&request_id);
        out.push(kind.wire());
        out.extend_from_slice(&digest);
        out.extend_from_slice(&size.to_le_bytes());
        out
    }

    fn evidence(
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = prelude(KIND_EVIDENCE_RESPONSE);
        out.extend_from_slice(&request_id);
        out.push(kind.wire());
        out.extend_from_slice(&digest);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    fn observation(request_id: [u8; 16], tx_hash: [u8; 32], value: RelayObservation) -> Vec<u8> {
        let mut out = prelude(KIND_RELAY_OBSERVATION);
        out.extend_from_slice(&request_id);
        out.extend_from_slice(&tx_hash);
        out.push(value.wire());
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn transaction_status_observation(
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        status: TransactionStatus,
        included_number: u64,
        included_hash: [u8; 32],
        latest_number: u64,
        latest_hash: [u8; 32],
        safe_number: u64,
        safe_hash: [u8; 32],
        finalized_number: u64,
        finalized_hash: [u8; 32],
    ) -> Vec<u8> {
        let mut out = prelude(KIND_TRANSACTION_STATUS_OBSERVATION);
        out.extend_from_slice(&request_id);
        out.extend_from_slice(&tx_hash);
        out.push(status.wire());
        out.extend_from_slice(&included_number.to_le_bytes());
        out.extend_from_slice(&included_hash);
        for (number, hash) in [
            (latest_number, latest_hash),
            (safe_number, safe_hash),
            (finalized_number, finalized_hash),
        ] {
            out.extend_from_slice(&number.to_le_bytes());
            out.extend_from_slice(&hash);
        }
        assert_eq!(out.len(), TRANSACTION_STATUS_RESPONSE_BYTES as usize);
        out
    }

    // This fixture mirrors the fixed status-observation wire fields; keeping
    // them named at call sites makes adversarial test mutations easy to audit.
    #[allow(clippy::too_many_arguments)]
    fn persist_transaction_status(
        store: &mut EthereumNodeStore,
        gateway: [u8; 16],
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        status: TransactionStatus,
        included_number: u64,
        included_hash: [u8; 32],
        finalized_number: u64,
        finalized_hash: [u8; 32],
        observed_at_unix: u64,
    ) {
        store
            .create_transaction_status_request(OutboundTransactionStatusRequest::new(
                request_id,
                gateway,
                tx_hash,
                observed_at_unix.saturating_sub(1).max(1),
                observed_at_unix + 100,
            ))
            .unwrap();
        let safe_number = finalized_number.max(included_number.saturating_sub(1)) + 1;
        let latest_number = safe_number.max(included_number) + 1;
        let attachment = transaction_status_observation(
            request_id,
            tx_hash,
            status,
            included_number,
            included_hash,
            latest_number,
            [finalized_hash[0].wrapping_add(2); 32],
            safe_number,
            [finalized_hash[0].wrapping_add(1); 32],
            finalized_number,
            finalized_hash,
        );
        store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &attachment),
                observed_at_unix,
            )
            .unwrap();
    }

    fn service_failure(request_id: [u8; 16], attachment_digest: [u8; 32]) -> Vec<u8> {
        let mut out = prelude(KIND_SERVICE_FAILURE);
        out.extend_from_slice(&request_id);
        out.extend_from_slice(&attachment_digest);
        out
    }

    #[test]
    fn authenticated_service_failure_is_exact_bound_terminal_and_restart_safe() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0xb1; 16];
        let source = [0xb2; 16];
        let request_id = [0xb3; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 9).unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let attachment = store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xb4; 32],
                1024,
                100,
                300,
            ))
            .unwrap();
        let lease = store
            .lease_next_outbound_message(binding, 101, 10)
            .unwrap()
            .unwrap();
        store
            .settle_outbound_message_queued(binding, &lease, 102)
            .unwrap();
        let digest: [u8; 32] = Sha256::digest(&attachment).into();

        let wrong = service_failure(request_id, [0xff; 32]);
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &wrong),
                    103,
                )
                .is_err()
        );
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Pending)
        );

        let exact = service_failure(request_id, digest);
        assert_eq!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &exact),
                    104,
                )
                .unwrap(),
            NodeMessageOutcome::ServiceFailed
        );
        assert_eq!(store.pending_message_evidence(request_id).unwrap(), None);
        assert_eq!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &exact),
                    105,
                )
                .unwrap(),
            NodeMessageOutcome::Duplicate
        );
        drop(store);

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Cancelled)
        );
        assert_eq!(reopened.pending_message_evidence(request_id).unwrap(), None);
    }

    #[test]
    fn authentication_precedes_parsing_and_source_hash_is_exactly_sixteen_bytes() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let request_id = [1; 16];
        let gateway = [2; 16];
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [3; 32],
                1000,
                100,
                200,
            ))
            .unwrap();

        for envelope in [
            AuthenticatedNodeEnvelope::new(false, gateway, b"not a message"),
            AuthenticatedNodeEnvelope::new(true, [4; 16], b"not a message"),
        ] {
            assert_eq!(
                store
                    .handle_gateway_attachment(gateway, envelope, 120)
                    .unwrap(),
                NodeMessageOutcome::IgnoredUnauthenticated
            );
        }
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Pending)
        );
        let unknown = manifest(
            [0xaa; 16],
            MessagingEvidenceKind::ReceiptProof,
            [0xbb; 32],
            100,
        );
        assert_eq!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &unknown),
                    121,
                )
                .unwrap(),
            NodeMessageOutcome::IgnoredUnauthenticated
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE eth_message_requests
                     SET expected_gateway_source_hash = ?2 WHERE request_id = ?1",
                    rusqlite::params![request_id.as_slice(), [9_u8; 15].as_slice()],
                )
                .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE eth_message_requests SET status = 2 WHERE request_id = ?1",
                [request_id.as_slice()],
            )
            .unwrap();
        assert!(store.message_request_status(request_id).is_err());
    }

    #[test]
    fn consensus_delivery_requires_local_checkpoint_and_imports_after_bulk_approval() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0x42; 16];
        let request_id = [0x43; 16];
        let bytes = consensus_bundle();
        let request = || {
            OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::Consensus,
                CONSENSUS_CHECKPOINT_ROOT,
                bytes.len() as u32,
                CONSENSUS_NOW,
                CONSENSUS_NOW + 600,
            )
        };

        assert!(
            store
                .create_evidence_request_at(request(), CONSENSUS_NOW)
                .unwrap_err()
                .to_string()
                .contains("no policy-approved checkpoint")
        );
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            CONSENSUS_CHECKPOINT_ROOT,
            CONSENSUS_NOW,
        );
        let stale = OutboundEvidenceRequest::new(
            [0x45; 16],
            gateway,
            MessagingEvidenceKind::Consensus,
            CONSENSUS_CHECKPOINT_ROOT,
            bytes.len() as u32,
            CONSENSUS_NOW - MAX_CONSENSUS_REQUEST_CLOCK_SKEW_SECONDS - 1,
            CONSENSUS_NOW + 600,
        );
        assert!(
            store
                .create_evidence_request_at(stale, CONSENSUS_NOW)
                .unwrap_err()
                .to_string()
                .contains("trusted local clock")
        );
        let wrong = OutboundEvidenceRequest::new(
            [0x44; 16],
            gateway,
            MessagingEvidenceKind::Consensus,
            [0x99; 32],
            bytes.len() as u32,
            CONSENSUS_NOW,
            CONSENSUS_NOW + 600,
        );
        assert!(
            store
                .create_evidence_request_at(wrong, CONSENSUS_NOW)
                .is_err()
        );
        store
            .create_evidence_request_at(request(), CONSENSUS_NOW)
            .unwrap();

        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let advertised = manifest(
            request_id,
            MessagingEvidenceKind::Consensus,
            digest,
            bytes.len() as u32,
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    CONSENSUS_NOW + 1,
                )
                .unwrap(),
            NodeMessageOutcome::BulkApprovalRequired(_)
        ));
        store
            .approve_bulk_evidence(request_id, digest, bytes.len() as u32, CONSENSUS_NOW + 2)
            .unwrap();
        let response = evidence(request_id, MessagingEvidenceKind::Consensus, digest, &bytes);
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &response),
                    CONSENSUS_NOW + 3,
                )
                .unwrap(),
            NodeMessageOutcome::EvidencePending(_)
        ));
        assert_eq!(
            store
                .process_pending_message_evidence_at(request_id, CONSENSUS_NOW + 4)
                .unwrap(),
            PendingEvidenceImportOutcome::Imported
        );
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Completed)
        );
        let header = store
            .latest_finalized_header(SEPOLIA_CHAIN_ID)
            .unwrap()
            .unwrap();
        assert_eq!(header.checkpoint_root(), CONSENSUS_CHECKPOINT_ROOT);
        drop(store);

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened
                .process_pending_message_evidence_at(request_id, CONSENSUS_NOW + 5)
                .unwrap(),
            PendingEvidenceImportOutcome::AlreadyCompleted
        );
        assert!(matches!(
            reopened
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &response),
                    CONSENSUS_NOW + 6,
                )
                .unwrap(),
            NodeMessageOutcome::Duplicate
        ));
    }

    #[test]
    fn revoked_checkpoint_blocks_pending_consensus_before_verification() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0x52; 16];
        let request_id = [0x53; 16];
        let bytes = consensus_bundle();
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            CONSENSUS_CHECKPOINT_ROOT,
            CONSENSUS_NOW,
        );
        store
            .create_evidence_request_at(
                OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::Consensus,
                    CONSENSUS_CHECKPOINT_ROOT,
                    bytes.len() as u32,
                    CONSENSUS_NOW,
                    CONSENSUS_NOW + 600,
                ),
                CONSENSUS_NOW,
            )
            .unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        store
            .approve_bulk_evidence(request_id, digest, bytes.len() as u32, CONSENSUS_NOW + 1)
            .unwrap_err();
        let advertised = manifest(
            request_id,
            MessagingEvidenceKind::Consensus,
            digest,
            bytes.len() as u32,
        );
        store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                CONSENSUS_NOW + 1,
            )
            .unwrap();
        store
            .approve_bulk_evidence(request_id, digest, bytes.len() as u32, CONSENSUS_NOW + 2)
            .unwrap();
        let response = evidence(request_id, MessagingEvidenceKind::Consensus, digest, &bytes);
        store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &response),
                CONSENSUS_NOW + 3,
            )
            .unwrap();
        store
            .record_checkpoint_revocation(
                SEPOLIA_CHAIN_ID,
                CONSENSUS_CHECKPOINT_ROOT,
                [0x77; 32],
                CONSENSUS_NOW + 4,
            )
            .unwrap();
        assert!(
            store
                .process_pending_message_evidence_at(request_id, CONSENSUS_NOW + 5)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );
        assert!(
            store
                .pending_message_evidence(request_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn receipt_bytes_require_manifest_correlation_and_remain_unverified() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (bytes, tx_hash) = receipt_bundle();
        let request_id = [0x11; 16];
        let gateway = [0x22; 16];
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                tx_hash,
                bytes.len() as u32,
                100,
                300,
            ))
            .unwrap();
        let response = evidence(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            digest,
            &bytes,
        );
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &response),
                    110,
                )
                .unwrap_err()
                .to_string()
                .contains("approved manifest")
        );
        let advertised = manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            digest,
            bytes.len() as u32,
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    111,
                )
                .unwrap(),
            NodeMessageOutcome::ManifestAccepted(_)
        ));
        assert_eq!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    112,
                )
                .unwrap(),
            NodeMessageOutcome::Duplicate
        );
        let outcome = store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &response),
                113,
            )
            .unwrap();
        let NodeMessageOutcome::EvidencePending(correlated) = outcome else {
            panic!("expected durable pending evidence")
        };
        assert_eq!(correlated.bytes(), bytes);
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::PendingVerification)
        );
        assert!(
            store
                .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, tx_hash)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &response),
                    114,
                )
                .unwrap(),
            NodeMessageOutcome::EvidencePending(_)
        ));
        let mut conflict = response.clone();
        *conflict.last_mut().unwrap() ^= 1;
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &conflict),
                    115,
                )
                .is_err()
        );
    }

    #[test]
    fn pending_evidence_survives_restart_and_failed_import_without_loss() {
        let profile = tempfile::tempdir().unwrap();
        let (bytes, tx_hash) = finalized_receipt_bundle_at_anchor();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let request_id = [0x19; 16];
        let gateway = [0x29; 16];
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::ReceiptProof,
                    tx_hash,
                    bytes.len() as u32,
                    100,
                    200,
                ))
                .unwrap();
            for message in [
                manifest(
                    request_id,
                    MessagingEvidenceKind::ReceiptProof,
                    digest,
                    bytes.len() as u32,
                ),
                evidence(
                    request_id,
                    MessagingEvidenceKind::ReceiptProof,
                    digest,
                    &bytes,
                ),
            ] {
                store
                    .handle_gateway_attachment(
                        gateway,
                        AuthenticatedNodeEnvelope::new(true, gateway, &message),
                        110,
                    )
                    .unwrap();
            }
            assert!(
                store
                    .process_pending_message_evidence_at(request_id, 120)
                    .is_err()
            );
            assert_eq!(
                store.message_request_status(request_id).unwrap(),
                Some(MessageRequestStatus::PendingVerification)
            );
        }

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let pending = reopened
            .pending_message_evidence(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.bytes(), bytes);
        assert_eq!(pending.subject(), tx_hash);
        let duplicate = evidence(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            digest,
            &bytes,
        );
        assert!(matches!(
            reopened
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &duplicate),
                    150,
                )
                .unwrap(),
            NodeMessageOutcome::EvidencePending(_)
        ));
        assert!(
            reopened
                .process_pending_message_evidence_at(request_id, 151)
                .is_err()
        );
        assert!(
            reopened
                .pending_message_evidence(request_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn reordered_dependencies_retry_to_a_no_progress_fixed_point() {
        let mut consensus_ready = false;
        let mut execution_ready = false;
        let mut attempts = Vec::new();
        let (completed, failures) = retry_to_fixed_point(
            vec![
                MessagingEvidenceKind::ReceiptProof,
                MessagingEvidenceKind::ExecutionHeader,
                MessagingEvidenceKind::Consensus,
            ],
            |kind| {
                attempts.push(kind);
                match kind {
                    MessagingEvidenceKind::Consensus => {
                        consensus_ready = true;
                        Ok(())
                    }
                    MessagingEvidenceKind::ExecutionHeader if consensus_ready => {
                        execution_ready = true;
                        Ok(())
                    }
                    MessagingEvidenceKind::ReceiptProof if execution_ready => Ok(()),
                    _ => Err("dependency unavailable"),
                }
            },
        );
        assert_eq!(completed, 3);
        assert!(failures.is_empty());
        assert_eq!(
            attempts,
            [
                MessagingEvidenceKind::ReceiptProof,
                MessagingEvidenceKind::ExecutionHeader,
                MessagingEvidenceKind::Consensus,
                MessagingEvidenceKind::ReceiptProof,
                MessagingEvidenceKind::ExecutionHeader,
                MessagingEvidenceKind::ReceiptProof,
            ]
        );
    }

    #[test]
    fn corrupt_pending_blob_fails_closed_and_completion_is_atomic() {
        fn queued(profile: &std::path::Path, request_id: [u8; 16]) -> EthereumNodeStore {
            let (bytes, tx_hash) = receipt_bundle();
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let gateway = [0x39; 16];
            let mut store = EthereumNodeStore::open_in_profile(profile).unwrap();
            store
                .create_evidence_request(OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::ReceiptProof,
                    tx_hash,
                    bytes.len() as u32,
                    100,
                    200,
                ))
                .unwrap();
            for message in [
                manifest(
                    request_id,
                    MessagingEvidenceKind::ReceiptProof,
                    digest,
                    bytes.len() as u32,
                ),
                evidence(
                    request_id,
                    MessagingEvidenceKind::ReceiptProof,
                    digest,
                    &bytes,
                ),
            ] {
                store
                    .handle_gateway_attachment(
                        gateway,
                        AuthenticatedNodeEnvelope::new(true, gateway, &message),
                        110,
                    )
                    .unwrap();
            }
            store
        }

        let corrupt_profile = tempfile::tempdir().unwrap();
        let corrupt_id = [0x49; 16];
        let corrupt = queued(corrupt_profile.path(), corrupt_id);
        corrupt
            .connection
            .execute(
                "UPDATE eth_pending_message_evidence SET evidence_blob = x'00' WHERE request_id = ?1",
                [corrupt_id.as_slice()],
            )
            .unwrap();
        assert!(corrupt.pending_message_evidence(corrupt_id).is_err());
        assert_eq!(
            corrupt.message_request_status(corrupt_id).unwrap(),
            Some(MessageRequestStatus::PendingVerification)
        );

        let complete_profile = tempfile::tempdir().unwrap();
        let complete_id = [0x59; 16];
        let mut complete = queued(complete_profile.path(), complete_id);
        let pending = complete
            .pending_message_evidence(complete_id)
            .unwrap()
            .unwrap();
        complete_pending_evidence(&mut complete.connection, &pending).unwrap();
        assert_eq!(
            complete.message_request_status(complete_id).unwrap(),
            Some(MessageRequestStatus::Completed)
        );
        assert!(
            complete
                .pending_message_evidence(complete_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            complete
                .process_pending_message_evidence_at(complete_id, 120)
                .unwrap(),
            PendingEvidenceImportOutcome::AlreadyCompleted
        );
    }

    #[test]
    fn bulk_approval_cancellation_and_expiry_survive_restart() {
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0x31; 16];
        let expired_id = [0x32; 16];
        let cancelled_id = [0x33; 16];
        let gateway = [0x44; 16];
        let digest = [0x55; 32];
        let approved;
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::ReceiptProof,
                    [0x66; 32],
                    6000,
                    100,
                    300,
                ))
                .unwrap();
            let advertised = manifest(
                request_id,
                MessagingEvidenceKind::ReceiptProof,
                digest,
                5000,
            );
            assert!(matches!(
                store
                    .handle_gateway_attachment(
                        gateway,
                        AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                        110,
                    )
                    .unwrap(),
                NodeMessageOutcome::BulkApprovalRequired(_)
            ));
            approved = store
                .approve_bulk_evidence(request_id, digest, 5000, 111)
                .unwrap();
            assert_eq!(
                approved[MAGIC.len() + 1 + std::mem::size_of::<u64>()],
                KIND_BULK_APPROVAL
            );

            for (id, expires) in [(expired_id, 120), (cancelled_id, 300)] {
                store
                    .create_evidence_request(OutboundEvidenceRequest::new(
                        id,
                        gateway,
                        MessagingEvidenceKind::ReceiptProof,
                        [0x77; 32],
                        1000,
                        100,
                        expires,
                    ))
                    .unwrap();
            }
            let expired_manifest = manifest(
                expired_id,
                MessagingEvidenceKind::ReceiptProof,
                [0x88; 32],
                100,
            );
            assert!(
                store
                    .handle_gateway_attachment(
                        gateway,
                        AuthenticatedNodeEnvelope::new(true, gateway, &expired_manifest),
                        120,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("expired")
            );
            store.cancel_message_request(cancelled_id).unwrap();
        }
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            store
                .approve_bulk_evidence(request_id, digest, 5000, 112)
                .unwrap(),
            approved
        );
        assert!(
            store
                .approve_bulk_evidence(request_id, [0x54; 32], 5000, 113)
                .is_err()
        );
        assert!(
            store
                .approve_bulk_evidence(request_id, digest, 5001, 113)
                .is_err()
        );
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Ready)
        );
        assert_eq!(
            store.message_request_status(expired_id).unwrap(),
            Some(MessageRequestStatus::Expired)
        );
        assert_eq!(
            store.message_request_status(cancelled_id).unwrap(),
            Some(MessageRequestStatus::Cancelled)
        );
        assert!(
            store
                .approve_bulk_evidence(request_id, digest, 5000, 300)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Expired)
        );
    }

    fn create_pending_bulk_review(
        store: &mut EthereumNodeStore,
        request_id: [u8; 16],
        gateway: [u8; 16],
        subject: [u8; 32],
        digest: [u8; 32],
        encoded_size: u32,
        expires_at_unix: u64,
    ) -> PendingBulkEvidenceReview {
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                subject,
                encoded_size.saturating_add(1000),
                100,
                expires_at_unix,
            ))
            .unwrap();
        let advertised = manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            digest,
            encoded_size,
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    101,
                )
                .unwrap(),
            NodeMessageOutcome::BulkApprovalRequired(_)
        ));
        let reviews = store.pending_bulk_evidence_reviews(gateway, 102).unwrap();
        reviews
            .into_iter()
            .find(|review| review.request_id() == request_id)
            .unwrap()
    }

    fn insert_awaiting_bulk_review(
        store: &EthereumNodeStore,
        request_id: [u8; 16],
        gateway: [u8; 16],
        expires_at_unix: u64,
    ) {
        let record = RequestRecord {
            request_id,
            expected_gateway_source_hash: gateway,
            operation: OperationKind::Evidence,
            evidence_kind: Some(MessagingEvidenceKind::ReceiptProof),
            subject: [request_id[0].wrapping_add(1); 32],
            checkpoint_context: None,
            maximum_response_bytes: 6000,
            bulk_approved: false,
            created_at_unix: 100,
            expires_at_unix,
            status: MessageRequestStatus::AwaitingBulkApproval,
            manifest_digest: Some([request_id[0]; 32]),
            manifest_size: Some(5000),
            relay_observation: None,
        };
        insert_request(&store.connection, &record).unwrap();
    }

    #[test]
    fn native_bulk_review_is_redacted_restart_safe_one_shot_and_outbox_exact() {
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0xc1; 16];
        let gateway = [0xc2; 16];
        let source = [0xc3; 16];
        let subject = [0xc4; 32];
        let manifest_digest = [0xc5; 32];
        let review = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            create_pending_bulk_review(
                &mut store,
                request_id,
                gateway,
                subject,
                manifest_digest,
                5000,
                300,
            )
        };
        assert_eq!(review.request_id(), request_id);
        assert_eq!(review.expected_gateway_source_hash(), gateway);
        assert_eq!(review.kind(), MessagingEvidenceKind::ReceiptProof);
        assert_eq!(review.subject(), subject);
        assert_eq!(review.checkpoint_epoch(), None);
        assert_eq!(review.checkpoint_root(), None);
        assert_eq!(review.manifest_digest(), manifest_digest);
        assert_eq!(review.encoded_size(), 5000);
        assert_eq!(review.expires_at_unix(), 300);
        assert_ne!(review.binding_digest(), [0; 32]);
        let debug = format!("{review:?}");
        assert!(!debug.contains("request_id"));
        assert!(!debug.contains("gateway"));
        assert!(!debug.contains("digest"));

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened
                .pending_bulk_evidence_reviews(gateway, 103)
                .unwrap(),
            vec![review.clone()]
        );
        let before_assurance = reopened.transaction_assurance(subject).unwrap();
        assert_eq!(
            reopened
                .resolve_bulk_evidence_review(&review, BulkEvidenceReviewDecision::Approve, 104,)
                .unwrap(),
            BulkEvidenceReviewResolution::Approved
        );
        assert_eq!(
            reopened.transaction_assurance(subject).unwrap(),
            before_assurance
        );
        assert_eq!(
            reopened.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::Ready)
        );
        assert!(
            reopened
                .resolve_bulk_evidence_review(&review, BulkEvidenceReviewDecision::Deny, 105,)
                .is_err()
        );

        let binding = OutboundMessageBinding::new(gateway, source, 7).unwrap();
        let lease = reopened
            .lease_next_outbound_message(binding, 106, 10)
            .unwrap()
            .unwrap();
        let record = read_request(&reopened.connection, request_id)
            .unwrap()
            .unwrap();
        let expected = encode_bulk_approval(&record, manifest_digest, 5000);
        assert_eq!(lease.kind(), OutboundMessageKind::BulkApproval);
        assert_eq!(lease.attachment(), expected);
        assert_eq!(
            lease.attachment()[MAGIC.len() + 1 + std::mem::size_of::<u64>()],
            KIND_BULK_APPROVAL
        );
        assert_eq!(
            reopened.transaction_assurance(subject).unwrap(),
            before_assurance
        );
    }

    #[test]
    fn native_bulk_review_binds_gateway_context_digest_size_and_record() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let request_id = [0xd1; 16];
        let gateway = [0xd2; 16];
        let review = create_pending_bulk_review(
            &mut store, request_id, gateway, [0xd3; 32], [0xd4; 32], 5000, 300,
        );

        let mut forged = review.clone();
        forged.expected_gateway_source_hash = [0xe1; 16];
        assert!(
            store
                .resolve_bulk_evidence_review(&forged, BulkEvidenceReviewDecision::Approve, 103)
                .is_err()
        );
        let mut forged = review.clone();
        forged.checkpoint_context = Some(CheckpointRequestContext {
            checkpoint_epoch: 1,
            checkpoint_root: [0xe2; 32],
        });
        assert!(
            store
                .resolve_bulk_evidence_review(&forged, BulkEvidenceReviewDecision::Approve, 103)
                .is_err()
        );
        let mut forged = review.clone();
        forged.manifest_digest = [0xe3; 32];
        assert!(
            store
                .resolve_bulk_evidence_review(&forged, BulkEvidenceReviewDecision::Approve, 103)
                .is_err()
        );
        let mut forged = review.clone();
        forged.encoded_size += 1;
        assert!(
            store
                .resolve_bulk_evidence_review(&forged, BulkEvidenceReviewDecision::Approve, 103)
                .is_err()
        );
        let mut forged = review.clone();
        forged.binding_digest = [0xe4; 32];
        assert!(
            store
                .resolve_bulk_evidence_review(&forged, BulkEvidenceReviewDecision::Approve, 103)
                .is_err()
        );
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::AwaitingBulkApproval)
        );

        store
            .connection
            .execute(
                "UPDATE eth_message_requests SET manifest_size = '5001' WHERE request_id = ?1",
                [request_id.as_slice()],
            )
            .unwrap();
        assert!(store.pending_bulk_evidence_reviews(gateway, 104).is_err());
        assert!(
            store
                .resolve_bulk_evidence_review(&review, BulkEvidenceReviewDecision::Approve, 104,)
                .is_err()
        );
    }

    #[test]
    fn native_bulk_review_carries_exact_composite_checkpoint_context() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0x44; 16];
        let request_id = [0xe6; 16];
        let subject = [0xe7; 32];
        let digest = [0xe8; 32];
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            REAL_CHECKPOINT_ROOT,
            CONSENSUS_NOW,
        );
        let context = insert_composite_request(
            &mut store,
            request_id,
            MessagingEvidenceKind::AccountStatePackage,
            subject,
            6000,
            CONSENSUS_NOW,
        );
        let advertised = contextual_manifest(
            request_id,
            MessagingEvidenceKind::AccountStatePackage,
            context,
            digest,
            5000,
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    CONSENSUS_NOW + 1,
                )
                .unwrap(),
            NodeMessageOutcome::BulkApprovalRequired(_)
        ));
        let review = store
            .pending_bulk_evidence_reviews(gateway, CONSENSUS_NOW + 2)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(review.kind(), MessagingEvidenceKind::AccountStatePackage);
        assert_eq!(review.subject(), subject);
        assert_eq!(review.checkpoint_epoch(), Some(context.checkpoint_epoch));
        assert_eq!(review.checkpoint_root(), Some(context.checkpoint_root));
    }

    #[test]
    fn expired_bulk_page_never_hides_a_live_review() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0xa9; 16];
        for marker in 1..=MAX_PENDING_BULK_EVIDENCE_REVIEWS as u8 {
            insert_awaiting_bulk_review(&store, [marker; 16], gateway, 110);
        }
        let live_id = [0xfe; 16];
        insert_awaiting_bulk_review(&store, live_id, gateway, 300);

        let reviews = store.pending_bulk_evidence_reviews(gateway, 110).unwrap();
        assert_eq!(
            reviews
                .iter()
                .map(PendingBulkEvidenceReview::request_id)
                .collect::<Vec<_>>(),
            vec![live_id]
        );
        for marker in 1..=MAX_PENDING_BULK_EVIDENCE_REVIEWS as u8 {
            assert_eq!(
                store.message_request_status([marker; 16]).unwrap(),
                Some(MessageRequestStatus::Expired)
            );
        }
    }

    #[test]
    fn live_bulk_reviews_drain_in_stable_bounded_pages() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0xb9; 16];
        let total = MAX_PENDING_BULK_EVIDENCE_REVIEWS + 1;
        for marker in 1..=total as u8 {
            insert_awaiting_bulk_review(&store, [marker; 16], gateway, 300);
        }

        let first = store.pending_bulk_evidence_reviews(gateway, 110).unwrap();
        assert_eq!(first.len(), MAX_PENDING_BULK_EVIDENCE_REVIEWS);
        assert_eq!(
            store.pending_bulk_evidence_reviews(gateway, 110).unwrap(),
            first
        );
        for review in &first {
            assert_eq!(
                store
                    .resolve_bulk_evidence_review(review, BulkEvidenceReviewDecision::Deny, 111,)
                    .unwrap(),
                BulkEvidenceReviewResolution::Denied
            );
        }
        let next = store.pending_bulk_evidence_reviews(gateway, 112).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].request_id(), [total as u8; 16]);
    }

    #[test]
    fn native_bulk_review_denial_expiry_and_races_fail_closed() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let gateway = [0xf1; 16];
        let denied = create_pending_bulk_review(
            &mut store, [0xf2; 16], gateway, [0xf3; 32], [0xf4; 32], 5000, 300,
        );
        assert_eq!(
            store
                .resolve_bulk_evidence_review(&denied, BulkEvidenceReviewDecision::Deny, 103,)
                .unwrap(),
            BulkEvidenceReviewResolution::Denied
        );
        assert_eq!(
            store.message_request_status(denied.request_id()).unwrap(),
            Some(MessageRequestStatus::Cancelled)
        );
        assert!(
            store
                .resolve_bulk_evidence_review(&denied, BulkEvidenceReviewDecision::Approve, 104,)
                .is_err()
        );

        let expiring = create_pending_bulk_review(
            &mut store, [0xf5; 16], gateway, [0xf6; 32], [0xf7; 32], 5000, 110,
        );
        assert!(
            store
                .pending_bulk_evidence_reviews(gateway, 110)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.message_request_status(expiring.request_id()).unwrap(),
            Some(MessageRequestStatus::Expired)
        );
        assert!(
            store
                .resolve_bulk_evidence_review(&expiring, BulkEvidenceReviewDecision::Approve, 111,)
                .is_err()
        );
    }

    #[test]
    fn transaction_status_is_exact_authenticated_restart_safe_and_never_confirmation() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x61; 16];
        let source = [0x62; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 7).unwrap();
        let request_id = [0x63; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);

        let request = store
            .create_transaction_status_request(OutboundTransactionStatusRequest::new(
                request_id, gateway, tx_hash, 100, 300,
            ))
            .unwrap();
        assert_eq!(request.len(), 73);
        assert_eq!(request[16], KIND_TRANSACTION_STATUS_REQUEST);
        assert!(
            store
                .has_active_transaction_status_request(tx_hash, gateway, 101)
                .unwrap()
        );
        assert_eq!(
            store
                .plan_transaction_status_poll(OutboundTransactionStatusRequest::new(
                    [0x68; 16], gateway, tx_hash, 101, 300,
                ))
                .unwrap(),
            RecordOutcome::Replay
        );
        let lease = store
            .lease_next_outbound_message(binding, 101, 10)
            .unwrap()
            .unwrap();
        assert_eq!(lease.kind(), OutboundMessageKind::TransactionStatusRequest);
        assert_eq!(lease.attachment(), request);
        store
            .settle_outbound_message_queued(binding, &lease, 102)
            .unwrap();

        let included = transaction_status_observation(
            request_id,
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x64; 32],
            1_003,
            [0x65; 32],
            1_002,
            [0x66; 32],
            1_001,
            [0x67; 32],
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &included),
                    111,
                )
                .unwrap(),
            NodeMessageOutcome::TransactionStatusObserved {
                request_id: observed_request_id,
                tx_hash: observed,
                status: TransactionStatus::Included,
            } if observed_request_id == request_id && observed == tx_hash
        ));
        let latest = store
            .latest_transaction_status_observation(tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(latest.status(), TransactionStatus::Included);
        assert_eq!(latest.included_block_number(), Some(1_000));
        assert_eq!(latest.included_block_hash(), Some([0x64; 32]));
        assert_eq!(latest.source_hash(), gateway);
        assert_eq!(latest.observed_at_unix(), 111);
        assert_eq!(latest.latest_head_number(), 1_003);
        assert_eq!(latest.safe_head_number(), 1_002);
        assert_eq!(latest.finalized_head_number(), 1_001);
        assert!(matches!(
            store.transaction_assurance(tx_hash).unwrap(),
            Some(TransactionAssurance::Signed {
                non_authoritative_observations,
            }) if non_authoritative_observations.is_empty()
        ));
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &included),
                    112,
                )
                .unwrap(),
            NodeMessageOutcome::Duplicate
        ));
        assert_eq!(
            store
                .plan_transaction_status_poll(OutboundTransactionStatusRequest::new(
                    [0x68; 16], gateway, tx_hash, 120, 320,
                ))
                .unwrap(),
            RecordOutcome::Replay
        );
        assert_eq!(
            store
                .plan_transaction_status_poll(OutboundTransactionStatusRequest::new(
                    [0x68; 16], gateway, tx_hash, 123, 323,
                ))
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert!(
            store
                .has_active_transaction_status_request(tx_hash, gateway, 123)
                .unwrap()
        );
        let newer_request_observation = transaction_status_observation(
            [0x68; 16],
            tx_hash,
            TransactionStatus::Pending,
            0,
            [0; 32],
            1_004,
            [0x69; 32],
            1_003,
            [0x6a; 32],
            1_002,
            [0x6b; 32],
        );
        store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &newer_request_observation),
                50,
            )
            .unwrap();
        // A corrected wall clock must not make an older receipt sequence look
        // newer merely because it has a larger display timestamp.
        let latest = store
            .latest_transaction_status_observation(tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(latest.status(), TransactionStatus::Pending);
        assert_eq!(latest.observed_at_unix(), 50);
        let mut conflicting = included.clone();
        *conflicting.last_mut().unwrap() ^= 1;
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &conflicting),
                    113,
                )
                .is_err()
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, source, &included),
                    114,
                )
                .unwrap(),
            NodeMessageOutcome::IgnoredUnauthenticated
        ));
        drop(store);

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened
                .latest_transaction_status_observation(tx_hash)
                .unwrap()
                .unwrap(),
            latest
        );
    }

    #[test]
    fn finalized_status_schedules_one_local_checkpoint_bound_receipt_request() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x71; 16];
        let source = [0x72; 16];
        let checkpoint_root = [0x73; 32];
        let status_request_id = [0x74; 16];
        let receipt_request_id = [0x75; 16];
        let now = CONSENSUS_NOW;
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        crate::bootstrap::install_test_active_checkpoint(&mut store, checkpoint_root, now);
        persist_transaction_status(
            &mut store,
            gateway,
            status_request_id,
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x76; 32],
            1_001,
            [0x77; 32],
            now + 1,
        );
        let assurance_before = store.transaction_assurance(tx_hash).unwrap();
        let schedule = FinalizedStatusReceiptRequest::new(
            receipt_request_id,
            status_request_id,
            gateway,
            256 * 1024,
            now + 2,
            now + 600,
        );
        assert_eq!(
            store.plan_finalized_receipt_after_status(schedule).unwrap(),
            RecordOutcome::Inserted
        );
        let receipt_request = read_request(&store.connection, receipt_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt_request.operation, OperationKind::Evidence);
        assert_eq!(
            receipt_request.evidence_kind,
            Some(MessagingEvidenceKind::FinalizedReceiptPackage)
        );
        assert_eq!(receipt_request.subject, tx_hash);
        assert_eq!(
            receipt_request.checkpoint_context.unwrap().checkpoint_root,
            checkpoint_root
        );
        assert_eq!(
            store
                .latest_finalized_receipt_request_progress(tx_hash, gateway)
                .unwrap(),
            Some(FinalizedReceiptRequestProgress {
                request_id: receipt_request_id,
                status: MessageRequestStatus::Pending,
                created_at_unix: now + 2,
                expires_at_unix: now + 600,
            })
        );
        assert_eq!(
            store.transaction_assurance(tx_hash).unwrap(),
            assurance_before
        );

        assert_eq!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x78; 16],
                    status_request_id,
                    gateway,
                    256 * 1024,
                    now + 3,
                    now + 600,
                ))
                .unwrap(),
            RecordOutcome::Replay
        );
        drop(store);
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            store.plan_finalized_receipt_after_status(schedule).unwrap(),
            RecordOutcome::Replay
        );

        // An authenticated terminal service failure permits a later fresh
        // status report to schedule proof work, without changing assurance.
        let binding = OutboundMessageBinding::new(gateway, source, 1).unwrap();
        let lease = store
            .lease_next_outbound_message(binding, now + 4, 10)
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id(), receipt_request_id);
        let digest: [u8; 32] = Sha256::digest(lease.attachment()).into();
        store
            .settle_outbound_message_queued(binding, &lease, now + 5)
            .unwrap();
        let failure = service_failure(receipt_request_id, digest);
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &failure),
                    now + 6,
                )
                .unwrap(),
            NodeMessageOutcome::ServiceFailed
        ));
        assert_eq!(
            store
                .latest_finalized_receipt_request_progress(tx_hash, gateway)
                .unwrap()
                .unwrap()
                .status(),
            MessageRequestStatus::Cancelled
        );
        let fresh_status_request_id = [0x79; 16];
        persist_transaction_status(
            &mut store,
            gateway,
            fresh_status_request_id,
            tx_hash,
            TransactionStatus::Included,
            1_002,
            [0x7a; 32],
            1_003,
            [0x7b; 32],
            now + 7,
        );
        assert_eq!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x7c; 16],
                    fresh_status_request_id,
                    gateway,
                    256 * 1024,
                    now + 8,
                    now + 600,
                ))
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store.transaction_assurance(tx_hash).unwrap(),
            assurance_before
        );
    }

    #[test]
    fn finalized_status_supersedes_a_settled_pre_final_receipt_request() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x7d; 16];
        let source = [0x7e; 16];
        let now = CONSENSUS_NOW;
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        crate::bootstrap::install_test_active_checkpoint(&mut store, [0x7f; 32], now);

        let first_status = [0x80; 16];
        let old_receipt = [0x81; 16];
        persist_transaction_status(
            &mut store,
            gateway,
            first_status,
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x82; 32],
            1_001,
            [0x83; 32],
            now + 1,
        );
        assert_eq!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    old_receipt,
                    first_status,
                    gateway,
                    256 * 1024,
                    now + 2,
                    now + 600,
                ))
                .unwrap(),
            RecordOutcome::Inserted
        );

        let binding = OutboundMessageBinding::new(gateway, source, 1).unwrap();
        let mut settled_old_receipt = false;
        for offset in 3..=5 {
            let lease = store
                .lease_next_outbound_message(binding, now + offset, 10)
                .unwrap()
                .unwrap();
            store
                .settle_outbound_message_queued(binding, &lease, now + offset)
                .unwrap();
            if lease.request_id() == old_receipt {
                settled_old_receipt = true;
                break;
            }
        }
        assert!(settled_old_receipt);

        let fresh_status = [0x84; 16];
        let fresh_receipt = [0x85; 16];
        persist_transaction_status(
            &mut store,
            gateway,
            fresh_status,
            tx_hash,
            TransactionStatus::Included,
            1_002,
            [0x86; 32],
            1_003,
            [0x87; 32],
            now + 6,
        );
        assert_eq!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    fresh_receipt,
                    fresh_status,
                    gateway,
                    256 * 1024,
                    now + 7,
                    now + 600,
                ))
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store.message_request_status(old_receipt).unwrap(),
            Some(MessageRequestStatus::Cancelled)
        );
        assert_eq!(
            store.message_request_status(fresh_receipt).unwrap(),
            Some(MessageRequestStatus::Pending)
        );
        assert!(matches!(
            store.transaction_assurance(tx_hash).unwrap(),
            Some(TransactionAssurance::Signed { .. })
        ));
    }

    #[test]
    fn finalized_status_receipt_scheduler_rejects_untrusted_or_ineligible_hints() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x81; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        let now = CONSENSUS_NOW;
        let status_request_id = [0x82; 16];
        persist_transaction_status(
            &mut store,
            gateway,
            status_request_id,
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x83; 32],
            1_001,
            [0x84; 32],
            now + 1,
        );
        // A service observation cannot bootstrap a checkpoint.
        assert!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x85; 16],
                    status_request_id,
                    gateway,
                    256 * 1024,
                    now + 2,
                    now + 600,
                ))
                .is_err()
        );
        crate::bootstrap::install_test_active_checkpoint(&mut store, [0x86; 32], now);
        assert!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x87; 16],
                    status_request_id,
                    [0x88; 16],
                    256 * 1024,
                    now + 2,
                    now + 600,
                ))
                .is_err()
        );

        let not_final_status_id = [0x89; 16];
        persist_transaction_status(
            &mut store,
            gateway,
            not_final_status_id,
            tx_hash,
            TransactionStatus::Included,
            1_010,
            [0x8a; 32],
            1_009,
            [0x8b; 32],
            now + 3,
        );
        assert!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x8c; 16],
                    not_final_status_id,
                    gateway,
                    256 * 1024,
                    now + 4,
                    now + 600,
                ))
                .is_err()
        );
        assert!(matches!(
            store.transaction_assurance(tx_hash).unwrap(),
            Some(TransactionAssurance::Signed {
                non_authoritative_observations,
            }) if non_authoritative_observations.is_empty()
        ));
    }

    #[test]
    fn finalized_status_receipt_scheduler_never_requeues_a_verified_receipt() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x91; 16];
        let now = CONSENSUS_NOW;
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        crate::bootstrap::install_test_active_checkpoint(&mut store, [0x92; 32], now);
        persist_transaction_status(
            &mut store,
            gateway,
            [0x93; 16],
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x94; 32],
            1_001,
            [0x95; 32],
            now + 1,
        );
        crate::receipt::install_test_receipt_for_transaction(&mut store, tx_hash, true);
        let assurance_before = store.transaction_assurance(tx_hash).unwrap();
        assert_eq!(
            store
                .plan_finalized_receipt_after_status(FinalizedStatusReceiptRequest::new(
                    [0x96; 16],
                    [0x93; 16],
                    gateway,
                    256 * 1024,
                    now + 2,
                    now + 600,
                ))
                .unwrap(),
            RecordOutcome::Replay
        );
        assert!(
            store
                .latest_finalized_receipt_request_progress(tx_hash, gateway)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.transaction_assurance(tx_hash).unwrap(),
            assurance_before
        );
    }

    #[test]
    fn transaction_status_rejects_wrong_binding_malformed_heads_and_corruption() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x71; 16];
        let request_id = [0x72; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        assert!(
            store
                .create_transaction_status_request(OutboundTransactionStatusRequest::new(
                    [0; 16], gateway, tx_hash, 100, 200,
                ))
                .is_err()
        );
        store
            .create_transaction_status_request(OutboundTransactionStatusRequest::new(
                request_id, gateway, tx_hash, 100, 200,
            ))
            .unwrap();

        let wrong_transaction = transaction_status_observation(
            request_id,
            [0x73; 32],
            TransactionStatus::Pending,
            0,
            [0; 32],
            100,
            [0x74; 32],
            99,
            [0x75; 32],
            98,
            [0x76; 32],
        );
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &wrong_transaction),
                    110,
                )
                .is_err()
        );
        let malformed_included = transaction_status_observation(
            request_id,
            tx_hash,
            TransactionStatus::Included,
            0,
            [0; 32],
            100,
            [0x74; 32],
            99,
            [0x75; 32],
            98,
            [0x76; 32],
        );
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &malformed_included),
                    110,
                )
                .is_err()
        );
        let malformed_order = transaction_status_observation(
            request_id,
            tx_hash,
            TransactionStatus::NotSeen,
            0,
            [0; 32],
            98,
            [0x74; 32],
            99,
            [0x75; 32],
            97,
            [0x76; 32],
        );
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &malformed_order),
                    110,
                )
                .is_err()
        );
        let accepted = transaction_status_observation(
            request_id,
            tx_hash,
            TransactionStatus::Pending,
            0,
            [0; 32],
            100,
            [0x74; 32],
            99,
            [0x75; 32],
            98,
            [0x76; 32],
        );
        store
            .handle_gateway_attachment(
                gateway,
                AuthenticatedNodeEnvelope::new(true, gateway, &accepted),
                111,
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_transaction_status_observations
                    SET latest_head_hash = zeroblob(32)",
                [],
            )
            .unwrap();
        assert!(
            store
                .latest_transaction_status_observation(tx_hash)
                .is_err()
        );
    }

    #[test]
    fn transaction_status_history_classifies_reinclusion_moves_and_inconsistent_heads() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x91; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);

        persist_transaction_status(
            &mut store,
            gateway,
            [0x92; 16],
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x93; 32],
            990,
            [0x94; 32],
            100,
        );
        assert_eq!(
            store
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap()
                .continuity(),
            TransactionStatusContinuity::FirstObservation
        );
        persist_transaction_status(
            &mut store,
            gateway,
            [0x95; 16],
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0x93; 32],
            991,
            [0x96; 32],
            101,
        );
        assert_eq!(
            store
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap()
                .continuity(),
            TransactionStatusContinuity::StillIncluded
        );
        persist_transaction_status(
            &mut store,
            gateway,
            [0x97; 16],
            tx_hash,
            TransactionStatus::Included,
            1_001,
            [0x98; 32],
            992,
            [0x99; 32],
            102,
        );
        assert_eq!(
            store
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap()
                .continuity(),
            TransactionStatusContinuity::IncludedMoved
        );
        persist_transaction_status(
            &mut store,
            gateway,
            [0x9a; 16],
            tx_hash,
            TransactionStatus::Pending,
            0,
            [0; 32],
            993,
            [0x9b; 32],
            103,
        );
        assert_eq!(
            store
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap()
                .continuity(),
            TransactionStatusContinuity::AwaitingReinclusion
        );
        persist_transaction_status(
            &mut store,
            gateway,
            [0x9c; 16],
            tx_hash,
            TransactionStatus::Included,
            1_001,
            [0x98; 32],
            994,
            [0x9d; 32],
            104,
        );
        assert_eq!(
            store
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap()
                .continuity(),
            TransactionStatusContinuity::Reincluded
        );
        persist_transaction_status(
            &mut store,
            gateway,
            [0x9e; 16],
            tx_hash,
            TransactionStatus::Pending,
            0,
            [0; 32],
            994,
            [0x9f; 32],
            105,
        );
        let view = store
            .transaction_status_history_view(tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(view.continuity(), TransactionStatusContinuity::Inconsistent);
        assert_eq!(view.latest().source_hash(), gateway);
        let prior_inclusion = view.previous_inclusion().unwrap();
        assert_eq!(prior_inclusion.source_hash(), gateway);
        assert_eq!(prior_inclusion.status(), TransactionStatus::Included);
        assert_eq!(prior_inclusion.included_block_number(), Some(1_001));
        assert_eq!(prior_inclusion.included_block_hash(), Some([0x98; 32]));
        assert_eq!(prior_inclusion.observed_at_unix(), 104);
        drop(store);

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened
                .transaction_status_history_view(tx_hash)
                .unwrap()
                .unwrap(),
            view
        );
    }

    #[test]
    fn transaction_status_history_never_joins_different_authenticated_sources() {
        let profile = tempfile::tempdir().unwrap();
        let source_a = [0xa1; 16];
        let source_b = [0xb1; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);

        persist_transaction_status(
            &mut store,
            source_a,
            [0xa2; 16],
            tx_hash,
            TransactionStatus::Included,
            1_000,
            [0xa3; 32],
            990,
            [0xa4; 32],
            100,
        );
        persist_transaction_status(
            &mut store,
            source_b,
            [0xb2; 16],
            tx_hash,
            TransactionStatus::Pending,
            0,
            [0; 32],
            1,
            [0xb3; 32],
            101,
        );
        let view = store
            .transaction_status_history_view(tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(view.latest().source_hash(), source_b);
        assert_eq!(
            view.continuity(),
            TransactionStatusContinuity::FirstObservation
        );
        assert!(view.previous_inclusion().is_none());

        persist_transaction_status(
            &mut store,
            source_b,
            [0xb4; 16],
            tx_hash,
            TransactionStatus::Included,
            1_001,
            [0xb5; 32],
            991,
            [0xb6; 32],
            102,
        );
        let view = store
            .transaction_status_history_view(tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(
            view.continuity(),
            TransactionStatusContinuity::StatusChanged
        );
        assert!(view.previous_inclusion().is_none());
    }

    #[test]
    fn v16_migration_preserves_legacy_requests_and_widens_status_lifecycle() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE eth_message_requests (
                    request_id BLOB PRIMARY KEY NOT NULL,
                    expected_gateway_source_hash BLOB NOT NULL,
                    operation_kind INTEGER NOT NULL,
                    evidence_kind INTEGER,
                    subject BLOB NOT NULL,
                    checkpoint_epoch TEXT,
                    checkpoint_root BLOB,
                    maximum_response_bytes TEXT NOT NULL,
                    bulk_approved INTEGER NOT NULL,
                    created_at_unix TEXT NOT NULL,
                    expires_at_unix TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    manifest_digest BLOB,
                    manifest_size TEXT,
                    relay_observation INTEGER,
                    record_digest BLOB NOT NULL,
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
                 );
                 CREATE TABLE eth_pending_message_evidence (
                    request_id BLOB PRIMARY KEY NOT NULL,
                    evidence_kind INTEGER NOT NULL,
                    subject BLOB NOT NULL,
                    evidence_digest BLOB NOT NULL,
                    encoded_size TEXT NOT NULL,
                    evidence_blob BLOB NOT NULL,
                    received_at_unix TEXT NOT NULL,
                    record_digest BLOB NOT NULL
                 );
                 CREATE TABLE eth_message_outbox (
                    request_id BLOB NOT NULL,
                    item_kind INTEGER NOT NULL,
                    gateway_destination_hash BLOB NOT NULL,
                    local_source_hash BLOB NOT NULL,
                    identity_session_generation TEXT NOT NULL,
                    attachment_digest BLOB NOT NULL,
                    state INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    lease_generation INTEGER NOT NULL,
                    lease_until_unix TEXT,
                    queued_at_unix TEXT,
                    record_digest BLOB NOT NULL,
                    PRIMARY KEY(request_id, item_kind)
                 );",
            )
            .unwrap();
        crate::workflow::create_schema(&transaction).unwrap();
        let legacy = RequestRecord {
            request_id: [0x81; 16],
            expected_gateway_source_hash: [0x82; 16],
            operation: OperationKind::Relay,
            evidence_kind: None,
            subject: [0x83; 32],
            checkpoint_context: None,
            maximum_response_bytes: 100,
            bulk_approved: false,
            created_at_unix: 100,
            expires_at_unix: 300,
            status: MessageRequestStatus::Pending,
            manifest_digest: None,
            manifest_size: None,
            relay_observation: None,
        };
        insert_request(&transaction, &legacy).unwrap();
        migrate_v16_to_v17(&transaction).unwrap();
        transaction.commit().unwrap();

        assert_eq!(
            read_request(&connection, legacy.request_id).unwrap(),
            Some(legacy)
        );
        let request_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table'
                   AND name = 'eth_message_requests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(request_sql.contains("operation_kind IN (1, 2, 3)"));
        let status_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table'
                   AND name = 'eth_transaction_status_observations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(status_table);
    }

    #[test]
    fn base_signed_relay_preserves_chain_in_wire_and_outbox_reconstruction() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x6a; 16];
        let source = [0x6b; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 7).unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let tx_hash = signed_fixture_for_chain_with_nonce(
            &mut store,
            ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
            22,
        );
        let signed = store
            .signed_transaction(ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap()
            .unwrap();
        let request_id = [0x6c; 16];
        let relay = store
            .create_signed_transaction_relay(request_id, gateway, &signed, 100, 300)
            .unwrap();

        assert_eq!(
            &relay[8..16],
            &ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID.to_le_bytes(),
        );
        assert_eq!(relay[16], KIND_SIGNED_RELAY);

        let lease = store
            .lease_next_outbound_message(binding, 101, 10)
            .unwrap()
            .unwrap();
        assert_eq!(lease.kind(), OutboundMessageKind::SignedTransactionRelay);
        assert_eq!(lease.attachment(), relay);
        store
            .release_outbound_message(binding, &lease, 102)
            .unwrap();

        drop(store);
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let replayed = reopened
            .lease_next_outbound_message(binding, 103, 10)
            .unwrap()
            .unwrap();
        assert_eq!(replayed.attachment(), relay);
    }

    #[test]
    fn relay_observations_are_transaction_exact_and_never_confirmation() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, _, tx_hash) = signed_fixture(&mut store);
        let stored = store
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap()
            .unwrap();
        let request_id = [0x71; 16];
        let expired_id = [0x74; 16];
        let cancelled_id = [0x75; 16];
        let gateway = [0x72; 16];
        let relay = store
            .create_signed_transaction_relay(request_id, gateway, &stored, 100, 300)
            .unwrap();
        assert_eq!(relay[16], KIND_SIGNED_RELAY);
        store
            .create_signed_transaction_relay(expired_id, gateway, &stored, 100, 105)
            .unwrap();
        store
            .create_signed_transaction_relay(cancelled_id, gateway, &stored, 100, 300)
            .unwrap();
        store.cancel_message_request(cancelled_id).unwrap();
        for (id, expected_status) in [
            (expired_id, MessageRequestStatus::Expired),
            (cancelled_id, MessageRequestStatus::Cancelled),
        ] {
            let blocked = observation(id, tx_hash, RelayObservation::GatewayAccepted);
            assert!(
                store
                    .handle_gateway_attachment(
                        gateway,
                        AuthenticatedNodeEnvelope::new(true, gateway, &blocked),
                        110,
                    )
                    .is_err()
            );
            assert_eq!(
                store.message_request_status(id).unwrap(),
                Some(expected_status)
            );
        }

        let wrong = observation(request_id, [0x73; 32], RelayObservation::RpcAccepted);
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &wrong),
                    110,
                )
                .is_err()
        );
        let accepted = observation(request_id, tx_hash, RelayObservation::RpcAccepted);
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &accepted),
                    111,
                )
                .unwrap(),
            NodeMessageOutcome::RelayObserved { .. }
        ));
        let Some(TransactionAssurance::Signed {
            non_authoritative_observations,
        }) = store.transaction_assurance(tx_hash).unwrap()
        else {
            panic!("relay observations must remain unconfirmed");
        };
        assert_eq!(
            non_authoritative_observations,
            vec![crate::NonAuthoritativeTransactionObservation::RpcAccepted]
        );
        store
            .connection
            .execute("DELETE FROM eth_assurance_history", [])
            .unwrap();
        let Some(TransactionAssurance::Signed {
            non_authoritative_observations,
        }) = store.transaction_assurance(tx_hash).unwrap()
        else {
            panic!("the durable relay record must retain non-authoritative progress");
        };
        assert_eq!(
            non_authoritative_observations,
            vec![crate::NonAuthoritativeTransactionObservation::RpcAccepted]
        );
        assert_eq!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &accepted),
                    112,
                )
                .unwrap(),
            NodeMessageOutcome::Duplicate
        );
        let conflict = observation(request_id, tx_hash, RelayObservation::RpcRejected);
        assert!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &conflict),
                    113,
                )
                .unwrap_err()
                .to_string()
                .contains("conflicting")
        );
    }

    #[test]
    fn outbound_lease_is_exact_restart_safe_and_attempt_bounded() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0xa1; 16];
        let source = [0xa2; 16];
        let request_id = [0xa3; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 7).unwrap();
        let expected = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::ReceiptProof,
                    [0xa4; 32],
                    1024,
                    100,
                    300,
                ))
                .unwrap()
        };
        let first = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let lease = store
                .lease_next_outbound_message(binding, 101, 10)
                .unwrap()
                .unwrap();
            assert_eq!(lease.kind(), OutboundMessageKind::EvidenceRequest);
            assert_eq!(lease.destination_hash(), gateway);
            assert_eq!(lease.source_hash(), source);
            assert_eq!(lease.attachment(), expected);
            let debug = format!("{lease:?}");
            assert!(!debug.contains(&alloy_primitives::hex::encode(gateway)));
            assert!(!debug.contains(&alloy_primitives::hex::encode(source)));
            assert!(!debug.contains(&alloy_primitives::hex::encode(&expected)));
            lease
        };
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            reopened
                .lease_next_outbound_message(
                    OutboundMessageBinding::new(gateway, source, 8).unwrap(),
                    102,
                    10,
                )
                .is_err()
        );
        assert!(
            reopened
                .release_outbound_message(
                    OutboundMessageBinding::new(gateway, source, 8).unwrap(),
                    &first,
                    102,
                )
                .is_err()
        );
        reopened
            .release_outbound_message(binding, &first, 102)
            .unwrap();
        let second = reopened
            .lease_next_outbound_message(binding, 103, 10)
            .unwrap()
            .unwrap();
        drop(reopened);
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            reopened
                .lease_next_outbound_message(binding, 112, 10)
                .unwrap()
                .is_none()
        );
        let third = reopened
            .lease_next_outbound_message(binding, 113, 10)
            .unwrap()
            .unwrap();
        assert_eq!(third.attachment(), second.attachment());
        reopened
            .release_outbound_message(binding, &third, 114)
            .unwrap();
        assert!(
            reopened
                .lease_next_outbound_message(binding, 115, 10)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn gateway_replacement_requires_terminal_gateway_bound_work() {
        let old_gateway = [0xd1; 16];
        let replacement = [0xd2; 16];
        let source = [0xd3; 16];
        let request_id = [0xd4; 16];
        let active_profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(active_profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                old_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xd5; 32],
                1024,
                100,
                300,
            ))
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed(replacement, 101)
                .is_err()
        );
        store
            .ensure_gateway_replacement_allowed(old_gateway, 101)
            .unwrap();

        let bulk_profile = tempfile::tempdir().unwrap();
        let mut bulk = EthereumNodeStore::open_in_profile(bulk_profile.path()).unwrap();
        bulk.create_evidence_request(OutboundEvidenceRequest::new(
            [0xe1; 16],
            old_gateway,
            MessagingEvidenceKind::ReceiptProof,
            [0xe2; 32],
            6_000,
            110,
            400,
        ))
        .unwrap();
        let bulk_binding = OutboundMessageBinding::new(old_gateway, source, 12).unwrap();
        let initial_request = bulk
            .lease_next_outbound_message(bulk_binding, 111, 10)
            .unwrap()
            .unwrap();
        bulk.settle_outbound_message_queued(bulk_binding, &initial_request, 112)
            .unwrap();
        let bulk_manifest = manifest(
            [0xe1; 16],
            MessagingEvidenceKind::ReceiptProof,
            [0xe3; 32],
            5_000,
        );
        assert!(matches!(
            bulk.handle_gateway_attachment(
                old_gateway,
                AuthenticatedNodeEnvelope::new(true, old_gateway, &bulk_manifest),
                113,
            )
            .unwrap(),
            NodeMessageOutcome::BulkApprovalRequired(_)
        ));
        bulk.approve_bulk_evidence([0xe1; 16], [0xe3; 32], 5_000, 114)
            .unwrap();
        bulk.ensure_gateway_replacement_allowed(old_gateway, 115)
            .unwrap();
        assert!(
            bulk.ensure_gateway_replacement_allowed(replacement, 115)
                .is_err()
        );

        let pending_profile = tempfile::tempdir().unwrap();
        let mut pending = EthereumNodeStore::open_in_profile(pending_profile.path()).unwrap();
        pending
            .create_evidence_request(OutboundEvidenceRequest::new(
                [0xe4; 16],
                old_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xe5; 32],
                1_024,
                120,
                130,
            ))
            .unwrap();
        let transaction = pending.connection.transaction().unwrap();
        let evidence = PendingMessageEvidence {
            request_id: [0xe4; 16],
            kind: MessagingEvidenceKind::ReceiptProof,
            subject: [0xe5; 32],
            digest: Sha256::digest(b"pending").into(),
            bytes: b"pending".to_vec(),
            received_at_unix: 121,
        };
        insert_pending_evidence(&transaction, &evidence).unwrap();
        let mut record = read_request(&transaction, [0xe4; 16]).unwrap().unwrap();
        record.status = MessageRequestStatus::PendingVerification;
        update_request(&transaction, &record).unwrap();
        transaction.commit().unwrap();
        assert!(
            pending
                .ensure_gateway_replacement_allowed(replacement, 500)
                .is_err()
        );

        let expired_profile = tempfile::tempdir().unwrap();
        let mut expired = EthereumNodeStore::open_in_profile(expired_profile.path()).unwrap();
        expired
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                old_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xd5; 32],
                1024,
                100,
                300,
            ))
            .unwrap();
        expired
            .ensure_gateway_replacement_allowed(replacement, 301)
            .unwrap();

        let lease_profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(lease_profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                old_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xd5; 32],
                1024,
                100,
                300,
            ))
            .unwrap();
        let binding = OutboundMessageBinding::new(old_gateway, source, 7).unwrap();
        let lease = store
            .lease_next_outbound_message(binding, 102, 10)
            .unwrap()
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed(replacement, 103)
                .is_err()
        );
        assert!(
            store
                .ensure_gateway_replacement_allowed(replacement, 301)
                .is_err()
        );
        store
            .settle_outbound_message_queued(binding, &lease, 104)
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed(replacement, 105)
                .is_err()
        );
    }

    #[test]
    fn queued_settlement_bulk_approval_and_relay_are_non_authoritative() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0xb1; 16];
        let source = [0xb2; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 9).unwrap();
        let bulk_id = [0xb3; 16];
        let bulk_digest = [0xb4; 32];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                bulk_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xb5; 32],
                6000,
                100,
                400,
            ))
            .unwrap();
        let advertised = manifest(
            bulk_id,
            MessagingEvidenceKind::ReceiptProof,
            bulk_digest,
            5000,
        );
        assert!(matches!(
            store
                .handle_gateway_attachment(
                    gateway,
                    AuthenticatedNodeEnvelope::new(true, gateway, &advertised),
                    101,
                )
                .unwrap(),
            NodeMessageOutcome::BulkApprovalRequired(_)
        ));
        let approval = store
            .approve_bulk_evidence(bulk_id, bulk_digest, 5000, 102)
            .unwrap();
        let bulk = store
            .lease_next_outbound_message(binding, 103, 10)
            .unwrap()
            .unwrap();
        assert_eq!(bulk.kind(), OutboundMessageKind::BulkApproval);
        assert_eq!(bulk.attachment(), approval);
        store
            .settle_outbound_message_queued(binding, &bulk, 104)
            .unwrap();

        let (_, _, tx_hash) = signed_fixture(&mut store);
        let signed = store
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap()
            .unwrap();
        let relay_id = [0xb6; 16];
        let relay_bytes = store
            .create_signed_transaction_relay(relay_id, gateway, &signed, 105, 400)
            .unwrap();
        let before = store.transaction_assurance(tx_hash).unwrap();
        let relay = store
            .lease_next_outbound_message(binding, 106, 10)
            .unwrap()
            .unwrap();
        assert_eq!(relay.kind(), OutboundMessageKind::SignedTransactionRelay);
        assert_eq!(relay.attachment(), relay_bytes);
        store
            .settle_outbound_message_queued(binding, &relay, 107)
            .unwrap();
        assert_eq!(store.transaction_assurance(tx_hash).unwrap(), before);
        drop(store);

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            reopened
                .lease_next_outbound_message(binding, 108, 10)
                .unwrap()
                .is_none()
        );
        assert_eq!(reopened.transaction_assurance(tx_hash).unwrap(), before);
    }

    #[test]
    fn outbound_corruption_cancellation_and_expiry_fail_closed() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0xc1; 16];
        let source = [0xc2; 16];
        let binding = OutboundMessageBinding::new(gateway, source, 10).unwrap();
        let corrupt_id = [0xc3; 16];
        let cancelled_id = [0xc4; 16];
        let expired_id = [0xc5; 16];
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        for (request_id, expires) in [(corrupt_id, 300), (cancelled_id, 300), (expired_id, 105)] {
            store
                .create_evidence_request(OutboundEvidenceRequest::new(
                    request_id,
                    gateway,
                    MessagingEvidenceKind::ReceiptProof,
                    [0xc6; 32],
                    1000,
                    100,
                    expires,
                ))
                .unwrap();
        }
        let corrupt = store
            .lease_next_outbound_message(binding, 101, 10)
            .unwrap()
            .unwrap();
        store
            .release_outbound_message(binding, &corrupt, 102)
            .unwrap();
        store.cancel_message_request(cancelled_id).unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_message_outbox SET attachment_digest = ?1
                 WHERE request_id = ?2",
                rusqlite::params![[0xff_u8; 32].as_slice(), corrupt_id.as_slice()],
            )
            .unwrap();
        drop(store);
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            reopened
                .lease_next_outbound_message(binding, 106, 10)
                .is_err()
        );
        assert_eq!(
            reopened.message_request_status(cancelled_id).unwrap(),
            Some(MessageRequestStatus::Cancelled)
        );
        assert!(
            reopened
                .lease_next_outbound_message(
                    OutboundMessageBinding::new([0xdd; 16], source, 10).unwrap(),
                    106,
                    10,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn gateway_replacement_rejects_coherently_rewritten_outbox_parent_mismatch() {
        let profile = tempfile::tempdir().unwrap();
        let parent_gateway = [0xca; 16];
        let rewritten_gateway = [0xcb; 16];
        let source = [0xcc; 16];
        let request_id = [0xcd; 16];
        let binding = OutboundMessageBinding::new(parent_gateway, source, 11).unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                parent_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0xce; 32],
                1_024,
                100,
                300,
            ))
            .unwrap();
        let lease = store
            .lease_next_outbound_message(binding, 101, 10)
            .unwrap()
            .unwrap();
        store
            .release_outbound_message(binding, &lease, 102)
            .unwrap();
        let attachment_digest: [u8; 32] = Sha256::digest(lease.attachment()).into();
        let rewritten_binding = OutboundMessageBinding::new(rewritten_gateway, source, 11).unwrap();
        let rewritten_digest = outbox_digest(
            request_id,
            lease.kind(),
            rewritten_binding,
            attachment_digest,
            OUTBOUND_READY,
            1,
            1,
            None,
            None,
        );
        store
            .connection
            .execute(
                "UPDATE eth_message_outbox
                 SET gateway_destination_hash = ?1, record_digest = ?2
                 WHERE request_id = ?3",
                rusqlite::params![
                    rewritten_gateway.as_slice(),
                    rewritten_digest.as_slice(),
                    request_id.as_slice()
                ],
            )
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed(rewritten_gateway, 103)
                .is_err()
        );
        let settled_digest = outbox_digest(
            request_id,
            lease.kind(),
            rewritten_binding,
            attachment_digest,
            OUTBOUND_SETTLED,
            1,
            1,
            None,
            Some(104),
        );
        store
            .connection
            .execute(
                "UPDATE eth_message_outbox
                 SET state = ?1, queued_at_unix = ?2, record_digest = ?3
                 WHERE request_id = ?4",
                rusqlite::params![
                    OUTBOUND_SETTLED,
                    104_u64.to_string(),
                    settled_digest.as_slice(),
                    request_id.as_slice()
                ],
            )
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed(rewritten_gateway, 105)
                .is_err()
        );
    }

    #[test]
    fn schema_five_migrates_atomically_to_the_message_ledger() {
        let profile = tempfile::tempdir().unwrap();
        {
            let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE eth_message_requests;
                     UPDATE eth_schema_version SET version = 5 WHERE singleton = 1;",
                )
                .unwrap();
        }
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let version: i64 = store
            .connection
            .query_row(
                "SELECT version FROM eth_schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, crate::schema::ETHEREUM_STORE_SCHEMA_VERSION);
        let request_count: u64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM eth_message_requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(request_count, 0);
    }

    #[test]
    fn schema_six_rebuilds_request_status_and_adds_pending_queue() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        {
            let transaction = connection.transaction().unwrap();
            transaction
                .execute_batch(
                    "CREATE TABLE eth_schema_version (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        version INTEGER NOT NULL
                     );
                     INSERT INTO eth_schema_version VALUES (1, 6);",
                )
                .unwrap();
            create_schema(&transaction).unwrap();
            for (request_id, operation) in [
                ([0xa1; 16], OperationKind::Evidence),
                ([0xa2; 16], OperationKind::Relay),
            ] {
                insert_request(
                    &transaction,
                    &RequestRecord {
                        request_id,
                        expected_gateway_source_hash: [0xb1; 16],
                        operation,
                        evidence_kind: (operation == OperationKind::Evidence)
                            .then_some(MessagingEvidenceKind::ReceiptProof),
                        subject: [0xc1; 32],
                        checkpoint_context: None,
                        maximum_response_bytes: 100,
                        bulk_approved: false,
                        created_at_unix: 100,
                        expires_at_unix: 200,
                        status: MessageRequestStatus::Completed,
                        manifest_digest: None,
                        manifest_size: None,
                        relay_observation: (operation == OperationKind::Relay)
                            .then_some(RelayObservation::RpcAccepted),
                    },
                )
                .unwrap();
            }
            transaction
                .execute_batch("DROP TABLE eth_pending_message_evidence;")
                .unwrap();
            transaction.commit().unwrap();
        }
        crate::schema::initialize(&mut connection).unwrap();
        let version: i64 = connection
            .query_row(
                "SELECT version FROM eth_schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let pending_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'eth_pending_message_evidence')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let request_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table'
                 AND name = 'eth_message_requests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, crate::schema::ETHEREUM_STORE_SCHEMA_VERSION);
        assert!(pending_table);
        assert!(request_sql.contains("status BETWEEN 1 AND 7"));
        assert_eq!(
            read_request(&connection, [0xa1; 16])
                .unwrap()
                .unwrap()
                .status,
            MessageRequestStatus::Ready
        );
        assert_eq!(
            read_request(&connection, [0xa2; 16])
                .unwrap()
                .unwrap()
                .status,
            MessageRequestStatus::Completed
        );
    }

    #[test]
    fn frozen_composite_receipt_cannot_bypass_local_transaction_policy() {
        let (package, raw_transaction, tx_hash, finalized_at) = finalized_receipt_package();
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0xd1; 16];
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            crate::bootstrap::install_test_active_checkpoint(
                &mut store,
                REAL_CHECKPOINT_ROOT,
                finalized_at,
            );
            assert!(
                store
                    .record_locally_signed_transaction(
                        &raw_transaction,
                        [0; 20],
                        [0x8b; 32],
                        finalized_at,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("signed transaction exceeds the storage limit")
            );
            let context = insert_composite_request(
                &mut store,
                request_id,
                MessagingEvidenceKind::FinalizedReceiptPackage,
                tx_hash,
                u32::try_from(package.len()).unwrap(),
                finalized_at,
            );
            retain_composite_response(
                &mut store,
                request_id,
                MessagingEvidenceKind::FinalizedReceiptPackage,
                context,
                &package,
                finalized_at + 1,
            );
            assert!(
                store
                    .process_pending_message_evidence_at(request_id, finalized_at + 4)
                    .unwrap_err()
                    .to_string()
                    .contains("no exact locally persisted transaction")
            );
            assert_eq!(
                store.message_request_status(request_id).unwrap(),
                Some(MessageRequestStatus::PendingVerification)
            );
            assert!(
                store
                    .pending_message_evidence(request_id)
                    .unwrap()
                    .is_some()
            );
            let authoritative: u64 = store
                .connection
                .query_row(
                    "SELECT
                        (SELECT count(*) FROM eth_verified_finalized_headers)
                      + (SELECT count(*) FROM eth_verified_execution_blocks)
                      + (SELECT count(*) FROM eth_verified_receipts)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(authoritative, 0);
            assert!(store.transaction_assurance(tx_hash).unwrap().is_none());
        }

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::PendingVerification)
        );
        assert!(
            reopened
                .pending_message_evidence(request_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn verified_compressed_inner_is_rejected_before_noncanonical_persistence() {
        let (canonical_package, _, tx_hash, finalized_at) = finalized_receipt_package();
        let verifier = Verifier::sepolia();
        let parsed = verifier
            .parse_finalized_receipt_evidence(&canonical_package)
            .unwrap();
        let compressed_consensus = compressed_bundle(parsed.consensus_bundle_bytes());
        let package = verifier
            .build_finalized_receipt_evidence(
                1_800_000_002,
                &compressed_consensus,
                parsed.execution_header_bytes(),
                parsed.finalized_receipt_bytes(),
            )
            .unwrap();
        // The verifier exercises all bounded gzip/hash checks and accepts the
        // exact proof; the node then rejects the noncanonical storage form.
        verifier
            .verify_finalized_receipt_evidence(
                &package,
                &BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
                tx_hash,
            )
            .unwrap();

        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            REAL_CHECKPOINT_ROOT,
            finalized_at,
        );
        let request_id = [0xd3; 16];
        let context = insert_composite_request(
            &mut store,
            request_id,
            MessagingEvidenceKind::FinalizedReceiptPackage,
            tx_hash,
            u32::try_from(package.len()).unwrap(),
            finalized_at,
        );
        retain_composite_response(
            &mut store,
            request_id,
            MessagingEvidenceKind::FinalizedReceiptPackage,
            context,
            &package,
            finalized_at + 1,
        );
        assert!(
            store
                .process_pending_message_evidence_at(request_id, finalized_at + 4)
                .unwrap_err()
                .to_string()
                .contains("canonical uncompressed form")
        );
        let authoritative: u64 = store
            .connection
            .query_row(
                "SELECT
                    (SELECT count(*) FROM eth_verified_finalized_headers)
                  + (SELECT count(*) FROM eth_verified_execution_blocks)
                  + (SELECT count(*) FROM eth_verified_receipts)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(authoritative, 0);
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(MessageRequestStatus::PendingVerification)
        );
    }

    #[test]
    fn synthetic_account_package_for_another_address_is_rejected_before_pending() {
        let local_address = [0x61; 20];
        let package = synthetic_parseable_account_package([0x62; 20]);
        let (_, _, _, finalized_at) = finalized_receipt_package();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        crate::bootstrap::install_test_active_checkpoint(
            &mut store,
            REAL_CHECKPOINT_ROOT,
            finalized_at,
        );
        store
            .install_wallet_account(ratspeak_eth_wallet::WalletAccount::sepolia(
                alloy_primitives::Address::from(local_address),
            ))
            .unwrap();
        let mut subject = [0; 32];
        subject[12..].copy_from_slice(&local_address);
        let request_id = [0xd2; 16];
        let context = insert_composite_request(
            &mut store,
            request_id,
            MessagingEvidenceKind::AccountStatePackage,
            subject,
            u32::try_from(package.len()).unwrap(),
            finalized_at,
        );
        let digest: [u8; 32] = Sha256::digest(&package).into();
        let size = u32::try_from(package.len()).unwrap();
        let manifest = contextual_manifest(
            request_id,
            MessagingEvidenceKind::AccountStatePackage,
            context,
            digest,
            size,
        );
        let outcome = store
            .handle_attachment_from_trusted_lxmf_adapter(
                [0x44; 16],
                [0x44; 16],
                &manifest,
                finalized_at + 1,
            )
            .unwrap();
        if matches!(outcome, NodeMessageOutcome::BulkApprovalRequired(_)) {
            store
                .approve_bulk_evidence(request_id, digest, size, finalized_at + 2)
                .unwrap();
        }
        let response = contextual_evidence(
            request_id,
            MessagingEvidenceKind::AccountStatePackage,
            context,
            digest,
            &package,
        );
        assert!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(
                    [0x44; 16],
                    [0x44; 16],
                    &response,
                    finalized_at + 3,
                )
                .unwrap_err()
                .to_string()
                .contains("subject mismatch")
        );
        assert!(
            store
                .pending_message_evidence(request_id)
                .unwrap()
                .is_none()
        );
        let count: u64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM eth_verified_account_imports",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn invalid_or_revoked_composite_receipt_never_partially_imports() {
        let (package, _, tx_hash, finalized_at) = finalized_receipt_package();

        for (case, root, revoke, mutate) in [
            ("wrong root", [0x91; 32], false, false),
            ("revoked", REAL_CHECKPOINT_ROOT, true, false),
            ("invalid proof", REAL_CHECKPOINT_ROOT, false, true),
            (
                "missing local transaction",
                REAL_CHECKPOINT_ROOT,
                false,
                false,
            ),
        ] {
            let profile = tempfile::tempdir().unwrap();
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            crate::bootstrap::install_test_active_checkpoint(&mut store, root, finalized_at);
            let request_id = match case {
                "wrong root" => [0xe1; 16],
                "revoked" => [0xe2; 16],
                "invalid proof" => [0xe3; 16],
                _ => [0xe4; 16],
            };
            let mut received = package.clone();
            if mutate {
                *received.last_mut().unwrap() ^= 1;
            }
            let context = insert_composite_request(
                &mut store,
                request_id,
                MessagingEvidenceKind::FinalizedReceiptPackage,
                tx_hash,
                u32::try_from(received.len()).unwrap(),
                finalized_at,
            );
            retain_composite_response(
                &mut store,
                request_id,
                MessagingEvidenceKind::FinalizedReceiptPackage,
                context,
                &received,
                finalized_at + 1,
            );
            if revoke {
                store
                    .record_checkpoint_revocation(
                        SEPOLIA_CHAIN_ID,
                        root,
                        [0x92; 32],
                        finalized_at + 3,
                    )
                    .unwrap();
            }
            assert!(
                store
                    .process_pending_message_evidence_at(request_id, finalized_at + 4)
                    .is_err(),
                "{case} unexpectedly imported"
            );
            let counts: (u64, u64, u64, u64) = store
                .connection
                .query_row(
                    "SELECT
                        (SELECT count(*) FROM eth_verified_finalized_headers),
                        (SELECT count(*) FROM eth_verified_execution_blocks),
                        (SELECT count(*) FROM eth_verified_receipts),
                        (SELECT count(*) FROM eth_verified_receipt_targets)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(counts, (0, 0, 0, 0), "{case} left authoritative rows");
            assert_eq!(
                store.message_request_status(request_id).unwrap(),
                Some(MessageRequestStatus::PendingVerification)
            );
            assert!(
                store
                    .pending_message_evidence(request_id)
                    .unwrap()
                    .is_some()
            );
            assert!(store.transaction_assurance(tx_hash).unwrap().is_none());
        }
    }
}
