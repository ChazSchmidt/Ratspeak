//! Sepolia proof-bundle construction for a gateway process.
//!
//! This crate accepts untrusted RPC response data and includes a bounded
//! operator-configured HTTPS execution provider. Endpoint credentials remain
//! process-local and are not durable gateway state. Its LXMF edge independently
//! reverifies one narrowly configured native attachment and emits unsigned
//! router intents; no signing identity, router, or daemon loop is included.
//! Bundle bytes are exposed only after the transport-neutral verifier checks
//! them from a separately supplied checkpoint anchor. A gateway result is still
//! non-authoritative; every receiving field node must verify it again.

use std::fmt;

mod beacon;
mod execution;
mod live_provider;
mod lxmf_service;
mod messaging;
mod provider;
mod receipt_backend;

pub use beacon::{
    BeaconCheckpointCard, BeaconClientError, BeaconConsensusClient, BeaconHttpPolicy,
    BeaconHttpResponse, BeaconHttpTransport, BeaconOperatorAuthorization,
    ReqwestBeaconHttpTransport,
};
pub use execution::{
    GatewayExecutionError, GatewayExecutionOutcome, GatewayExecutionPolicy,
    GatewayExecutionProvider, GatewayExecutor, GatewayProviderFailure, RelayProviderObservation,
    RelayProviderStatus,
};
pub use live_provider::{
    LiveProviderError, LiveSepoliaGatewayProvider, VerifiedConsensusFloor,
    VerifiedConsensusFloorSink,
};
pub use lxmf_service::{
    GATEWAY_LXMF_ATTACHMENT_NAME, GatewayLxmfFrameKind, GatewayLxmfOutboundIntent,
    GatewayLxmfService, GatewayLxmfServiceError, GatewayLxmfServiceOutcome,
};

pub use provider::{
    EvmAnchorRpcProvider, ExactReceiptProofBackend, GatewayHttpResponse, GatewayHttpTransport,
    HttpEndpointPolicy, HttpTransportFailure, OperatorAuthorization, ProviderConfigurationError,
    ProviderHttpPolicy, ReqwestGatewayHttpTransport, SepoliaRpcProvider, SystemUnixClock,
    UnixClock, UnsupportedReceiptProofBackend, UntrustedReceiptLocation,
    VerifiedStorageEvidenceBundles,
};
pub use receipt_backend::CompleteBlockReceiptProofBackend;

pub use messaging::{
    AcceptedBulkApproval, AcceptedEvidenceRequest, AcceptedSignedRelay,
    AcceptedTransactionStatusRequest, AuthenticatedGatewayEnvelope, DurableGatewayAdmission,
    DurableGatewayOutcome, EvidenceCheckpointContext, GatewayAdmissionError, GatewayJob,
    GatewayJobKind, GatewayJobState, GatewayLease, GatewayMessageError, GatewayMessageOutcome,
    GatewayRateLimit, GatewayRelayGuard, GatewayResultKind, GatewayStoredResult,
    MessagingEvidenceKind, RelayObservation, TransactionPresence, TransactionStatusHead,
    TransactionStatusObservation,
};

use ratspeak_eth_verifier::{
    BeaconCheckpointRoot, KIND_EXECUTION_HEADER_PROOF, KIND_FINALIZED_TX_RECEIPT_PROOF,
    KIND_PINNED_CONSENSUS_BOOTSTRAP, KIND_STORAGE_PROOF, KIND_TX_RECEIPT_PROOF, MAGIC,
    MAX_ANCESTRY_HEADER_BYTES, MAX_ANCESTRY_HEADERS, MAX_BUNDLE_BYTES, MAX_PROOF_NODE_BYTES,
    MAX_PROOF_NODES, MemoryAccountStore, OpStackSequencerAnchor, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK,
    U256, VERSION, VerifiedAccount, VerifiedEvmAnchor, VerifiedExecutionBlock,
    VerifiedExecutionHeader, Verifier, chain_definition,
};

const KIND_ACCOUNT_PROOF: u8 = 3;
const MAX_BOOTSTRAP_BYTES: usize = 1024 * 1024;
const MAX_CONSENSUS_UPDATE_BYTES: usize = 512 * 1024;
const MAX_CONSENSUS_UPDATES: usize = 128;
const MAX_EXECUTION_HEADER_BYTES: usize = 1024 * 1024;
const MAX_OP_STACK_COMMITMENT_BYTES: usize = 1024 * 1024;
const MAX_OP_STACK_L2_HEADER_BYTES: usize = 64 * 1024;
const MAX_TRANSACTION_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_BYTES: usize = 512 * 1024;

pub type Result<T> = std::result::Result<T, GatewayBuildError>;

/// A deliberately redacted gateway error.
///
/// RPC adapters may log provider diagnostics in their own protected context,
/// but must not add endpoint URLs, authorization values, or response bodies to
/// this error before it crosses a process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayBuildError {
    #[error("gateway input uses an unsupported chain/network")]
    UnsupportedNetwork,
    #[error("gateway input contains an empty required payload")]
    EmptyPayload,
    #[error("gateway input exceeds a configured size limit")]
    SizeLimit,
    #[error("gateway input contains too many items")]
    TooManyItems,
    #[error("gateway input length cannot be represented on the wire")]
    LengthOverflow,
    #[error("local Ethereum verification rejected the gateway input")]
    LocalVerificationFailed,
}

/// Decoded Beacon RPC material. Every field remains untrusted until verified.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedConsensusRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub bootstrap_ssz: Vec<u8>,
    pub updates_ssz: Vec<Vec<u8>>,
    pub finality_update_ssz: Option<Vec<u8>>,
}

impl fmt::Debug for UntrustedConsensusRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedConsensusRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("bootstrap_ssz_len", &self.bootstrap_ssz.len())
            .field("updates_count", &self.updates_ssz.len())
            .field("updates_total_bytes", &total_bytes(&self.updates_ssz))
            .field(
                "finality_update_len",
                &self.finality_update_ssz.as_ref().map(Vec::len),
            )
            .finish()
    }
}

/// An execution header returned as canonical RLP by an RPC adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedExecutionHeaderRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub rlp_header: Vec<u8>,
}

impl fmt::Debug for UntrustedExecutionHeaderRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedExecutionHeaderRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("rlp_header_len", &self.rlp_header.len())
            .finish()
    }
}

/// Decoded `eth_getProof` account evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedAccountProofRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub address: [u8; 20],
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
}

impl fmt::Debug for UntrustedAccountProofRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedAccountProofRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("block_number", &self.block_number)
            .field("account_proof_count", &self.account_proof.len())
            .field("account_proof_bytes", &total_bytes(&self.account_proof))
            .finish()
    }
}

/// Decoded EIP-1186 storage evidence for one slot under an already verified
/// contract account.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedStorageProofRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub account_address: [u8; 20],
    pub storage_root: [u8; 32],
    pub key: [u8; 32],
    pub value: U256,
    pub proof: Vec<Vec<u8>>,
}

impl fmt::Debug for UntrustedStorageProofRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedStorageProofRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("block_number", &self.block_number)
            .field("proof_count", &self.proof.len())
            .field("proof_bytes", &total_bytes(&self.proof))
            .finish()
    }
}

/// Exact transaction and receipt evidence returned by a proof-capable adapter.
///
/// G1 does not fetch whole blocks or derive these MPT proof nodes. Adapters
/// supplying them are untrusted; local verification authenticates both values
/// at the same transaction index before bytes can be emitted.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedTxReceiptProofRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub tx_index: u64,
    pub raw_tx: Vec<u8>,
    pub receipt: Vec<u8>,
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub tx_proof: Vec<Vec<u8>>,
    pub receipt_proof: Vec<Vec<u8>>,
}

/// Exact descendant-to-target execution headers returned by an untrusted RPC.
/// The headers are ordered from the finalized anchor's parent down to target.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedExecutionAncestryRpcInput {
    pub chain_id: u64,
    pub network: String,
    pub captured_at_unix: u64,
    pub anchor_block_number: u64,
    pub anchor_block_hash: [u8; 32],
    pub target_block_number: u64,
    pub target_block_hash: [u8; 32],
    pub rlp_headers: Vec<Vec<u8>>,
}

impl fmt::Debug for UntrustedExecutionAncestryRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedExecutionAncestryRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("anchor_block_number", &self.anchor_block_number)
            .field("target_block_number", &self.target_block_number)
            .field("header_count", &self.rlp_headers.len())
            .field("header_bytes", &total_bytes(&self.rlp_headers))
            .finish()
    }
}

impl fmt::Debug for UntrustedTxReceiptProofRpcInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedTxReceiptProofRpcInput")
            .field("chain_id", &self.chain_id)
            .field("network_len", &self.network.len())
            .field("captured_at_unix", &self.captured_at_unix)
            .field("block_number", &self.block_number)
            .field("tx_index", &self.tx_index)
            .field("raw_tx_len", &self.raw_tx.len())
            .field("receipt_len", &self.receipt.len())
            .field("tx_proof_count", &self.tx_proof.len())
            .field("tx_proof_bytes", &total_bytes(&self.tx_proof))
            .field("receipt_proof_count", &self.receipt_proof.len())
            .field("receipt_proof_bytes", &total_bytes(&self.receipt_proof))
            .finish()
    }
}

/// A bundle that was locally checked before being exposed by this crate.
///
/// This type records a gateway-side validation result, not transport authority
/// or receiving-application trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayBundle {
    kind: GatewayBundleKind,
    bytes: Vec<u8>,
}

impl GatewayBundle {
    pub fn kind(&self) -> GatewayBundleKind {
        self.kind
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayBundleKind {
    ConsensusBootstrap,
    ExecutionHeader,
    AccountProof,
    StorageProof,
    TxReceiptProof,
    AccountStateEvidence,
    FinalizedReceiptEvidence,
}

/// A locally verified checkpoint-to-execution builder.
///
/// The supplied `BeaconCheckpointRoot` is a verification input. This crate
/// does not decide whether the application approved or cross-checked it.
pub struct SepoliaGatewayBuilder {
    checkpoint_root: [u8; 32],
    consensus_bundle: GatewayBundle,
    execution_bundle: GatewayBundle,
    verified_consensus: VerifiedExecutionHeader,
    verified_execution: VerifiedExecutionBlock,
}

impl SepoliaGatewayBuilder {
    /// Builds and verifies the kind-12 and kind-6 anchor bundles.
    pub fn from_untrusted_rpc(
        checkpoint: &BeaconCheckpointRoot,
        consensus: &UntrustedConsensusRpcInput,
        execution: &UntrustedExecutionHeaderRpcInput,
    ) -> Result<Self> {
        Self::from_untrusted_rpc_with_verifier(consensus, execution, |bytes, verifier| {
            verifier.verify_consensus_bootstrap(bytes, checkpoint)
        })
    }

    /// Builds an anchor using an explicit trusted daemon clock sample.
    pub fn from_untrusted_rpc_at_unix(
        checkpoint: &BeaconCheckpointRoot,
        consensus: &UntrustedConsensusRpcInput,
        execution: &UntrustedExecutionHeaderRpcInput,
        now_unix: u64,
    ) -> Result<Self> {
        Self::from_untrusted_rpc_with_verifier(consensus, execution, |bytes, verifier| {
            verifier.verify_consensus_bootstrap_at_unix(bytes, checkpoint, now_unix)
        })
    }

    fn from_untrusted_rpc_with_verifier(
        consensus: &UntrustedConsensusRpcInput,
        execution: &UntrustedExecutionHeaderRpcInput,
        verify: impl FnOnce(&[u8], &Verifier) -> ratspeak_eth_verifier::Result<VerifiedExecutionHeader>,
    ) -> Result<Self> {
        let consensus_bytes = encode_consensus_bootstrap(consensus)?;
        let execution_bytes = encode_execution_header(execution)?;
        let verifier = Verifier::sepolia();
        let verified_consensus = verify(&consensus_bytes, &verifier)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        let verified_execution = verifier
            .verify_execution_header(&execution_bytes, &verified_consensus)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;

        Ok(Self {
            checkpoint_root: verified_consensus.checkpoint_root(),
            consensus_bundle: GatewayBundle {
                kind: GatewayBundleKind::ConsensusBootstrap,
                bytes: consensus_bytes,
            },
            execution_bundle: GatewayBundle {
                kind: GatewayBundleKind::ExecutionHeader,
                bytes: execution_bytes,
            },
            verified_consensus,
            verified_execution,
        })
    }

    pub fn consensus_bundle(&self) -> &GatewayBundle {
        &self.consensus_bundle
    }

    /// Independently configured root used to verify this builder.
    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn execution_bundle(&self) -> &GatewayBundle {
        &self.execution_bundle
    }

    /// Finalized execution block selected by the locally verified anchor.
    pub fn execution_block_number(&self) -> u64 {
        self.verified_execution.execution_block_number()
    }

    pub fn finalized_slot(&self) -> u64 {
        self.verified_consensus.finalized_slot()
    }

    pub fn execution_block_hash(&self) -> [u8; 32] {
        self.verified_execution.execution_block_hash()
    }

    pub fn execution_parent_hash(&self) -> [u8; 32] {
        self.verified_execution.parent_hash()
    }

    pub fn execution_state_root(&self) -> [u8; 32] {
        self.verified_execution.state_root()
    }

    pub fn execution_transactions_root(&self) -> [u8; 32] {
        self.verified_execution.transactions_root()
    }

    pub fn execution_receipts_root(&self) -> [u8; 32] {
        self.verified_execution.receipts_root()
    }

    /// Converts the locally Helios-verified Sepolia execution block into the
    /// stack-neutral anchor consumed by OP/Nitro proof collection.
    pub fn evm_anchor(&self) -> VerifiedEvmAnchor {
        VerifiedEvmAnchor::from(&self.verified_execution)
    }

    /// Encodes account evidence and verifies it against the consensus-derived
    /// state root before exposing the bytes.
    pub fn build_account_proof(
        &self,
        input: &UntrustedAccountProofRpcInput,
    ) -> Result<GatewayBundle> {
        let bytes = encode_account_proof(input)?;
        Verifier::sepolia()
            .verify_account_from_consensus(
                &bytes,
                &self.verified_consensus,
                &mut MemoryAccountStore::default(),
            )
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::AccountProof,
            bytes,
        })
    }

    /// Wraps the consensus anchor, execution header, and exact account proof
    /// into one restart-safe response and re-verifies the complete package.
    pub fn build_account_state_evidence(
        &self,
        input: &UntrustedAccountProofRpcInput,
    ) -> Result<GatewayBundle> {
        let expected_address = input.address;
        let created_at_unix = input.captured_at_unix;
        let account = self.build_account_proof(input)?;
        let verifier = Verifier::sepolia();
        let bytes = verifier
            .build_account_state_evidence(
                created_at_unix,
                self.consensus_bundle.bytes(),
                self.execution_bundle.bytes(),
                account.bytes(),
            )
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        verifier
            .verify_account_state_evidence(
                &bytes,
                &BeaconCheckpointRoot::sepolia(self.checkpoint_root),
                expected_address,
            )
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::AccountStateEvidence,
            bytes,
        })
    }

    /// Encodes exact transaction and receipt evidence and verifies both MPT
    /// inclusions against the consensus-authenticated execution block.
    pub fn build_tx_receipt_proof(
        &self,
        input: &UntrustedTxReceiptProofRpcInput,
    ) -> Result<GatewayBundle> {
        let bytes = encode_tx_receipt_proof(input)?;
        Verifier::sepolia()
            .verify_tx_receipt(&bytes, &self.verified_execution)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::TxReceiptProof,
            bytes,
        })
    }

    /// Builds one bounded response which first authenticates the target block
    /// through exact execution ancestry, then authenticates the transaction and
    /// receipt against that target's trie roots.
    pub fn build_finalized_tx_receipt_proof(
        &self,
        ancestry: &UntrustedExecutionAncestryRpcInput,
        receipt: &UntrustedTxReceiptProofRpcInput,
    ) -> Result<GatewayBundle> {
        validate_network(ancestry.chain_id, &ancestry.network)?;
        if ancestry.anchor_block_number != self.execution_block_number()
            || ancestry.anchor_block_hash != self.execution_block_hash()
            || ancestry.target_block_number != receipt.block_number
            || ancestry.target_block_hash != receipt.block_hash
        {
            return Err(GatewayBuildError::LocalVerificationFailed);
        }
        if ancestry.rlp_headers.len() > MAX_ANCESTRY_HEADERS {
            return Err(GatewayBuildError::TooManyItems);
        }
        for header in &ancestry.rlp_headers {
            validate_payload(header, MAX_ANCESTRY_HEADER_BYTES)?;
        }
        let receipt_bytes = encode_tx_receipt_proof(receipt)?;
        let mut bytes = prelude(KIND_FINALIZED_TX_RECEIPT_PROOF);
        bytes.extend_from_slice(&ancestry.captured_at_unix.to_le_bytes());
        bytes.extend_from_slice(&ancestry.anchor_block_number.to_le_bytes());
        bytes.extend_from_slice(&ancestry.anchor_block_hash);
        bytes.extend_from_slice(&ancestry.target_block_number.to_le_bytes());
        bytes.extend_from_slice(&ancestry.target_block_hash);
        append(
            &mut bytes,
            &wire_u16(ancestry.rlp_headers.len())?.to_le_bytes(),
        )?;
        for header in &ancestry.rlp_headers {
            write_bytes(&mut bytes, header)?;
        }
        write_bytes(&mut bytes, &receipt_bytes)?;
        let bytes = finish(bytes)?;
        Verifier::sepolia()
            .verify_finalized_tx_receipt(&bytes, &self.verified_execution)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::TxReceiptProof,
            bytes,
        })
    }

    /// Wraps one exact finalized receipt with the consensus and execution
    /// anchor used to build it, then verifies the aggregate before release.
    pub fn build_finalized_receipt_evidence(
        &self,
        ancestry: &UntrustedExecutionAncestryRpcInput,
        receipt: &UntrustedTxReceiptProofRpcInput,
    ) -> Result<GatewayBundle> {
        let expected_tx_hash = receipt.tx_hash;
        let created_at_unix = ancestry.captured_at_unix;
        let receipt = self.build_finalized_tx_receipt_proof(ancestry, receipt)?;
        let verifier = Verifier::sepolia();
        let bytes = verifier
            .build_finalized_receipt_evidence(
                created_at_unix,
                self.consensus_bundle.bytes(),
                self.execution_bundle.bytes(),
                receipt.bytes(),
            )
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        verifier
            .verify_finalized_receipt_evidence(
                &bytes,
                &BeaconCheckpointRoot::sepolia(self.checkpoint_root),
                expected_tx_hash,
            )
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::FinalizedReceiptEvidence,
            bytes,
        })
    }
}

/// Compact gateway-side material for authenticating one OP Stack execution
/// anchor from Ethereum Sepolia. All fields remain untrusted on transport; the
/// phone repeats the complete verification before accepting the L2 state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpStackAnchorEvidence {
    chain_id: u64,
    system_config_account_proof: GatewayBundle,
    signer_storage_proof: GatewayBundle,
    decompressed_commitment: Vec<u8>,
    l2_header_rlp: Vec<u8>,
}

impl OpStackAnchorEvidence {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn system_config_account_proof(&self) -> &[u8] {
        self.system_config_account_proof.bytes()
    }
    pub fn signer_storage_proof(&self) -> &[u8] {
        self.signer_storage_proof.bytes()
    }
    pub fn decompressed_commitment(&self) -> &[u8] {
        &self.decompressed_commitment
    }
    pub fn l2_header_rlp(&self) -> &[u8] {
        &self.l2_header_rlp
    }

    pub fn verify(&self, l1_anchor: &VerifiedEvmAnchor) -> Result<VerifiedEvmAnchor> {
        OpStackSequencerAnchor::verify_from_l1_evidence(
            self.chain_id,
            l1_anchor,
            self.system_config_account_proof(),
            self.signer_storage_proof(),
            self.decompressed_commitment(),
            self.l2_header_rlp(),
        )
        .map_err(|_| GatewayBuildError::LocalVerificationFailed)
    }
}

/// Stack-neutral proof packager for an execution block already authenticated by
/// Ethereum, OP Stack, or Nitro verification.
///
/// RPC responses remain untrusted. Every emitted bundle is locally reverified
/// against the supplied anchor before leaving this builder.
pub struct EvmAnchorGatewayBuilder {
    anchor: VerifiedEvmAnchor,
}

impl EvmAnchorGatewayBuilder {
    pub fn new(anchor: VerifiedEvmAnchor) -> Self {
        Self { anchor }
    }

    pub fn anchor(&self) -> &VerifiedEvmAnchor {
        &self.anchor
    }

    pub fn verify_account(&self, input: &UntrustedAccountProofRpcInput) -> Result<VerifiedAccount> {
        let bytes = encode_account_proof(input)?;
        Verifier::for_chain(self.anchor.chain_id())
            .map_err(|_| GatewayBuildError::UnsupportedNetwork)?
            .verify_account_from_anchor(&bytes, &self.anchor, &mut MemoryAccountStore::default())
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)
    }

    pub fn build_account_proof(
        &self,
        input: &UntrustedAccountProofRpcInput,
    ) -> Result<GatewayBundle> {
        self.verify_account(input)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::AccountProof,
            bytes: encode_account_proof(input)?,
        })
    }

    pub fn build_storage_proof(
        &self,
        account: &VerifiedAccount,
        input: &UntrustedStorageProofRpcInput,
    ) -> Result<GatewayBundle> {
        let bytes = encode_storage_proof(input)?;
        Verifier::for_chain(self.anchor.chain_id())
            .map_err(|_| GatewayBuildError::UnsupportedNetwork)?
            .verify_storage_proof(&bytes, account)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::StorageProof,
            bytes,
        })
    }

    /// Packages the L1 SystemConfig account/storage proofs with one signed OP
    /// execution commitment and matching L2 header, then locally verifies the
    /// exact package before returning it.
    pub fn build_op_stack_anchor_evidence(
        &self,
        l2_chain_id: u64,
        account_input: &UntrustedAccountProofRpcInput,
        storage_input: &UntrustedStorageProofRpcInput,
        decompressed_commitment: &[u8],
        l2_header_rlp: &[u8],
    ) -> Result<OpStackAnchorEvidence> {
        if self.anchor.chain_id() != SEPOLIA_CHAIN_ID {
            return Err(GatewayBuildError::UnsupportedNetwork);
        }
        if decompressed_commitment.is_empty()
            || decompressed_commitment.len() > MAX_OP_STACK_COMMITMENT_BYTES
            || l2_header_rlp.is_empty()
            || l2_header_rlp.len() > MAX_OP_STACK_L2_HEADER_BYTES
        {
            return Err(GatewayBuildError::SizeLimit);
        }
        let account = self.verify_account(account_input)?;
        let account_bundle = self.build_account_proof(account_input)?;
        let storage_bundle = self.build_storage_proof(&account, storage_input)?;
        let evidence = OpStackAnchorEvidence {
            chain_id: l2_chain_id,
            system_config_account_proof: account_bundle,
            signer_storage_proof: storage_bundle,
            decompressed_commitment: decompressed_commitment.to_vec(),
            l2_header_rlp: l2_header_rlp.to_vec(),
        };
        evidence.verify(&self.anchor)?;
        Ok(evidence)
    }

    pub fn build_tx_receipt_proof(
        &self,
        input: &UntrustedTxReceiptProofRpcInput,
    ) -> Result<GatewayBundle> {
        let bytes = encode_tx_receipt_proof(input)?;
        Verifier::for_chain(self.anchor.chain_id())
            .map_err(|_| GatewayBuildError::UnsupportedNetwork)?
            .verify_tx_receipt_from_anchor(&bytes, &self.anchor)
            .map_err(|_| GatewayBuildError::LocalVerificationFailed)?;
        Ok(GatewayBundle {
            kind: GatewayBundleKind::TxReceiptProof,
            bytes,
        })
    }
}

fn encode_consensus_bootstrap(input: &UntrustedConsensusRpcInput) -> Result<Vec<u8>> {
    validate_network(input.chain_id, &input.network)?;
    validate_payload(&input.bootstrap_ssz, MAX_BOOTSTRAP_BYTES)?;
    if input.updates_ssz.len() > MAX_CONSENSUS_UPDATES {
        return Err(GatewayBuildError::TooManyItems);
    }
    for update in &input.updates_ssz {
        validate_payload(update, MAX_CONSENSUS_UPDATE_BYTES)?;
    }
    if let Some(finality) = &input.finality_update_ssz {
        validate_payload(finality, MAX_CONSENSUS_UPDATE_BYTES)?;
    }

    let mut out = prelude(KIND_PINNED_CONSENSUS_BOOTSTRAP);
    out.extend_from_slice(&input.captured_at_unix.to_le_bytes());
    write_bytes(&mut out, &input.bootstrap_ssz)?;
    append(&mut out, &wire_u16(input.updates_ssz.len())?.to_le_bytes())?;
    for update in &input.updates_ssz {
        write_bytes(&mut out, update)?;
    }
    match &input.finality_update_ssz {
        Some(finality) => {
            out.push(1);
            write_bytes(&mut out, finality)?;
        }
        None => out.push(0),
    }
    finish(out)
}

fn encode_execution_header(input: &UntrustedExecutionHeaderRpcInput) -> Result<Vec<u8>> {
    validate_network(input.chain_id, &input.network)?;
    validate_payload(&input.rlp_header, MAX_EXECUTION_HEADER_BYTES)?;
    let mut out = prelude_for(input.chain_id, &input.network, KIND_EXECUTION_HEADER_PROOF)?;
    out.extend_from_slice(&input.captured_at_unix.to_le_bytes());
    write_bytes(&mut out, &input.rlp_header)?;
    finish(out)
}

fn encode_account_proof(input: &UntrustedAccountProofRpcInput) -> Result<Vec<u8>> {
    validate_network(input.chain_id, &input.network)?;
    validate_nodes(&input.account_proof)?;
    let mut out = prelude_for(input.chain_id, &input.network, KIND_ACCOUNT_PROOF)?;
    out.extend_from_slice(&input.captured_at_unix.to_le_bytes());
    out.extend_from_slice(&input.block_number.to_le_bytes());
    out.extend_from_slice(&input.block_hash);
    out.extend_from_slice(&input.state_root);
    out.extend_from_slice(&input.address);
    out.extend_from_slice(&input.balance.to_be_bytes::<32>());
    out.extend_from_slice(&input.nonce.to_le_bytes());
    out.extend_from_slice(&input.code_hash);
    out.extend_from_slice(&input.storage_root);
    write_nodes(&mut out, &input.account_proof)?;
    finish(out)
}

fn encode_storage_proof(input: &UntrustedStorageProofRpcInput) -> Result<Vec<u8>> {
    validate_network(input.chain_id, &input.network)?;
    validate_nodes(&input.proof)?;
    let mut out = prelude_for(input.chain_id, &input.network, KIND_STORAGE_PROOF)?;
    out.extend_from_slice(&input.captured_at_unix.to_le_bytes());
    out.extend_from_slice(&input.block_number.to_le_bytes());
    out.extend_from_slice(&input.block_hash);
    out.extend_from_slice(&input.account_address);
    out.extend_from_slice(&input.storage_root);
    out.extend_from_slice(&input.key);
    out.extend_from_slice(&input.value.to_be_bytes::<32>());
    write_nodes(&mut out, &input.proof)?;
    finish(out)
}

fn encode_tx_receipt_proof(input: &UntrustedTxReceiptProofRpcInput) -> Result<Vec<u8>> {
    validate_network(input.chain_id, &input.network)?;
    validate_payload(&input.raw_tx, MAX_TRANSACTION_BYTES)?;
    validate_payload(&input.receipt, MAX_RECEIPT_BYTES)?;
    validate_nodes(&input.tx_proof)?;
    validate_nodes(&input.receipt_proof)?;
    let mut out = prelude_for(input.chain_id, &input.network, KIND_TX_RECEIPT_PROOF)?;
    out.extend_from_slice(&input.captured_at_unix.to_le_bytes());
    out.extend_from_slice(&input.block_number.to_le_bytes());
    out.extend_from_slice(&input.block_hash);
    out.extend_from_slice(&input.tx_hash);
    out.extend_from_slice(&input.tx_index.to_le_bytes());
    write_bytes(&mut out, &input.raw_tx)?;
    write_bytes(&mut out, &input.receipt)?;
    out.extend_from_slice(&input.transactions_root);
    out.extend_from_slice(&input.receipts_root);
    write_nodes(&mut out, &input.tx_proof)?;
    write_nodes(&mut out, &input.receipt_proof)?;
    finish(out)
}

fn validate_network(chain_id: u64, network: &str) -> Result<()> {
    let Some(definition) = chain_definition(chain_id) else {
        return Err(GatewayBuildError::UnsupportedNetwork);
    };
    if definition.network != network {
        return Err(GatewayBuildError::UnsupportedNetwork);
    }
    Ok(())
}

fn validate_payload(payload: &[u8], max: usize) -> Result<()> {
    if payload.is_empty() {
        return Err(GatewayBuildError::EmptyPayload);
    }
    if payload.len() > max {
        return Err(GatewayBuildError::SizeLimit);
    }
    Ok(())
}

fn validate_nodes(nodes: &[Vec<u8>]) -> Result<()> {
    if nodes.is_empty() {
        return Err(GatewayBuildError::EmptyPayload);
    }
    if nodes.len() > MAX_PROOF_NODES {
        return Err(GatewayBuildError::TooManyItems);
    }
    for node in nodes {
        validate_payload(node, MAX_PROOF_NODE_BYTES)?;
    }
    Ok(())
}

fn total_bytes(values: &[Vec<u8>]) -> usize {
    values
        .iter()
        .fold(0_usize, |total, value| total.saturating_add(value.len()))
}

fn prelude(kind: u8) -> Vec<u8> {
    prelude_for(SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, kind).expect("Sepolia is a built-in network")
}

fn prelude_for(chain_id: u64, network: &str, kind: u8) -> Result<Vec<u8>> {
    validate_network(chain_id, network)?;
    let network_len = wire_u16(network.len())?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&network_len.to_le_bytes());
    out.extend_from_slice(network.as_bytes());
    out.push(kind);
    Ok(out)
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    append(out, &wire_u32(value.len())?.to_le_bytes())?;
    append(out, value)?;
    Ok(())
}

fn write_nodes(out: &mut Vec<u8>, nodes: &[Vec<u8>]) -> Result<()> {
    append(out, &wire_u32(nodes.len())?.to_le_bytes())?;
    for node in nodes {
        write_bytes(out, node)?;
    }
    Ok(())
}

fn wire_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| GatewayBuildError::LengthOverflow)
}

fn wire_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| GatewayBuildError::LengthOverflow)
}

fn append(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let new_len = out
        .len()
        .checked_add(value.len())
        .ok_or(GatewayBuildError::LengthOverflow)?;
    if new_len > MAX_BUNDLE_BYTES {
        return Err(GatewayBuildError::SizeLimit);
    }
    out.extend_from_slice(value);
    Ok(())
}

fn finish(out: Vec<u8>) -> Result<Vec<u8>> {
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(GatewayBuildError::SizeLimit);
    }
    Ok(out)
}

// Trusted fixture-era clock for captured Sepolia proofs. Keep historical tests
// independent of wall time without relaxing production checkpoint freshness.
#[cfg(test)]
pub(crate) const FIXTURE_NOW_UNIX: u64 = 1_788_034_160;

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, keccak256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount};
    use base64::Engine;
    use ratspeak_eth_verifier::{PinnedCheckpoint, VerifyError};
    use sha2::{Digest, Sha256};

    use super::*;

    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    fn decode(value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .unwrap()
    }

    fn sha256(value: &[u8]) -> [u8; 32] {
        Sha256::digest(value).into()
    }

    fn consensus_input() -> UntrustedConsensusRpcInput {
        UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: 0,
            bootstrap_ssz: decode(include_str!(
                "../../ratspeak-eth-verifier/tests/fixtures/sepolia-bootstrap-343888.ssz.b64"
            )),
            updates_ssz: Vec::new(),
            finality_update_ssz: None,
        }
    }

    fn execution_input() -> UntrustedExecutionHeaderRpcInput {
        let captured = decode(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-execution-header-11574048.rseth.b64"
        ));
        let parsed = Verifier::sepolia()
            .parse_execution_header_proof(&captured)
            .unwrap();
        UntrustedExecutionHeaderRpcInput {
            chain_id: parsed.chain_id,
            network: parsed.network,
            captured_at_unix: parsed.created_at_unix,
            rlp_header: parsed.rlp_header,
        }
    }

    fn receipt_input() -> UntrustedTxReceiptProofRpcInput {
        let captured = decode(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(&captured)
            .unwrap();
        UntrustedTxReceiptProofRpcInput {
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
        }
    }

    fn builder() -> SepoliaGatewayBuilder {
        SepoliaGatewayBuilder::from_untrusted_rpc_at_unix(
            &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            &consensus_input(),
            &execution_input(),
            FIXTURE_NOW_UNIX,
        )
        .unwrap()
    }

    #[test]
    fn sepolia_builder_exports_ethereum_finalized_shared_anchor() {
        let anchor = builder().evm_anchor();
        assert_eq!(anchor.chain_id(), SEPOLIA_CHAIN_ID);
        assert_eq!(anchor.network(), SEPOLIA_NETWORK);
        assert_eq!(
            anchor.assurance(),
            ratspeak_eth_verifier::AnchorAssurance::EthereumFinalized
        );
        assert_ne!(anchor.state_root(), [0; 32]);
    }

    #[test]
    fn anchor_and_receipt_are_byte_stable_and_verifier_accepted() {
        let builder = builder();
        let expected_execution = decode(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-execution-header-11574048.rseth.b64"
        ));
        assert_eq!(builder.execution_bundle().bytes(), expected_execution);
        assert_eq!(
            builder.consensus_bundle().bytes(),
            encode_consensus_bootstrap(&consensus_input()).unwrap()
        );
        assert_eq!(
            sha256(builder.consensus_bundle().bytes()),
            [
                0xab, 0x4e, 0x72, 0xd6, 0x8e, 0x97, 0x61, 0xa1, 0x7e, 0xb1, 0x86, 0xe9, 0xa5, 0x32,
                0x82, 0x25, 0x8a, 0xaa, 0x66, 0x8e, 0x80, 0xa8, 0x7f, 0x4f, 0x9a, 0x1f, 0xa0, 0xeb,
                0xf4, 0x4e, 0x97, 0x92,
            ]
        );

        let receipt = builder.build_tx_receipt_proof(&receipt_input()).unwrap();
        let expected_receipt = decode(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        assert_eq!(receipt.bytes(), expected_receipt);
        assert_eq!(receipt.kind(), GatewayBundleKind::TxReceiptProof);
    }

    #[test]
    fn finalized_receipt_envelope_is_locally_verified_even_at_anchor() {
        let builder = builder();
        let receipt = receipt_input();
        let ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: receipt.captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: receipt.block_number,
            target_block_hash: receipt.block_hash,
            rlp_headers: vec![],
        };
        let bundle = builder
            .build_finalized_tx_receipt_proof(&ancestry, &receipt)
            .unwrap();
        assert_eq!(bundle.kind(), GatewayBundleKind::TxReceiptProof);
        let parsed = Verifier::sepolia()
            .parse_finalized_tx_receipt_proof(bundle.bytes())
            .unwrap();
        assert_eq!(parsed.receipt_proof.tx_hash, receipt.tx_hash);
        assert!(parsed.ancestry_headers.is_empty());
        Verifier::sepolia()
            .verify_finalized_tx_receipt(bundle.bytes(), &builder.verified_execution)
            .unwrap();
    }

    #[test]
    fn finalized_receipt_package_is_byte_stable_and_exactly_context_bound() {
        let builder = builder();
        let receipt = receipt_input();
        let ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: receipt.captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: receipt.block_number,
            target_block_hash: receipt.block_hash,
            rlp_headers: vec![],
        };
        let first = builder
            .build_finalized_receipt_evidence(&ancestry, &receipt)
            .unwrap();
        let second = builder
            .build_finalized_receipt_evidence(&ancestry, &receipt)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.kind(), GatewayBundleKind::FinalizedReceiptEvidence);
        assert!(first.bytes().len() <= ratspeak_eth_verifier::MAX_COMPOSITE_EVIDENCE_BYTES);
        Verifier::sepolia()
            .verify_finalized_receipt_evidence(
                first.bytes(),
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                receipt.tx_hash,
            )
            .unwrap();
        assert!(
            Verifier::sepolia()
                .verify_finalized_receipt_evidence(
                    first.bytes(),
                    &BeaconCheckpointRoot::sepolia([0x55; 32]),
                    receipt.tx_hash,
                )
                .is_err()
        );
        assert!(
            Verifier::sepolia()
                .verify_finalized_receipt_evidence(
                    first.bytes(),
                    &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                    [0x66; 32],
                )
                .is_err()
        );
    }

    #[test]
    fn finalized_receipt_builder_rejects_unbounded_or_mismatched_ancestry() {
        let builder = builder();
        let receipt = receipt_input();
        let mut ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: receipt.captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: receipt.block_number,
            target_block_hash: receipt.block_hash,
            rlp_headers: vec![vec![1]; MAX_ANCESTRY_HEADERS + 1],
        };
        assert_eq!(
            builder.build_finalized_tx_receipt_proof(&ancestry, &receipt),
            Err(GatewayBuildError::TooManyItems)
        );
        ancestry.rlp_headers.clear();
        ancestry.target_block_hash[0] ^= 1;
        assert_eq!(
            builder.build_finalized_tx_receipt_proof(&ancestry, &receipt),
            Err(GatewayBuildError::LocalVerificationFailed)
        );
    }

    #[test]
    fn account_encoding_is_byte_stable_and_verifier_accepted() {
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
        let account_proof = trie
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();
        let input = UntrustedAccountProofRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: 1_780_000_000,
            block_number: 42,
            block_hash: [0x22; 32],
            state_root,
            address,
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash.0,
            storage_root: account.storage_root.0,
            account_proof,
        };

        let first = encode_account_proof(&input).unwrap();
        let second = encode_account_proof(&input).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            sha256(&first),
            [
                0xf7, 0x6a, 0x19, 0x8b, 0x99, 0xd2, 0x33, 0x52, 0x38, 0x2f, 0x66, 0xe4, 0xd9, 0xa3,
                0x3d, 0x07, 0xae, 0xf4, 0xd5, 0x34, 0xe4, 0x17, 0x17, 0x6b, 0xaa, 0x8d, 0xa6, 0x83,
                0x29, 0xd8, 0xa7, 0x2d,
            ]
        );
        let parsed = Verifier::sepolia().parse_account_proof(&first).unwrap();
        assert_eq!(parsed.address, address);
        Verifier::sepolia()
            .verify_and_import(
                &first,
                &PinnedCheckpoint::sepolia(42, [0x22; 32], state_root),
                &mut MemoryAccountStore::default(),
            )
            .unwrap();
    }

    #[test]
    fn rejects_wrong_network_empty_oversized_and_excessive_inputs() {
        let mut consensus = consensus_input();
        consensus.chain_id = 1;
        assert_eq!(
            encode_consensus_bootstrap(&consensus),
            Err(GatewayBuildError::UnsupportedNetwork)
        );

        let mut consensus = consensus_input();
        consensus.bootstrap_ssz = vec![1; MAX_BOOTSTRAP_BYTES];
        consensus.updates_ssz = vec![vec![2; MAX_CONSENSUS_UPDATE_BYTES]; 2];
        assert_eq!(
            encode_consensus_bootstrap(&consensus),
            Err(GatewayBuildError::SizeLimit)
        );

        let mut execution = execution_input();
        execution.rlp_header.clear();
        assert_eq!(
            encode_execution_header(&execution),
            Err(GatewayBuildError::EmptyPayload)
        );

        execution.rlp_header = vec![0; MAX_EXECUTION_HEADER_BYTES + 1];
        assert_eq!(
            encode_execution_header(&execution),
            Err(GatewayBuildError::SizeLimit)
        );

        let mut receipt = receipt_input();
        receipt.tx_proof = vec![vec![1]; MAX_PROOF_NODES + 1];
        assert_eq!(
            encode_tx_receipt_proof(&receipt),
            Err(GatewayBuildError::TooManyItems)
        );
    }

    #[test]
    fn malformed_or_inconsistent_rpc_evidence_is_not_emitted() {
        let mut execution = execution_input();
        execution.rlp_header[0] ^= 1;
        assert!(matches!(
            SepoliaGatewayBuilder::from_untrusted_rpc_at_unix(
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                &consensus_input(),
                &execution,
                FIXTURE_NOW_UNIX,
            ),
            Err(GatewayBuildError::LocalVerificationFailed)
        ));

        let builder = builder();
        let mut receipt = receipt_input();
        receipt.tx_hash[0] ^= 1;
        assert_eq!(
            builder.build_tx_receipt_proof(&receipt),
            Err(GatewayBuildError::LocalVerificationFailed)
        );
    }

    #[test]
    fn checkpoint_root_is_separate_from_consensus_wire_data() {
        let bytes = encode_consensus_bootstrap(&consensus_input()).unwrap();
        let parsed = Verifier::sepolia()
            .parse_consensus_bootstrap(&bytes)
            .unwrap();
        assert_eq!(parsed.bootstrap_ssz, consensus_input().bootstrap_ssz);
        assert!(matches!(
            Verifier::sepolia().verify_consensus_bootstrap_at_unix(
                &bytes,
                &BeaconCheckpointRoot::sepolia([0; 32]),
                FIXTURE_NOW_UNIX,
            ),
            Err(VerifyError::ConsensusVerification(_))
        ));
    }

    #[test]
    fn gateway_errors_do_not_echo_rpc_material() {
        let error = GatewayBuildError::LocalVerificationFailed.to_string();
        assert_eq!(
            error,
            "local Ethereum verification rejected the gateway input"
        );
        assert!(!error.contains("http"));
        assert!(!error.contains("authorization"));
    }

    #[test]
    fn untrusted_input_debug_is_redacted_and_bounded() {
        const MARKER: &str = "https://secret.invalid/DEBUG_MARKER";
        let marker_bytes = MARKER.as_bytes().to_vec();
        let large_marker_bytes = MARKER.as_bytes().repeat(128);
        let marker_debug = format!("{:?}", MARKER.as_bytes());

        let consensus = UntrustedConsensusRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: MARKER.to_owned(),
            captured_at_unix: 7,
            bootstrap_ssz: marker_bytes.clone(),
            updates_ssz: vec![large_marker_bytes.clone(), large_marker_bytes.clone()],
            finality_update_ssz: Some(large_marker_bytes.clone()),
        };
        let execution = UntrustedExecutionHeaderRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: MARKER.to_owned(),
            captured_at_unix: 8,
            rlp_header: marker_bytes.clone(),
        };
        let account = UntrustedAccountProofRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: MARKER.to_owned(),
            captured_at_unix: 9,
            block_number: 10,
            block_hash: [0x44; 32],
            state_root: [0x44; 32],
            address: [0x44; 20],
            balance: U256::from(0x4444_u64),
            nonce: 11,
            code_hash: [0x44; 32],
            storage_root: [0x44; 32],
            account_proof: vec![marker_bytes.clone(), large_marker_bytes.clone()],
        };
        let receipt = UntrustedTxReceiptProofRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: MARKER.to_owned(),
            captured_at_unix: 12,
            block_number: 13,
            block_hash: [0x44; 32],
            tx_hash: [0x44; 32],
            tx_index: 14,
            raw_tx: marker_bytes.clone(),
            receipt: large_marker_bytes.clone(),
            transactions_root: [0x44; 32],
            receipts_root: [0x44; 32],
            tx_proof: vec![marker_bytes.clone()],
            receipt_proof: vec![large_marker_bytes],
        };

        for rendered in [
            format!("{consensus:?}"),
            format!("{execution:?}"),
            format!("{account:?}"),
            format!("{receipt:?}"),
        ] {
            assert!(rendered.len() < 512, "debug output was not bounded");
            assert!(!rendered.contains(MARKER));
            assert!(!rendered.contains("DEBUG_MARKER"));
            assert!(!rendered.contains("secret.invalid"));
            assert!(!rendered.contains(&marker_debug));
            assert!(!rendered.contains("[68, 68, 68"));
            assert!(!rendered.contains("17476"));
        }
    }

    #[test]
    fn captured_header_hash_is_the_expected_block() {
        let builder = builder();
        assert_eq!(
            B256::from(builder.verified_execution.execution_block_hash()),
            B256::from_slice(&[
                0x60, 0x99, 0x2b, 0xa4, 0x99, 0x4f, 0x72, 0x2f, 0x26, 0x20, 0x37, 0xf1, 0x44, 0x2d,
                0x7b, 0x15, 0xb9, 0xf6, 0x64, 0x1e, 0xd8, 0x8c, 0x3c, 0xf8, 0x37, 0xd9, 0xf9, 0x90,
                0x40, 0x36, 0x31, 0xd1,
            ])
        );
    }
}
