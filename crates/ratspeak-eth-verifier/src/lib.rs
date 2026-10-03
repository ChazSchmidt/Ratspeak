//! Transport-neutral verification for RatSpeak Ethereum proof bundles.
//!
//! Consensus verification starts from a checkpoint installed independently
//! of incoming proof bundles. A hash-matched RLP execution header supplies
//! execution trie roots that can then authenticate account and exact receipt
//! proofs without assigning authority to their transport.

use std::collections::HashMap;
use std::io::Read;

pub use alloy_primitives::U256;
use alloy_primitives::{B256, Bytes, keccak256};
use alloy_trie::proof::verify_proof;
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY, Nibbles, TrieAccount};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};

mod anchor;
mod base_sepolia;
mod chains;
mod composite;
mod consensus;
mod execution;
mod finalized_receipt;
mod manual_checkpoint;
mod nitro;
mod opstack;
mod receipt;
mod storage;

pub use anchor::{AnchorAssurance, VerifiedEvmAnchor};
pub use base_sepolia::{BaseSepoliaSequencerAnchor, VerifiedBaseSepoliaHeader};
pub use chains::{
    ARBITRUM_SEPOLIA, ARBITRUM_SEPOLIA_CHAIN_ID, BASE_SEPOLIA, BASE_SEPOLIA_CHAIN_ID,
    ChainDefinition, ETHEREUM_SEPOLIA, ETHEREUM_SEPOLIA_CHAIN_ID, NitroConfig, OP_SEPOLIA,
    OP_SEPOLIA_CHAIN_ID, OpStackConfig, ROBINHOOD_TESTNET, ROBINHOOD_TESTNET_CHAIN_ID,
    StackConfig, SUPPORTED_CHAINS, VerificationFamily, chain_definition,
};
pub use composite::{
    AccountStateEvidencePackage, FinalizedReceiptEvidencePackage, VerifiedAccountStateEvidence,
    VerifiedFinalizedReceiptEvidence,
};
pub use consensus::{
    BeaconCheckpointRoot, ConsensusBootstrapBundle, ExecutionHeaderProvenance,
    SEPOLIA_GENESIS_TIME, SEPOLIA_GENESIS_VALIDATORS_ROOT, SEPOLIA_SECONDS_PER_SLOT,
    SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD, VerifiedExecutionHeader,
    encode_pinned_consensus_bootstrap, sepolia_consensus_update_slot, sepolia_slot_at_unix,
    sepolia_slot_start_unix, split_and_tag_beacon_json_updates, tag_beacon_json_payload,
};
pub use execution::{ExecutionHeaderProofBundle, VerifiedExecutionBlock};
pub use finalized_receipt::{
    FinalizedTxReceiptProofBundle, MAX_ANCESTRY_HEADER_BYTES, MAX_ANCESTRY_HEADERS,
    VerifiedFinalizedTxReceipt,
};
pub use manual_checkpoint::{
    MAX_MANUAL_CHECKPOINT_FILE_BYTES, ManualCheckpointFile, encode_manual_checkpoint_file,
    manual_checkpoint_file_fingerprint,
};
pub use nitro::NitroConfirmedEndpoint;
pub use opstack::OpStackSequencerAnchor;
pub use receipt::{TxReceiptProofBundle, VerifiedEvmTxReceipt, VerifiedTxReceipt};
pub use storage::{StorageProofBundle, VerifiedStorageValue};

pub const MAGIC: &[u8; 6] = b"RSETH1";
pub const VERSION: u8 = 1;
pub const SEPOLIA_CHAIN_ID: u64 = ETHEREUM_SEPOLIA_CHAIN_ID;
pub const SEPOLIA_NETWORK: &str = ETHEREUM_SEPOLIA.network;
pub const BASE_SEPOLIA_NETWORK: &str = BASE_SEPOLIA.network;
pub const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
/// Aggregate limit for a self-contained evidence package transported as a Resource.
pub const MAX_COMPOSITE_EVIDENCE_BYTES: usize = MAX_BUNDLE_BYTES;
pub const MAX_PROOF_NODES: usize = 1_024;
pub const MAX_PROOF_NODE_BYTES: usize = 16 * 1024;

const KIND_FINALIZED_HEADER: u8 = 1;
const KIND_BEACON_FINALITY_BUNDLE: u8 = 2;
const KIND_ACCOUNT_PROOF: u8 = 3;
pub const KIND_TX_RECEIPT_PROOF: u8 = 5;
pub const KIND_EXECUTION_HEADER_PROOF: u8 = 6;
const KIND_COMPACT_CONSENSUS_BOOTSTRAP: u8 = 7;
const KIND_COMPRESSED_BUNDLE: u8 = 11;
pub const KIND_PINNED_CONSENSUS_BOOTSTRAP: u8 = 12;
pub const KIND_FINALIZED_TX_RECEIPT_PROOF: u8 = 13;
pub const KIND_STORAGE_PROOF: u8 = 14;
const COMPRESSION_ALGORITHM_GZIP: u8 = 1;
const MAX_NETWORK_BYTES: usize = 32;

pub type Result<T> = std::result::Result<T, VerifyError>;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("bundle exceeds the {MAX_BUNDLE_BYTES}-byte limit")]
    OversizedBundle,
    #[error("decompressed bundle exceeds the {MAX_BUNDLE_BYTES}-byte limit")]
    OversizedDecompressedBundle,
    #[error("composite evidence exceeds the {MAX_COMPOSITE_EVIDENCE_BYTES}-byte limit")]
    OversizedCompositeEvidence,
    #[error("bundle has wrong magic")]
    WrongMagic,
    #[error("unsupported bundle version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported chain/network {chain_id}/{network}")]
    UnsupportedNetwork { chain_id: u64, network: String },
    #[error("unsupported bundle kind {0}")]
    UnsupportedKind(u8),
    #[error("self-authenticated header bundles cannot establish application trust")]
    UntrustedHeader,
    #[error("nested compressed bundles are not accepted")]
    NestedCompression,
    #[error("unsupported compression algorithm {0}")]
    UnsupportedCompressionAlgorithm(u8),
    #[error("compressed bundle declares an invalid uncompressed length")]
    InvalidUncompressedLength,
    #[error("compressed bundle contains trailing gzip data")]
    TrailingCompressedData,
    #[error("compressed bundle hash mismatch")]
    CompressedBundleHashMismatch,
    #[error("malformed bundle: {0}")]
    Malformed(&'static str),
    #[error("proof contains too many nodes")]
    TooManyProofNodes,
    #[error("proof node exceeds the {MAX_PROOF_NODE_BYTES}-byte limit")]
    OversizedProofNode,
    #[error("bundle checkpoint does not match the pinned checkpoint")]
    CheckpointMismatch,
    #[error("account proof verification failed: {0}")]
    InvalidAccountProof(String),
    #[error("consensus payload is empty")]
    EmptyConsensusPayload,
    #[error("consensus payload exceeds its size limit")]
    OversizedConsensusPayload,
    #[error("consensus bundle contains too many updates")]
    TooManyConsensusUpdates,
    #[error("consensus payload decode failed: {0}")]
    ConsensusDecode(String),
    #[error("Beacon JSON exceeds a structural limit")]
    ConsensusJsonLimit,
    #[error("Beacon JSON contains a duplicate object key")]
    ConsensusJsonDuplicateKey,
    #[error("Beacon JSON does not match the required response schema")]
    ConsensusJsonSchema,
    #[error("consensus verification failed: {0}")]
    ConsensusVerification(String),
    #[error("local clock predates Sepolia genesis")]
    InvalidLocalClock,
    #[error("checkpoint anchor is newer than the local clock")]
    FutureCheckpoint,
    #[error("checkpoint anchor exceeds the local 14-day maximum age")]
    StaleCheckpoint,
    #[error("verified consensus state has no supported execution payload header")]
    MissingExecutionHeader,
    #[error("receipt proof does not match the verified execution block")]
    ReceiptHeaderMismatch,
    #[error("account proof is for a different requested address")]
    UnexpectedAccount,
    #[error("receipt proof is for a different requested transaction")]
    UnexpectedTransaction,
    #[error("execution header does not match the consensus-verified block")]
    ExecutionHeaderMismatch,
    #[error("execution header timestamp does not match its consensus slot")]
    ExecutionTimestampMismatch,
    #[error("invalid execution header: {0}")]
    InvalidExecutionHeader(String),
    #[error("execution ancestry contains too many headers")]
    TooManyAncestryHeaders,
    #[error("execution ancestry header exceeds its size limit")]
    OversizedAncestryHeader,
    #[error("execution ancestry does not form the exact parent chain to its target")]
    InvalidExecutionAncestry,
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("transaction receipt proof verification failed: {0}")]
    InvalidReceiptProof(String),
    #[error("bundle was already imported")]
    Replay,
    #[error("verified account store failed: {0}")]
    AccountStore(String),
    #[error("gzip decompression failed: {0}")]
    Decompression(#[source] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCheckpoint {
    chain_id: u64,
    network: &'static str,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
}

impl PinnedCheckpoint {
    /// Constructs a Sepolia checkpoint obtained outside the incoming bundle.
    pub fn sepolia(
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> Self {
        Self {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK,
            execution_block_number,
            execution_block_hash,
            state_root,
        }
    }

    /// Constructs a checkpoint for any supported EVM network after its
    /// stack-specific verifier has authenticated the execution block.
    pub fn for_network(
        chain_id: u64,
        network: &str,
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<Self> {
        let definition = chain_definition(chain_id).ok_or_else(|| VerifyError::UnsupportedNetwork {
            chain_id,
            network: network.to_owned(),
        })?;
        if definition.network != network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id,
                network: network.to_owned(),
            });
        }
        Ok(Self {
            chain_id,
            network: definition.network,
            execution_block_number,
            execution_block_hash,
            state_root,
        })
    }

    /// Compatibility constructor for the original Base Sepolia experiment.
    pub fn base_sepolia(
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> Self {
        Self::for_network(
            BASE_SEPOLIA_CHAIN_ID,
            BASE_SEPOLIA_NETWORK,
            execution_block_number,
            execution_block_hash,
            state_root,
        )
        .expect("Base Sepolia is a built-in chain")
    }

    pub fn execution_block_number(&self) -> u64 {
        self.execution_block_number
    }

    pub fn execution_block_hash(&self) -> [u8; 32] {
        self.execution_block_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProofBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccount {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    address: [u8; 20],
    balance: U256,
    nonce: u64,
    code_hash: [u8; 32],
    storage_root: [u8; 32],
    /// SHA-256 of the canonical uncompressed bundle bytes.
    proof_bundle_hash: [u8; 32],
}

impl VerifiedAccount {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    pub fn balance(&self) -> U256 {
        self.balance
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn code_hash(&self) -> [u8; 32] {
        self.code_hash
    }

    pub fn storage_root(&self) -> [u8; 32] {
        self.storage_root
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }

    /// Stable replay key for this verified account subject.
    pub fn semantic_import_key(&self) -> [u8; 32] {
        verified_account_import_key(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AccountStoreError(String);

impl AccountStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Stores a verified account and rejects a semantic replay atomically.
pub trait VerifiedAccountStore {
    fn record_if_new(
        &mut self,
        account: &VerifiedAccount,
    ) -> std::result::Result<bool, AccountStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryAccountStore {
    accounts: HashMap<[u8; 32], VerifiedAccount>,
}

impl MemoryAccountStore {
    pub fn account_at_checkpoint(
        &self,
        chain_id: u64,
        block_hash: [u8; 32],
        address: [u8; 20],
    ) -> Option<&VerifiedAccount> {
        self.accounts.values().find(|account| {
            account.chain_id == chain_id
                && account.block_hash == block_hash
                && account.address == address
        })
    }
}

impl VerifiedAccountStore for MemoryAccountStore {
    fn record_if_new(
        &mut self,
        account: &VerifiedAccount,
    ) -> std::result::Result<bool, AccountStoreError> {
        let verified_import_key = verified_account_import_key(account);
        if self.accounts.contains_key(&verified_import_key) {
            return Ok(false);
        }
        self.accounts.insert(verified_import_key, account.clone());
        Ok(true)
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    chain_id: u64,
    network: &'static str,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::sepolia()
    }
}

impl Verifier {
    pub fn for_chain(chain_id: u64) -> Result<Self> {
        let definition = chain_definition(chain_id).ok_or_else(|| VerifyError::UnsupportedNetwork {
            chain_id,
            network: "unknown".to_owned(),
        })?;
        Ok(Self {
            chain_id,
            network: definition.network,
        })
    }

    pub fn sepolia() -> Self {
        Self::for_chain(SEPOLIA_CHAIN_ID).expect("Sepolia is a built-in chain")
    }

    pub fn base_sepolia() -> Self {
        Self::for_chain(BASE_SEPOLIA_CHAIN_ID).expect("Base Sepolia is a built-in chain")
    }

    pub fn op_sepolia() -> Self {
        Self::for_chain(OP_SEPOLIA_CHAIN_ID).expect("OP Sepolia is a built-in chain")
    }

    pub fn arbitrum_sepolia() -> Self {
        Self::for_chain(ARBITRUM_SEPOLIA_CHAIN_ID).expect("Arbitrum Sepolia is a built-in chain")
    }

    pub fn robinhood_testnet() -> Self {
        Self::for_chain(ROBINHOOD_TESTNET_CHAIN_ID)
            .expect("Robinhood Chain Testnet is a built-in chain")
    }

    /// Parses an uncompressed account-proof bundle without establishing trust.
    pub fn parse_account_proof(&self, bytes: &[u8]) -> Result<AccountProofBundle> {
        parse_account_proof(bytes, self.chain_id, self.network)
    }

    /// Verifies and records an account proof against an independently pinned checkpoint.
    pub fn verify_and_import(
        &self,
        bytes: &[u8],
        checkpoint: &PinnedCheckpoint,
        account_store: &mut impl VerifiedAccountStore,
    ) -> Result<VerifiedAccount> {
        self.validate_checkpoint_network(checkpoint)?;
        let canonical = self.canonical_bundle(bytes)?;
        let prelude = parse_prelude(&canonical, self.chain_id, self.network)?;
        let bundle = match prelude.kind {
            KIND_FINALIZED_HEADER
            | KIND_BEACON_FINALITY_BUNDLE
            | KIND_COMPACT_CONSENSUS_BOOTSTRAP => return Err(VerifyError::UntrustedHeader),
            KIND_ACCOUNT_PROOF => parse_account_proof(&canonical, self.chain_id, self.network)?,
            kind => return Err(VerifyError::UnsupportedKind(kind)),
        };

        let verified = verify_account(bundle, checkpoint, sha256(&canonical))?;
        let recorded = account_store
            .record_if_new(&verified)
            .map_err(|error| VerifyError::AccountStore(error.0))?;
        if !recorded {
            return Err(VerifyError::Replay);
        }
        Ok(verified)
    }

    /// Verifies and records an account against any stack-authenticated EVM anchor.
    pub fn verify_account_from_anchor(
        &self,
        bytes: &[u8],
        anchor: &VerifiedEvmAnchor,
        account_store: &mut impl VerifiedAccountStore,
    ) -> Result<VerifiedAccount> {
        if anchor.chain_id() != self.chain_id || anchor.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: anchor.chain_id(),
                network: anchor.network().to_owned(),
            });
        }
        self.verify_and_import(bytes, &anchor.pinned_checkpoint(), account_store)
    }

    /// Verifies and records an account against a consensus-derived execution header.
    pub fn verify_account_from_consensus(
        &self,
        bytes: &[u8],
        header: &VerifiedExecutionHeader,
        account_store: &mut impl VerifiedAccountStore,
    ) -> Result<VerifiedAccount> {
        if header.chain_id() != self.chain_id || header.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: header.chain_id(),
                network: header.network().to_owned(),
            });
        }
        let checkpoint = PinnedCheckpoint {
            chain_id: header.chain_id(),
            network: SEPOLIA_NETWORK,
            execution_block_number: header.execution_block_number(),
            execution_block_hash: header.execution_block_hash(),
            state_root: header.state_root(),
        };
        self.verify_and_import(bytes, &checkpoint, account_store)
    }

    fn validate_checkpoint_network(&self, checkpoint: &PinnedCheckpoint) -> Result<()> {
        if checkpoint.chain_id != self.chain_id || checkpoint.network != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: checkpoint.chain_id,
                network: checkpoint.network.to_owned(),
            });
        }
        Ok(())
    }

    fn canonical_bundle(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let prelude = parse_prelude(bytes, self.chain_id, self.network)?;
        if prelude.kind != KIND_COMPRESSED_BUNDLE {
            return Ok(bytes.to_vec());
        }
        let inner = decompress_bundle(bytes, self.chain_id, self.network)?;
        let inner_prelude = parse_prelude(&inner, self.chain_id, self.network)?;
        if inner_prelude.kind == KIND_COMPRESSED_BUNDLE {
            return Err(VerifyError::NestedCompression);
        }
        Ok(inner)
    }
}

fn verify_account(
    bundle: AccountProofBundle,
    checkpoint: &PinnedCheckpoint,
    proof_bundle_hash: [u8; 32],
) -> Result<VerifiedAccount> {
    if bundle.chain_id != checkpoint.chain_id
        || bundle.network != checkpoint.network
        || bundle.block_number != checkpoint.execution_block_number
        || bundle.block_hash != checkpoint.execution_block_hash
        || bundle.state_root != checkpoint.state_root
    {
        return Err(VerifyError::CheckpointMismatch);
    }

    let account = TrieAccount {
        nonce: bundle.nonce,
        balance: bundle.balance,
        storage_root: B256::from(bundle.storage_root),
        code_hash: B256::from(bundle.code_hash),
    };
    let expected_value = if is_empty_account(&account) {
        None
    } else {
        Some(alloy_rlp::encode(account))
    };
    let proof_nodes = bundle
        .account_proof
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect::<Vec<_>>();
    verify_proof(
        B256::from(checkpoint.state_root),
        Nibbles::unpack(keccak256(bundle.address)),
        expected_value,
        proof_nodes.iter(),
    )
    .map_err(|error| VerifyError::InvalidAccountProof(error.to_string()))?;

    Ok(VerifiedAccount {
        chain_id: bundle.chain_id,
        network: bundle.network,
        block_number: bundle.block_number,
        block_hash: bundle.block_hash,
        state_root: bundle.state_root,
        address: bundle.address,
        balance: bundle.balance,
        nonce: bundle.nonce,
        code_hash: bundle.code_hash,
        storage_root: bundle.storage_root,
        proof_bundle_hash,
    })
}

fn parse_account_proof(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<AccountProofBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_ACCOUNT_PROOF {
        return Err(
            if matches!(
                prelude.kind,
                KIND_FINALIZED_HEADER
                    | KIND_BEACON_FINALITY_BUNDLE
                    | KIND_COMPACT_CONSENSUS_BOOTSTRAP
            ) {
                VerifyError::UntrustedHeader
            } else {
                VerifyError::UnsupportedKind(prelude.kind)
            },
        );
    }

    let created_at_unix = cursor.u64()?;
    let block_number = cursor.u64()?;
    let block_hash = cursor.array32()?;
    let state_root = cursor.array32()?;
    let address = cursor.array20()?;
    let balance = U256::from_be_bytes(cursor.array32()?);
    let nonce = cursor.u64()?;
    let code_hash = cursor.array32()?;
    let storage_root = cursor.array32()?;
    let account_proof = cursor.node_list()?;
    cursor.finish()?;

    Ok(AccountProofBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        block_number,
        block_hash,
        state_root,
        address,
        balance,
        nonce,
        code_hash,
        storage_root,
        account_proof,
    })
}

fn decompress_bundle(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_COMPRESSED_BUNDLE {
        return Err(VerifyError::UnsupportedKind(prelude.kind));
    }
    let _created_at_unix = cursor.u64()?;
    let algorithm = cursor.u8()?;
    if algorithm != COMPRESSION_ALGORITHM_GZIP {
        return Err(VerifyError::UnsupportedCompressionAlgorithm(algorithm));
    }
    let uncompressed_len =
        usize::try_from(cursor.u64()?).map_err(|_| VerifyError::InvalidUncompressedLength)?;
    if uncompressed_len == 0 {
        return Err(VerifyError::InvalidUncompressedLength);
    }
    if uncompressed_len > MAX_BUNDLE_BYTES {
        return Err(VerifyError::OversizedDecompressedBundle);
    }
    let expected_hash = cursor.array32()?;
    let compressed = cursor.sized_bytes(MAX_BUNDLE_BYTES, "compressed payload too large")?;
    cursor.finish()?;

    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut inner = Vec::with_capacity(uncompressed_len.min(64 * 1024));
    {
        let mut limited = decoder.by_ref().take((MAX_BUNDLE_BYTES + 1) as u64);
        limited
            .read_to_end(&mut inner)
            .map_err(VerifyError::Decompression)?;
    }
    if inner.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::OversizedDecompressedBundle);
    }
    if !decoder.into_inner().is_empty() {
        return Err(VerifyError::TrailingCompressedData);
    }
    if inner.len() != uncompressed_len {
        return Err(VerifyError::InvalidUncompressedLength);
    }
    if sha256(&inner) != expected_hash {
        return Err(VerifyError::CompressedBundleHashMismatch);
    }
    Ok(inner)
}

#[derive(Debug)]
struct Prelude {
    chain_id: u64,
    network: String,
    kind: u8,
}

fn parse_prelude(bytes: &[u8], expected_chain_id: u64, expected_network: &str) -> Result<Prelude> {
    Cursor::new(bytes)?.prelude(expected_chain_id, expected_network)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(VerifyError::OversizedBundle);
        }
        Ok(Self { bytes, pos: 0 })
    }

    fn prelude(&mut self, expected_chain_id: u64, expected_network: &str) -> Result<Prelude> {
        if self.take(MAGIC.len())? != MAGIC {
            return Err(VerifyError::WrongMagic);
        }
        let version = self.u8()?;
        if version != VERSION {
            return Err(VerifyError::UnsupportedVersion(version));
        }
        let chain_id = self.u64()?;
        let network = self.string(MAX_NETWORK_BYTES)?;
        if chain_id != expected_chain_id || network != expected_network {
            return Err(VerifyError::UnsupportedNetwork { chain_id, network });
        }
        let kind = self.u8()?;
        Ok(Prelude {
            chain_id,
            network,
            kind,
        })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(VerifyError::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(VerifyError::Malformed("unexpected end of bundle"));
        }
        let start = self.pos;
        self.pos = end;
        Ok(&self.bytes[start..end])
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn array20(&mut self) -> Result<[u8; 20]> {
        let mut bytes = [0; 20];
        bytes.copy_from_slice(self.take(20)?);
        Ok(bytes)
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.take(32)?);
        Ok(bytes)
    }

    fn string(&mut self, max_len: usize) -> Result<String> {
        let len = self.u16()? as usize;
        if len > max_len {
            return Err(VerifyError::Malformed("string exceeds limit"));
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| VerifyError::Malformed("invalid utf-8"))
    }

    fn sized_bytes(&mut self, max_len: usize, message: &'static str) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > max_len {
            return Err(VerifyError::Malformed(message));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn node_list(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = self.u32()? as usize;
        if count == 0 {
            return Err(VerifyError::Malformed("account proof is empty"));
        }
        if count > MAX_PROOF_NODES {
            return Err(VerifyError::TooManyProofNodes);
        }
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.u32()? as usize;
            if len > MAX_PROOF_NODE_BYTES {
                return Err(VerifyError::OversizedProofNode);
            }
            nodes.push(self.take(len)?.to_vec());
        }
        Ok(nodes)
    }

    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifyError::Malformed("trailing bytes"))
        }
    }
}

fn is_empty_account(account: &TrieAccount) -> bool {
    account.nonce == 0
        && account.balance == U256::ZERO
        && account.storage_root == EMPTY_ROOT_HASH
        && account.code_hash == KECCAK_EMPTY
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn verified_account_import_key(account: &VerifiedAccount) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-account-import-v1");
    hasher.update(account.chain_id.to_le_bytes());
    hasher.update((account.network.len() as u16).to_le_bytes());
    hasher.update(account.network.as_bytes());
    hasher.update(account.block_number.to_le_bytes());
    hasher.update(account.block_hash);
    hasher.update(account.state_root);
    hasher.update(account.address);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles};
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    struct Fixture {
        bytes: Vec<u8>,
        checkpoint: PinnedCheckpoint,
        state_root_offset: usize,
        proof_offset: usize,
    }

    fn account_fixture() -> Fixture {
        let address = [0x11; 20];
        let account = TrieAccount {
            nonce: 7,
            balance: U256::from(123_456_789u64),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };
        let key = Nibbles::unpack(keccak256(address));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([key]));
        builder.add_leaf(key, &alloy_rlp::encode(account));
        let state_root: [u8; 32] = builder.root().into();
        let proof = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();
        let block_hash = [0x22; 32];

        let mut bytes = prelude(KIND_ACCOUNT_PROOF);
        bytes.extend_from_slice(&1_780_000_000u64.to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        let state_root_offset = bytes.len();
        bytes.extend_from_slice(&state_root);
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&account.balance.to_be_bytes::<32>());
        bytes.extend_from_slice(&account.nonce.to_le_bytes());
        bytes.extend_from_slice(account.code_hash.as_slice());
        bytes.extend_from_slice(account.storage_root.as_slice());
        bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        let proof_offset = bytes.len() + 4;
        for node in proof {
            write_bytes(&mut bytes, &node);
        }

        Fixture {
            bytes,
            checkpoint: PinnedCheckpoint::sepolia(42, block_hash, state_root),
            state_root_offset,
            proof_offset,
        }
    }

    fn prelude(kind: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        write_string(&mut bytes, SEPOLIA_NETWORK);
        bytes.push(kind);
        bytes
    }

    fn write_string(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn gzip_bundle(inner: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(inner).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut bytes = prelude(KIND_COMPRESSED_BUNDLE);
        bytes.extend_from_slice(&1_780_000_001u64.to_le_bytes());
        bytes.push(COMPRESSION_ALGORITHM_GZIP);
        bytes.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&sha256(inner));
        write_bytes(&mut bytes, &compressed);
        bytes
    }

    #[test]
    fn parses_and_verifies_account_proof_against_pinned_checkpoint() {
        let fixture = account_fixture();
        let verifier = Verifier::sepolia();
        let parsed = verifier.parse_account_proof(&fixture.bytes).unwrap();
        assert_eq!(parsed.address, [0x11; 20]);
        assert_eq!(parsed.balance, U256::from(123_456_789u64));

        let verified = verifier
            .verify_and_import(
                &fixture.bytes,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default(),
            )
            .unwrap();
        assert_eq!(verified.address, [0x11; 20]);
        assert_eq!(verified.state_root, fixture.checkpoint.state_root());
    }

    #[test]
    fn rejects_checkpoint_root_supplied_by_bundle_instead_of_pin() {
        let mut fixture = account_fixture();
        fixture.checkpoint.state_root[0] ^= 1;
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &fixture.bytes,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::CheckpointMismatch)
        ));
    }

    #[test]
    fn rejects_checkpoint_block_mismatch() {
        let mut fixture = account_fixture();
        fixture.checkpoint.execution_block_hash[0] ^= 1;
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &fixture.bytes,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::CheckpointMismatch)
        ));
    }

    #[test]
    fn rejects_mutated_account_claim_and_proof() {
        let fixture = account_fixture();
        let mut changed_claim = fixture.bytes.clone();
        changed_claim[fixture.state_root_offset + 32 + 20 + 31] ^= 1;
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &changed_claim,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::InvalidAccountProof(_))
        ));

        let mut changed_proof = fixture.bytes;
        changed_proof[fixture.proof_offset] ^= 1;
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &changed_proof,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::InvalidAccountProof(_)) | Err(VerifyError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_self_authenticated_header_imports() {
        let fixture = account_fixture();
        let bytes = prelude(KIND_FINALIZED_HEADER);
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &bytes,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::UntrustedHeader)
        ));
    }

    #[test]
    fn rejects_wrong_magic_version_network_and_kind() {
        let fixture = account_fixture();
        let verifier = Verifier::sepolia();
        let mut bytes = fixture.bytes.clone();
        bytes[0] = b'X';
        assert!(matches!(
            verifier.parse_account_proof(&bytes),
            Err(VerifyError::WrongMagic)
        ));

        let mut bytes = fixture.bytes.clone();
        bytes[MAGIC.len()] = 99;
        assert!(matches!(
            verifier.parse_account_proof(&bytes),
            Err(VerifyError::UnsupportedVersion(99))
        ));

        let mut bytes = fixture.bytes.clone();
        let chain_offset = MAGIC.len() + 1;
        bytes[chain_offset..chain_offset + 8].copy_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            verifier.parse_account_proof(&bytes),
            Err(VerifyError::UnsupportedNetwork { .. })
        ));

        assert!(matches!(
            verifier.verify_and_import(
                &prelude(99),
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::UnsupportedKind(99))
        ));
    }

    #[test]
    fn rejects_oversized_and_trailing_bundles() {
        let fixture = account_fixture();
        assert!(matches!(
            Verifier::sepolia().parse_account_proof(&vec![0; MAX_BUNDLE_BYTES + 1]),
            Err(VerifyError::OversizedBundle)
        ));

        let mut bytes = fixture.bytes;
        bytes.push(0);
        assert!(matches!(
            Verifier::sepolia().parse_account_proof(&bytes),
            Err(VerifyError::Malformed("trailing bytes"))
        ));
    }

    #[test]
    fn rejects_excessive_proof_counts_and_node_lengths_before_allocation() {
        let fixture = account_fixture();
        let mut too_many_nodes = fixture.bytes.clone();
        let proof_count_offset = fixture.proof_offset - 8;
        too_many_nodes[proof_count_offset..proof_count_offset + 4]
            .copy_from_slice(&((MAX_PROOF_NODES + 1) as u32).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().parse_account_proof(&too_many_nodes),
            Err(VerifyError::TooManyProofNodes)
        ));

        let mut oversized_node = fixture.bytes;
        let first_node_length_offset = fixture.proof_offset - 4;
        oversized_node[first_node_length_offset..first_node_length_offset + 4]
            .copy_from_slice(&((MAX_PROOF_NODE_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().parse_account_proof(&oversized_node),
            Err(VerifyError::OversizedProofNode)
        ));
    }

    #[test]
    fn imports_gzip_bundle_and_replays_on_semantic_import_key() {
        let fixture = account_fixture();
        let compressed = gzip_bundle(&fixture.bytes);
        let verifier = Verifier::sepolia();
        let mut replay = MemoryAccountStore::default();
        verifier
            .verify_and_import(&compressed, &fixture.checkpoint, &mut replay)
            .unwrap();
        assert!(matches!(
            verifier.verify_and_import(&fixture.bytes, &fixture.checkpoint, &mut replay),
            Err(VerifyError::Replay)
        ));
    }

    #[test]
    fn untrusted_timestamp_cannot_bypass_semantic_replay_key() {
        let fixture = account_fixture();
        let verifier = Verifier::sepolia();
        let mut replay = MemoryAccountStore::default();
        verifier
            .verify_and_import(&fixture.bytes, &fixture.checkpoint, &mut replay)
            .unwrap();

        let mut changed_timestamp = fixture.bytes;
        let timestamp_offset = prelude(KIND_ACCOUNT_PROOF).len();
        changed_timestamp[timestamp_offset..timestamp_offset + 8]
            .copy_from_slice(&1_780_000_099u64.to_le_bytes());
        assert!(matches!(
            verifier.verify_and_import(&changed_timestamp, &fixture.checkpoint, &mut replay),
            Err(VerifyError::Replay)
        ));
    }

    #[test]
    fn rejects_compressed_hash_length_and_nested_bundle_failures() {
        let fixture = account_fixture();

        let mut bad_hash = gzip_bundle(&fixture.bytes);
        let hash_offset = prelude(KIND_COMPRESSED_BUNDLE).len() + 8 + 1 + 8;
        bad_hash[hash_offset] ^= 1;
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &bad_hash,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::CompressedBundleHashMismatch)
        ));

        let mut bad_len = gzip_bundle(&fixture.bytes);
        let len_offset = prelude(KIND_COMPRESSED_BUNDLE).len() + 8 + 1;
        bad_len[len_offset..len_offset + 8]
            .copy_from_slice(&((fixture.bytes.len() + 1) as u64).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &bad_len,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::InvalidUncompressedLength)
        ));

        let nested = gzip_bundle(&gzip_bundle(&fixture.bytes));
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &nested,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::NestedCompression)
        ));
    }

    #[test]
    fn rejects_declared_or_actual_decompression_over_limit() {
        let fixture = account_fixture();
        let mut declared_oversize = gzip_bundle(&fixture.bytes);
        let len_offset = prelude(KIND_COMPRESSED_BUNDLE).len() + 8 + 1;
        declared_oversize[len_offset..len_offset + 8]
            .copy_from_slice(&((MAX_BUNDLE_BYTES + 1) as u64).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &declared_oversize,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::OversizedDecompressedBundle)
        ));

        let oversized_inner = vec![0; MAX_BUNDLE_BYTES + 1];
        let mut compressed = gzip_bundle(&oversized_inner);
        compressed[len_offset..len_offset + 8]
            .copy_from_slice(&(MAX_BUNDLE_BYTES as u64).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &compressed,
                &fixture.checkpoint,
                &mut MemoryAccountStore::default()
            ),
            Err(VerifyError::OversizedDecompressedBundle)
        ));
    }

    #[test]
    fn base_sepolia_account_proof_uses_same_trie_verifier() {
        let address = [0x44; 20];
        let account = TrieAccount {
            nonce: 2,
            balance: U256::from(987_654u64),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };
        let key = Nibbles::unpack(keccak256(address));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([key]));
        builder.add_leaf(key, &alloy_rlp::encode(account));
        let state_root: [u8; 32] = builder.root().into();
        let proof = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();
        let block_hash = [0x55; 32];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&BASE_SEPOLIA_CHAIN_ID.to_le_bytes());
        write_string(&mut bytes, BASE_SEPOLIA_NETWORK);
        bytes.push(KIND_ACCOUNT_PROOF);
        bytes.extend_from_slice(&1_780_000_000u64.to_le_bytes());
        bytes.extend_from_slice(&77u64.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        bytes.extend_from_slice(&state_root);
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&account.balance.to_be_bytes::<32>());
        bytes.extend_from_slice(&account.nonce.to_le_bytes());
        bytes.extend_from_slice(account.code_hash.as_slice());
        bytes.extend_from_slice(account.storage_root.as_slice());
        bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        for node in proof {
            write_bytes(&mut bytes, &node);
        }

        let verified = Verifier::base_sepolia()
            .verify_and_import(
                &bytes,
                &PinnedCheckpoint::base_sepolia(77, block_hash, state_root),
                &mut MemoryAccountStore::default(),
            )
            .unwrap();
        assert_eq!(verified.chain_id(), BASE_SEPOLIA_CHAIN_ID);
        assert_eq!(verified.network(), BASE_SEPOLIA_NETWORK);
        assert_eq!(verified.address(), address);
        assert_eq!(verified.balance(), U256::from(987_654u64));
    }

    #[test]
    fn account_store_failure_does_not_claim_an_import() {
        struct FailingStore;
        impl VerifiedAccountStore for FailingStore {
            fn record_if_new(
                &mut self,
                _account: &VerifiedAccount,
            ) -> std::result::Result<bool, AccountStoreError> {
                Err(AccountStoreError::new("unavailable"))
            }
        }

        let fixture = account_fixture();
        assert!(matches!(
            Verifier::sepolia().verify_and_import(
                &fixture.bytes,
                &fixture.checkpoint,
                &mut FailingStore
            ),
            Err(VerifyError::AccountStore(message)) if message == "unavailable"
        ));
    }
}
