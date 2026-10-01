//! Profile-local state for the experimental Ratspeak Ethereum node.
//!
//! This crate owns the single Ethereum database for a Ratspeak profile. It
//! stores public evidence and replay state, never wallet secrets. Database
//! rows are returned as stored snapshots rather than verifier-authenticated
//! types; callers must re-run verification to recreate a `Verified*` value.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use alloy_primitives::Address;
pub use ratspeak_eth_verifier::MAX_MANUAL_CHECKPOINT_FILE_BYTES;
use ratspeak_eth_verifier::{U256, VerifiedAccount};
use ratspeak_eth_wallet::WalletAccount;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

mod assurance;
mod bootstrap;
mod checkpoint;
mod consensus;
mod evidence;
mod field_node;
mod messaging;
mod receipt;
mod schema;
mod transaction;
mod workflow;

pub use assurance::{
    AssuranceEventKind, AssuranceSubjectKind, NonAuthoritativeTransactionObservation,
    StoredAssuranceEvent,
};
pub use bootstrap::{
    ApprovedCheckpointAnchor, CheckpointBootstrapPolicy, CheckpointCandidate,
    CheckpointPolicyError, CheckpointProviderObservation, ConfiguredCheckpointProvider,
    ManualCheckpointInstallError, ManualCheckpointReview, ManualCheckpointReviewResolution,
    ManualCheckpointSource, NativeCheckpointApproval, PendingManualCheckpointReview,
};
pub use checkpoint::{
    CheckpointApproval, CheckpointApprovalBasis, CheckpointSourceAttestation, CheckpointSourceKind,
    StoredCheckpointApproval,
};
pub use consensus::{StoredExecutionBlock, StoredFinalizedHeader};
pub use evidence::{EvidenceKind, StoredReplayRecord};
pub use field_node::{
    AccountAssurance, AccountEvidence, FieldNodeClock, FieldTransferRequest, OperationStatus,
    PlatformTransferCustody, PreparedFieldTransfer, TransactionAssurance,
};
pub use messaging::{
    BulkEvidenceReviewDecision, BulkEvidenceReviewResolution, CorrelatedEvidence, EvidenceManifest,
    FinalizedReceiptRequestProgress, FinalizedStatusReceiptRequest,
    MAX_PENDING_BULK_EVIDENCE_REVIEWS, MIN_TRANSACTION_STATUS_POLL_INTERVAL_SECONDS,
    MessageRequestStatus, MessagingEvidenceKind, NodeMessageOutcome, OutboundEvidenceRequest,
    OutboundMessageBinding, OutboundMessageKind, OutboundMessageLease,
    OutboundTransactionStatusRequest, PendingBulkEvidenceReview, PendingEvidenceImportOutcome,
    PendingMessageEvidence, RelayObservation, StoredTransactionStatusObservation,
    TransactionStatus, TransactionStatusContinuity, TransactionStatusHistoryView,
};
pub use receipt::StoredReceiptRecord;
pub use transaction::StoredSignedTransaction;
pub use workflow::{
    AccountSyncProgress, AccountSyncStage, EvidenceSyncPlan, EvidenceSyncTrigger,
    MAX_SYNC_TRANSACTIONS_PER_PLAN, PlannedEvidenceRequest, PlannedRelayRequest,
};

pub const ETHEREUM_STORE_DIRECTORY: &str = "ethereum";
pub const ETHEREUM_STORE_FILENAME: &str = "ethereum.sqlite";

static ETHEREUM_STORE_OPEN_LOCK: Mutex<()> = Mutex::new(());

pub type Result<T> = std::result::Result<T, NodeStoreError>;

#[derive(Debug, thiserror::Error)]
#[error("Ethereum node store failed: {0}")]
pub struct NodeStoreError(String);

impl NodeStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn sqlite(error: rusqlite::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    Inserted,
    Replay,
}

/// Public account state read from the node database.
///
/// This is deliberately not a verifier `VerifiedAccount`. A local database
/// digest detects accidental corruption but does not authenticate a database
/// against a process capable of rewriting the user's profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAccountRecord {
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
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Option<Vec<u8>>,
}

impl StoredAccountRecord {
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

    /// Canonical account-proof bytes retained for re-verification.
    ///
    /// `None` is retained only for internal upgrade of a row migrated from the
    /// pre-E1 schema. Public account lookup does not expose such a row as verified.
    pub fn canonical_bundle(&self) -> Option<&[u8]> {
        self.canonical_bundle.as_deref()
    }

    fn matches_verified_state(&self, account: &VerifiedAccount) -> bool {
        self.chain_id == account.chain_id()
            && self.network == account.network()
            && self.block_number == account.block_number()
            && self.block_hash == account.block_hash()
            && self.state_root == account.state_root()
            && self.address == account.address()
            && self.balance == account.balance()
            && self.nonce == account.nonce()
            && self.code_hash == account.code_hash()
            && self.storage_root == account.storage_root()
    }
}

#[derive(Debug)]
pub struct EthereumNodeStore {
    connection: rusqlite::Connection,
    path: PathBuf,
}

impl EthereumNodeStore {
    /// Opens `<ratspeak_data_dir>/ethereum/ethereum.sqlite`.
    pub fn open_in_profile(ratspeak_data_dir: impl AsRef<Path>) -> Result<Self> {
        let _open_guard = ETHEREUM_STORE_OPEN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        fs::create_dir_all(ratspeak_data_dir.as_ref())
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let trusted_profile = fs::canonicalize(ratspeak_data_dir.as_ref())
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let directory = trusted_profile.join(ETHEREUM_STORE_DIRECTORY);
        prepare_private_directory(&directory)?;
        let path = directory.join(ETHEREUM_STORE_FILENAME);
        prepare_private_database_file(&path)?;

        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = rusqlite::Connection::open_with_flags(&path, flags)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        connection
            .busy_timeout(Duration::from_secs(30))
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA synchronous=FULL;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        schema::initialize(&mut connection)?;
        validate_database_integrity(&connection)?;

        let mut store = Self { connection, path };
        bootstrap::recover_interrupted_manual_reviews(&mut store)?;
        Ok(store)
    }

    /// Opens an already initialized profile store for frequent status reads.
    ///
    /// Application polling must not repeat migrations, recovery writes,
    /// journal-mode negotiation, or a whole-database integrity scan while the
    /// transport worker may be committing evidence. Startup and every writer
    /// still use `open_in_profile`, which performs those checks. Individual
    /// read APIs continue validating every authority-bearing record digest.
    pub fn open_existing_read_only_in_profile(ratspeak_data_dir: impl AsRef<Path>) -> Result<Self> {
        let trusted_profile = fs::canonicalize(ratspeak_data_dir.as_ref())
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let directory = trusted_profile.join(ETHEREUM_STORE_DIRECTORY);
        validate_existing_store_directory(&directory)?;
        let path = directory.join(ETHEREUM_STORE_FILENAME);
        validate_existing_database_file(&path)?;

        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = rusqlite::Connection::open_with_flags(&path, flags)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA query_only=ON;",
            )
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        schema::validate_current(&connection)?;
        Ok(Self { connection, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Installs only the profile's public Sepolia account. Reinstalling the
    /// same account is idempotent; replacing it is rejected so platform vault
    /// custody cannot silently drift to another account.
    pub fn install_wallet_account(&mut self, account: WalletAccount) -> Result<RecordOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        if let Some(existing) = read_wallet_account(&transaction)? {
            if existing != account {
                return Err(NodeStoreError::new(
                    "Ethereum profile is already bound to another wallet account",
                ));
            }
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok(RecordOutcome::Replay);
        }

        let address = *account.address().0;
        let record_digest = wallet_profile_digest(account.chain_id(), account.network(), address);
        transaction
            .execute(
                "INSERT INTO eth_wallet_profile (
                    singleton, chain_id, network, address, record_digest
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                rusqlite::params![
                    account.chain_id().to_string(),
                    account.network(),
                    address.as_slice(),
                    record_digest.as_slice(),
                ],
            )
            .map_err(NodeStoreError::sqlite)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(RecordOutcome::Inserted)
    }

    /// Reads the public account needed to restore native runtime binding.
    /// Malformed or rewritten metadata fails closed instead of selecting it.
    pub fn wallet_account(&self) -> Result<Option<WalletAccount>> {
        read_wallet_account(&self.connection)
    }

    /// Stores a verified account and its canonical proof bytes atomically.
    ///
    /// The corresponding consensus-authenticated execution block must already
    /// be present. The returned row remains a stored snapshot, not a recreated
    /// `VerifiedAccount`.
    pub fn record_verified_account(
        &mut self,
        account: &VerifiedAccount,
        canonical_bundle: &[u8],
    ) -> Result<RecordOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_verified_account_in(&transaction, account, canonical_bundle)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn account_at_checkpoint(
        &self,
        chain_id: u64,
        block_hash: [u8; 32],
        address: [u8; 20],
    ) -> Result<Option<StoredAccountRecord>> {
        checkpoint::ensure_supported_network(chain_id, ratspeak_eth_verifier::SEPOLIA_NETWORK)?;
        let stored = self
            .connection
            .query_row(
                "SELECT import_key, chain_id, network, block_number, block_hash, state_root,
                        address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                        record_digest, canonical_bundle
                 FROM eth_verified_account_imports
                 WHERE chain_id = ?1 AND block_hash = ?2 AND address = ?3
                   AND canonical_bundle IS NOT NULL",
                rusqlite::params![
                    chain_id.to_string(),
                    block_hash.as_slice(),
                    address.as_slice()
                ],
                read_stored_account,
            )
            .optional()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        stored.map(validate_stored_account).transpose()
    }
}

pub(crate) fn record_verified_account_in(
    transaction: &rusqlite::Transaction<'_>,
    account: &VerifiedAccount,
    canonical_bundle: &[u8],
) -> Result<RecordOutcome> {
    checkpoint::ensure_supported_network(account.chain_id(), account.network())?;
    evidence::validate_canonical_bundle(
        canonical_bundle,
        account.proof_bundle_hash(),
        "account proof",
    )?;
    let import_key = account.semantic_import_key();
    let account_digest = record_digest(account);
    let block = consensus::read_execution_block(
        transaction,
        account.chain_id(),
        account.network(),
        account.block_hash(),
    )?
    .ok_or_else(|| NodeStoreError::new("verified account has no persisted execution evidence"))?;
    if account.block_number() != block.execution_block_number()
        || account.state_root() != block.state_root()
    {
        return Err(NodeStoreError::new(
            "verified account conflicts with persisted execution commitments",
        ));
    }
    let mut changed = transaction
        .execute(
            "INSERT INTO eth_verified_account_imports (
                import_key, chain_id, network, block_number, block_hash, state_root,
                address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                record_digest, canonical_bundle
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(import_key) DO NOTHING",
            rusqlite::params![
                import_key.as_slice(),
                account.chain_id().to_string(),
                account.network(),
                account.block_number().to_string(),
                account.block_hash().as_slice(),
                account.state_root().as_slice(),
                account.address().as_slice(),
                account.balance().to_be_bytes::<32>().as_slice(),
                account.nonce().to_string(),
                account.code_hash().as_slice(),
                account.storage_root().as_slice(),
                account.proof_bundle_hash().as_slice(),
                account_digest.as_slice(),
                canonical_bundle,
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                NodeStoreError::new("account proof conflicts with an immutable verified subject")
            } else {
                NodeStoreError::sqlite(error)
            }
        })?;
    if changed == 0 {
        let stored = account_by_import_key(transaction, import_key)?.ok_or_else(|| {
            NodeStoreError::new("account import conflict has no corresponding record")
        })?;
        if !stored.matches_verified_state(account) {
            return Err(NodeStoreError::new(
                "account import conflicts with different verified state",
            ));
        }
        if stored.canonical_bundle.is_none() {
            changed = transaction
                .execute(
                    "UPDATE eth_verified_account_imports
                     SET proof_bundle_hash = ?1, record_digest = ?2, canonical_bundle = ?3
                     WHERE import_key = ?4 AND canonical_bundle IS NULL",
                    rusqlite::params![
                        account.proof_bundle_hash().as_slice(),
                        account_digest.as_slice(),
                        canonical_bundle,
                        import_key.as_slice(),
                    ],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
    }
    let replay_outcome = evidence::record_replay(
        transaction,
        account.chain_id(),
        account.network(),
        EvidenceKind::AccountProof,
        import_key,
        import_key,
    )?;
    Ok(
        if changed == 1 || replay_outcome == RecordOutcome::Inserted {
            RecordOutcome::Inserted
        } else {
            RecordOutcome::Replay
        },
    )
}

type StoredAccountRow = (
    Vec<u8>,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
);

struct StoredWalletProfileRow {
    chain_id: String,
    network: String,
    address: Vec<u8>,
    record_digest: Vec<u8>,
}

fn read_wallet_account(connection: &rusqlite::Connection) -> Result<Option<WalletAccount>> {
    let row: Option<StoredWalletProfileRow> = connection
        .query_row(
            "SELECT chain_id, network, address, record_digest
             FROM eth_wallet_profile WHERE singleton = 1",
            [],
            |row| {
                Ok(StoredWalletProfileRow {
                    chain_id: row.get(0)?,
                    network: row.get(1)?,
                    address: row.get(2)?,
                    record_digest: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.chain_id != ratspeak_eth_wallet::SEPOLIA_CHAIN_ID.to_string()
        || row.network != ratspeak_eth_wallet::SEPOLIA_NETWORK
        || row.address.len() != 20
        || row.record_digest.len() != 32
    {
        return Err(NodeStoreError::new("invalid Ethereum wallet profile"));
    }
    let address: [u8; 20] = row
        .address
        .try_into()
        .map_err(|_| NodeStoreError::new("invalid Ethereum wallet address"))?;
    let expected = wallet_profile_digest(
        ratspeak_eth_wallet::SEPOLIA_CHAIN_ID,
        ratspeak_eth_wallet::SEPOLIA_NETWORK,
        address,
    );
    if row.record_digest.as_slice() != expected {
        return Err(NodeStoreError::new(
            "Ethereum wallet profile integrity check failed",
        ));
    }
    Ok(Some(WalletAccount::sepolia(Address::from(address))))
}

fn wallet_profile_digest(chain_id: u64, network: &str, address: [u8; 20]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.wallet-profile.v1");
    hasher.update(chain_id.to_be_bytes());
    hasher.update((network.len() as u64).to_be_bytes());
    hasher.update(network.as_bytes());
    hasher.update(address);
    hasher.finalize().into()
}

fn read_stored_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAccountRow> {
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
    ))
}

fn validate_stored_account(stored: StoredAccountRow) -> Result<StoredAccountRecord> {
    let (
        import_key,
        chain_id,
        network,
        block_number,
        block_hash,
        state_root,
        address,
        balance,
        nonce,
        code_hash,
        storage_root,
        proof_bundle_hash,
        stored_digest,
        canonical_bundle,
    ) = stored;
    let account = StoredAccountRecord {
        chain_id: parse_stored_u64(&chain_id, "chain id")?,
        network,
        block_number: parse_stored_u64(&block_number, "block number")?,
        block_hash: stored_array(&block_hash, "block hash")?,
        state_root: stored_array(&state_root, "state root")?,
        address: stored_array(&address, "address")?,
        balance: U256::from_be_bytes(stored_array::<32>(&balance, "balance")?),
        nonce: parse_stored_u64(&nonce, "nonce")?,
        code_hash: stored_array(&code_hash, "code hash")?,
        storage_root: stored_array(&storage_root, "storage root")?,
        proof_bundle_hash: stored_array(&proof_bundle_hash, "proof bundle hash")?,
        canonical_bundle,
    };
    if let Some(canonical_bundle) = &account.canonical_bundle {
        evidence::validate_canonical_bundle(
            canonical_bundle,
            account.proof_bundle_hash,
            "account proof",
        )?;
    }
    if stored_array::<32>(&import_key, "account import key")? != semantic_import_key(&account) {
        return Err(NodeStoreError::new(
            "stored account import key does not match its subject",
        ));
    }
    if stored_array::<32>(&stored_digest, "account record digest")? != record_digest(&account) {
        return Err(NodeStoreError::new(
            "stored account record digest does not match its values",
        ));
    }
    Ok(account)
}

fn account_by_import_key(
    connection: &rusqlite::Connection,
    import_key: [u8; 32],
) -> Result<Option<StoredAccountRecord>> {
    let stored = connection
        .query_row(
            "SELECT import_key, chain_id, network, block_number, block_hash, state_root,
                    address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                    record_digest, canonical_bundle
             FROM eth_verified_account_imports
             WHERE import_key = ?1",
            [import_key.as_slice()],
            read_stored_account,
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    stored.map(validate_stored_account).transpose()
}

trait AccountRecordView {
    fn chain_id(&self) -> u64;
    fn network(&self) -> &str;
    fn block_number(&self) -> u64;
    fn block_hash(&self) -> [u8; 32];
    fn state_root(&self) -> [u8; 32];
    fn address(&self) -> [u8; 20];
    fn balance(&self) -> U256;
    fn nonce(&self) -> u64;
    fn code_hash(&self) -> [u8; 32];
    fn storage_root(&self) -> [u8; 32];
    fn proof_bundle_hash(&self) -> [u8; 32];
}

impl AccountRecordView for VerifiedAccount {
    fn chain_id(&self) -> u64 {
        VerifiedAccount::chain_id(self)
    }
    fn network(&self) -> &str {
        VerifiedAccount::network(self)
    }
    fn block_number(&self) -> u64 {
        VerifiedAccount::block_number(self)
    }
    fn block_hash(&self) -> [u8; 32] {
        VerifiedAccount::block_hash(self)
    }
    fn state_root(&self) -> [u8; 32] {
        VerifiedAccount::state_root(self)
    }
    fn address(&self) -> [u8; 20] {
        VerifiedAccount::address(self)
    }
    fn balance(&self) -> U256 {
        VerifiedAccount::balance(self)
    }
    fn nonce(&self) -> u64 {
        VerifiedAccount::nonce(self)
    }
    fn code_hash(&self) -> [u8; 32] {
        VerifiedAccount::code_hash(self)
    }
    fn storage_root(&self) -> [u8; 32] {
        VerifiedAccount::storage_root(self)
    }
    fn proof_bundle_hash(&self) -> [u8; 32] {
        VerifiedAccount::proof_bundle_hash(self)
    }
}

impl AccountRecordView for StoredAccountRecord {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn block_number(&self) -> u64 {
        self.block_number
    }
    fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }
    fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
    fn address(&self) -> [u8; 20] {
        self.address
    }
    fn balance(&self) -> U256 {
        self.balance
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn code_hash(&self) -> [u8; 32] {
        self.code_hash
    }
    fn storage_root(&self) -> [u8; 32] {
        self.storage_root
    }
    fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

fn semantic_import_key(account: &impl AccountRecordView) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-account-import-v1");
    hasher.update(account.chain_id().to_le_bytes());
    hasher.update((account.network().len() as u16).to_le_bytes());
    hasher.update(account.network().as_bytes());
    hasher.update(account.block_number().to_le_bytes());
    hasher.update(account.block_hash());
    hasher.update(account.state_root());
    hasher.update(account.address());
    hasher.finalize().into()
}

fn record_digest(account: &impl AccountRecordView) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-verified-account-record-v1");
    hasher.update(account.chain_id().to_le_bytes());
    hasher.update((account.network().len() as u16).to_le_bytes());
    hasher.update(account.network().as_bytes());
    hasher.update(account.block_number().to_le_bytes());
    hasher.update(account.block_hash());
    hasher.update(account.state_root());
    hasher.update(account.address());
    hasher.update(account.balance().to_be_bytes::<32>());
    hasher.update(account.nonce().to_le_bytes());
    hasher.update(account.code_hash());
    hasher.update(account.storage_root());
    hasher.update(account.proof_bundle_hash());
    hasher.finalize().into()
}

fn prepare_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(NodeStoreError::new(
                "Ethereum store directory must not be a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(NodeStoreError::new(
                "Ethereum store path is not a directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| NodeStoreError::new(error.to_string()))?;
        }
        Err(error) => return Err(NodeStoreError::new(error.to_string())),
    }
    set_private_permissions(path, 0o700)
}

fn validate_existing_store_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| NodeStoreError::new(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(NodeStoreError::new(
            "Ethereum store directory is not a regular directory",
        ));
    }
    Ok(())
}

fn validate_existing_database_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| NodeStoreError::new(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NodeStoreError::new(
            "Ethereum database path is not a regular file",
        ));
    }
    Ok(())
}

fn prepare_private_database_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(NodeStoreError::new(
                "Ethereum database must not be a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(NodeStoreError::new(
                "Ethereum database path is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(error) = create_private_file(path) {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(NodeStoreError::new(error.to_string()));
                }
                let metadata = fs::symlink_metadata(path)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(NodeStoreError::new(
                        "Ethereum database path is not a regular file",
                    ));
                }
            }
        }
        Err(error) => return Err(NodeStoreError::new(error.to_string())),
    }
    set_private_permissions(path, 0o600)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(|_| ())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| NodeStoreError::new(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn parse_stored_u64(value: &str, field: &'static str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| NodeStoreError::new(format!("invalid stored {field}")))
}

fn validate_database_integrity(connection: &rusqlite::Connection) -> Result<()> {
    let quick_check = connection
        .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
        .map_err(NodeStoreError::sqlite)?;
    if quick_check != "ok" {
        return Err(NodeStoreError::new(format!(
            "Ethereum database integrity check failed: {quick_check}"
        )));
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(NodeStoreError::sqlite)?;
    if foreign_key_check
        .exists([])
        .map_err(NodeStoreError::sqlite)?
    {
        return Err(NodeStoreError::new(
            "Ethereum database contains broken evidence references",
        ));
    }
    Ok(())
}

fn stored_array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| NodeStoreError::new(format!("invalid stored {field}")))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};

    use alloy_primitives::{U256, keccak256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount};
    use ratspeak_eth_verifier::{
        MAGIC, MemoryAccountStore, PinnedCheckpoint, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, VERSION,
        VerifiedAccount, Verifier,
    };

    use super::*;

    struct Fixture {
        bytes: Vec<u8>,
        checkpoint: PinnedCheckpoint,
    }

    fn account_fixture() -> Fixture {
        account_fixture_with_balance(U256::from(123_456_789u64))
    }

    fn account_fixture_with_balance(balance: U256) -> Fixture {
        let address = [0x11; 20];
        let account = TrieAccount {
            nonce: 7,
            balance,
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

        let mut bytes = prelude(3);
        bytes.extend_from_slice(&1_780_000_000u64.to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
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

        Fixture {
            bytes,
            checkpoint: PinnedCheckpoint::sepolia(42, block_hash, state_root),
        }
    }

    fn prelude(kind: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(kind);
        bytes
    }

    fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn verify_account_fixture(fixture: &Fixture) -> VerifiedAccount {
        let mut memory = MemoryAccountStore::default();
        Verifier::sepolia()
            .verify_and_import(&fixture.bytes, &fixture.checkpoint, &mut memory)
            .unwrap()
    }

    fn install_account_execution(store: &mut EthereumNodeStore, account: &VerifiedAccount) {
        consensus::install_test_execution_evidence(
            store,
            account.block_number(),
            account.block_hash(),
            account.state_root(),
            [0xd1; 32],
            [0xd2; 32],
        );
    }

    #[test]
    fn public_wallet_binding_is_durable_idempotent_and_not_replaceable() {
        let profile = tempfile::tempdir().unwrap();
        let first = WalletAccount::sepolia(Address::from([0x11; 20]));
        let second = WalletAccount::sepolia(Address::from([0x22; 20]));
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            assert_eq!(store.wallet_account().unwrap(), None);
            assert_eq!(
                store.install_wallet_account(first).unwrap(),
                RecordOutcome::Inserted
            );
            assert_eq!(
                store.install_wallet_account(first).unwrap(),
                RecordOutcome::Replay
            );
            assert!(store.install_wallet_account(second).is_err());
        }
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(store.wallet_account().unwrap(), Some(first));
    }

    #[test]
    fn read_only_status_open_reads_committed_state_while_writer_is_active() {
        let profile = tempfile::tempdir().unwrap();
        let account = WalletAccount::sepolia(Address::from([0x11; 20]));
        let mut writer = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        writer.install_wallet_account(account).unwrap();
        writer.connection.execute_batch("BEGIN IMMEDIATE").unwrap();

        let mut reader =
            EthereumNodeStore::open_existing_read_only_in_profile(profile.path()).unwrap();
        assert_eq!(reader.wallet_account().unwrap(), Some(account));
        assert!(reader.install_wallet_account(account).is_err());

        writer.connection.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn read_only_status_open_does_not_create_an_uninitialized_store() {
        let profile = tempfile::tempdir().unwrap();
        assert!(EthereumNodeStore::open_existing_read_only_in_profile(profile.path()).is_err());
        assert!(!profile.path().join(ETHEREUM_STORE_DIRECTORY).exists());
    }

    #[test]
    fn rewritten_public_wallet_binding_fails_closed() {
        let profile = tempfile::tempdir().unwrap();
        let account = WalletAccount::sepolia(Address::from([0x11; 20]));
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store.install_wallet_account(account).unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_wallet_profile SET address = ?1 WHERE singleton = 1",
                [[0x22; 20].as_slice()],
            )
            .unwrap();
        assert!(store.wallet_account().is_err());
    }

    #[test]
    fn persists_verified_account_and_rejects_replay_across_reopen() {
        let fixture = account_fixture();
        let expected = verify_account_fixture(&fixture);
        let profile = tempfile::tempdir().unwrap();
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            install_account_execution(&mut store, &expected);
            assert_eq!(
                store
                    .record_verified_account(&expected, &fixture.bytes)
                    .unwrap(),
                RecordOutcome::Inserted
            );
        }

        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = store
            .account_at_checkpoint(
                expected.chain_id(),
                expected.block_hash(),
                expected.address(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored.balance(), expected.balance());
        assert_eq!(stored.nonce(), expected.nonce());
        assert_eq!(stored.canonical_bundle(), Some(fixture.bytes.as_slice()));
        assert_eq!(
            store
                .record_verified_account(&expected, &fixture.bytes)
                .unwrap(),
            RecordOutcome::Replay
        );
    }

    #[test]
    fn distinguishes_absent_account_from_verified_zero_balance() {
        let fixture = account_fixture_with_balance(U256::ZERO);
        let verified = verify_account_fixture(&fixture);
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        install_account_execution(&mut store, &verified);
        store
            .record_verified_account(&verified, &fixture.bytes)
            .unwrap();

        assert!(
            store
                .account_at_checkpoint(verified.chain_id(), verified.block_hash(), [0xff; 20],)
                .unwrap()
                .is_none()
        );
        let zero = store
            .account_at_checkpoint(
                verified.chain_id(),
                verified.block_hash(),
                verified.address(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(zero.balance(), U256::ZERO);
        assert!(zero.canonical_bundle().is_some());
    }

    #[test]
    fn account_record_requires_execution_evidence_and_canonical_bytes() {
        let fixture = account_fixture();
        let verified = verify_account_fixture(&fixture);
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            store
                .record_verified_account(&verified, &fixture.bytes)
                .unwrap_err()
                .to_string()
                .contains("no persisted execution evidence")
        );
        install_account_execution(&mut store, &verified);
        let mut noncanonical = fixture.bytes.clone();
        noncanonical.push(0);
        assert!(
            store
                .record_verified_account(&verified, &noncanonical)
                .unwrap_err()
                .to_string()
                .contains("evidence hash does not match")
        );
        assert!(
            store
                .account_at_checkpoint(
                    verified.chain_id(),
                    verified.block_hash(),
                    verified.address(),
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fails_closed_on_corrupted_account_proof_bytes() {
        let fixture = account_fixture();
        let verified = verify_account_fixture(&fixture);
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        install_account_execution(&mut store, &verified);
        store
            .record_verified_account(&verified, &fixture.bytes)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET canonical_bundle = x'00'",
                [],
            )
            .unwrap();
        assert!(
            store
                .account_at_checkpoint(
                    verified.chain_id(),
                    verified.block_hash(),
                    verified.address(),
                )
                .unwrap_err()
                .to_string()
                .contains("evidence hash does not match")
        );
    }

    #[test]
    fn upgrades_a_legacy_account_snapshot_with_canonical_evidence() {
        let fixture = account_fixture();
        let verified = verify_account_fixture(&fixture);
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        install_account_execution(&mut store, &verified);
        store
            .record_verified_account(&verified, &fixture.bytes)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET canonical_bundle = NULL",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .record_verified_account(&verified, &fixture.bytes)
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store
                .account_at_checkpoint(
                    verified.chain_id(),
                    verified.block_hash(),
                    verified.address(),
                )
                .unwrap()
                .unwrap()
                .canonical_bundle(),
            Some(fixture.bytes.as_slice())
        );
    }

    #[test]
    fn uses_one_private_database_under_the_profile() {
        let profile = tempfile::tempdir().unwrap();
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            store.path(),
            profile
                .path()
                .join(ETHEREUM_STORE_DIRECTORY)
                .join(ETHEREUM_STORE_FILENAME)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory_mode = fs::metadata(profile.path().join(ETHEREUM_STORE_DIRECTORY))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let database_mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(database_mode, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_targets() {
        use std::os::unix::fs::symlink;

        let profile = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), profile.path().join(ETHEREUM_STORE_DIRECTORY)).unwrap();
        assert!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );

        let profile = tempfile::tempdir().unwrap();
        let directory = profile.path().join(ETHEREUM_STORE_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        let target = tempfile::NamedTempFile::new().unwrap();
        symlink(target.path(), directory.join(ETHEREUM_STORE_FILENAME)).unwrap();
        assert!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
    }

    #[test]
    fn rejects_unknown_schema_versions() {
        let profile = tempfile::tempdir().unwrap();
        let path = {
            let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store.path().to_path_buf()
        };
        rusqlite::Connection::open(path)
            .unwrap()
            .execute("UPDATE eth_schema_version SET version = 99", [])
            .unwrap();
        assert!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap_err()
                .to_string()
                .contains("unsupported Ethereum store schema version 99")
        );
    }

    #[test]
    fn rejects_a_corrupted_database_file_on_reopen() {
        let profile = tempfile::tempdir().unwrap();
        let directory = profile.path().join(ETHEREUM_STORE_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join(ETHEREUM_STORE_FILENAME),
            b"not a sqlite database",
        )
        .unwrap();
        assert!(EthereumNodeStore::open_in_profile(profile.path()).is_err());
    }

    fn checkpoint_attestation(
        source_fingerprint: [u8; 32],
        observation_hash: [u8; 32],
        observed_at_unix: u64,
    ) -> CheckpointSourceAttestation {
        CheckpointSourceAttestation::new(
            CheckpointSourceKind::BeaconApi,
            source_fingerprint,
            observation_hash,
            observed_at_unix,
        )
    }

    fn checkpoint_approval(
        root: [u8; 32],
        basis: CheckpointApprovalBasis,
        attestations: Vec<CheckpointSourceAttestation>,
    ) -> CheckpointApproval {
        CheckpointApproval::sepolia(root, basis, 1_780_000_000, attestations)
    }

    #[test]
    fn persists_checkpoint_approval_and_secret_free_attestations() {
        let profile = tempfile::tempdir().unwrap();
        let approval = checkpoint_approval(
            [0x31; 32],
            CheckpointApprovalBasis::ProviderAgreement,
            vec![
                checkpoint_attestation([0x41; 32], [0x51; 32], 1_779_999_900),
                checkpoint_attestation([0x42; 32], [0x52; 32], 1_779_999_901),
            ],
        );
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            assert_eq!(
                store.record_checkpoint_approval(&approval).unwrap(),
                RecordOutcome::Inserted
            );
            assert_eq!(
                store.record_checkpoint_approval(&approval).unwrap(),
                RecordOutcome::Replay
            );
        }

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = store
            .checkpoint_approval(SEPOLIA_CHAIN_ID, [0x31; 32])
            .unwrap()
            .unwrap();
        assert_eq!(stored.checkpoint_root(), [0x31; 32]);
        assert_eq!(
            stored.approval_basis(),
            CheckpointApprovalBasis::ProviderAgreement
        );
        assert_eq!(stored.attestations().len(), 2);
        assert_eq!(stored.attestations()[0].source_fingerprint(), [0x41; 32]);
        let history = store
            .checkpoint_assurance_history(SEPOLIA_CHAIN_ID, [0x31; 32])
            .unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(
            history.last().unwrap().event_kind(),
            AssuranceEventKind::CheckpointApproved
        );
    }

    #[test]
    fn appends_checkpoint_revocation_without_deleting_approval() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let approval = checkpoint_approval(
            [0x32; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            Vec::new(),
        );
        store.record_checkpoint_approval(&approval).unwrap();
        assert_eq!(
            store
                .record_checkpoint_revocation(
                    SEPOLIA_CHAIN_ID,
                    [0x32; 32],
                    [0x33; 32],
                    1_780_000_100,
                )
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert!(
            store
                .checkpoint_approval(SEPOLIA_CHAIN_ID, [0x32; 32])
                .unwrap()
                .is_some()
        );
        let history = store
            .checkpoint_assurance_history(SEPOLIA_CHAIN_ID, [0x32; 32])
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[1].event_kind(),
            AssuranceEventKind::CheckpointRevoked
        );
    }

    #[test]
    fn rejects_conflicting_checkpoint_decision_atomically() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let original = checkpoint_approval(
            [0x61; 32],
            CheckpointApprovalBasis::ProviderAgreement,
            vec![checkpoint_attestation(
                [0x71; 32],
                [0x81; 32],
                1_779_999_900,
            )],
        );
        store.record_checkpoint_approval(&original).unwrap();
        let conflicting = CheckpointApproval::sepolia(
            [0x61; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            1_780_000_001,
            vec![checkpoint_attestation(
                [0x72; 32],
                [0x82; 32],
                1_779_999_901,
            )],
        );
        assert!(
            store
                .record_checkpoint_approval(&conflicting)
                .unwrap_err()
                .to_string()
                .contains("immutable decision")
        );
        let stored = store
            .checkpoint_approval(SEPOLIA_CHAIN_ID, [0x61; 32])
            .unwrap()
            .unwrap();
        assert_eq!(stored.attestations().len(), 1);
        assert_eq!(
            stored.approval_basis(),
            CheckpointApprovalBasis::ProviderAgreement
        );
    }

    #[test]
    fn rejects_one_source_attesting_conflicting_roots_at_the_same_time() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let first = checkpoint_approval(
            [0x91; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            vec![checkpoint_attestation(
                [0xa1; 32],
                [0xb1; 32],
                1_779_999_900,
            )],
        );
        store.record_checkpoint_approval(&first).unwrap();
        let second = CheckpointApproval::new(
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            [0x92; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            1_780_000_000,
            checkpoint::CheckpointApprovalWindow {
                checkpoint_epoch: 2,
                valid_until_unix: 1_780_000_001,
            },
            vec![checkpoint_attestation(
                [0xa1; 32],
                [0xb2; 32],
                1_779_999_900,
            )],
        );
        assert!(
            store
                .record_checkpoint_approval(&second)
                .unwrap_err()
                .to_string()
                .contains("immutable observation")
        );
        assert!(
            store
                .checkpoint_approval(SEPOLIA_CHAIN_ID, [0x92; 32])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_wrong_network_checkpoint_and_corrupted_profile_pin() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let wrong = CheckpointApproval::new(
            1,
            "mainnet",
            [0xc1; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            1_780_000_000,
            crate::checkpoint::CheckpointApprovalWindow {
                checkpoint_epoch: 1,
                valid_until_unix: 1_780_000_001,
            },
            Vec::new(),
        );
        assert!(
            store
                .record_checkpoint_approval(&wrong)
                .unwrap_err()
                .to_string()
                .contains("unsupported Ethereum store network")
        );
        assert!(
            store
                .account_at_checkpoint(1, [0; 32], [0; 20])
                .unwrap_err()
                .to_string()
                .contains("unsupported Ethereum store network")
        );
        let path = store.path().to_path_buf();
        drop(store);
        rusqlite::Connection::open(path)
            .unwrap()
            .execute(
                "UPDATE eth_network_profile SET chain_id = '1' WHERE singleton = 1",
                [],
            )
            .unwrap();
        assert!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap_err()
                .to_string()
                .contains("different or corrupted network")
        );
    }

    #[test]
    fn migrates_v1_schema_without_discarding_account_rows() {
        let profile = tempfile::tempdir().unwrap();
        let directory = profile.path().join(ETHEREUM_STORE_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        let path = directory.join(ETHEREUM_STORE_FILENAME);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE eth_schema_version (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    version INTEGER NOT NULL
                 );
                 INSERT INTO eth_schema_version (singleton, version) VALUES (1, 1);
                 CREATE TABLE eth_verified_account_imports (
                    import_key BLOB PRIMARY KEY NOT NULL CHECK(length(import_key) = 32),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    block_number TEXT NOT NULL,
                    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                    address BLOB NOT NULL CHECK(length(address) = 20),
                    balance BLOB NOT NULL CHECK(length(balance) = 32),
                    nonce TEXT NOT NULL,
                    code_hash BLOB NOT NULL CHECK(length(code_hash) = 32),
                    storage_root BLOB NOT NULL CHECK(length(storage_root) = 32),
                    proof_bundle_hash BLOB NOT NULL CHECK(length(proof_bundle_hash) = 32),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
                 );
                 INSERT INTO eth_verified_account_imports (
                    import_key, chain_id, network, block_number, block_hash, state_root,
                    address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                    record_digest
                 ) VALUES (
                    zeroblob(32), '11155111', 'sepolia', '1', zeroblob(32),
                    zeroblob(32), zeroblob(20), zeroblob(32), '0', zeroblob(32),
                    zeroblob(32), zeroblob(32), zeroblob(32)
                 );",
            )
            .unwrap();
        drop(connection);

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (version, rows, canonical_column): (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM eth_verified_account_imports),
                    (SELECT count(*) FROM pragma_table_info('eth_verified_account_imports')
                     WHERE name = 'canonical_bundle')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, schema::ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(rows, 1);
        assert_eq!(canonical_column, 1);
        assert!(
            store
                .account_at_checkpoint(SEPOLIA_CHAIN_ID, [0; 32], [0; 20])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fails_closed_on_mutated_verified_values() {
        let fixture = account_fixture();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let expected = verify_account_fixture(&fixture);
        install_account_execution(&mut store, &expected);
        store
            .record_verified_account(&expected, &fixture.bytes)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET balance = zeroblob(32)",
                [],
            )
            .unwrap();
        let error = store
            .account_at_checkpoint(
                expected.chain_id(),
                expected.block_hash(),
                expected.address(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("record digest does not match"));
    }

    #[test]
    fn fails_closed_on_mismatched_record_key() {
        let fixture = account_fixture();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let expected = verify_account_fixture(&fixture);
        install_account_execution(&mut store, &expected);
        store
            .record_verified_account(&expected, &fixture.bytes)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET import_key = zeroblob(32)",
                [],
            )
            .unwrap();
        let error = store
            .account_at_checkpoint(
                expected.chain_id(),
                expected.block_hash(),
                expected.address(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("import key does not match"));
    }

    #[test]
    fn enforces_unique_checkpoint_subjects() {
        let fixture = account_fixture();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let expected = verify_account_fixture(&fixture);
        install_account_execution(&mut store, &expected);
        store
            .record_verified_account(&expected, &fixture.bytes)
            .unwrap();
        let result = store.connection.execute(
            "INSERT INTO eth_verified_account_imports (
                import_key, chain_id, network, block_number, block_hash, state_root,
                address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                record_digest, recorded_at_unix
             SELECT zeroblob(32), chain_id, network, block_number, block_hash, state_root,
                address, balance, nonce, code_hash, storage_root, proof_bundle_hash,
                record_digest, recorded_at_unix FROM eth_verified_account_imports",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn concurrent_import_records_exactly_once() {
        let fixture = account_fixture();
        let profile = tempfile::tempdir().unwrap();
        let verified = verify_account_fixture(&fixture);
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            install_account_execution(&mut store, &verified);
        }
        let first_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let second_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let run = |mut store: EthereumNodeStore,
                   verified: VerifiedAccount,
                   bytes: Vec<u8>,
                   barrier: Arc<Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                store.record_verified_account(&verified, &bytes)
            })
        };
        let first = run(
            first_store,
            verified.clone(),
            fixture.bytes.clone(),
            Arc::clone(&barrier),
        );
        let second = run(second_store, verified, fixture.bytes, Arc::clone(&barrier));
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(RecordOutcome::Inserted)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(RecordOutcome::Replay)))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_first_open_uses_the_same_profile_database() {
        let profile = tempfile::tempdir().unwrap();
        let profile_path = Arc::new(profile.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(2));
        let open = |profile_path: Arc<PathBuf>, barrier: Arc<Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                EthereumNodeStore::open_in_profile(profile_path.as_path())
                    .map(|store| store.path().to_path_buf())
            })
        };
        let first = open(Arc::clone(&profile_path), Arc::clone(&barrier));
        let second = open(Arc::clone(&profile_path), Arc::clone(&barrier));
        assert_eq!(
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap()
        );
    }
}
