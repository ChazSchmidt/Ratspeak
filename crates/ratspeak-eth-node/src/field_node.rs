use alloy_primitives::{Address, U256};
use ratspeak_eth_verifier::{
    KIND_TX_RECEIPT_PROOF, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, VerifiedTxReceipt, VerifyError,
    sepolia_slot_start_unix,
};
use ratspeak_eth_wallet::{
    NATIVE_TRANSFER_GAS_LIMIT, OperationId, PreparedTransfer, ReviewContext, SignedTransfer,
    TransferIntent, WalletAccount,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{AssuranceEventKind, NonAuthoritativeTransactionObservation};
use crate::bootstrap::{
    CheckpointPolicyError, ensure_active_checkpoint_at, ensure_active_checkpoint_at_connection,
};
use crate::consensus::{
    read_execution_block, read_finalized_header_by_proof_hash, read_latest_finalized_header,
};
use crate::messaging::{RelayObservation, stored_relay_observations};
use crate::transaction::record_locally_signed_transaction_in;
use crate::{
    EthereumNodeStore, NodeStoreError, Result, StoredAccountRecord, StoredReceiptRecord,
    StoredSignedTransaction, account_by_import_key, parse_stored_u64, stored_array,
};

const REVIEW_CONTEXT_DOMAIN: &[u8] = b"ratspeak.ethereum.field-node-context.v2";

/// Proof-backed public account data. A zero balance can appear only in this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvidence {
    balance: U256,
    nonce: u64,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    checkpoint_root: [u8; 32],
    proof_hash: [u8; 32],
    chain_evidence_at_unix: u64,
    local_verified_at_unix: u64,
    local_verification_age_seconds: u64,
    age_seconds: u64,
}

impl AccountEvidence {
    pub const fn balance(&self) -> U256 {
        self.balance
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }
    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
    pub const fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }
    pub const fn proof_hash(&self) -> [u8; 32] {
        self.proof_hash
    }
    pub const fn chain_evidence_at_unix(&self) -> u64 {
        self.chain_evidence_at_unix
    }
    /// Age of the local verification/import operation. This is informational
    /// and never establishes chain freshness.
    pub const fn local_verification_age_seconds(&self) -> u64 {
        self.local_verification_age_seconds
    }
    pub const fn age_seconds(&self) -> u64 {
        self.age_seconds
    }
}

/// Account display state. `Unknown` deliberately carries no numeric balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountAssurance {
    Unknown,
    Stale(AccountEvidence),
    CurrentVerified(AccountEvidence),
}

impl AccountAssurance {
    pub const fn evidence(&self) -> Option<&AccountEvidence> {
        match self {
            Self::Unknown => None,
            Self::Stale(evidence) | Self::CurrentVerified(evidence) => Some(evidence),
        }
    }
}

/// User-selected fields for one plain Sepolia native-ETH transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTransferRequest {
    to: Address,
    value: U256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl FieldTransferRequest {
    pub const fn new(
        to: Address,
        value: U256,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Self {
        Self {
            to,
            value,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }
}

/// Opaque pending operation. It contains W1's immutable prepared transfer but
/// exposes neither arbitrary bytes nor an independent signing API.
pub struct PreparedFieldTransfer {
    operation_id: OperationId,
    review_digest: [u8; 32],
    prepared: PreparedTransfer,
}

impl std::fmt::Debug for PreparedFieldTransfer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedFieldTransfer")
            .field("operation_id", &self.operation_id)
            .field("review_digest", &self.review_digest)
            .finish_non_exhaustive()
    }
}

impl PreparedFieldTransfer {
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn review(&self) -> &ratspeak_eth_wallet::TransferReview {
        self.prepared.review()
    }

    /// Canonical bytes shown by a native review surface before this one-shot
    /// pending operation is consumed by [`EthereumNodeStore::authorize_and_store`].
    pub fn canonical_signing_bytes(&self) -> &[u8] {
        self.prepared.canonical_signing_bytes()
    }
}

/// Platform custody consumes exactly one W1 prepared transfer and returns W1's
/// validated signed result. Implementations own native user-presence, secret
/// handling, and a fresh trusted clock sample immediately before W1 signing.
/// They must return an error, not a signature, if the transfer expired while
/// the native prompt or secret-unlock work was in progress. Custody must not
/// submit, persist, or otherwise export signed bytes: the node commits and
/// validates them before the relay layer may observe them.
pub trait PlatformTransferCustody {
    type Error;

    fn authorize_and_sign(
        &mut self,
        prepared: PreparedTransfer,
    ) -> std::result::Result<SignedTransfer, Self::Error>;
}

/// Trusted application clock sampled on both sides of native authorization.
pub trait FieldNodeClock {
    fn now_unix(&mut self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Prepared,
    /// Custody began but no signed result was atomically persisted. It cannot be replayed.
    Interrupted,
    Cancelled,
    Signed {
        tx_hash: [u8; 32],
    },
}

/// Transaction state. Relay observations are explicitly non-authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionAssurance {
    Signed {
        non_authoritative_observations: Vec<NonAuthoritativeTransactionObservation>,
    },
    NeedsReverification(StoredReceiptRecord),
    FinalizedSuccess(StoredReceiptRecord),
    FinalizedFailure(StoredReceiptRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredOperationState {
    Prepared,
    Authorizing,
    Cancelled,
    Signed,
}

impl StoredOperationState {
    const fn as_i64(self) -> i64 {
        match self {
            Self::Prepared => 1,
            Self::Authorizing => 2,
            Self::Cancelled => 3,
            Self::Signed => 4,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Authorizing),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::Signed),
            _ => Err(NodeStoreError::new("invalid stored field operation state")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredOperation {
    operation_id: [u8; 16],
    chain_id: u64,
    network: String,
    sender: [u8; 20],
    nonce: u64,
    signing_hash: [u8; 32],
    review_context_digest: [u8; 32],
    review_digest: [u8; 32],
    prepared_at_unix: u64,
    expires_at_unix: u64,
    account_block_number: u64,
    account_block_hash: [u8; 32],
    account_state_root: [u8; 32],
    checkpoint_root: [u8; 32],
    account_proof_hash: [u8; 32],
    evidence_verified_at_unix: u64,
    chain_evidence_at_unix: u64,
    maximum_evidence_age_seconds: u64,
    state: StoredOperationState,
    tx_hash: Option<[u8; 32]>,
}

pub(crate) fn create_schema(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_field_operations (
            operation_id BLOB PRIMARY KEY NOT NULL CHECK(length(operation_id) = 16),
            chain_id TEXT NOT NULL,
            network TEXT NOT NULL,
            sender BLOB NOT NULL CHECK(length(sender) = 20),
            nonce TEXT NOT NULL,
            signing_hash BLOB NOT NULL CHECK(length(signing_hash) = 32),
            review_context_digest BLOB NOT NULL CHECK(length(review_context_digest) = 32),
            review_digest BLOB NOT NULL CHECK(length(review_digest) = 32),
            prepared_at_unix TEXT NOT NULL,
            expires_at_unix TEXT NOT NULL,
            account_block_number TEXT NOT NULL,
            account_block_hash BLOB NOT NULL CHECK(length(account_block_hash) = 32),
            account_state_root BLOB NOT NULL CHECK(length(account_state_root) = 32),
            checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
            account_proof_hash BLOB NOT NULL CHECK(length(account_proof_hash) = 32),
            evidence_verified_at_unix TEXT NOT NULL,
            chain_evidence_at_unix TEXT NOT NULL,
            maximum_evidence_age_seconds TEXT NOT NULL,
            state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4),
            tx_hash BLOB CHECK(tx_hash IS NULL OR length(tx_hash) = 32),
            record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
            recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
            CHECK((state = 4 AND tx_hash IS NOT NULL) OR (state != 4 AND tx_hash IS NULL))
        );",
        )
        .map_err(NodeStoreError::sqlite)
}

impl EthereumNodeStore {
    /// Reads the newest proof-backed account record and labels it current only
    /// when it matches the latest finalized execution head and the caller's age policy.
    pub fn account_assurance(
        &self,
        account: WalletAccount,
        now_unix: u64,
        maximum_age_seconds: u64,
    ) -> Result<AccountAssurance> {
        if account.chain_id() != SEPOLIA_CHAIN_ID || account.network() != SEPOLIA_NETWORK {
            return Err(NodeStoreError::new("wallet account is not Sepolia"));
        }
        let address = *account.address().0;
        let Some((stored, verified_at)) = latest_account(&self.connection, address)? else {
            return Ok(AccountAssurance::Unknown);
        };
        // A future local import timestamp means this clock/database pairing is
        // ambiguous. It cannot make otherwise old chain evidence current.
        if verified_at == 0 || verified_at > now_unix {
            return Ok(AccountAssurance::Unknown);
        }
        let block = read_execution_block(
            &self.connection,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            stored.block_hash(),
        )?
        .ok_or_else(|| NodeStoreError::new("account lost its persisted execution evidence"))?;
        if block.state_root() != stored.state_root()
            || block.execution_block_number() != stored.block_number()
        {
            return Err(NodeStoreError::new(
                "account conflicts with its execution evidence",
            ));
        }
        let Some(current_head) = self.latest_finalized_header(SEPOLIA_CHAIN_ID)? else {
            return Ok(AccountAssurance::Unknown);
        };
        if current_head.execution_block_number() != stored.block_number()
            || current_head.execution_block_hash() != stored.block_hash()
            || current_head.state_root() != stored.state_root()
            || current_head.checkpoint_root() != block.checkpoint_root()
        {
            return Ok(AccountAssurance::Unknown);
        }
        let chain_evidence_at_unix = sepolia_slot_start_unix(current_head.finalized_slot())
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let Some(age_seconds) = now_unix.checked_sub(chain_evidence_at_unix) else {
            return Ok(AccountAssurance::Unknown);
        };
        if age_seconds > maximum_age_seconds
            || !checkpoint_is_active_at(self, block.checkpoint_root(), now_unix)?
        {
            return Ok(AccountAssurance::Unknown);
        }
        let evidence = AccountEvidence {
            balance: stored.balance(),
            nonce: stored.nonce(),
            block_number: stored.block_number(),
            block_hash: stored.block_hash(),
            state_root: stored.state_root(),
            checkpoint_root: block.checkpoint_root(),
            proof_hash: stored.proof_bundle_hash(),
            chain_evidence_at_unix,
            local_verified_at_unix: verified_at,
            local_verification_age_seconds: now_unix - verified_at,
            age_seconds,
        };
        Ok(AccountAssurance::CurrentVerified(evidence))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_native_transfer(
        &mut self,
        account: WalletAccount,
        request: FieldTransferRequest,
        operation_id: OperationId,
        prepared_at_unix: u64,
        expires_at_unix: u64,
        maximum_evidence_age_seconds: u64,
    ) -> Result<PreparedFieldTransfer> {
        let AccountAssurance::CurrentVerified(evidence) =
            self.account_assurance(account, prepared_at_unix, maximum_evidence_age_seconds)?
        else {
            return Err(NodeStoreError::new(
                "a current verified account proof is required",
            ));
        };
        let context_bytes = canonical_review_context(&account, &evidence);
        let review_context = ReviewContext::from_canonical_bytes(&context_bytes)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let intent = TransferIntent::new(
            SEPOLIA_CHAIN_ID,
            account.address(),
            request.to,
            request.value,
            evidence.nonce,
            request.max_fee_per_gas,
            request.max_priority_fee_per_gas,
        );
        let prepared = account
            .prepare_transfer(
                intent,
                operation_id,
                review_context,
                prepared_at_unix,
                expires_at_unix,
            )
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        if prepared.review().maximum_total_cost() > evidence.balance {
            return Err(NodeStoreError::new(
                "current verified balance is below the maximum transfer cost",
            ));
        }
        let review = prepared.review();
        let stored = StoredOperation {
            operation_id: *operation_id.as_bytes(),
            chain_id: review.chain_id(),
            network: review.network().to_owned(),
            sender: *review.from().0,
            nonce: review.nonce(),
            signing_hash: review.signing_hash().0,
            review_context_digest: review.review_context().digest().0,
            review_digest: review.review_digest().0,
            prepared_at_unix: review.prepared_at_unix(),
            expires_at_unix: review.expires_at_unix(),
            account_block_number: evidence.block_number,
            account_block_hash: evidence.block_hash,
            account_state_root: evidence.state_root,
            checkpoint_root: evidence.checkpoint_root,
            account_proof_hash: evidence.proof_hash,
            evidence_verified_at_unix: evidence.local_verified_at_unix,
            chain_evidence_at_unix: evidence.chain_evidence_at_unix,
            maximum_evidence_age_seconds,
            state: StoredOperationState::Prepared,
            tx_hash: None,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        insert_operation(&transaction, &stored)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(PreparedFieldTransfer {
            operation_id,
            review_digest: stored.review_digest,
            prepared,
        })
    }

    pub fn cancel_operation(&mut self, operation_id: OperationId) -> Result<OperationStatus> {
        self.cancel_operation_if_present(operation_id)?
            .ok_or_else(|| NodeStoreError::new("unknown field operation"))
    }

    /// Cancels an operation when its row still exists. A missing row means no
    /// durable signing authority remains and is therefore already reconciled.
    pub fn cancel_operation_if_present(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<OperationStatus>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let Some(mut stored) = read_operation(&transaction, *operation_id.as_bytes())? else {
            return Ok(None);
        };
        match stored.state {
            StoredOperationState::Signed => {
                return Err(NodeStoreError::new("signed operation cannot be cancelled"));
            }
            StoredOperationState::Cancelled => return Ok(Some(OperationStatus::Cancelled)),
            StoredOperationState::Prepared => {
                stored.state = StoredOperationState::Cancelled;
                update_operation_state(&transaction, &stored)?;
            }
            StoredOperationState::Authorizing => {
                return Err(NodeStoreError::new(
                    "authorizing operation must be recovered before reuse",
                ));
            }
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(Some(OperationStatus::Cancelled))
    }

    /// Invalidates operations whose in-memory capability was lost when the
    /// application stopped. Custody returns signed bytes only to
    /// [`Self::authorize_and_store`]; that method validates and commits them
    /// before its caller can wake relay work. Therefore an `Authorizing` row
    /// found at startup has no durably stored or relay-visible transaction and
    /// can safely release its nonce reservation.
    pub fn reconcile_interrupted_operations(&mut self) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let operation_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT operation_id FROM eth_field_operations
                     WHERE state IN (?1, ?2)",
                )
                .map_err(NodeStoreError::sqlite)?;
            let rows = statement
                .query_map(
                    [
                        StoredOperationState::Prepared.as_i64(),
                        StoredOperationState::Authorizing.as_i64(),
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(NodeStoreError::sqlite)?;
            let mut operation_ids = Vec::new();
            for row in rows {
                let bytes = row.map_err(NodeStoreError::sqlite)?;
                operation_ids.push(stored_array(&bytes, "operation identifier")?);
            }
            operation_ids
        };
        for operation_id in &operation_ids {
            let mut stored = read_operation(&transaction, *operation_id)?
                .ok_or_else(|| NodeStoreError::new("field operation disappeared"))?;
            if !matches!(
                stored.state,
                StoredOperationState::Prepared | StoredOperationState::Authorizing
            ) {
                return Err(NodeStoreError::new(
                    "field operation changed during startup reconciliation",
                ));
            }
            stored.state = StoredOperationState::Cancelled;
            update_operation_state(&transaction, &stored)?;
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(operation_ids.len())
    }

    pub fn operation_status(&self, operation_id: OperationId) -> Result<Option<OperationStatus>> {
        Ok(
            read_operation(&self.connection, *operation_id.as_bytes())?.map(|stored| match stored
                .state
            {
                StoredOperationState::Prepared => OperationStatus::Prepared,
                StoredOperationState::Authorizing => OperationStatus::Interrupted,
                StoredOperationState::Cancelled => OperationStatus::Cancelled,
                StoredOperationState::Signed => OperationStatus::Signed {
                    tx_hash: stored.tx_hash.expect("validated signed operation"),
                },
            }),
        )
    }

    pub fn authorize_and_store<C: PlatformTransferCustody, K: FieldNodeClock>(
        &mut self,
        pending: PreparedFieldTransfer,
        custody: &mut C,
        clock: &mut K,
    ) -> Result<StoredSignedTransaction> {
        let operation_id = *pending.operation_id.as_bytes();
        let authorization_started_at_unix = clock.now_unix();
        {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(NodeStoreError::sqlite)?;
            let mut stored = read_operation(&transaction, operation_id)?
                .ok_or_else(|| NodeStoreError::new("unknown field operation"))?;
            validate_pending(&stored, &pending)?;
            validate_operation_evidence(&transaction, &stored, authorization_started_at_unix)?;
            if stored.state != StoredOperationState::Prepared {
                return Err(NodeStoreError::new("field operation was already consumed"));
            }
            if !time_is_current(&stored, authorization_started_at_unix) {
                stored.state = StoredOperationState::Cancelled;
                update_operation_state(&transaction, &stored)?;
                transaction.commit().map_err(NodeStoreError::sqlite)?;
                return Err(NodeStoreError::new(
                    "field operation is outside its validity window",
                ));
            }
            stored.state = StoredOperationState::Authorizing;
            update_operation_state(&transaction, &stored)?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
        }

        let signed = match custody.authorize_and_sign(pending.prepared) {
            Ok(signed) => signed,
            Err(_) => {
                self.cancel_authorizing_operation(operation_id)?;
                return Err(NodeStoreError::new(
                    "platform custody rejected the transfer",
                ));
            }
        };
        let signed_at_unix = clock.now_unix();
        let finalized = (|| {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(NodeStoreError::sqlite)?;
            let mut stored = read_operation(&transaction, operation_id)?
                .ok_or_else(|| NodeStoreError::new("unknown field operation"))?;
            if stored.state != StoredOperationState::Authorizing {
                return Err(NodeStoreError::new(
                    "field operation authorization state changed",
                ));
            }
            validate_operation_evidence(&transaction, &stored, signed_at_unix)?;
            validate_signed(&stored, &signed, signed_at_unix)?;
            let (_, transaction_record) = record_locally_signed_transaction_in(
                &transaction,
                signed.raw_transaction(),
                stored.sender,
                stored.review_digest,
                signed_at_unix,
            )?;
            if transaction_record.tx_hash() != signed.tx_hash().0
                || transaction_record.signing_hash() != stored.signing_hash
                || transaction_record.nonce() != stored.nonce
            {
                return Err(NodeStoreError::new(
                    "signed transaction does not match the durable review",
                ));
            }
            stored.state = StoredOperationState::Signed;
            stored.tx_hash = Some(transaction_record.tx_hash());
            update_operation_state(&transaction, &stored)?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            Ok(transaction_record)
        })();
        match finalized {
            Ok(transaction_record) => Ok(transaction_record),
            Err(error) => {
                // A failed or rolled-back finalization has not exposed signed
                // bytes to relay. If SQLite reports an ambiguous commit and
                // the row is already Signed, this cancellation fails closed
                // instead of overwriting the durable transaction.
                self.cancel_authorizing_operation(operation_id)?;
                Err(error)
            }
        }
    }

    fn cancel_authorizing_operation(&mut self, operation_id: [u8; 16]) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let mut stored = read_operation(&transaction, operation_id)?
            .ok_or_else(|| NodeStoreError::new("unknown field operation"))?;
        if stored.state != StoredOperationState::Authorizing {
            return Err(NodeStoreError::new(
                "field operation authorization state changed",
            ));
        }
        stored.state = StoredOperationState::Cancelled;
        update_operation_state(&transaction, &stored)?;
        transaction.commit().map_err(NodeStoreError::sqlite)
    }

    pub fn transaction_assurance(&self, tx_hash: [u8; 32]) -> Result<Option<TransactionAssurance>> {
        let Some(transaction) = self.signed_transaction_by_hash(tx_hash)? else {
            return Ok(None);
        };
        if transaction.chain_id() == SEPOLIA_CHAIN_ID {
            if let Some(receipt) = self.receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, tx_hash)? {
                return Ok(Some(TransactionAssurance::NeedsReverification(receipt)));
            }
        }
        let mut observations: Vec<_> = self
            .transaction_assurance_history(transaction.chain_id(), tx_hash)?
            .into_iter()
            .filter_map(|event| match event.event_kind() {
                AssuranceEventKind::TransportDelivered => {
                    Some(NonAuthoritativeTransactionObservation::TransportDelivered)
                }
                AssuranceEventKind::GatewayAcknowledged => {
                    Some(NonAuthoritativeTransactionObservation::GatewayAcknowledged)
                }
                AssuranceEventKind::RpcAccepted => {
                    Some(NonAuthoritativeTransactionObservation::RpcAccepted)
                }
                _ => None,
            })
            .collect();
        for observation in stored_relay_observations(&self.connection, tx_hash)? {
            let observation = match observation {
                RelayObservation::GatewayAccepted => {
                    Some(NonAuthoritativeTransactionObservation::GatewayAcknowledged)
                }
                RelayObservation::RpcAccepted => {
                    Some(NonAuthoritativeTransactionObservation::RpcAccepted)
                }
                RelayObservation::RpcRejected => None,
            };
            if let Some(observation) = observation
                && !observations.contains(&observation)
            {
                observations.push(observation);
            }
        }
        Ok(Some(TransactionAssurance::Signed {
            non_authoritative_observations: observations,
        }))
    }

    /// Replays the complete stored consensus, execution-header, transaction,
    /// and receipt proof chain before returning finalized success or failure.
    /// Relay/RPC observations and previously stored classifications cannot
    /// reach either finalized result.
    pub fn transaction_assurance_reverified(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<TransactionAssurance>> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        self.transaction_assurance_reverified_at(tx_hash, now_unix)
    }

    fn transaction_assurance_reverified_at(
        &self,
        tx_hash: [u8; 32],
        now_unix: u64,
    ) -> Result<Option<TransactionAssurance>> {
        let Some(transaction) = self.signed_transaction_by_hash(tx_hash)? else {
            return Ok(None);
        };
        if transaction.chain_id() != SEPOLIA_CHAIN_ID {
            // OP/Nitro receipts live in the stack-neutral verified-EVM store.
            // Until their persisted anchor evidence can be replayed here, do
            // not promote a durable classification to verified assurance.
            return self.transaction_assurance(tx_hash);
        }
        let Some(receipt) = self.receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, tx_hash)? else {
            return self.transaction_assurance(tx_hash);
        };
        let verifier = ratspeak_eth_verifier::Verifier::sepolia();
        let verified_receipt =
            match verifier.parse_finalized_tx_receipt_proof(receipt.canonical_bundle()) {
                Ok(parsed) => {
                    let anchor = read_execution_block(
                        &self.connection,
                        SEPOLIA_CHAIN_ID,
                        SEPOLIA_NETWORK,
                        parsed.anchor_block_hash,
                    )?
                    .ok_or_else(|| {
                        NodeStoreError::new("receipt lost its persisted finalized anchor")
                    })?;
                    let consensus = read_finalized_header_by_proof_hash(
                        &self.connection,
                        SEPOLIA_CHAIN_ID,
                        SEPOLIA_NETWORK,
                        anchor.consensus_bundle_hash(),
                    )?
                    .ok_or_else(|| {
                        NodeStoreError::new("receipt lost its persisted consensus evidence")
                    })?;
                    let verified_consensus = crate::messaging::reverify_historical_consensus(
                        self, &verifier, &consensus, now_unix,
                    )?;
                    let verified_anchor = verifier
                        .verify_execution_header(anchor.canonical_bundle(), &verified_consensus)
                        .map_err(|error| NodeStoreError::new(error.to_string()))?;
                    let verified = verifier
                        .verify_finalized_tx_receipt(receipt.canonical_bundle(), &verified_anchor)
                        .map_err(|error| NodeStoreError::new(error.to_string()))?;
                    verified.into_parts().1
                }
                Err(VerifyError::UnsupportedKind(KIND_TX_RECEIPT_PROOF)) => {
                    let block = read_execution_block(
                        &self.connection,
                        SEPOLIA_CHAIN_ID,
                        SEPOLIA_NETWORK,
                        receipt.block_hash(),
                    )?
                    .ok_or_else(|| {
                        NodeStoreError::new("receipt lost its persisted execution evidence")
                    })?;
                    let consensus = read_finalized_header_by_proof_hash(
                        &self.connection,
                        SEPOLIA_CHAIN_ID,
                        SEPOLIA_NETWORK,
                        block.consensus_bundle_hash(),
                    )?
                    .ok_or_else(|| {
                        NodeStoreError::new("receipt lost its persisted consensus evidence")
                    })?;
                    let verified_consensus = crate::messaging::reverify_historical_consensus(
                        self, &verifier, &consensus, now_unix,
                    )?;
                    let verified_block = verifier
                        .verify_execution_header(block.canonical_bundle(), &verified_consensus)
                        .map_err(|error| NodeStoreError::new(error.to_string()))?;
                    verifier
                        .verify_tx_receipt(receipt.canonical_bundle(), &verified_block)
                        .map_err(|error| NodeStoreError::new(error.to_string()))?
                }
                Err(error) => return Err(NodeStoreError::new(error.to_string())),
            };
        classify_verified_receipt(&transaction, receipt, &verified_receipt).map(Some)
    }
}

fn canonical_review_context(account: &WalletAccount, evidence: &AccountEvidence) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REVIEW_CONTEXT_DOMAIN.len() + 8 + 20 + 32 * 4 + 8 * 2);
    bytes.extend_from_slice(REVIEW_CONTEXT_DOMAIN);
    bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_be_bytes());
    bytes.extend_from_slice(account.address().as_slice());
    bytes.extend_from_slice(&evidence.checkpoint_root);
    bytes.extend_from_slice(&evidence.block_number.to_be_bytes());
    bytes.extend_from_slice(&evidence.block_hash);
    bytes.extend_from_slice(&evidence.state_root);
    bytes.extend_from_slice(&evidence.proof_hash);
    bytes.extend_from_slice(&evidence.chain_evidence_at_unix.to_be_bytes());
    bytes
}

fn latest_account(
    connection: &rusqlite::Connection,
    address: [u8; 20],
) -> Result<Option<(StoredAccountRecord, u64)>> {
    let row = connection
        .query_row(
            "SELECT import_key, recorded_at_unix FROM eth_verified_account_imports
         WHERE chain_id = ?1 AND network = ?2 AND address = ?3 AND canonical_bundle IS NOT NULL
         ORDER BY length(block_number) DESC, block_number DESC, recorded_at_unix DESC LIMIT 1",
            rusqlite::params![
                SEPOLIA_CHAIN_ID.to_string(),
                SEPOLIA_NETWORK,
                address.as_slice()
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((key, verified_at)) = row else {
        return Ok(None);
    };
    let verified_at = u64::try_from(verified_at)
        .map_err(|_| NodeStoreError::new("invalid account verification time"))?;
    if verified_at == 0 {
        return Err(NodeStoreError::new("account verification time is missing"));
    }
    let account = account_by_import_key(connection, stored_array(&key, "account import key")?)?
        .ok_or_else(|| NodeStoreError::new("account index lost its proof record"))?;
    Ok(Some((account, verified_at)))
}

fn insert_operation(connection: &rusqlite::Connection, stored: &StoredOperation) -> Result<()> {
    if read_operation(connection, stored.operation_id)?.is_some() {
        return Err(NodeStoreError::new(
            "field operation identifier was already used",
        ));
    }
    let digest = operation_digest(stored);
    connection.execute(
        "INSERT INTO eth_field_operations (
            operation_id, chain_id, network, sender, nonce, signing_hash,
            review_context_digest, review_digest, prepared_at_unix, expires_at_unix,
            account_block_number, account_block_hash, account_state_root, checkpoint_root,
            account_proof_hash, evidence_verified_at_unix, chain_evidence_at_unix,
            maximum_evidence_age_seconds, state, tx_hash, record_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        rusqlite::params![
            stored.operation_id.as_slice(), stored.chain_id.to_string(), stored.network,
            stored.sender.as_slice(), stored.nonce.to_string(), stored.signing_hash.as_slice(),
            stored.review_context_digest.as_slice(), stored.review_digest.as_slice(),
            stored.prepared_at_unix.to_string(), stored.expires_at_unix.to_string(),
            stored.account_block_number.to_string(), stored.account_block_hash.as_slice(),
            stored.account_state_root.as_slice(), stored.checkpoint_root.as_slice(),
            stored.account_proof_hash.as_slice(), stored.evidence_verified_at_unix.to_string(),
            stored.chain_evidence_at_unix.to_string(), stored.maximum_evidence_age_seconds.to_string(),
            stored.state.as_i64(), stored.tx_hash.as_ref().map(<[u8; 32]>::as_slice),
            digest.as_slice(),
        ],
    ).map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            NodeStoreError::new(
                "an active field operation already reserves the current account nonce",
            )
        } else { NodeStoreError::sqlite(error) }
    })?;
    Ok(())
}

fn read_operation(
    connection: &rusqlite::Connection,
    operation_id: [u8; 16],
) -> Result<Option<StoredOperation>> {
    let row = connection
        .query_row(
            "SELECT operation_id, chain_id, network, sender, nonce, signing_hash,
                review_context_digest, review_digest, prepared_at_unix, expires_at_unix,
                account_block_number, account_block_hash, account_state_root, checkpoint_root,
                account_proof_hash, evidence_verified_at_unix, chain_evidence_at_unix,
                maximum_evidence_age_seconds, state, tx_hash, record_digest
         FROM eth_field_operations WHERE operation_id = ?1",
            [operation_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, Option<Vec<u8>>>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored = StoredOperation {
        operation_id: stored_array(&row.0, "operation identifier")?,
        chain_id: parse_stored_u64(&row.1, "operation chain id")?,
        network: row.2,
        sender: stored_array(&row.3, "operation sender")?,
        nonce: parse_stored_u64(&row.4, "operation nonce")?,
        signing_hash: stored_array(&row.5, "operation signing hash")?,
        review_context_digest: stored_array(&row.6, "operation review context")?,
        review_digest: stored_array(&row.7, "operation review digest")?,
        prepared_at_unix: parse_stored_u64(&row.8, "operation preparation time")?,
        expires_at_unix: parse_stored_u64(&row.9, "operation expiry")?,
        account_block_number: parse_stored_u64(&row.10, "operation account block")?,
        account_block_hash: stored_array(&row.11, "operation account block hash")?,
        account_state_root: stored_array(&row.12, "operation account state root")?,
        checkpoint_root: stored_array(&row.13, "operation checkpoint root")?,
        account_proof_hash: stored_array(&row.14, "operation account proof hash")?,
        evidence_verified_at_unix: parse_stored_u64(&row.15, "operation evidence time")?,
        chain_evidence_at_unix: parse_stored_u64(&row.16, "operation chain evidence time")?,
        maximum_evidence_age_seconds: parse_stored_u64(&row.17, "operation evidence age")?,
        state: StoredOperationState::from_i64(row.18)?,
        tx_hash: row
            .19
            .as_deref()
            .map(|value| stored_array(value, "operation transaction hash"))
            .transpose()?,
    };
    if stored.chain_id != SEPOLIA_CHAIN_ID
        || stored.network != SEPOLIA_NETWORK
        || stored.operation_id != operation_id
        || stored.review_digest == [0; 32]
        || stored.review_context_digest == [0; 32]
        || stored.signing_hash == [0; 32]
        || stored.account_proof_hash == [0; 32]
        || stored.evidence_verified_at_unix == 0
        || stored.chain_evidence_at_unix == 0
        || (stored.state == StoredOperationState::Signed) != stored.tx_hash.is_some()
        || stored_array::<32>(&row.20, "operation record digest")? != operation_digest(&stored)
    {
        return Err(NodeStoreError::new("stored field operation is corrupted"));
    }
    Ok(Some(stored))
}

pub(crate) fn ensure_no_pending_field_operations(connection: &rusqlite::Connection) -> Result<()> {
    let identifiers = {
        let mut statement = connection
            .prepare("SELECT operation_id FROM eth_field_operations ORDER BY rowid")
            .map_err(NodeStoreError::sqlite)?;
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(NodeStoreError::sqlite)?
            .map(|row| {
                stored_array(
                    &row.map_err(NodeStoreError::sqlite)?,
                    "operation identifier",
                )
            })
            .collect::<Result<Vec<[u8; 16]>>>()?
    };
    for identifier in identifiers {
        let operation = read_operation(connection, identifier)?
            .ok_or_else(|| NodeStoreError::new("field operation disappeared"))?;
        if matches!(
            operation.state,
            StoredOperationState::Prepared | StoredOperationState::Authorizing
        ) {
            return Err(NodeStoreError::new(
                "pending field operation blocks gateway replacement",
            ));
        }
    }
    Ok(())
}

fn update_operation_state(transaction: &Transaction<'_>, stored: &StoredOperation) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE eth_field_operations SET state = ?1, tx_hash = ?2, record_digest = ?3
         WHERE operation_id = ?4",
            rusqlite::params![
                stored.state.as_i64(),
                stored.tx_hash.as_ref().map(<[u8; 32]>::as_slice),
                operation_digest(stored).as_slice(),
                stored.operation_id.as_slice()
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed != 1 {
        return Err(NodeStoreError::new("field operation state update was lost"));
    }
    Ok(())
}

fn operation_digest(stored: &StoredOperation) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-field-operation-v2");
    hasher.update(stored.operation_id);
    hasher.update(stored.chain_id.to_be_bytes());
    hasher.update((stored.network.len() as u16).to_be_bytes());
    hasher.update(stored.network.as_bytes());
    hasher.update(stored.sender);
    hasher.update(stored.nonce.to_be_bytes());
    hasher.update(stored.signing_hash);
    hasher.update(stored.review_context_digest);
    hasher.update(stored.review_digest);
    hasher.update(stored.prepared_at_unix.to_be_bytes());
    hasher.update(stored.expires_at_unix.to_be_bytes());
    hasher.update(stored.account_block_number.to_be_bytes());
    hasher.update(stored.account_block_hash);
    hasher.update(stored.account_state_root);
    hasher.update(stored.checkpoint_root);
    hasher.update(stored.account_proof_hash);
    hasher.update(stored.evidence_verified_at_unix.to_be_bytes());
    hasher.update(stored.chain_evidence_at_unix.to_be_bytes());
    hasher.update(stored.maximum_evidence_age_seconds.to_be_bytes());
    hasher.update(stored.state.as_i64().to_be_bytes());
    hasher.update(stored.tx_hash.unwrap_or([0; 32]));
    hasher.finalize().into()
}

fn validate_pending(stored: &StoredOperation, pending: &PreparedFieldTransfer) -> Result<()> {
    let review = pending.prepared.review();
    if stored.operation_id != *pending.operation_id.as_bytes()
        || stored.review_digest != pending.review_digest
        || stored.review_digest != review.review_digest().0
        || stored.review_context_digest != review.review_context().digest().0
        || stored.chain_id != review.chain_id()
        || stored.network != review.network()
        || stored.sender != *review.from().0
        || stored.nonce != review.nonce()
        || stored.signing_hash != review.signing_hash().0
        || stored.prepared_at_unix != review.prepared_at_unix()
        || stored.expires_at_unix != review.expires_at_unix()
        || review.gas_limit() != NATIVE_TRANSFER_GAS_LIMIT
    {
        return Err(NodeStoreError::new(
            "prepared transfer does not match its durable operation",
        ));
    }
    let account = WalletAccount::sepolia(Address::from(stored.sender));
    let evidence = AccountEvidence {
        balance: U256::ZERO,
        nonce: stored.nonce,
        block_number: stored.account_block_number,
        block_hash: stored.account_block_hash,
        state_root: stored.account_state_root,
        checkpoint_root: stored.checkpoint_root,
        proof_hash: stored.account_proof_hash,
        chain_evidence_at_unix: stored.chain_evidence_at_unix,
        local_verified_at_unix: stored.evidence_verified_at_unix,
        local_verification_age_seconds: 0,
        age_seconds: 0,
    };
    let expected_context =
        ReviewContext::from_canonical_bytes(&canonical_review_context(&account, &evidence))
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
    if expected_context.digest().0 != stored.review_context_digest {
        return Err(NodeStoreError::new(
            "durable review context no longer matches its evidence",
        ));
    }
    Ok(())
}

fn validate_operation_evidence(
    connection: &rusqlite::Connection,
    stored: &StoredOperation,
    now_unix: u64,
) -> Result<()> {
    let (key, local_verified_at_unix) = connection
        .query_row(
            "SELECT import_key, recorded_at_unix FROM eth_verified_account_imports
             WHERE chain_id = ?1 AND network = ?2 AND address = ?3
               AND block_hash = ?4 AND proof_bundle_hash = ?5
               AND canonical_bundle IS NOT NULL",
            rusqlite::params![
                stored.chain_id.to_string(),
                stored.network,
                stored.sender.as_slice(),
                stored.account_block_hash.as_slice(),
                stored.account_proof_hash.as_slice(),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .ok_or_else(|| NodeStoreError::new("durable operation lost its account proof"))?;
    let local_verified_at_unix = u64::try_from(local_verified_at_unix)
        .map_err(|_| NodeStoreError::new("invalid account verification time"))?;
    let account = account_by_import_key(connection, stored_array(&key, "account import key")?)?
        .ok_or_else(|| NodeStoreError::new("durable operation lost its account record"))?;
    if account.address() != stored.sender
        || account.nonce() != stored.nonce
        || account.block_number() != stored.account_block_number
        || account.block_hash() != stored.account_block_hash
        || account.state_root() != stored.account_state_root
        || account.proof_bundle_hash() != stored.account_proof_hash
        || local_verified_at_unix != stored.evidence_verified_at_unix
    {
        return Err(NodeStoreError::new(
            "durable operation conflicts with its account proof",
        ));
    }
    let block = read_execution_block(
        connection,
        stored.chain_id,
        &stored.network,
        stored.account_block_hash,
    )?
    .ok_or_else(|| NodeStoreError::new("durable operation lost its execution evidence"))?;
    let latest = read_latest_finalized_header(connection, stored.chain_id)?
        .ok_or_else(|| NodeStoreError::new("durable operation has no finalized head"))?;
    if block.execution_block_number() != stored.account_block_number
        || block.state_root() != stored.account_state_root
        || block.checkpoint_root() != stored.checkpoint_root
        || latest.execution_block_number() != stored.account_block_number
        || latest.execution_block_hash() != stored.account_block_hash
        || latest.state_root() != stored.account_state_root
        || latest.checkpoint_root() != stored.checkpoint_root
        || sepolia_slot_start_unix(latest.finalized_slot())
            .map_err(|error| NodeStoreError::new(error.to_string()))?
            != stored.chain_evidence_at_unix
    {
        return Err(NodeStoreError::new(
            "durable operation account evidence is no longer current",
        ));
    }
    ensure_active_checkpoint_at_connection(connection, stored.checkpoint_root, now_unix)
        .map_err(checkpoint_policy_store_error)?;
    Ok(())
}

fn checkpoint_is_active_at(
    store: &EthereumNodeStore,
    checkpoint_root: [u8; 32],
    now_unix: u64,
) -> Result<bool> {
    match ensure_active_checkpoint_at(store, checkpoint_root, now_unix) {
        Ok(()) => Ok(true),
        Err(
            CheckpointPolicyError::NoApprovedCheckpoint
            | CheckpointPolicyError::StaleCheckpoint
            | CheckpointPolicyError::CheckpointRollback
            | CheckpointPolicyError::RevokedCheckpoint,
        ) => Ok(false),
        Err(error) => Err(checkpoint_policy_store_error(error)),
    }
}

fn checkpoint_policy_store_error(error: CheckpointPolicyError) -> NodeStoreError {
    match error {
        CheckpointPolicyError::Store(error) => error,
        error => NodeStoreError::new(format!(
            "checkpoint policy rejected account evidence: {error}"
        )),
    }
}

fn validate_signed(stored: &StoredOperation, signed: &SignedTransfer, now_unix: u64) -> Result<()> {
    let review = signed.review();
    if !time_is_current(stored, now_unix) {
        return Err(NodeStoreError::new(
            "signed transfer or its account evidence expired during authorization",
        ));
    }
    if stored.operation_id != *review.operation_id().as_bytes()
        || stored.review_digest != review.review_digest().0
        || stored.review_context_digest != review.review_context().digest().0
        || stored.chain_id != review.chain_id()
        || stored.network != review.network()
        || stored.sender != *review.from().0
        || stored.nonce != review.nonce()
        || stored.signing_hash != review.signing_hash().0
        || stored.prepared_at_unix != review.prepared_at_unix()
        || stored.expires_at_unix != review.expires_at_unix()
    {
        return Err(NodeStoreError::new(
            "signed transfer does not match its durable review",
        ));
    }
    Ok(())
}

fn time_is_current(stored: &StoredOperation, now_unix: u64) -> bool {
    now_unix >= stored.prepared_at_unix
        && now_unix < stored.expires_at_unix
        && now_unix >= stored.evidence_verified_at_unix
        && now_unix
            .checked_sub(stored.chain_evidence_at_unix)
            .is_some_and(|age| age <= stored.maximum_evidence_age_seconds)
}

trait ReceiptAuthority {
    fn chain_id(&self) -> u64;
    fn network(&self) -> &str;
    fn block_number(&self) -> u64;
    fn block_hash(&self) -> [u8; 32];
    fn tx_hash(&self) -> [u8; 32];
    fn tx_index(&self) -> u64;
    fn succeeded(&self) -> bool;
    fn checkpoint_root(&self) -> [u8; 32];
    fn consensus_bundle_hash(&self) -> [u8; 32];
    fn execution_header_proof_hash(&self) -> [u8; 32];
    fn proof_bundle_hash(&self) -> [u8; 32];
}

impl ReceiptAuthority for VerifiedTxReceipt {
    fn chain_id(&self) -> u64 {
        self.chain_id()
    }
    fn network(&self) -> &str {
        self.network()
    }
    fn block_number(&self) -> u64 {
        self.block_number()
    }
    fn block_hash(&self) -> [u8; 32] {
        self.block_hash()
    }
    fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash()
    }
    fn tx_index(&self) -> u64 {
        self.tx_index()
    }
    fn succeeded(&self) -> bool {
        self.succeeded()
    }
    fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root()
    }
    fn consensus_bundle_hash(&self) -> [u8; 32] {
        self.consensus_bundle_hash()
    }
    fn execution_header_proof_hash(&self) -> [u8; 32] {
        self.execution_header_proof_hash()
    }
    fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash()
    }
}

fn classify_verified_receipt(
    transaction: &StoredSignedTransaction,
    receipt: StoredReceiptRecord,
    verified: &impl ReceiptAuthority,
) -> Result<TransactionAssurance> {
    if verified.chain_id() != transaction.chain_id()
        || verified.network() != transaction.network()
        || verified.tx_hash() != transaction.tx_hash()
        || receipt.tx_hash() != transaction.tx_hash()
        || verified.block_number() != receipt.block_number()
        || verified.block_hash() != receipt.block_hash()
        || verified.tx_index() != receipt.tx_index()
        || verified.succeeded() != receipt.succeeded()
        || verified.checkpoint_root() != receipt.checkpoint_root()
        || verified.consensus_bundle_hash() != receipt.consensus_bundle_hash()
        || verified.execution_header_proof_hash() != receipt.execution_header_proof_hash()
        || verified.proof_bundle_hash() != receipt.proof_bundle_hash()
    {
        return Err(NodeStoreError::new(
            "verified receipt does not match the exact local transaction evidence",
        ));
    }
    Ok(if verified.succeeded() {
        TransactionAssurance::FinalizedSuccess(receipt)
    } else {
        TransactionAssurance::FinalizedFailure(receipt)
    })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256, keccak256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount};
    use ratspeak_eth_verifier::{MAGIC, MemoryAccountStore, PinnedCheckpoint, VERSION, Verifier};
    use ratspeak_eth_wallet::{TransferAuthorizer, WalletSecret};

    use super::*;
    use crate::consensus::install_test_active_execution_evidence;
    use crate::transaction::test_support::signed_fixture_for_chain_with_nonce;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const EVIDENCE_TIME: u64 = 1_800_000_000;

    struct Setup {
        _profile: tempfile::TempDir,
        store: EthereumNodeStore,
        secret: WalletSecret,
        account: WalletAccount,
    }

    fn setup(balance: U256) -> Setup {
        let secret = WalletSecret::import_recovery_phrase(PHRASE).unwrap();
        let account = secret.account().unwrap();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        install_verified_account(
            &mut store,
            *account.address().0,
            balance,
            7,
            42,
            [0x22; 32],
            EVIDENCE_TIME,
        );
        Setup {
            _profile: profile,
            store,
            secret,
            account,
        }
    }

    fn install_verified_account(
        store: &mut EthereumNodeStore,
        address: [u8; 20],
        balance: U256,
        nonce: u64,
        block_number: u64,
        block_hash: [u8; 32],
        evidence_time: u64,
    ) {
        let trie_account = TrieAccount {
            nonce,
            balance,
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };
        let key = Nibbles::unpack(keccak256(address));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([key]));
        builder.add_leaf(key, &alloy_rlp::encode(trie_account));
        let state_root: [u8; 32] = builder.root().into();
        let proof = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();
        let mut canonical = prelude(3);
        canonical.extend_from_slice(&1_780_000_000u64.to_le_bytes());
        canonical.extend_from_slice(&block_number.to_le_bytes());
        canonical.extend_from_slice(&block_hash);
        canonical.extend_from_slice(&state_root);
        canonical.extend_from_slice(&address);
        canonical.extend_from_slice(&balance.to_be_bytes::<32>());
        canonical.extend_from_slice(&trie_account.nonce.to_le_bytes());
        canonical.extend_from_slice(trie_account.code_hash.as_slice());
        canonical.extend_from_slice(trie_account.storage_root.as_slice());
        canonical.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        for node in proof {
            canonical.extend_from_slice(&(node.len() as u32).to_le_bytes());
            canonical.extend_from_slice(&node);
        }
        let checkpoint = PinnedCheckpoint::sepolia(block_number, block_hash, state_root);
        let mut memory = MemoryAccountStore::default();
        let verified = Verifier::sepolia()
            .verify_and_import(&canonical, &checkpoint, &mut memory)
            .unwrap();
        install_test_active_execution_evidence(
            store,
            verified.block_number(),
            verified.block_hash(),
            verified.state_root(),
            [0x31; 32],
            [0x32; 32],
            evidence_time,
        );
        store
            .record_verified_account(&verified, &canonical)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET recorded_at_unix = ?1",
                [evidence_time],
            )
            .unwrap();
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

    fn operation(value: U256) -> (FieldTransferRequest, OperationId) {
        operation_with_id(value, 0x55)
    }

    fn operation_with_id(value: U256, identifier: u8) -> (FieldTransferRequest, OperationId) {
        (
            FieldTransferRequest::new(Address::from([0x44; 20]), value, 20, 2),
            OperationId::new([identifier; 16]).unwrap(),
        )
    }

    struct Allow;
    impl TransferAuthorizer for Allow {
        type Error = ();
        fn authorize_transfer(
            &mut self,
            _: &ratspeak_eth_wallet::TransferReview,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
    }

    struct SigningCustody {
        secret: WalletSecret,
        replacement: Option<PreparedTransfer>,
        signing_time_unix: u64,
        calls: usize,
        signatures_produced: usize,
    }

    struct RejectingCustody {
        calls: usize,
    }

    struct TestClock {
        samples: std::collections::VecDeque<u64>,
        last: u64,
    }

    impl TestClock {
        fn fixed(now_unix: u64) -> Self {
            Self {
                samples: [now_unix, now_unix].into(),
                last: now_unix,
            }
        }

        fn changing(first: u64, second: u64) -> Self {
            Self {
                samples: [first, second].into(),
                last: second,
            }
        }
    }

    impl FieldNodeClock for TestClock {
        fn now_unix(&mut self) -> u64 {
            let next = self.samples.pop_front().unwrap_or(self.last);
            self.last = next;
            next
        }
    }

    impl PlatformTransferCustody for SigningCustody {
        type Error = ratspeak_eth_wallet::WalletError;
        fn authorize_and_sign(
            &mut self,
            prepared: PreparedTransfer,
        ) -> std::result::Result<SignedTransfer, Self::Error> {
            self.calls += 1;
            let result = self
                .replacement
                .take()
                .unwrap_or(prepared)
                .authorize_and_sign(&self.secret, &mut Allow, self.signing_time_unix);
            if result.is_ok() {
                self.signatures_produced += 1;
            }
            result
        }
    }

    impl PlatformTransferCustody for RejectingCustody {
        type Error = ();

        fn authorize_and_sign(
            &mut self,
            _prepared: PreparedTransfer,
        ) -> std::result::Result<SignedTransfer, Self::Error> {
            self.calls += 1;
            Err(())
        }
    }

    #[test]
    fn unknown_never_becomes_zero_and_verified_zero_is_explicitly_labeled() {
        let profile = tempfile::tempdir().unwrap();
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let account = WalletSecret::import_recovery_phrase(PHRASE)
            .unwrap()
            .account()
            .unwrap();
        assert_eq!(
            store.account_assurance(account, EVIDENCE_TIME, 30).unwrap(),
            AccountAssurance::Unknown
        );

        let setup = setup(U256::ZERO);
        let current = setup
            .store
            .account_assurance(setup.account, EVIDENCE_TIME + 5, 10)
            .unwrap();
        assert!(matches!(
            current,
            AccountAssurance::CurrentVerified(ref evidence) if evidence.balance() == U256::ZERO
        ));
        let stale = setup
            .store
            .account_assurance(setup.account, EVIDENCE_TIME + 20, 10)
            .unwrap();
        assert_eq!(stale, AccountAssurance::Unknown);
    }

    #[test]
    fn fresh_import_time_cannot_refresh_old_or_future_chain_evidence() {
        let mut old = setup(U256::ZERO);
        let much_later = EVIDENCE_TIME + 3_600;
        old.store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET recorded_at_unix = ?1",
                [much_later],
            )
            .unwrap();
        assert_eq!(
            old.store
                .account_assurance(old.account, much_later, 60)
                .unwrap(),
            AccountAssurance::Unknown,
            "a fresh local import must not refresh old chain state"
        );
        let (request, operation_id) = operation(U256::from(1u64));
        assert!(
            old.store
                .prepare_native_transfer(
                    old.account,
                    request,
                    operation_id,
                    much_later,
                    much_later + 30,
                    60,
                )
                .is_err()
        );

        let future_now = EVIDENCE_TIME - 1;
        old.store
            .connection
            .execute(
                "UPDATE eth_verified_account_imports SET recorded_at_unix = ?1",
                [future_now - 1],
            )
            .unwrap();
        assert_eq!(
            old.store
                .account_assurance(old.account, future_now, u64::MAX)
                .unwrap(),
            AccountAssurance::Unknown,
            "future chain slots must fail closed even within an unlimited age policy"
        );
    }

    #[test]
    fn chain_freshness_survives_restart_without_using_reopen_time() {
        let setup = setup(U256::from(123u64));
        let profile_path = setup._profile.path().to_owned();
        let account = setup.account;
        drop(setup.store);
        let reopened = EthereumNodeStore::open_in_profile(profile_path).unwrap();
        let assurance = reopened
            .account_assurance(account, EVIDENCE_TIME + 5, 30)
            .unwrap();
        assert!(matches!(
            assurance,
            AccountAssurance::CurrentVerified(ref evidence)
                if evidence.balance() == U256::from(123u64)
                    && evidence.chain_evidence_at_unix() <= EVIDENCE_TIME
                    && evidence.local_verification_age_seconds() == 5
        ));
    }

    #[test]
    fn preparation_rejects_cost_above_current_verified_balance() {
        let mut setup = setup(U256::from(1_000u64));
        let (request, operation_id) = operation(U256::from(1_000u64));
        let error = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap_err();
        assert!(error.to_string().contains("maximum transfer cost"));
        assert_eq!(setup.store.operation_status(operation_id).unwrap(), None);
    }

    #[test]
    fn expired_or_revoked_checkpoint_never_reaches_custody() {
        let mut expired = setup(U256::from(1_000_000u64));
        let valid_until = expired
            .store
            .latest_checkpoint_approval()
            .unwrap()
            .unwrap()
            .valid_until_unix();
        assert_eq!(
            expired
                .store
                .account_assurance(expired.account, valid_until, u64::MAX)
                .unwrap(),
            AccountAssurance::Unknown
        );
        let (request, operation_id) = operation(U256::from(10u64));
        assert!(
            expired
                .store
                .prepare_native_transfer(
                    expired.account,
                    request,
                    operation_id,
                    valid_until,
                    valid_until + 5,
                    u64::MAX,
                )
                .is_err()
        );
        let expired_custody = SigningCustody {
            secret: expired.secret,
            replacement: None,
            signing_time_unix: valid_until,
            calls: 0,
            signatures_produced: 0,
        };
        assert_eq!(expired_custody.calls, 0);

        let mut revoked = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = revoked
            .store
            .prepare_native_transfer(
                revoked.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 10,
                60,
            )
            .unwrap();
        let root = revoked
            .store
            .latest_checkpoint_approval()
            .unwrap()
            .unwrap()
            .checkpoint_root();
        revoked
            .store
            .record_checkpoint_revocation(SEPOLIA_CHAIN_ID, root, [0x91; 32], EVIDENCE_TIME + 2)
            .unwrap();
        assert_eq!(
            revoked
                .store
                .account_assurance(revoked.account, EVIDENCE_TIME + 2, 60)
                .unwrap(),
            AccountAssurance::Unknown
        );
        let mut revoked_custody = SigningCustody {
            secret: revoked.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 2,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 2);
        assert!(
            revoked
                .store
                .authorize_and_store(pending, &mut revoked_custody, &mut clock)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );
        assert_eq!(revoked_custody.calls, 0);
        assert_eq!(revoked_custody.signatures_produced, 0);
        assert_eq!(
            revoked.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Prepared)
        );
    }

    #[test]
    fn prepares_signs_and_persists_exact_review_across_restart() {
        let mut first = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = first
            .store
            .prepare_native_transfer(
                first.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        assert_eq!(pending.review().nonce(), 7);
        let mut custody = SigningCustody {
            secret: first.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 2,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 2);
        let signed = first
            .store
            .authorize_and_store(pending, &mut custody, &mut clock)
            .unwrap();
        assert_eq!(custody.calls, 1);
        assert_eq!(custody.signatures_produced, 1);
        assert_eq!(signed.nonce(), 7);
        assert_eq!(
            first.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Signed {
                tx_hash: signed.tx_hash()
            })
        );
        drop(first.store);
        let reopened = EthereumNodeStore::open_in_profile(first._profile.path()).unwrap();
        assert!(
            reopened
                .signed_transaction(SEPOLIA_CHAIN_ID, signed.tx_hash())
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            reopened.transaction_assurance(signed.tx_hash()).unwrap(),
            Some(TransactionAssurance::Signed { .. })
        ));
    }

    #[test]
    fn gateway_replacement_rejects_prepared_and_authorizing_field_operations() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        assert!(
            setup
                .store
                .ensure_gateway_replacement_allowed([0xa9; 16], EVIDENCE_TIME + 2)
                .is_err()
        );

        let transaction = setup.store.connection.transaction().unwrap();
        let mut stored = read_operation(&transaction, *operation_id.as_bytes())
            .unwrap()
            .unwrap();
        stored.state = StoredOperationState::Authorizing;
        update_operation_state(&transaction, &stored).unwrap();
        transaction.commit().unwrap();
        assert!(
            setup
                .store
                .ensure_gateway_replacement_allowed([0xa9; 16], EVIDENCE_TIME + 3)
                .is_err()
        );
    }

    #[test]
    fn cancellation_expiry_and_operation_replay_survive_restart() {
        let mut first = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = first
            .store
            .prepare_native_transfer(
                first.account,
                request.clone(),
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 5,
                10,
            )
            .unwrap();
        drop(first.store);
        let mut store = EthereumNodeStore::open_in_profile(first._profile.path()).unwrap();
        assert_eq!(
            store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Prepared)
        );
        assert!(
            store
                .prepare_native_transfer(
                    first.account,
                    request,
                    operation_id,
                    EVIDENCE_TIME + 2,
                    EVIDENCE_TIME + 6,
                    10,
                )
                .unwrap_err()
                .to_string()
                .contains("already used")
        );
        assert_eq!(
            store.cancel_operation(operation_id).unwrap(),
            OperationStatus::Cancelled
        );
        let mut custody = SigningCustody {
            secret: first.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 3,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 3);
        assert!(
            store
                .authorize_and_store(pending, &mut custody, &mut clock)
                .is_err()
        );
        assert_eq!(custody.calls, 0);

        let mut second = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = second
            .store
            .prepare_native_transfer(
                second.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 5,
                10,
            )
            .unwrap();
        let mut custody = SigningCustody {
            secret: second.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 5,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 5);
        assert!(
            second
                .store
                .authorize_and_store(pending, &mut custody, &mut clock)
                .is_err()
        );
        assert_eq!(custody.calls, 0);
        assert_eq!(
            second.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
    }

    #[test]
    fn active_nonce_reservation_blocks_duplicates_and_prepared_cancellation_releases_it() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (first_request, first_operation) = operation_with_id(U256::from(10u64), 0x55);
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                first_request,
                first_operation,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();

        let (second_request, second_operation) = operation_with_id(U256::from(10u64), 0x56);
        let error = setup
            .store
            .prepare_native_transfer(
                setup.account,
                second_request.clone(),
                second_operation,
                EVIDENCE_TIME + 2,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reserves the current account nonce")
        );

        assert_eq!(
            setup.store.cancel_operation(first_operation).unwrap(),
            OperationStatus::Cancelled
        );
        let prepared = setup
            .store
            .prepare_native_transfer(
                setup.account,
                second_request,
                second_operation,
                EVIDENCE_TIME + 2,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        assert_eq!(prepared.review().nonce(), 7);
    }

    #[test]
    fn separate_store_handles_allow_only_one_active_nonce_reservation() {
        let mut first = setup(U256::from(1_000_000u64));
        let profile_path = first._profile.path().to_owned();
        let mut second = EthereumNodeStore::open_in_profile(profile_path).unwrap();
        let (request, first_operation) = operation_with_id(U256::from(10u64), 0x55);
        first
            .store
            .prepare_native_transfer(
                first.account,
                request,
                first_operation,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        let (request, second_operation) = operation_with_id(U256::from(10u64), 0x56);
        assert!(
            second
                .prepare_native_transfer(
                    first.account,
                    request,
                    second_operation,
                    EVIDENCE_TIME + 2,
                    EVIDENCE_TIME + 60,
                    10,
                )
                .unwrap_err()
                .to_string()
                .contains("reserves the current account nonce")
        );
    }

    #[test]
    fn startup_reconciliation_cancels_authorizing_operation_without_a_signed_record() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation_with_id(U256::from(10u64), 0x55);
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        let transaction = setup.store.connection.transaction().unwrap();
        let mut stored = read_operation(&transaction, *operation_id.as_bytes())
            .unwrap()
            .unwrap();
        stored.state = StoredOperationState::Authorizing;
        update_operation_state(&transaction, &stored).unwrap();
        transaction.commit().unwrap();

        drop(setup.store);
        let mut reopened = EthereumNodeStore::open_in_profile(setup._profile.path()).unwrap();
        assert_eq!(reopened.reconcile_interrupted_operations().unwrap(), 1);
        assert_eq!(
            reopened.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
        assert!(
            reopened
                .unconfirmed_signed_transactions(SEPOLIA_CHAIN_ID)
                .unwrap()
                .is_empty()
        );
        let (request, other_operation) = operation_with_id(U256::from(10u64), 0x56);
        reopened
            .prepare_native_transfer(
                setup.account,
                request,
                other_operation,
                EVIDENCE_TIME + 2,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
    }

    #[test]
    fn signed_nonce_reservation_requires_a_newer_verified_account_nonce() {
        let (mut setup, signed) = signed_setup();
        let (request, blocked_operation) = operation_with_id(U256::from(10u64), 0x56);
        assert!(
            setup
                .store
                .prepare_native_transfer(
                    setup.account,
                    request,
                    blocked_operation,
                    EVIDENCE_TIME + 3,
                    EVIDENCE_TIME + 60,
                    10,
                )
                .unwrap_err()
                .to_string()
                .contains("reserves the current account nonce")
        );
        assert!(
            setup
                .store
                .cancel_operation(OperationId::new([0x55; 16]).unwrap())
                .unwrap_err()
                .to_string()
                .contains("signed operation")
        );

        install_verified_account(
            &mut setup.store,
            *setup.account.address().0,
            U256::from(1_000_000u64),
            signed.nonce() + 1,
            43,
            [0x23; 32],
            EVIDENCE_TIME + 10,
        );
        let (request, next_operation) = operation_with_id(U256::from(10u64), 0x57);
        let prepared = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                next_operation,
                EVIDENCE_TIME + 24,
                EVIDENCE_TIME + 80,
                60,
            )
            .unwrap();
        assert_eq!(prepared.review().nonce(), signed.nonce() + 1);
    }

    #[test]
    fn startup_reconciliation_cancels_operations_whose_capabilities_were_lost() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 20,
                30,
            )
            .unwrap();

        drop(setup.store);
        let mut reopened = EthereumNodeStore::open_in_profile(setup._profile.path()).unwrap();
        assert_eq!(reopened.reconcile_interrupted_operations().unwrap(), 1);
        assert_eq!(
            reopened.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
        assert_eq!(reopened.reconcile_interrupted_operations().unwrap(), 0);
    }

    #[test]
    fn custody_expiry_during_native_authorization_produces_no_signature() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 5,
                60,
            )
            .unwrap();
        let mut custody = SigningCustody {
            secret: setup.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 5,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::changing(EVIDENCE_TIME + 2, EVIDENCE_TIME + 5);
        assert!(
            setup
                .store
                .authorize_and_store(pending, &mut custody, &mut clock)
                .unwrap_err()
                .to_string()
                .contains("custody rejected")
        );
        assert_eq!(custody.calls, 1);
        assert_eq!(custody.signatures_produced, 0);
        assert_eq!(
            setup.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
        assert!(
            setup
                .store
                .transaction_assurance([0; 32])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn custody_cancellation_releases_the_nonce_without_a_restart() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation_with_id(U256::from(10u64), 0x55);
        let pending = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 20,
                30,
            )
            .unwrap();
        let mut custody = RejectingCustody { calls: 0 };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 2);
        assert!(
            setup
                .store
                .authorize_and_store(pending, &mut custody, &mut clock)
                .unwrap_err()
                .to_string()
                .contains("custody rejected")
        );
        assert_eq!(custody.calls, 1);
        assert_eq!(
            setup.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
        assert!(
            setup
                .store
                .unconfirmed_signed_transactions(SEPOLIA_CHAIN_ID)
                .unwrap()
                .is_empty()
        );

        let (retry, retry_operation_id) = operation_with_id(U256::from(10u64), 0x56);
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                retry,
                retry_operation_id,
                EVIDENCE_TIME + 3,
                EVIDENCE_TIME + 20,
                30,
            )
            .unwrap();
    }

    #[test]
    fn post_custody_validation_failure_cancels_and_releases_nonce_immediately() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 5,
                60,
            )
            .unwrap();
        let mut custody = SigningCustody {
            secret: setup.secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 2,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::changing(EVIDENCE_TIME + 2, EVIDENCE_TIME + 5);
        assert!(
            setup
                .store
                .authorize_and_store(pending, &mut custody, &mut clock)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert_eq!(custody.signatures_produced, 1);
        assert_eq!(
            setup.store.operation_status(operation_id).unwrap(),
            Some(OperationStatus::Cancelled)
        );
        assert!(
            setup
                .store
                .unconfirmed_signed_transactions(SEPOLIA_CHAIN_ID)
                .unwrap()
                .is_empty()
        );
        let (retry, retry_operation_id) = operation_with_id(U256::from(10u64), 0x57);
        setup
            .store
            .prepare_native_transfer(
                setup.account,
                retry,
                retry_operation_id,
                EVIDENCE_TIME + 3,
                EVIDENCE_TIME + 20,
                60,
            )
            .unwrap();
    }

    #[test]
    fn rejects_wrong_sender_nonce_context_and_mutated_review() {
        for case in 0..4 {
            let mut setup = setup(U256::from(1_000_000u64));
            let (request, operation_id) = operation(U256::from(10u64));
            let pending = setup
                .store
                .prepare_native_transfer(
                    setup.account,
                    request,
                    operation_id,
                    EVIDENCE_TIME + 1,
                    EVIDENCE_TIME + 60,
                    10,
                )
                .unwrap();
            let other_secret = WalletSecret::generate().unwrap();
            let signing_secret = if case == 0 {
                other_secret
            } else {
                WalletSecret::import_recovery_phrase(PHRASE).unwrap()
            };
            let signing_account = signing_secret.account().unwrap();
            let from = if case == 0 {
                signing_account.address()
            } else {
                setup.account.address()
            };
            let nonce = if case == 1 { 8 } else { 7 };
            let context = ReviewContext::from_canonical_bytes(if case == 2 {
                b"wrong context"
            } else {
                b"replacement"
            })
            .unwrap();
            let value = if case == 3 {
                U256::from(11u64)
            } else {
                U256::from(10u64)
            };
            let replacement = signing_account
                .prepare_transfer(
                    TransferIntent::new(
                        SEPOLIA_CHAIN_ID,
                        from,
                        Address::from([0x44; 20]),
                        value,
                        nonce,
                        20,
                        2,
                    ),
                    operation_id,
                    context,
                    EVIDENCE_TIME + 1,
                    EVIDENCE_TIME + 60,
                )
                .unwrap();
            let mut custody = SigningCustody {
                secret: signing_secret,
                replacement: Some(replacement),
                signing_time_unix: EVIDENCE_TIME + 2,
                calls: 0,
                signatures_produced: 0,
            };
            let mut clock = TestClock::fixed(EVIDENCE_TIME + 2);
            assert!(
                setup
                    .store
                    .authorize_and_store(pending, &mut custody, &mut clock)
                    .is_err()
            );
            assert_eq!(
                setup.store.operation_status(operation_id).unwrap(),
                Some(OperationStatus::Cancelled)
            );
            assert!(
                setup
                    .store
                    .signed_transaction(SEPOLIA_CHAIN_ID, [0; 32])
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn corrupted_chain_or_context_fails_closed() {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let _pending = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        let mut stored = read_operation(&setup.store.connection, *operation_id.as_bytes())
            .unwrap()
            .unwrap();
        stored.chain_id = 1;
        setup.store.connection.execute(
            "UPDATE eth_field_operations SET chain_id = '1', record_digest = ?1 WHERE operation_id = ?2",
            rusqlite::params![operation_digest(&stored).as_slice(), operation_id.as_bytes().as_slice()],
        ).unwrap();
        assert!(setup.store.operation_status(operation_id).is_err());
    }

    #[test]
    fn base_relay_observation_remains_base_scoped_and_unconfirmed() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let tx_hash = signed_fixture_for_chain_with_nonce(
            &mut store,
            ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
            41,
        );
        store
            .record_non_authoritative_transaction_observation(
                ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
                tx_hash,
                NonAuthoritativeTransactionObservation::RpcAccepted,
                [0x91; 32],
                EVIDENCE_TIME + 20,
            )
            .unwrap();

        let Some(TransactionAssurance::Signed {
            non_authoritative_observations,
        }) = store.transaction_assurance_reverified(tx_hash).unwrap()
        else {
            panic!("Base relay observation changed transaction assurance");
        };
        assert_eq!(non_authoritative_observations.len(), 1);
        let history = store
            .transaction_assurance_history(
                ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
                tx_hash,
            )
            .unwrap();
        assert!(history.iter().any(|event| {
            event.chain_id() == ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID
                && event.network() == ratspeak_eth_verifier::BASE_SEPOLIA.network
        }));
        assert!(
            store
                .transaction_assurance_history(SEPOLIA_CHAIN_ID, tx_hash)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn relay_and_rpc_observations_never_confirm_a_transaction() {
        let (mut setup, signed) = signed_setup();
        for (index, observation) in [
            NonAuthoritativeTransactionObservation::TransportDelivered,
            NonAuthoritativeTransactionObservation::GatewayAcknowledged,
            NonAuthoritativeTransactionObservation::RpcAccepted,
        ]
        .into_iter()
        .enumerate()
        {
            setup
                .store
                .record_non_authoritative_transaction_observation(
                    SEPOLIA_CHAIN_ID,
                    signed.tx_hash(),
                    observation,
                    [0x80 + index as u8; 32],
                    EVIDENCE_TIME + 10 + index as u64,
                )
                .unwrap();
        }
        let Some(TransactionAssurance::Signed {
            non_authoritative_observations,
        }) = setup.store.transaction_assurance(signed.tx_hash()).unwrap()
        else {
            panic!("relay observation changed Ethereum assurance")
        };
        assert_eq!(non_authoritative_observations.len(), 3);
        assert!(matches!(
            setup
                .store
                .transaction_assurance_reverified(signed.tx_hash())
                .unwrap(),
            Some(TransactionAssurance::Signed { .. })
        ));
    }

    fn signed_setup() -> (Setup, StoredSignedTransaction) {
        let mut setup = setup(U256::from(1_000_000u64));
        let (request, operation_id) = operation(U256::from(10u64));
        let pending = setup
            .store
            .prepare_native_transfer(
                setup.account,
                request,
                operation_id,
                EVIDENCE_TIME + 1,
                EVIDENCE_TIME + 60,
                10,
            )
            .unwrap();
        let secret = std::mem::replace(&mut setup.secret, WalletSecret::generate().unwrap());
        let mut custody = SigningCustody {
            secret,
            replacement: None,
            signing_time_unix: EVIDENCE_TIME + 2,
            calls: 0,
            signatures_produced: 0,
        };
        let mut clock = TestClock::fixed(EVIDENCE_TIME + 2);
        let signed = setup
            .store
            .authorize_and_store(pending, &mut custody, &mut clock)
            .unwrap();
        (setup, signed)
    }

    #[derive(Clone)]
    struct TestReceiptAuthority {
        receipt: StoredReceiptRecord,
        tx_hash: [u8; 32],
    }
    impl ReceiptAuthority for TestReceiptAuthority {
        fn chain_id(&self) -> u64 {
            self.receipt.chain_id()
        }
        fn network(&self) -> &str {
            self.receipt.network()
        }
        fn block_number(&self) -> u64 {
            self.receipt.block_number()
        }
        fn block_hash(&self) -> [u8; 32] {
            self.receipt.block_hash()
        }
        fn tx_hash(&self) -> [u8; 32] {
            self.tx_hash
        }
        fn tx_index(&self) -> u64 {
            self.receipt.tx_index()
        }
        fn succeeded(&self) -> bool {
            self.receipt.succeeded()
        }
        fn checkpoint_root(&self) -> [u8; 32] {
            self.receipt.checkpoint_root()
        }
        fn consensus_bundle_hash(&self) -> [u8; 32] {
            self.receipt.consensus_bundle_hash()
        }
        fn execution_header_proof_hash(&self) -> [u8; 32] {
            self.receipt.execution_header_proof_hash()
        }
        fn proof_bundle_hash(&self) -> [u8; 32] {
            self.receipt.proof_bundle_hash()
        }
    }

    #[test]
    fn stored_receipts_need_exact_reverification_for_success_or_failure() {
        for succeeded in [true, false] {
            let (mut setup, signed) = signed_setup();
            let receipt = crate::receipt::install_test_receipt_for_transaction(
                &mut setup.store,
                signed.tx_hash(),
                succeeded,
            );
            assert!(matches!(
                setup.store.transaction_assurance(signed.tx_hash()).unwrap(),
                Some(TransactionAssurance::NeedsReverification(_))
            ));
            assert!(
                setup
                    .store
                    .transaction_assurance_reverified_at(signed.tx_hash(), EVIDENCE_TIME)
                    .is_err(),
                "stored receipt fields and non-canonical test evidence cannot self-confirm"
            );
            let authority = TestReceiptAuthority {
                receipt: receipt.clone(),
                tx_hash: signed.tx_hash(),
            };
            let assurance =
                classify_verified_receipt(&signed, receipt.clone(), &authority).unwrap();
            assert!(matches!(
                (succeeded, assurance),
                (true, TransactionAssurance::FinalizedSuccess(_))
                    | (false, TransactionAssurance::FinalizedFailure(_))
            ));
            let wrong = TestReceiptAuthority {
                tx_hash: [0xee; 32],
                ..authority
            };
            assert!(classify_verified_receipt(&signed, receipt, &wrong).is_err());
        }
    }

    #[test]
    fn corrupted_stored_receipt_proof_never_reaches_finalized_assurance() {
        let (mut setup, signed) = signed_setup();
        crate::receipt::install_test_receipt_for_transaction(
            &mut setup.store,
            signed.tx_hash(),
            true,
        );
        setup
            .store
            .connection
            .execute(
                "UPDATE eth_verified_receipts SET canonical_bundle = zeroblob(8)
                 WHERE tx_hash = ?1",
                [signed.tx_hash().as_slice()],
            )
            .unwrap();
        assert!(
            setup
                .store
                .transaction_assurance_reverified_at(signed.tx_hash(), EVIDENCE_TIME)
                .unwrap_err()
                .to_string()
                .contains("receipt proof")
        );
    }

    #[test]
    fn revoked_checkpoint_prevents_stored_receipt_finalization_before_proof_replay() {
        let (mut setup, signed) = signed_setup();
        let receipt = crate::receipt::install_test_receipt_for_transaction(
            &mut setup.store,
            signed.tx_hash(),
            true,
        );
        setup
            .store
            .record_checkpoint_revocation(
                SEPOLIA_CHAIN_ID,
                receipt.checkpoint_root(),
                [0x93; 32],
                EVIDENCE_TIME + 3,
            )
            .unwrap();
        assert!(
            setup
                .store
                .transaction_assurance_reverified_at(signed.tx_hash(), EVIDENCE_TIME + 4)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );
    }
}
