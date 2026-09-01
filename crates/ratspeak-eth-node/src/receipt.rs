use alloy_consensus::Header;
use alloy_rlp::Decodable;
use ratspeak_eth_verifier::{
    ExecutionHeaderProvenance, SEPOLIA_NETWORK, VerifiedExecutionBlock, VerifiedFinalizedTxReceipt,
    VerifiedTxReceipt, Verifier,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{
    AssuranceEventInput, AssuranceEventKind, AssuranceSubjectKind, record_assurance,
};
use crate::checkpoint::ensure_supported_network;
use crate::consensus::{provenance_from_i64, provenance_i64, read_execution_block};
use crate::evidence::{EvidenceKind, record_replay, validate_canonical_bundle};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

/// Exact finalized receipt evidence retained as a database snapshot.
///
/// This is not a verifier `VerifiedTxReceipt`; callers must replay the stored
/// canonical proof through the verifier to regain that authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceiptRecord {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    tx_hash: [u8; 32],
    tx_index: u64,
    succeeded: bool,
    cumulative_gas_used: u64,
    logs_count: u64,
    verified_at_unix: u64,
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    consensus_bundle_hash: [u8; 32],
    execution_header_proof_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl StoredReceiptRecord {
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

    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    pub fn tx_index(&self) -> u64 {
        self.tx_index
    }

    pub fn succeeded(&self) -> bool {
        self.succeeded
    }

    pub fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used
    }

    pub fn logs_count(&self) -> u64 {
        self.logs_count
    }

    /// Local verification time for current records. Rows migrated from schema
    /// v2 carry their legacy local record time because no distinct verification
    /// timestamp existed in that schema.
    pub fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn provenance(&self) -> ExecutionHeaderProvenance {
        self.provenance
    }

    pub fn consensus_bundle_hash(&self) -> [u8; 32] {
        self.consensus_bundle_hash
    }

    pub fn execution_header_proof_hash(&self) -> [u8; 32] {
        self.execution_header_proof_hash
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }

    pub fn canonical_bundle(&self) -> &[u8] {
        &self.canonical_bundle
    }
}

#[derive(Debug, Clone)]
struct ReceiptValues {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    tx_hash: [u8; 32],
    tx_index: u64,
    succeeded: bool,
    cumulative_gas_used: u64,
    logs_count: u64,
    verified_at_unix: u64,
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    consensus_bundle_hash: [u8; 32],
    execution_header_proof_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptTargetAuthorityKind {
    DirectFinalizedHeader = 1,
    FinalizedAncestry = 2,
}

impl ReceiptTargetAuthorityKind {
    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::DirectFinalizedHeader),
            2 => Ok(Self::FinalizedAncestry),
            _ => Err(NodeStoreError::new(
                "invalid stored receipt target authority kind",
            )),
        }
    }
}

/// Durable snapshot of the block authority needed by one exact receipt proof.
/// It is never returned as a verifier-authenticated type; assurance always
/// replays the canonical proof chain instead of trusting this row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredReceiptTargetAuthority {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
    anchor_block_hash: [u8; 32],
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    consensus_bundle_hash: [u8; 32],
    authority_kind: ReceiptTargetAuthorityKind,
    authority_bundle_hash: [u8; 32],
}

impl StoredReceiptTargetAuthority {
    fn from_verified(
        block: &VerifiedExecutionBlock,
        anchor_block_hash: [u8; 32],
        authority_kind: ReceiptTargetAuthorityKind,
    ) -> Self {
        Self {
            chain_id: block.chain_id(),
            network: block.network().to_owned(),
            block_number: block.execution_block_number(),
            block_hash: block.execution_block_hash(),
            parent_hash: block.parent_hash(),
            state_root: block.state_root(),
            receipts_root: block.receipts_root(),
            transactions_root: block.transactions_root(),
            anchor_block_hash,
            checkpoint_root: block.checkpoint_root(),
            provenance: block.provenance(),
            consensus_bundle_hash: block.consensus_bundle_hash(),
            authority_kind,
            authority_bundle_hash: block.proof_bundle_hash(),
        }
    }

    fn from_direct_block(block: &crate::StoredExecutionBlock) -> Result<Self> {
        #[cfg(test)]
        if block
            .canonical_bundle()
            .starts_with(b"test execution evidence:")
        {
            return Ok(Self {
                chain_id: block.chain_id(),
                network: block.network().to_owned(),
                block_number: block.execution_block_number(),
                block_hash: block.execution_block_hash(),
                parent_hash: [0; 32],
                state_root: block.state_root(),
                receipts_root: block.receipts_root(),
                transactions_root: block.transactions_root(),
                anchor_block_hash: block.execution_block_hash(),
                checkpoint_root: block.checkpoint_root(),
                provenance: block.provenance(),
                consensus_bundle_hash: block.consensus_bundle_hash(),
                authority_kind: ReceiptTargetAuthorityKind::DirectFinalizedHeader,
                authority_bundle_hash: block.proof_bundle_hash(),
            });
        }
        let parsed = Verifier::sepolia()
            .parse_execution_header_proof(block.canonical_bundle())
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let mut remaining = parsed.rlp_header.as_slice();
        let header = Header::decode(&mut remaining).map_err(|error| {
            NodeStoreError::new(format!("invalid stored execution header: {error}"))
        })?;
        if !remaining.is_empty()
            || header.number != block.execution_block_number()
            || header.hash_slow().0 != block.execution_block_hash()
            || header.state_root.0 != block.state_root()
            || header.receipts_root.0 != block.receipts_root()
            || header.transactions_root.0 != block.transactions_root()
        {
            return Err(NodeStoreError::new(
                "stored execution header does not match its receipt authority values",
            ));
        }
        Ok(Self {
            chain_id: block.chain_id(),
            network: block.network().to_owned(),
            block_number: block.execution_block_number(),
            block_hash: block.execution_block_hash(),
            parent_hash: header.parent_hash.0,
            state_root: block.state_root(),
            receipts_root: block.receipts_root(),
            transactions_root: block.transactions_root(),
            anchor_block_hash: block.execution_block_hash(),
            checkpoint_root: block.checkpoint_root(),
            provenance: block.provenance(),
            consensus_bundle_hash: block.consensus_bundle_hash(),
            authority_kind: ReceiptTargetAuthorityKind::DirectFinalizedHeader,
            authority_bundle_hash: block.proof_bundle_hash(),
        })
    }
}

impl ReceiptValues {
    fn from_verified(
        receipt: &VerifiedTxReceipt,
        canonical_bundle: &[u8],
        verified_at_unix: u64,
    ) -> Result<Self> {
        ensure_supported_network(receipt.chain_id(), receipt.network())?;
        validate_canonical_bundle(
            canonical_bundle,
            receipt.proof_bundle_hash(),
            "receipt proof",
        )?;
        Ok(Self {
            chain_id: receipt.chain_id(),
            network: receipt.network().to_owned(),
            block_number: receipt.block_number(),
            block_hash: receipt.block_hash(),
            tx_hash: receipt.tx_hash(),
            tx_index: receipt.tx_index(),
            succeeded: receipt.succeeded(),
            cumulative_gas_used: receipt.cumulative_gas_used(),
            logs_count: receipt.logs_count(),
            verified_at_unix,
            checkpoint_root: receipt.checkpoint_root(),
            provenance: receipt.provenance(),
            consensus_bundle_hash: receipt.consensus_bundle_hash(),
            execution_header_proof_hash: receipt.execution_header_proof_hash(),
            proof_bundle_hash: receipt.proof_bundle_hash(),
            canonical_bundle: canonical_bundle.to_vec(),
        })
    }

    fn from_zero_distance_verified(
        receipt: &VerifiedTxReceipt,
        parsed: &ratspeak_eth_verifier::FinalizedTxReceiptProofBundle,
        target_block: &VerifiedExecutionBlock,
        verified_at_unix: u64,
    ) -> Result<Self> {
        // The outer verified value authenticates the submitted kind-13 bytes,
        // but the durable alias is the embedded kind-5 proof. Reverify those
        // exact bytes before they can become immutable evidence, then bind all
        // semantic and authority fields to the caller-held outer result. The
        // proof hashes intentionally differ because they name different
        // canonical encodings.
        let inner = Verifier::sepolia()
            .verify_tx_receipt(&parsed.receipt_proof_bytes, target_block)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        if inner.chain_id() != receipt.chain_id()
            || inner.network() != receipt.network()
            || inner.block_number() != receipt.block_number()
            || inner.block_hash() != receipt.block_hash()
            || inner.tx_hash() != receipt.tx_hash()
            || inner.tx_index() != receipt.tx_index()
            || inner.succeeded() != receipt.succeeded()
            || inner.cumulative_gas_used() != receipt.cumulative_gas_used()
            || inner.logs_count() != receipt.logs_count()
            || inner.checkpoint_root() != receipt.checkpoint_root()
            || inner.provenance() != receipt.provenance()
            || inner.consensus_bundle_hash() != receipt.consensus_bundle_hash()
            || inner.execution_header_proof_hash() != receipt.execution_header_proof_hash()
        {
            return Err(NodeStoreError::new(
                "zero-distance receipt wrapper does not bind its verified inner proof",
            ));
        }
        Self::from_verified(&inner, &parsed.receipt_proof_bytes, verified_at_unix)
    }

    fn as_stored(&self) -> StoredReceiptRecord {
        StoredReceiptRecord {
            chain_id: self.chain_id,
            network: self.network.clone(),
            block_number: self.block_number,
            block_hash: self.block_hash,
            tx_hash: self.tx_hash,
            tx_index: self.tx_index,
            succeeded: self.succeeded,
            cumulative_gas_used: self.cumulative_gas_used,
            logs_count: self.logs_count,
            verified_at_unix: self.verified_at_unix,
            checkpoint_root: self.checkpoint_root,
            provenance: self.provenance,
            consensus_bundle_hash: self.consensus_bundle_hash,
            execution_header_proof_hash: self.execution_header_proof_hash,
            proof_bundle_hash: self.proof_bundle_hash,
            canonical_bundle: self.canonical_bundle.clone(),
        }
    }
}

impl EthereumNodeStore {
    /// Stores an exact verifier-authenticated receipt and its canonical proof.
    ///
    /// Finalized success/failure assurance is appended only from this opaque
    /// verifier result. Transport, gateway, and RPC APIs cannot call this path.
    pub fn record_verified_receipt(
        &mut self,
        receipt: &VerifiedTxReceipt,
        canonical_bundle: &[u8],
        verified_at_unix: u64,
    ) -> Result<RecordOutcome> {
        self.record_receipt_values(
            ReceiptValues::from_verified(receipt, canonical_bundle, verified_at_unix)?,
            None,
        )
    }

    /// Atomically stores the ancestry-derived target authority and its exact
    /// receipt. The target snapshot cannot establish assurance by itself.
    pub fn record_verified_finalized_receipt(
        &mut self,
        verified: &VerifiedFinalizedTxReceipt,
        canonical_bundle: &[u8],
        verified_at_unix: u64,
    ) -> Result<RecordOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_verified_finalized_receipt_in(
            &transaction,
            verified,
            canonical_bundle,
            verified_at_unix,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    fn record_receipt_values(
        &mut self,
        values: ReceiptValues,
        supplied_target: Option<StoredReceiptTargetAuthority>,
    ) -> Result<RecordOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_receipt_values_in(&transaction, values, supplied_target)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn receipt_by_transaction_hash(
        &self,
        chain_id: u64,
        tx_hash: [u8; 32],
    ) -> Result<Option<StoredReceiptRecord>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_receipt_by_tx_hash(&self.connection, chain_id, SEPOLIA_NETWORK, tx_hash)
    }
}

pub(crate) fn record_verified_finalized_receipt_in(
    transaction: &Transaction<'_>,
    verified: &VerifiedFinalizedTxReceipt,
    canonical_bundle: &[u8],
    verified_at_unix: u64,
) -> Result<RecordOutcome> {
    let parsed = Verifier::sepolia()
        .parse_finalized_tx_receipt_proof(canonical_bundle)
        .map_err(|error| NodeStoreError::new(error.to_string()))?;
    if parsed.target_block_number != verified.target_block().execution_block_number()
        || parsed.target_block_hash != verified.target_block().execution_block_hash()
        || parsed.receipt_proof.tx_hash != verified.receipt().tx_hash()
    {
        return Err(NodeStoreError::new(
            "finalized receipt authority does not match its canonical ancestry",
        ));
    }
    let values = if parsed.ancestry_headers.is_empty() {
        ReceiptValues::from_zero_distance_verified(
            verified.receipt(),
            &parsed,
            verified.target_block(),
            verified_at_unix,
        )?
    } else {
        ReceiptValues::from_verified(verified.receipt(), canonical_bundle, verified_at_unix)?
    };
    record_receipt_values_in(
        transaction,
        values,
        Some(StoredReceiptTargetAuthority::from_verified(
            verified.target_block(),
            parsed.anchor_block_hash,
            if parsed.ancestry_headers.is_empty() {
                ReceiptTargetAuthorityKind::DirectFinalizedHeader
            } else {
                ReceiptTargetAuthorityKind::FinalizedAncestry
            },
        )),
    )
}

fn record_receipt_values_in(
    transaction: &Transaction<'_>,
    values: ReceiptValues,
    supplied_target: Option<StoredReceiptTargetAuthority>,
) -> Result<RecordOutcome> {
    ensure_supported_network(values.chain_id, &values.network)?;
    if values.verified_at_unix == 0 {
        return Err(NodeStoreError::new(
            "verified receipt is missing a local verification time",
        ));
    }
    validate_canonical_bundle(
        &values.canonical_bundle,
        values.proof_bundle_hash,
        "receipt proof",
    )?;
    let target = if let Some(target) = supplied_target {
        match target.authority_kind {
            ReceiptTargetAuthorityKind::DirectFinalizedHeader => {
                // Zero-distance finalized wrappers are normalized to their
                // exact inner receipt proof. Re-establish the supplied
                // target from the persisted direct execution authority;
                // parsing the normalized kind-5 receipt as an outer kind-13
                // ancestry envelope would be both incorrect and brittle.
                let block = read_execution_block(
                    transaction,
                    values.chain_id,
                    &values.network,
                    values.block_hash,
                )?
                .ok_or_else(|| {
                    NodeStoreError::new("receipt has no persisted execution evidence")
                })?;
                let expected = StoredReceiptTargetAuthority::from_direct_block(&block)?;
                if target != expected {
                    return Err(NodeStoreError::new(
                        "zero-distance receipt target conflicts with persisted finalized execution evidence",
                    ));
                }
            }
            ReceiptTargetAuthorityKind::FinalizedAncestry => {
                let ancestry = Verifier::sepolia()
                    .parse_finalized_tx_receipt_proof(&values.canonical_bundle)
                    .map_err(|error| NodeStoreError::new(error.to_string()))?;
                let anchor = read_execution_block(
                    transaction,
                    values.chain_id,
                    &values.network,
                    ancestry.anchor_block_hash,
                )?
                .ok_or_else(|| {
                    NodeStoreError::new("receipt ancestry has no persisted finalized anchor")
                })?;
                if ancestry.anchor_block_number != anchor.execution_block_number()
                    || ancestry.target_block_number != values.block_number
                    || ancestry.target_block_hash != values.block_hash
                    || ancestry.receipt_proof.tx_hash != values.tx_hash
                    || target.anchor_block_hash != ancestry.anchor_block_hash
                    || values.checkpoint_root != anchor.checkpoint_root()
                    || values.provenance != anchor.provenance()
                    || values.consensus_bundle_hash != anchor.consensus_bundle_hash()
                {
                    return Err(NodeStoreError::new(
                        "receipt ancestry conflicts with persisted finalized execution evidence",
                    ));
                }
            }
        }
        target
    } else {
        let block = read_execution_block(
            transaction,
            values.chain_id,
            &values.network,
            values.block_hash,
        )?
        .ok_or_else(|| NodeStoreError::new("receipt has no persisted execution evidence"))?;
        if values.block_number != block.execution_block_number()
            || values.checkpoint_root != block.checkpoint_root()
            || values.provenance != block.provenance()
            || values.consensus_bundle_hash != block.consensus_bundle_hash()
            || values.execution_header_proof_hash != block.proof_bundle_hash()
        {
            return Err(NodeStoreError::new(
                "receipt conflicts with persisted finalized execution evidence",
            ));
        }
        StoredReceiptTargetAuthority::from_direct_block(&block)?
    };
    validate_target_for_receipt(&target, &values)?;
    record_receipt_target(transaction, &target)?;

    let mut stored = values.as_stored();
    let digest = receipt_digest(&stored);
    let changed = transaction
        .execute(
            "INSERT INTO eth_verified_receipts (
                    chain_id, network, block_number, block_hash, tx_hash, tx_index,
                    succeeded, cumulative_gas_used, logs_count, verified_at_unix, checkpoint_root,
                    provenance, consensus_bundle_hash, execution_header_proof_hash,
                    proof_bundle_hash, canonical_bundle, record_digest
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                    ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
                 )
                 ON CONFLICT(chain_id, network, block_hash, tx_index) DO NOTHING",
            rusqlite::params![
                stored.chain_id.to_string(),
                stored.network,
                stored.block_number.to_string(),
                stored.block_hash.as_slice(),
                stored.tx_hash.as_slice(),
                stored.tx_index.to_string(),
                i64::from(stored.succeeded),
                stored.cumulative_gas_used.to_string(),
                stored.logs_count.to_string(),
                stored.verified_at_unix.to_string(),
                stored.checkpoint_root.as_slice(),
                provenance_i64(stored.provenance),
                stored.consensus_bundle_hash.as_slice(),
                stored.execution_header_proof_hash.as_slice(),
                stored.proof_bundle_hash.as_slice(),
                stored.canonical_bundle,
                digest.as_slice(),
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                NodeStoreError::new("receipt conflicts with an immutable finalized subject")
            } else {
                NodeStoreError::sqlite(error)
            }
        })?;
    if changed == 0 {
        let existing = read_receipt_by_subject(
            transaction,
            stored.chain_id,
            &stored.network,
            stored.block_hash,
            stored.tx_index,
        )?
        .ok_or_else(|| NodeStoreError::new("receipt replay has no corresponding record"))?;
        if !same_receipt_evidence(&existing, &stored) {
            return Err(NodeStoreError::new(
                "receipt subject conflicts with immutable verified evidence",
            ));
        }
        // Local verification time is observation metadata, not part of the
        // immutable Ethereum subject. Preserve the first durable time so an
        // exact later sync generation converges instead of conflicting.
        stored.verified_at_unix = existing.verified_at_unix;
    }
    let replay = record_replay(
        transaction,
        stored.chain_id,
        &stored.network,
        EvidenceKind::ReceiptProof,
        receipt_subject_key(&stored),
        receipt_subject_key(&stored),
    )?;
    let mut assurance = RecordOutcome::Replay;
    if crate::transaction::read_signed_transaction(
        transaction,
        stored.chain_id,
        &stored.network,
        stored.tx_hash,
    )?
    .is_some()
    {
        assurance = record_assurance(
            transaction,
            AssuranceEventInput {
                chain_id: stored.chain_id,
                network: &stored.network,
                subject_kind: AssuranceSubjectKind::Transaction,
                subject_key: stored.tx_hash,
                event_kind: if stored.succeeded {
                    AssuranceEventKind::FinalizedReceiptSucceeded
                } else {
                    AssuranceEventKind::FinalizedReceiptFailed
                },
                evidence_hash: stored.proof_bundle_hash,
                observed_at_unix: stored.verified_at_unix,
            },
        )?;
    }
    Ok(
        if changed == 1 || replay == RecordOutcome::Inserted || assurance == RecordOutcome::Inserted
        {
            RecordOutcome::Inserted
        } else {
            RecordOutcome::Replay
        },
    )
}

fn same_receipt_evidence(left: &StoredReceiptRecord, right: &StoredReceiptRecord) -> bool {
    left.chain_id == right.chain_id
        && left.network == right.network
        && left.block_number == right.block_number
        && left.block_hash == right.block_hash
        && left.tx_hash == right.tx_hash
        && left.tx_index == right.tx_index
        && left.succeeded == right.succeeded
        && left.cumulative_gas_used == right.cumulative_gas_used
        && left.logs_count == right.logs_count
        && left.checkpoint_root == right.checkpoint_root
        && left.provenance == right.provenance
        && left.consensus_bundle_hash == right.consensus_bundle_hash
        && left.execution_header_proof_hash == right.execution_header_proof_hash
        && left.proof_bundle_hash == right.proof_bundle_hash
        && left.canonical_bundle == right.canonical_bundle
}

fn validate_target_for_receipt(
    target: &StoredReceiptTargetAuthority,
    receipt: &ReceiptValues,
) -> Result<()> {
    if target.chain_id != receipt.chain_id
        || target.network != receipt.network
        || target.block_number != receipt.block_number
        || target.block_hash != receipt.block_hash
        || target.receipts_root == [0; 32]
        || target.transactions_root == [0; 32]
        || target.checkpoint_root != receipt.checkpoint_root
        || target.provenance != receipt.provenance
        || target.consensus_bundle_hash != receipt.consensus_bundle_hash
        || target.authority_bundle_hash != receipt.execution_header_proof_hash
    {
        return Err(NodeStoreError::new(
            "receipt target authority conflicts with verified receipt evidence",
        ));
    }
    Ok(())
}

fn record_receipt_target(
    transaction: &Transaction<'_>,
    target: &StoredReceiptTargetAuthority,
) -> Result<RecordOutcome> {
    ensure_supported_network(target.chain_id, &target.network)?;
    let digest = receipt_target_digest(target);
    let changed = transaction
        .execute(
            "INSERT INTO eth_verified_receipt_targets (
                chain_id, network, block_number, block_hash, parent_hash,
                state_root, receipts_root, transactions_root, anchor_block_hash,
                checkpoint_root, provenance, consensus_bundle_hash, authority_kind,
                authority_bundle_hash, record_digest
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             )
             ON CONFLICT(chain_id, network, block_hash, authority_bundle_hash) DO NOTHING",
            rusqlite::params![
                target.chain_id.to_string(),
                target.network.as_str(),
                target.block_number.to_string(),
                target.block_hash.as_slice(),
                target.parent_hash.as_slice(),
                target.state_root.as_slice(),
                target.receipts_root.as_slice(),
                target.transactions_root.as_slice(),
                target.anchor_block_hash.as_slice(),
                target.checkpoint_root.as_slice(),
                provenance_i64(target.provenance),
                target.consensus_bundle_hash.as_slice(),
                target.authority_kind as i64,
                target.authority_bundle_hash.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                NodeStoreError::new("receipt target conflicts with its finalized anchor")
            } else {
                NodeStoreError::sqlite(error)
            }
        })?;
    if changed == 1 {
        return Ok(RecordOutcome::Inserted);
    }
    let stored = read_receipt_target(
        transaction,
        target.chain_id,
        &target.network,
        target.block_hash,
        target.authority_bundle_hash,
    )?
    .ok_or_else(|| NodeStoreError::new("receipt target replay has no corresponding record"))?;
    if stored != *target {
        return Err(NodeStoreError::new(
            "receipt target conflicts with immutable finalized ancestry",
        ));
    }
    Ok(RecordOutcome::Replay)
}

fn read_receipt_target(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    block_hash: [u8; 32],
    authority_bundle_hash: [u8; 32],
) -> Result<Option<StoredReceiptTargetAuthority>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, block_number, block_hash, parent_hash,
                    state_root, receipts_root, transactions_root, anchor_block_hash,
                    checkpoint_root, provenance, consensus_bundle_hash, authority_kind,
                    authority_bundle_hash, record_digest
             FROM eth_verified_receipt_targets
             WHERE chain_id = ?1 AND network = ?2
               AND block_hash = ?3 AND authority_bundle_hash = ?4",
            rusqlite::params![
                chain_id.to_string(),
                network,
                block_hash.as_slice(),
                authority_bundle_hash.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored = StoredReceiptTargetAuthority {
        chain_id: parse_stored_u64(&row.0, "receipt target chain id")?,
        network: row.1,
        block_number: parse_stored_u64(&row.2, "receipt target block number")?,
        block_hash: stored_array(&row.3, "receipt target block hash")?,
        parent_hash: stored_array(&row.4, "receipt target parent hash")?,
        state_root: stored_array(&row.5, "receipt target state root")?,
        receipts_root: stored_array(&row.6, "receipt target receipts root")?,
        transactions_root: stored_array(&row.7, "receipt target transactions root")?,
        anchor_block_hash: stored_array(&row.8, "receipt target anchor block hash")?,
        checkpoint_root: stored_array(&row.9, "receipt target checkpoint root")?,
        provenance: provenance_from_i64(row.10)?,
        consensus_bundle_hash: stored_array(&row.11, "receipt target consensus bundle hash")?,
        authority_kind: ReceiptTargetAuthorityKind::from_i64(row.12)?,
        authority_bundle_hash: stored_array(&row.13, "receipt target authority bundle hash")?,
    };
    if stored_array::<32>(&row.14, "receipt target record digest")?
        != receipt_target_digest(&stored)
    {
        return Err(NodeStoreError::new(
            "stored receipt target digest does not match its values",
        ));
    }
    Ok(Some(stored))
}

pub(crate) fn migrate_v9_receipt_targets(transaction: &Transaction<'_>) -> Result<()> {
    let legacy = {
        let mut statement = transaction
            .prepare(
                "SELECT DISTINCT chain_id, network, block_number, block_hash,
                        checkpoint_root, provenance, consensus_bundle_hash,
                        execution_header_proof_hash
                 FROM eth_verified_receipts",
            )
            .map_err(NodeStoreError::sqlite)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            })
            .map_err(NodeStoreError::sqlite)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(NodeStoreError::sqlite)?
    };
    for row in legacy {
        let chain_id = parse_stored_u64(&row.0, "legacy receipt chain id")?;
        let block_number = parse_stored_u64(&row.2, "legacy receipt block number")?;
        let block_hash = stored_array(&row.3, "legacy receipt block hash")?;
        let checkpoint_root = stored_array(&row.4, "legacy receipt checkpoint root")?;
        let provenance = provenance_from_i64(row.5)?;
        let consensus_bundle_hash = stored_array(&row.6, "legacy receipt consensus bundle hash")?;
        let authority_bundle_hash = stored_array(&row.7, "legacy receipt execution proof hash")?;
        let block = read_execution_block(transaction, chain_id, &row.1, block_hash)?
            .ok_or_else(|| NodeStoreError::new("legacy receipt lost its execution authority"))?;
        let target = StoredReceiptTargetAuthority::from_direct_block(&block)?;
        if target.block_number != block_number
            || target.checkpoint_root != checkpoint_root
            || target.provenance != provenance
            || target.consensus_bundle_hash != consensus_bundle_hash
            || target.authority_bundle_hash != authority_bundle_hash
        {
            return Err(NodeStoreError::new(
                "legacy receipt conflicts with its direct finalized authority",
            ));
        }
        record_receipt_target(transaction, &target)?;
    }
    Ok(())
}

pub(crate) fn read_receipt_by_tx_hash(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    tx_hash: [u8; 32],
) -> Result<Option<StoredReceiptRecord>> {
    read_receipt_query(
        connection,
        "WHERE chain_id = ?1 AND network = ?2 AND tx_hash = ?3",
        rusqlite::params![chain_id.to_string(), network, tx_hash.as_slice()],
    )
}

fn read_receipt_by_subject(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    block_hash: [u8; 32],
    tx_index: u64,
) -> Result<Option<StoredReceiptRecord>> {
    read_receipt_query(
        connection,
        "WHERE chain_id = ?1 AND network = ?2 AND block_hash = ?3 AND tx_index = ?4",
        rusqlite::params![
            chain_id.to_string(),
            network,
            block_hash.as_slice(),
            tx_index.to_string()
        ],
    )
}

fn read_receipt_query<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    where_clause: &str,
    params: P,
) -> Result<Option<StoredReceiptRecord>> {
    let sql = format!(
        "SELECT chain_id, network, block_number, block_hash, tx_hash, tx_index,
                succeeded, cumulative_gas_used, logs_count, verified_at_unix, checkpoint_root,
                provenance, consensus_bundle_hash, execution_header_proof_hash,
                proof_bundle_hash, canonical_bundle, record_digest
         FROM eth_verified_receipts {where_clause}"
    );
    let row = connection
        .query_row(&sql, params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, Vec<u8>>(16)?,
            ))
        })
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let receipt = validate_receipt(row)?;
    let target = read_receipt_target(
        connection,
        receipt.chain_id,
        &receipt.network,
        receipt.block_hash,
        receipt.execution_header_proof_hash,
    )?
    .ok_or_else(|| NodeStoreError::new("receipt lost its durable target authority"))?;
    if target.block_number != receipt.block_number
        || target.block_hash != receipt.block_hash
        || target.checkpoint_root != receipt.checkpoint_root
        || target.provenance != receipt.provenance
        || target.consensus_bundle_hash != receipt.consensus_bundle_hash
        || target.authority_bundle_hash != receipt.execution_header_proof_hash
    {
        return Err(NodeStoreError::new(
            "receipt conflicts with its durable target authority",
        ));
    }
    Ok(Some(receipt))
}

type ReceiptRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    String,
    String,
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn validate_receipt(row: ReceiptRow) -> Result<StoredReceiptRecord> {
    let stored = StoredReceiptRecord {
        chain_id: parse_stored_u64(&row.0, "receipt chain id")?,
        network: row.1,
        block_number: parse_stored_u64(&row.2, "receipt block number")?,
        block_hash: stored_array(&row.3, "receipt block hash")?,
        tx_hash: stored_array(&row.4, "receipt transaction hash")?,
        tx_index: parse_stored_u64(&row.5, "receipt transaction index")?,
        succeeded: match row.6 {
            0 => false,
            1 => true,
            _ => return Err(NodeStoreError::new("invalid stored receipt status")),
        },
        cumulative_gas_used: parse_stored_u64(&row.7, "cumulative gas used")?,
        logs_count: parse_stored_u64(&row.8, "receipt logs count")?,
        verified_at_unix: parse_stored_u64(&row.9, "receipt verification time")?,
        checkpoint_root: stored_array(&row.10, "receipt checkpoint root")?,
        provenance: provenance_from_i64(row.11)?,
        consensus_bundle_hash: stored_array(&row.12, "receipt consensus bundle hash")?,
        execution_header_proof_hash: stored_array(&row.13, "execution header proof hash")?,
        proof_bundle_hash: stored_array(&row.14, "receipt proof bundle hash")?,
        canonical_bundle: row.15,
    };
    validate_canonical_bundle(
        &stored.canonical_bundle,
        stored.proof_bundle_hash,
        "receipt proof",
    )?;
    if stored_array::<32>(&row.16, "receipt record digest")? != receipt_digest(&stored) {
        return Err(NodeStoreError::new(
            "stored receipt digest does not match its values",
        ));
    }
    Ok(stored)
}

fn receipt_subject_key(receipt: &StoredReceiptRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-receipt-subject-v1");
    hasher.update(receipt.chain_id.to_le_bytes());
    hasher.update((receipt.network.len() as u16).to_le_bytes());
    hasher.update(receipt.network.as_bytes());
    hasher.update(receipt.block_hash);
    hasher.update(receipt.tx_index.to_le_bytes());
    hasher.finalize().into()
}

fn receipt_digest(receipt: &StoredReceiptRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-receipt-record-v1");
    hasher.update(receipt_subject_key(receipt));
    hasher.update(receipt.block_number.to_le_bytes());
    hasher.update(receipt.tx_hash);
    hasher.update([u8::from(receipt.succeeded)]);
    hasher.update(receipt.cumulative_gas_used.to_le_bytes());
    hasher.update(receipt.logs_count.to_le_bytes());
    hasher.update(receipt.verified_at_unix.to_le_bytes());
    hasher.update(receipt.checkpoint_root);
    hasher.update(provenance_i64(receipt.provenance).to_le_bytes());
    hasher.update(receipt.consensus_bundle_hash);
    hasher.update(receipt.execution_header_proof_hash);
    hasher.update(receipt.proof_bundle_hash);
    hasher.finalize().into()
}

fn receipt_target_digest(target: &StoredReceiptTargetAuthority) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-receipt-target-v1");
    hasher.update(target.chain_id.to_le_bytes());
    hasher.update((target.network.len() as u16).to_le_bytes());
    hasher.update(target.network.as_bytes());
    hasher.update(target.block_number.to_le_bytes());
    hasher.update(target.block_hash);
    hasher.update(target.parent_hash);
    hasher.update(target.state_root);
    hasher.update(target.receipts_root);
    hasher.update(target.transactions_root);
    hasher.update(target.anchor_block_hash);
    hasher.update(target.checkpoint_root);
    hasher.update(provenance_i64(target.provenance).to_le_bytes());
    hasher.update(target.consensus_bundle_hash);
    hasher.update((target.authority_kind as i64).to_le_bytes());
    hasher.update(target.authority_bundle_hash);
    hasher.finalize().into()
}

#[cfg(test)]
pub(crate) fn install_test_receipt_for_transaction(
    store: &mut EthereumNodeStore,
    tx_hash: [u8; 32],
    succeeded: bool,
) -> StoredReceiptRecord {
    use base64::Engine;

    let canonical = base64::engine::general_purpose::STANDARD
        .decode(
            include_str!(
                "../../ratspeak-eth-verifier/tests/fixtures/\
                 sepolia-receipt-11574048-0.rseth.b64"
            )
            .trim(),
        )
        .unwrap();
    let parsed = ratspeak_eth_verifier::Verifier::sepolia()
        .parse_tx_receipt_proof(&canonical)
        .unwrap();
    let block = crate::consensus::install_test_execution_evidence(
        store,
        parsed.block_number,
        parsed.block_hash,
        [0xf1; 32],
        parsed.receipts_root,
        parsed.transactions_root,
    );
    let values = ReceiptValues {
        chain_id: ratspeak_eth_verifier::SEPOLIA_CHAIN_ID,
        network: SEPOLIA_NETWORK.to_owned(),
        block_number: parsed.block_number,
        block_hash: parsed.block_hash,
        tx_hash,
        tx_index: parsed.tx_index,
        succeeded,
        cumulative_gas_used: 21_000,
        logs_count: 0,
        verified_at_unix: 2_000,
        checkpoint_root: block.checkpoint_root(),
        provenance: block.provenance(),
        consensus_bundle_hash: block.consensus_bundle_hash(),
        execution_header_proof_hash: block.proof_bundle_hash(),
        proof_bundle_hash: Sha256::digest(&canonical).into(),
        canonical_bundle: canonical,
    };
    let stored = values.as_stored();
    store.record_receipt_values(values, None).unwrap();
    stored
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::consensus::install_test_execution_evidence;
    use crate::transaction::test_support::{signed_fixture, signed_fixture_tx_hash};
    use ratspeak_eth_verifier::{SEPOLIA_CHAIN_ID, Verifier};

    const REAL_CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    fn receipt_bundle() -> (Vec<u8>, ratspeak_eth_verifier::TxReceiptProofBundle) {
        let canonical = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/\
                     sepolia-receipt-11574048-0.rseth.b64"
                )
                .trim(),
            )
            .unwrap();
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(&canonical)
            .unwrap();
        (canonical, parsed)
    }

    fn receipt_values(
        canonical: Vec<u8>,
        parsed: &ratspeak_eth_verifier::TxReceiptProofBundle,
        block: &crate::StoredExecutionBlock,
        succeeded: bool,
    ) -> ReceiptValues {
        ReceiptValues {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            block_number: parsed.block_number,
            block_hash: parsed.block_hash,
            tx_hash: parsed.tx_hash,
            tx_index: parsed.tx_index,
            succeeded,
            cumulative_gas_used: 21_000,
            logs_count: 0,
            verified_at_unix: 200,
            checkpoint_root: block.checkpoint_root(),
            provenance: block.provenance(),
            consensus_bundle_hash: block.consensus_bundle_hash(),
            execution_header_proof_hash: block.proof_bundle_hash(),
            proof_bundle_hash: Sha256::digest(&canonical).into(),
            canonical_bundle: canonical,
        }
    }

    fn real_consensus_bundle() -> Vec<u8> {
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
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&(bootstrap.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&bootstrap);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.push(0);
        bytes
    }

    fn finalized_at_anchor(
        receipt: &[u8],
        parsed: &ratspeak_eth_verifier::TxReceiptProofBundle,
    ) -> Vec<u8> {
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
        bytes.extend_from_slice(receipt);
        bytes
    }

    fn finalized_at_parent(
        receipt: &[u8],
        parsed: &ratspeak_eth_verifier::TxReceiptProofBundle,
        target: &Header,
    ) -> Vec<u8> {
        let target_rlp = alloy_rlp::encode(target);
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
        bytes.extend_from_slice(&target.number.to_le_bytes());
        bytes.extend_from_slice(&target.hash_slow().0);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&(target_rlp.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&target_rlp);
        bytes.extend_from_slice(&(receipt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(receipt);
        bytes
    }

    fn synthetic_parent_values(
        canonical: Vec<u8>,
        parsed: &ratspeak_eth_verifier::TxReceiptProofBundle,
        anchor: &crate::StoredExecutionBlock,
        target: &Header,
    ) -> (ReceiptValues, StoredReceiptTargetAuthority) {
        let authority_bundle_hash: [u8; 32] = Sha256::digest(&canonical).into();
        (
            ReceiptValues {
                chain_id: SEPOLIA_CHAIN_ID,
                network: SEPOLIA_NETWORK.to_owned(),
                block_number: target.number,
                block_hash: target.hash_slow().0,
                tx_hash: parsed.tx_hash,
                tx_index: parsed.tx_index,
                succeeded: true,
                cumulative_gas_used: 21_000,
                logs_count: 0,
                verified_at_unix: 200,
                checkpoint_root: anchor.checkpoint_root(),
                provenance: anchor.provenance(),
                consensus_bundle_hash: anchor.consensus_bundle_hash(),
                execution_header_proof_hash: authority_bundle_hash,
                proof_bundle_hash: authority_bundle_hash,
                canonical_bundle: canonical,
            },
            StoredReceiptTargetAuthority {
                chain_id: SEPOLIA_CHAIN_ID,
                network: SEPOLIA_NETWORK.to_owned(),
                block_number: target.number,
                block_hash: target.hash_slow().0,
                parent_hash: target.parent_hash.0,
                state_root: target.state_root.0,
                receipts_root: target.receipts_root.0,
                transactions_root: target.transactions_root.0,
                anchor_block_hash: anchor.execution_block_hash(),
                checkpoint_root: anchor.checkpoint_root(),
                provenance: anchor.provenance(),
                consensus_bundle_hash: anchor.consensus_bundle_hash(),
                authority_kind: ReceiptTargetAuthorityKind::FinalizedAncestry,
                authority_bundle_hash,
            },
        )
    }

    #[test]
    fn finalized_envelope_persists_replays_and_reopens_with_consensus_provenance() {
        let (receipt_bytes, parsed) = receipt_bundle();
        let canonical = finalized_at_anchor(&receipt_bytes, &parsed);
        let profile = tempfile::tempdir().unwrap();
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let now = crate::bootstrap::trusted_now_unix().unwrap();
            crate::bootstrap::install_test_active_checkpoint(&mut store, REAL_CHECKPOINT_ROOT, now);
            let verifier = Verifier::sepolia();
            let consensus_bytes = real_consensus_bundle();
            let consensus = verifier
                .verify_consensus_bootstrap_at_unix(
                    &consensus_bytes,
                    &ratspeak_eth_verifier::BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
                    now,
                )
                .unwrap();
            store
                .record_verified_finalized_header(&consensus, &consensus_bytes)
                .unwrap();
            let execution_bytes = base64::engine::general_purpose::STANDARD
                .decode(
                    include_str!(
                        "../../ratspeak-eth-verifier/tests/fixtures/\
                         sepolia-execution-header-11574048.rseth.b64"
                    )
                    .trim(),
                )
                .unwrap();
            let anchor = verifier
                .verify_execution_header(&execution_bytes, &consensus)
                .unwrap();
            store
                .record_verified_execution_block(&anchor, &execution_bytes)
                .unwrap();
            let verified = verifier
                .verify_finalized_tx_receipt(&canonical, &anchor)
                .unwrap();
            assert_eq!(verified.receipt().tx_hash(), parsed.tx_hash);

            // A caller-held verified wrapper cannot authenticate different
            // parseable inner proof bytes merely because the subject fields
            // still match. Rejection must be atomic before any receipt target,
            // receipt row, or transaction assurance is appended.
            let inner_offset = canonical
                .windows(receipt_bytes.len())
                .position(|window| window == receipt_bytes)
                .unwrap();
            let mut substituted = canonical.clone();
            let last_inner_byte = inner_offset + receipt_bytes.len() - 1;
            substituted[last_inner_byte] ^= 1;
            assert!(
                store
                    .record_verified_finalized_receipt(&verified, &substituted, now)
                    .is_err()
            );
            assert!(
                store
                    .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                    .unwrap()
                    .is_none()
            );
            let rejected_target_count: u64 = store
                .connection
                .query_row(
                    "SELECT count(*) FROM eth_verified_receipt_targets",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rejected_target_count, 0);
            assert!(
                store
                    .transaction_assurance_history(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                    .unwrap()
                    .is_empty()
            );

            // A zero-distance envelope names the same direct execution-header
            // authority as the legacy receipt form. Keep that authority stable
            // when evidence for the block arrives through both encodings.
            let direct = verifier.verify_tx_receipt(&receipt_bytes, &anchor).unwrap();
            store
                .record_verified_receipt(&direct, &receipt_bytes, now)
                .unwrap();
            assert_eq!(
                store
                    .record_verified_finalized_receipt(&verified, &canonical, now)
                    .unwrap(),
                RecordOutcome::Replay
            );
            assert_eq!(
                store
                    .record_verified_finalized_receipt(&verified, &canonical, now)
                    .unwrap(),
                RecordOutcome::Replay
            );
            let target_count: u64 = store
                .connection
                .query_row(
                    "SELECT count(*) FROM eth_verified_receipt_targets
                     WHERE chain_id = ?1 AND network = ?2 AND block_hash = ?3",
                    rusqlite::params![
                        SEPOLIA_CHAIN_ID.to_string(),
                        SEPOLIA_NETWORK,
                        parsed.block_hash.as_slice()
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(target_count, 1);
        }

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = reopened
            .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored.canonical_bundle(), receipt_bytes);
        assert_eq!(stored.checkpoint_root(), REAL_CHECKPOINT_ROOT);
    }

    #[test]
    fn zero_distance_wrapper_then_direct_receipt_is_the_same_durable_evidence() {
        let (receipt_bytes, parsed) = receipt_bundle();
        let canonical = finalized_at_anchor(&receipt_bytes, &parsed);
        let profile = tempfile::tempdir().unwrap();
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let now = crate::bootstrap::trusted_now_unix().unwrap();
            crate::bootstrap::install_test_active_checkpoint(&mut store, REAL_CHECKPOINT_ROOT, now);
            let verifier = Verifier::sepolia();
            let consensus_bytes = real_consensus_bundle();
            let consensus = verifier
                .verify_consensus_bootstrap_at_unix(
                    &consensus_bytes,
                    &ratspeak_eth_verifier::BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
                    now,
                )
                .unwrap();
            store
                .record_verified_finalized_header(&consensus, &consensus_bytes)
                .unwrap();
            let execution_bytes = base64::engine::general_purpose::STANDARD
                .decode(
                    include_str!(
                        "../../ratspeak-eth-verifier/tests/fixtures/\
                         sepolia-execution-header-11574048.rseth.b64"
                    )
                    .trim(),
                )
                .unwrap();
            let anchor = verifier
                .verify_execution_header(&execution_bytes, &consensus)
                .unwrap();
            store
                .record_verified_execution_block(&anchor, &execution_bytes)
                .unwrap();
            let wrapped = verifier
                .verify_finalized_tx_receipt(&canonical, &anchor)
                .unwrap();
            assert_eq!(
                store
                    .record_verified_finalized_receipt(&wrapped, &canonical, now)
                    .unwrap(),
                RecordOutcome::Inserted
            );
            let direct = verifier.verify_tx_receipt(&receipt_bytes, &anchor).unwrap();
            assert_eq!(
                store
                    .record_verified_receipt(&direct, &receipt_bytes, now)
                    .unwrap(),
                RecordOutcome::Replay
            );
        }

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = reopened
            .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored.canonical_bundle(), receipt_bytes);
        let verifier = Verifier::sepolia();
        let block = reopened
            .execution_block(SEPOLIA_CHAIN_ID, parsed.block_hash)
            .unwrap()
            .unwrap();
        let consensus = crate::consensus::read_finalized_header_by_proof_hash(
            &reopened.connection,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            block.consensus_bundle_hash(),
        )
        .unwrap()
        .unwrap();
        let now = crate::bootstrap::trusted_now_unix().unwrap();
        let verified_consensus =
            crate::messaging::reverify_historical_consensus(&reopened, &verifier, &consensus, now)
                .unwrap();
        let verified_block = verifier
            .verify_execution_header(block.canonical_bundle(), &verified_consensus)
            .unwrap();
        verifier
            .verify_tx_receipt(stored.canonical_bundle(), &verified_block)
            .unwrap();
        let target_count: u64 = reopened
            .connection
            .query_row(
                "SELECT count(*) FROM eth_verified_receipt_targets
                 WHERE chain_id = ?1 AND network = ?2 AND block_hash = ?3",
                rusqlite::params![
                    SEPOLIA_CHAIN_ID.to_string(),
                    SEPOLIA_NETWORK,
                    parsed.block_hash.as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(target_count, 1);
    }

    #[test]
    fn derived_parent_target_is_atomic_immutable_and_corruption_detected_after_reopen() {
        let (receipt_bytes, parsed) = receipt_bundle();
        let target = Header {
            number: parsed.block_number - 1,
            parent_hash: [0x41; 32].into(),
            state_root: [0x42; 32].into(),
            receipts_root: [0x43; 32].into(),
            transactions_root: [0x44; 32].into(),
            ..Default::default()
        };
        let canonical = finalized_at_parent(&receipt_bytes, &parsed, &target);
        let donor_profile = tempfile::tempdir().unwrap();
        let mut donor = EthereumNodeStore::open_in_profile(donor_profile.path()).unwrap();
        let donor_anchor = install_test_execution_evidence(
            &mut donor,
            parsed.block_number,
            parsed.block_hash,
            [0x45; 32],
            parsed.receipts_root,
            parsed.transactions_root,
        );
        let (missing_values, missing_authority) =
            synthetic_parent_values(canonical.clone(), &parsed, &donor_anchor, &target);
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            store
                .record_receipt_values(missing_values, Some(missing_authority))
                .unwrap_err()
                .to_string()
                .contains("no persisted finalized anchor")
        );
        assert!(
            store
                .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                .unwrap()
                .is_none()
        );

        let anchor = install_test_execution_evidence(
            &mut store,
            parsed.block_number,
            parsed.block_hash,
            [0x45; 32],
            parsed.receipts_root,
            parsed.transactions_root,
        );
        let (values, authority) =
            synthetic_parent_values(canonical.clone(), &parsed, &anchor, &target);
        assert_eq!(
            store
                .record_receipt_values(values.clone(), Some(authority.clone()))
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store
                .record_receipt_values(values.clone(), Some(authority.clone()))
                .unwrap(),
            RecordOutcome::Replay
        );
        let mut conflicting = authority.clone();
        conflicting.state_root[0] ^= 1;
        assert!(
            store
                .record_receipt_values(values, Some(conflicting))
                .unwrap_err()
                .to_string()
                .contains("immutable finalized ancestry")
        );
        drop(store);

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let receipt = reopened
            .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.block_hash(), target.hash_slow().0);
        assert_eq!(receipt.canonical_bundle(), canonical);
        reopened
            .connection
            .execute(
                "UPDATE eth_verified_receipt_targets SET parent_hash = zeroblob(32)",
                [],
            )
            .unwrap();
        assert!(
            reopened
                .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                .unwrap_err()
                .to_string()
                .contains("target digest")
        );
    }

    #[test]
    fn v9_legacy_receipt_migrates_to_direct_target_authority_without_data_loss() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let database_path = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let now = crate::bootstrap::trusted_now_unix().unwrap();
            crate::bootstrap::install_test_active_checkpoint(&mut store, REAL_CHECKPOINT_ROOT, now);
            let verifier = Verifier::sepolia();
            let consensus_bytes = real_consensus_bundle();
            let consensus = verifier
                .verify_consensus_bootstrap_at_unix(
                    &consensus_bytes,
                    &ratspeak_eth_verifier::BeaconCheckpointRoot::sepolia(REAL_CHECKPOINT_ROOT),
                    now,
                )
                .unwrap();
            store
                .record_verified_finalized_header(&consensus, &consensus_bytes)
                .unwrap();
            let execution_bytes = base64::engine::general_purpose::STANDARD
                .decode(
                    include_str!(
                        "../../ratspeak-eth-verifier/tests/fixtures/\
                         sepolia-execution-header-11574048.rseth.b64"
                    )
                    .trim(),
                )
                .unwrap();
            let block = verifier
                .verify_execution_header(&execution_bytes, &consensus)
                .unwrap();
            store
                .record_verified_execution_block(&block, &execution_bytes)
                .unwrap();
            let receipt = verifier.verify_tx_receipt(&canonical, &block).unwrap();
            store
                .record_verified_receipt(&receipt, &canonical, now)
                .unwrap();
            store.path().to_owned()
        };

        let connection = rusqlite::Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 ALTER TABLE eth_verified_receipts RENAME TO eth_verified_receipts_v10;
                 CREATE TABLE eth_verified_receipts (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    block_number TEXT NOT NULL,
                    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
                    tx_index TEXT NOT NULL,
                    succeeded INTEGER NOT NULL CHECK(succeeded IN (0, 1)),
                    cumulative_gas_used TEXT NOT NULL,
                    logs_count TEXT NOT NULL,
                    verified_at_unix TEXT NOT NULL,
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    provenance INTEGER NOT NULL,
                    consensus_bundle_hash BLOB NOT NULL CHECK(length(consensus_bundle_hash) = 32),
                    execution_header_proof_hash BLOB NOT NULL
                        CHECK(length(execution_header_proof_hash) = 32),
                    proof_bundle_hash BLOB NOT NULL CHECK(length(proof_bundle_hash) = 32),
                    canonical_bundle BLOB NOT NULL CHECK(length(canonical_bundle) > 0),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, block_hash, tx_index),
                    FOREIGN KEY(chain_id, network, block_hash)
                        REFERENCES eth_verified_execution_blocks(
                            chain_id, network, execution_block_hash
                        ),
                    UNIQUE(chain_id, network, tx_hash),
                    UNIQUE(chain_id, network, proof_bundle_hash)
                 );
                 INSERT INTO eth_verified_receipts SELECT * FROM eth_verified_receipts_v10;
                 DROP TABLE eth_verified_receipts_v10;
                 DROP TABLE eth_verified_receipt_targets;
                 UPDATE eth_schema_version SET version = 9;",
            )
            .unwrap();
        drop(connection);

        let migrated = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let version: i64 = migrated
            .connection
            .query_row(
                "SELECT version FROM eth_schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let target_count: i64 = migrated
            .connection
            .query_row(
                "SELECT count(*) FROM eth_verified_receipt_targets",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, crate::schema::ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(target_count, 1);
        assert_eq!(
            migrated
                .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                .unwrap()
                .unwrap()
                .canonical_bundle(),
            canonical
        );
    }

    #[test]
    fn persists_exact_receipt_and_only_then_records_finalized_assurance() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let tx_hash = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let block = install_test_execution_evidence(
                &mut store,
                parsed.block_number,
                parsed.block_hash,
                [0xa1; 32],
                parsed.receipts_root,
                parsed.transactions_root,
            );
            let (sender, review, tx_hash) = signed_fixture(&mut store);
            assert_ne!(sender, [0; 20]);
            // ReceiptValues is private and production values are constructed
            // only from VerifiedTxReceipt. This store-level test substitutes
            // the W1-native fixture hash solely to exercise assurance linkage.
            let mut values = receipt_values(canonical.clone(), &parsed, &block, true);
            values.tx_hash = tx_hash;
            assert_eq!(
                store.record_receipt_values(values.clone(), None).unwrap(),
                RecordOutcome::Inserted
            );
            let mut later_reverification = values.clone();
            later_reverification.verified_at_unix += 600;
            assert_eq!(
                store
                    .record_receipt_values(later_reverification, None)
                    .unwrap(),
                RecordOutcome::Replay
            );
            assert_ne!(review, [0; 32]);
            tx_hash
        };

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = store
            .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap()
            .unwrap();
        assert!(stored.succeeded());
        assert_eq!(stored.verified_at_unix(), 200);
        assert_eq!(stored.canonical_bundle(), canonical);
        let history = store
            .transaction_assurance_history(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].event_kind(),
            AssuranceEventKind::LocalSignatureRecorded
        );
        assert_eq!(
            history[1].event_kind(),
            AssuranceEventKind::FinalizedReceiptSucceeded
        );
    }

    #[test]
    fn receipt_without_local_transaction_does_not_manufacture_transaction_assurance() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let block = install_test_execution_evidence(
            &mut store,
            parsed.block_number,
            parsed.block_hash,
            [0xb1; 32],
            parsed.receipts_root,
            parsed.transactions_root,
        );
        let values = receipt_values(canonical, &parsed, &block, false);
        store.record_receipt_values(values, None).unwrap();
        assert!(
            store
                .transaction_assurance_history(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn receipt_recorded_before_local_transaction_converges_to_finalized_assurance() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let block = install_test_execution_evidence(
            &mut store,
            parsed.block_number,
            parsed.block_hash,
            [0xb2; 32],
            parsed.receipts_root,
            parsed.transactions_root,
        );
        // See the store-level fixture note in the linkage test above.
        let mut values = receipt_values(canonical, &parsed, &block, false);
        values.tx_hash = signed_fixture_tx_hash();
        store.record_receipt_values(values, None).unwrap();
        signed_fixture(&mut store);
        let history = store
            .transaction_assurance_history(SEPOLIA_CHAIN_ID, signed_fixture_tx_hash())
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[1].event_kind(),
            AssuranceEventKind::FinalizedReceiptFailed
        );
    }

    #[test]
    fn rejects_receipt_without_execution_evidence_atomically() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let values = ReceiptValues {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            block_number: parsed.block_number,
            block_hash: parsed.block_hash,
            tx_hash: parsed.tx_hash,
            tx_index: parsed.tx_index,
            succeeded: true,
            cumulative_gas_used: 21_000,
            logs_count: 0,
            verified_at_unix: 200,
            checkpoint_root: [0xc2; 32],
            provenance: ExecutionHeaderProvenance::CheckpointAnchor,
            consensus_bundle_hash: [0xc3; 32],
            execution_header_proof_hash: [0xc4; 32],
            proof_bundle_hash: Sha256::digest(&canonical).into(),
            canonical_bundle: canonical,
        };
        let replay_key = receipt_subject_key(&values.as_stored());
        assert!(
            store
                .record_receipt_values(values, None)
                .unwrap_err()
                .to_string()
                .contains("no persisted execution evidence")
        );
        assert!(
            store
                .replay_record(SEPOLIA_CHAIN_ID, EvidenceKind::ReceiptProof, replay_key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_conflicting_or_corrupted_receipt_evidence() {
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let block = install_test_execution_evidence(
            &mut store,
            parsed.block_number,
            parsed.block_hash,
            [0xd1; 32],
            parsed.receipts_root,
            parsed.transactions_root,
        );
        let values = receipt_values(canonical, &parsed, &block, true);
        store.record_receipt_values(values.clone(), None).unwrap();
        let mut conflicting = values;
        conflicting.succeeded = false;
        assert!(
            store
                .record_receipt_values(conflicting, None)
                .unwrap_err()
                .to_string()
                .contains("immutable verified evidence")
        );
        store
            .connection
            .execute(
                "UPDATE eth_verified_receipts SET canonical_bundle = x'00'",
                [],
            )
            .unwrap();
        assert!(
            store
                .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, parsed.tx_hash)
                .unwrap_err()
                .to_string()
                .contains("evidence hash does not match")
        );
    }

    #[test]
    fn synthetic_transaction_scoped_failed_receipt_rolls_back_but_cannot_claim_finality() {
        // Persistence-only seam: the verifier's frozen fixture is a contract
        // transaction, so this test deliberately substitutes the hash of the
        // supported native-transfer fixture *after* cryptographic verification.
        // It proves SQLite transaction/assurance behavior, not receipt proof
        // validity; verifier tests cover that boundary with the real bytes.
        let (canonical, parsed) = receipt_bundle();
        let profile = tempfile::tempdir().unwrap();
        {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let (_, _, tx_hash) = signed_fixture(&mut store);
            let block = install_test_execution_evidence(
                &mut store,
                parsed.block_number,
                parsed.block_hash,
                [0xd2; 32],
                parsed.receipts_root,
                parsed.transactions_root,
            );
            let mut values = receipt_values(canonical, &parsed, &block, false);
            values.tx_hash = tx_hash;

            {
                let transaction = store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                assert_eq!(
                    record_receipt_values_in(&transaction, values.clone(), None).unwrap(),
                    RecordOutcome::Inserted
                );
                assert!(
                    read_receipt_by_tx_hash(
                        &transaction,
                        SEPOLIA_CHAIN_ID,
                        SEPOLIA_NETWORK,
                        tx_hash,
                    )
                    .unwrap()
                    .is_some()
                );
                // Drop without commit to emulate a failure after all verified
                // rows and assurance have been staged.
            }
            assert!(
                store
                    .receipt_by_transaction_hash(SEPOLIA_CHAIN_ID, tx_hash)
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                store.transaction_assurance(tx_hash).unwrap(),
                Some(crate::TransactionAssurance::Signed { .. })
            ));

            let transaction = store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            record_receipt_values_in(&transaction, values, None).unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                store.transaction_assurance(tx_hash).unwrap(),
                Some(crate::TransactionAssurance::NeedsReverification(_))
            ));
            assert!(
                store
                    .transaction_assurance_history(SEPOLIA_CHAIN_ID, tx_hash)
                    .unwrap()
                    .iter()
                    .any(|event| event.event_kind() == AssuranceEventKind::FinalizedReceiptFailed)
            );
        }

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let tx_hash = signed_fixture_tx_hash();
        assert!(matches!(
            reopened.transaction_assurance(tx_hash).unwrap(),
            Some(crate::TransactionAssurance::NeedsReverification(_))
        ));
    }
}
