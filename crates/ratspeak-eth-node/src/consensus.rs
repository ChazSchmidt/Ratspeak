use ratspeak_eth_verifier::{
    ExecutionHeaderProvenance, SEPOLIA_NETWORK, VerifiedExecutionBlock, VerifiedExecutionHeader,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::checkpoint::{ensure_supported_network, read_checkpoint};
use crate::evidence::{EvidenceKind, record_replay, validate_canonical_bundle};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

/// Persisted consensus result plus the canonical bytes needed to verify it again.
///
/// This database snapshot is deliberately not a verifier `VerifiedExecutionHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFinalizedHeader {
    chain_id: u64,
    network: String,
    finalized_slot: u64,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    beacon_transactions_root: [u8; 32],
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl StoredFinalizedHeader {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn finalized_slot(&self) -> u64 {
        self.finalized_slot
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

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    pub fn beacon_transactions_root(&self) -> [u8; 32] {
        self.beacon_transactions_root
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn provenance(&self) -> ExecutionHeaderProvenance {
        self.provenance
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }

    /// Canonical uncompressed consensus bundle bytes.
    pub fn canonical_bundle(&self) -> &[u8] {
        &self.canonical_bundle
    }
}

/// Persisted RLP execution-header result and its canonical proof bundle.
///
/// This database snapshot is deliberately not a verifier `VerifiedExecutionBlock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExecutionBlock {
    chain_id: u64,
    network: String,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    consensus_bundle_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl StoredExecutionBlock {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
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

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    pub fn transactions_root(&self) -> [u8; 32] {
        self.transactions_root
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

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }

    /// Canonical uncompressed execution-header bundle bytes.
    pub fn canonical_bundle(&self) -> &[u8] {
        &self.canonical_bundle
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizedHeaderValues {
    chain_id: u64,
    network: String,
    finalized_slot: u64,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    beacon_transactions_root: [u8; 32],
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl FinalizedHeaderValues {
    pub(crate) fn from_verified(
        header: &VerifiedExecutionHeader,
        canonical_bundle: &[u8],
    ) -> Result<Self> {
        ensure_supported_network(header.chain_id(), header.network())?;
        validate_canonical_bundle(
            canonical_bundle,
            header.proof_bundle_hash(),
            "consensus bootstrap",
        )?;
        Ok(Self {
            chain_id: header.chain_id(),
            network: header.network().to_owned(),
            finalized_slot: header.finalized_slot(),
            execution_block_number: header.execution_block_number(),
            execution_block_hash: header.execution_block_hash(),
            state_root: header.state_root(),
            receipts_root: header.receipts_root(),
            beacon_transactions_root: header.beacon_transactions_root(),
            checkpoint_root: header.checkpoint_root(),
            provenance: header.provenance(),
            proof_bundle_hash: header.proof_bundle_hash(),
            canonical_bundle: canonical_bundle.to_vec(),
        })
    }

    fn as_stored(&self) -> StoredFinalizedHeader {
        StoredFinalizedHeader {
            chain_id: self.chain_id,
            network: self.network.clone(),
            finalized_slot: self.finalized_slot,
            execution_block_number: self.execution_block_number,
            execution_block_hash: self.execution_block_hash,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            beacon_transactions_root: self.beacon_transactions_root,
            checkpoint_root: self.checkpoint_root,
            provenance: self.provenance,
            proof_bundle_hash: self.proof_bundle_hash,
            canonical_bundle: self.canonical_bundle.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionBlockValues {
    chain_id: u64,
    network: String,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
    checkpoint_root: [u8; 32],
    provenance: ExecutionHeaderProvenance,
    consensus_bundle_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl ExecutionBlockValues {
    pub(crate) fn from_verified(
        block: &VerifiedExecutionBlock,
        canonical_bundle: &[u8],
    ) -> Result<Self> {
        ensure_supported_network(block.chain_id(), block.network())?;
        validate_canonical_bundle(
            canonical_bundle,
            block.proof_bundle_hash(),
            "execution header",
        )?;
        Ok(Self {
            chain_id: block.chain_id(),
            network: block.network().to_owned(),
            execution_block_number: block.execution_block_number(),
            execution_block_hash: block.execution_block_hash(),
            state_root: block.state_root(),
            receipts_root: block.receipts_root(),
            transactions_root: block.transactions_root(),
            checkpoint_root: block.checkpoint_root(),
            provenance: block.provenance(),
            consensus_bundle_hash: block.consensus_bundle_hash(),
            proof_bundle_hash: block.proof_bundle_hash(),
            canonical_bundle: canonical_bundle.to_vec(),
        })
    }

    fn as_stored(&self) -> StoredExecutionBlock {
        StoredExecutionBlock {
            chain_id: self.chain_id,
            network: self.network.clone(),
            execution_block_number: self.execution_block_number,
            execution_block_hash: self.execution_block_hash,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            transactions_root: self.transactions_root,
            checkpoint_root: self.checkpoint_root,
            provenance: self.provenance,
            consensus_bundle_hash: self.consensus_bundle_hash,
            proof_bundle_hash: self.proof_bundle_hash,
            canonical_bundle: self.canonical_bundle.clone(),
        }
    }
}

impl EthereumNodeStore {
    /// Stores a Helios-verified finalized header and advances the profile head.
    ///
    /// `canonical_bundle` must be the uncompressed bytes whose SHA-256 is held
    /// by `header`. The referenced checkpoint must already have an approval
    /// record; this method does not infer approval from the bundle or header.
    /// Storage presence is not current policy evaluation: the future checkpoint
    /// manager must also evaluate source history and any revocation events.
    pub fn record_verified_finalized_header(
        &mut self,
        header: &VerifiedExecutionHeader,
        canonical_bundle: &[u8],
    ) -> Result<RecordOutcome> {
        self.record_finalized_header_values(FinalizedHeaderValues::from_verified(
            header,
            canonical_bundle,
        )?)
    }

    fn record_finalized_header_values(
        &mut self,
        values: FinalizedHeaderValues,
    ) -> Result<RecordOutcome> {
        ensure_supported_network(values.chain_id, &values.network)?;
        validate_canonical_bundle(
            &values.canonical_bundle,
            values.proof_bundle_hash,
            "consensus bootstrap",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_finalized_header_values_in(&transaction, values, false)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn latest_finalized_header(&self, chain_id: u64) -> Result<Option<StoredFinalizedHeader>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_latest_finalized_header(&self.connection, chain_id)
    }

    /// Stores execution trie roots authenticated by a persisted finalized header.
    pub fn record_verified_execution_block(
        &mut self,
        block: &VerifiedExecutionBlock,
        canonical_bundle: &[u8],
    ) -> Result<RecordOutcome> {
        self.record_execution_block_values(ExecutionBlockValues::from_verified(
            block,
            canonical_bundle,
        )?)
    }

    fn record_execution_block_values(
        &mut self,
        values: ExecutionBlockValues,
    ) -> Result<RecordOutcome> {
        ensure_supported_network(values.chain_id, &values.network)?;
        validate_canonical_bundle(
            &values.canonical_bundle,
            values.proof_bundle_hash,
            "execution header",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_execution_block_values_in(&transaction, values)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn execution_block(
        &self,
        chain_id: u64,
        execution_block_hash: [u8; 32],
    ) -> Result<Option<StoredExecutionBlock>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_execution_block(
            &self.connection,
            chain_id,
            SEPOLIA_NETWORK,
            execution_block_hash,
        )
    }
}

/// Writes one already verified consensus header inside the caller's durable
/// transaction. Composite evidence may arrive out of order, so a historical
/// row can be retained without moving the profile's latest-head pointer back.
pub(crate) fn record_finalized_header_values_in(
    transaction: &Transaction<'_>,
    values: FinalizedHeaderValues,
    allow_historical: bool,
) -> Result<RecordOutcome> {
    ensure_supported_network(values.chain_id, &values.network)?;
    validate_canonical_bundle(
        &values.canonical_bundle,
        values.proof_bundle_hash,
        "consensus bootstrap",
    )?;
    if read_checkpoint(transaction, values.chain_id, values.checkpoint_root)?.is_none() {
        return Err(NodeStoreError::new(
            "verified consensus header references an unapproved checkpoint",
        ));
    }

    let latest = read_latest_finalized_header(transaction, values.chain_id)?;
    let historical = latest
        .as_ref()
        .is_some_and(|head| values.finalized_slot < head.finalized_slot);
    if let Some(latest) = &latest {
        if historical && !allow_historical {
            return Err(NodeStoreError::new(
                "verified consensus header would roll back finalized state",
            ));
        }
        if !historical && values.execution_block_number < latest.execution_block_number {
            return Err(NodeStoreError::new(
                "verified consensus header would roll back finalized state",
            ));
        }
        if values.finalized_slot > latest.finalized_slot
            && values.execution_block_number == latest.execution_block_number
            && values.execution_block_hash != latest.execution_block_hash
        {
            return Err(NodeStoreError::new(
                "verified consensus header conflicts at a finalized block height",
            ));
        }
    }

    let stored_values = values.as_stored();
    let digest = finalized_header_digest(&stored_values);
    let changed = transaction
        .execute(
            "INSERT INTO eth_verified_finalized_headers (
                chain_id, network, finalized_slot, execution_block_number,
                execution_block_hash, state_root, receipts_root,
                beacon_transactions_root, checkpoint_root, provenance,
                proof_bundle_hash, canonical_bundle, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(chain_id, network, finalized_slot) DO NOTHING",
            rusqlite::params![
                values.chain_id.to_string(),
                values.network,
                values.finalized_slot.to_string(),
                values.execution_block_number.to_string(),
                values.execution_block_hash.as_slice(),
                values.state_root.as_slice(),
                values.receipts_root.as_slice(),
                values.beacon_transactions_root.as_slice(),
                values.checkpoint_root.as_slice(),
                provenance_i64(values.provenance),
                values.proof_bundle_hash.as_slice(),
                values.canonical_bundle,
                digest.as_slice(),
            ],
        )
        .map_err(|error| immutable_conflict(error, "finalized header"))?;

    if changed == 0 {
        let stored = read_finalized_header_at_slot(
            transaction,
            values.chain_id,
            &values.network,
            values.finalized_slot,
        )?
        .ok_or_else(|| {
            NodeStoreError::new("finalized header replay has no corresponding record")
        })?;
        if stored != stored_values {
            return Err(NodeStoreError::new(
                "finalized slot conflicts with immutable verified state",
            ));
        }
    }

    let replay_outcome = record_replay(
        transaction,
        values.chain_id,
        &values.network,
        EvidenceKind::ConsensusBootstrap,
        values.proof_bundle_hash,
        finalized_subject_key(&stored_values),
    )?;
    if changed == 1 && !historical {
        let pointer_digest =
            latest_pointer_digest(values.chain_id, &values.network, values.finalized_slot);
        transaction
            .execute(
                "INSERT INTO eth_latest_finalized_header (
                    chain_id, network, finalized_slot, record_digest
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(chain_id, network) DO UPDATE SET
                    finalized_slot = excluded.finalized_slot,
                    record_digest = excluded.record_digest",
                rusqlite::params![
                    values.chain_id.to_string(),
                    values.network,
                    values.finalized_slot.to_string(),
                    pointer_digest.as_slice(),
                ],
            )
            .map_err(NodeStoreError::sqlite)?;
    }
    Ok(
        if changed == 1 || replay_outcome == RecordOutcome::Inserted {
            RecordOutcome::Inserted
        } else {
            RecordOutcome::Replay
        },
    )
}

pub(crate) fn record_execution_block_values_in(
    transaction: &Transaction<'_>,
    values: ExecutionBlockValues,
) -> Result<RecordOutcome> {
    ensure_supported_network(values.chain_id, &values.network)?;
    validate_canonical_bundle(
        &values.canonical_bundle,
        values.proof_bundle_hash,
        "execution header",
    )?;
    let consensus = read_finalized_header_by_proof_hash(
        transaction,
        values.chain_id,
        &values.network,
        values.consensus_bundle_hash,
    )?
    .ok_or_else(|| NodeStoreError::new("execution block has no persisted consensus evidence"))?;
    if values.execution_block_number != consensus.execution_block_number
        || values.execution_block_hash != consensus.execution_block_hash
        || values.state_root != consensus.state_root
        || values.receipts_root != consensus.receipts_root
        || values.checkpoint_root != consensus.checkpoint_root
        || values.provenance != consensus.provenance
    {
        return Err(NodeStoreError::new(
            "execution block conflicts with persisted consensus commitments",
        ));
    }

    let stored_values = values.as_stored();
    let digest = execution_block_digest(&stored_values);
    let changed = transaction
        .execute(
            "INSERT INTO eth_verified_execution_blocks (
                chain_id, network, execution_block_number, execution_block_hash,
                state_root, receipts_root, transactions_root, checkpoint_root,
                provenance, consensus_bundle_hash, proof_bundle_hash,
                canonical_bundle, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(chain_id, network, execution_block_hash) DO NOTHING",
            rusqlite::params![
                values.chain_id.to_string(),
                values.network,
                values.execution_block_number.to_string(),
                values.execution_block_hash.as_slice(),
                values.state_root.as_slice(),
                values.receipts_root.as_slice(),
                values.transactions_root.as_slice(),
                values.checkpoint_root.as_slice(),
                provenance_i64(values.provenance),
                values.consensus_bundle_hash.as_slice(),
                values.proof_bundle_hash.as_slice(),
                values.canonical_bundle,
                digest.as_slice(),
            ],
        )
        .map_err(|error| immutable_conflict(error, "execution block"))?;
    if changed == 0 {
        let stored = read_execution_block(
            transaction,
            values.chain_id,
            &values.network,
            values.execution_block_hash,
        )?
        .ok_or_else(|| NodeStoreError::new("execution block replay has no corresponding record"))?;
        if stored != stored_values {
            return Err(NodeStoreError::new(
                "execution block hash conflicts with immutable verified state",
            ));
        }
    }
    let replay_outcome = record_replay(
        transaction,
        values.chain_id,
        &values.network,
        EvidenceKind::ExecutionHeader,
        values.proof_bundle_hash,
        execution_subject_key(&stored_values),
    )?;
    Ok(
        if changed == 1 || replay_outcome == RecordOutcome::Inserted {
            RecordOutcome::Inserted
        } else {
            RecordOutcome::Replay
        },
    )
}

pub(crate) fn read_latest_finalized_header(
    connection: &rusqlite::Connection,
    chain_id: u64,
) -> Result<Option<StoredFinalizedHeader>> {
    let pointer = connection
        .query_row(
            "SELECT network, finalized_slot, record_digest
             FROM eth_latest_finalized_header WHERE chain_id = ?1",
            [chain_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((network, slot, digest)) = pointer else {
        return Ok(None);
    };
    let slot = parse_stored_u64(&slot, "latest finalized slot")?;
    if stored_array::<32>(&digest, "latest finalized pointer digest")?
        != latest_pointer_digest(chain_id, &network, slot)
    {
        return Err(NodeStoreError::new(
            "stored latest finalized pointer digest does not match its values",
        ));
    }
    read_finalized_header_at_slot(connection, chain_id, &network, slot)?.map_or_else(
        || {
            Err(NodeStoreError::new(
                "latest finalized pointer has no corresponding header",
            ))
        },
        |header| Ok(Some(header)),
    )
}

pub(crate) fn read_finalized_header_by_proof_hash(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    proof_bundle_hash: [u8; 32],
) -> Result<Option<StoredFinalizedHeader>> {
    read_finalized_header_query(
        connection,
        "WHERE chain_id = ?1 AND network = ?2 AND proof_bundle_hash = ?3",
        rusqlite::params![chain_id.to_string(), network, proof_bundle_hash.as_slice()],
    )
}

pub(crate) fn read_finalized_header_by_execution_hash(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    execution_block_hash: [u8; 32],
) -> Result<Option<StoredFinalizedHeader>> {
    read_finalized_header_query(
        connection,
        "WHERE chain_id = ?1 AND network = ?2 AND execution_block_hash = ?3",
        rusqlite::params![
            chain_id.to_string(),
            network,
            execution_block_hash.as_slice()
        ],
    )
}

fn read_finalized_header_at_slot(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    finalized_slot: u64,
) -> Result<Option<StoredFinalizedHeader>> {
    read_finalized_header_query(
        connection,
        "WHERE chain_id = ?1 AND network = ?2 AND finalized_slot = ?3",
        rusqlite::params![chain_id.to_string(), network, finalized_slot.to_string()],
    )
}

fn read_finalized_header_query<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    where_clause: &str,
    params: P,
) -> Result<Option<StoredFinalizedHeader>> {
    let sql = format!(
        "SELECT chain_id, network, finalized_slot, execution_block_number,
                execution_block_hash, state_root, receipts_root,
                beacon_transactions_root, checkpoint_root, provenance,
                proof_bundle_hash, canonical_bundle, record_digest
         FROM eth_verified_finalized_headers {where_clause}"
    );
    let row = connection
        .query_row(&sql, params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
            ))
        })
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    validate_finalized_header(row).map(Some)
}

type FinalizedHeaderRow = (
    String,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn validate_finalized_header(row: FinalizedHeaderRow) -> Result<StoredFinalizedHeader> {
    let stored = StoredFinalizedHeader {
        chain_id: parse_stored_u64(&row.0, "finalized header chain id")?,
        network: row.1,
        finalized_slot: parse_stored_u64(&row.2, "finalized slot")?,
        execution_block_number: parse_stored_u64(&row.3, "execution block number")?,
        execution_block_hash: stored_array(&row.4, "execution block hash")?,
        state_root: stored_array(&row.5, "state root")?,
        receipts_root: stored_array(&row.6, "receipts root")?,
        beacon_transactions_root: stored_array(&row.7, "Beacon transactions root")?,
        checkpoint_root: stored_array(&row.8, "checkpoint root")?,
        provenance: provenance_from_i64(row.9)?,
        proof_bundle_hash: stored_array(&row.10, "consensus bundle hash")?,
        canonical_bundle: row.11,
    };
    validate_canonical_bundle(
        &stored.canonical_bundle,
        stored.proof_bundle_hash,
        "consensus bootstrap",
    )?;
    if stored_array::<32>(&row.12, "finalized header record digest")?
        != finalized_header_digest(&stored)
    {
        return Err(NodeStoreError::new(
            "stored finalized header digest does not match its values",
        ));
    }
    Ok(stored)
}

pub(crate) fn read_execution_block(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    block_hash: [u8; 32],
) -> Result<Option<StoredExecutionBlock>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, execution_block_number, execution_block_hash,
                    state_root, receipts_root, transactions_root, checkpoint_root,
                    provenance, consensus_bundle_hash, proof_bundle_hash,
                    canonical_bundle, record_digest
             FROM eth_verified_execution_blocks
             WHERE chain_id = ?1 AND network = ?2 AND execution_block_hash = ?3",
            rusqlite::params![chain_id.to_string(), network, block_hash.as_slice()],
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
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    validate_execution_block(row).map(Some)
}

type ExecutionBlockRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn validate_execution_block(row: ExecutionBlockRow) -> Result<StoredExecutionBlock> {
    let stored = StoredExecutionBlock {
        chain_id: parse_stored_u64(&row.0, "execution block chain id")?,
        network: row.1,
        execution_block_number: parse_stored_u64(&row.2, "execution block number")?,
        execution_block_hash: stored_array(&row.3, "execution block hash")?,
        state_root: stored_array(&row.4, "state root")?,
        receipts_root: stored_array(&row.5, "receipts root")?,
        transactions_root: stored_array(&row.6, "transactions root")?,
        checkpoint_root: stored_array(&row.7, "checkpoint root")?,
        provenance: provenance_from_i64(row.8)?,
        consensus_bundle_hash: stored_array(&row.9, "consensus bundle hash")?,
        proof_bundle_hash: stored_array(&row.10, "execution header proof hash")?,
        canonical_bundle: row.11,
    };
    validate_canonical_bundle(
        &stored.canonical_bundle,
        stored.proof_bundle_hash,
        "execution header",
    )?;
    if stored_array::<32>(&row.12, "execution block record digest")?
        != execution_block_digest(&stored)
    {
        return Err(NodeStoreError::new(
            "stored execution block digest does not match its values",
        ));
    }
    Ok(stored)
}

pub(crate) fn provenance_i64(provenance: ExecutionHeaderProvenance) -> i64 {
    match provenance {
        ExecutionHeaderProvenance::CheckpointAnchor => 1,
        ExecutionHeaderProvenance::HeliosFinalityUpdate => 2,
    }
}

pub(crate) fn provenance_from_i64(value: i64) -> Result<ExecutionHeaderProvenance> {
    match value {
        1 => Ok(ExecutionHeaderProvenance::CheckpointAnchor),
        2 => Ok(ExecutionHeaderProvenance::HeliosFinalityUpdate),
        _ => Err(NodeStoreError::new(
            "invalid stored execution header provenance",
        )),
    }
}

fn finalized_subject_key(header: &StoredFinalizedHeader) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-finalized-header-subject-v1");
    hasher.update(header.chain_id.to_le_bytes());
    update_string(&mut hasher, &header.network);
    hasher.update(header.finalized_slot.to_le_bytes());
    hasher.finalize().into()
}

fn finalized_header_digest(header: &StoredFinalizedHeader) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-finalized-header-record-v1");
    hasher.update(finalized_subject_key(header));
    hasher.update(header.execution_block_number.to_le_bytes());
    hasher.update(header.execution_block_hash);
    hasher.update(header.state_root);
    hasher.update(header.receipts_root);
    hasher.update(header.beacon_transactions_root);
    hasher.update(header.checkpoint_root);
    hasher.update(provenance_i64(header.provenance).to_le_bytes());
    hasher.update(header.proof_bundle_hash);
    hasher.finalize().into()
}

fn execution_subject_key(block: &StoredExecutionBlock) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-execution-block-subject-v1");
    hasher.update(block.chain_id.to_le_bytes());
    update_string(&mut hasher, &block.network);
    hasher.update(block.execution_block_hash);
    hasher.finalize().into()
}

fn execution_block_digest(block: &StoredExecutionBlock) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-execution-block-record-v1");
    hasher.update(execution_subject_key(block));
    hasher.update(block.execution_block_number.to_le_bytes());
    hasher.update(block.state_root);
    hasher.update(block.receipts_root);
    hasher.update(block.transactions_root);
    hasher.update(block.checkpoint_root);
    hasher.update(provenance_i64(block.provenance).to_le_bytes());
    hasher.update(block.consensus_bundle_hash);
    hasher.update(block.proof_bundle_hash);
    hasher.finalize().into()
}

fn latest_pointer_digest(chain_id: u64, network: &str, slot: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-latest-finalized-pointer-v1");
    hasher.update(chain_id.to_le_bytes());
    update_string(&mut hasher, network);
    hasher.update(slot.to_le_bytes());
    hasher.finalize().into()
}

fn update_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u16).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn immutable_conflict(error: rusqlite::Error, subject: &'static str) -> NodeStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        NodeStoreError::new(format!(
            "{subject} conflicts with an immutable verified subject"
        ))
    } else {
        NodeStoreError::sqlite(error)
    }
}

#[cfg(test)]
pub(crate) fn install_test_execution_evidence(
    store: &mut EthereumNodeStore,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
) -> StoredExecutionBlock {
    install_test_execution_evidence_with_policy(
        store,
        execution_block_number,
        execution_block_hash,
        state_root,
        receipts_root,
        transactions_root,
        None,
    )
}

#[cfg(test)]
pub(crate) fn install_test_active_execution_evidence(
    store: &mut EthereumNodeStore,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
    now_unix: u64,
) -> StoredExecutionBlock {
    install_test_execution_evidence_with_policy(
        store,
        execution_block_number,
        execution_block_hash,
        state_root,
        receipts_root,
        transactions_root,
        Some(now_unix),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn install_test_execution_evidence_with_policy(
    store: &mut EthereumNodeStore,
    execution_block_number: u64,
    execution_block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    transactions_root: [u8; 32],
    active_at_unix: Option<u64>,
) -> StoredExecutionBlock {
    let checkpoint_root = store
        .latest_checkpoint_approval()
        .unwrap()
        .map_or([0xed; 32], |approval| approval.checkpoint_root());
    if let Some(now_unix) = active_at_unix {
        crate::bootstrap::install_test_active_checkpoint(store, checkpoint_root, now_unix);
    } else if store
        .checkpoint_approval(ratspeak_eth_verifier::SEPOLIA_CHAIN_ID, checkpoint_root)
        .unwrap()
        .is_none()
    {
        let approval = crate::CheckpointApproval::sepolia(
            checkpoint_root,
            crate::CheckpointApprovalBasis::ExplicitUserApproval,
            1_780_000_000,
            Vec::new(),
        );
        let _ = store.record_checkpoint_approval(&approval).unwrap();
    }
    let mut consensus_bundle = b"test consensus evidence:".to_vec();
    consensus_bundle.extend_from_slice(&execution_block_hash);
    let derived_slot =
        ratspeak_eth_verifier::sepolia_slot_at_unix(active_at_unix.unwrap_or(1_780_000_000))
            .unwrap();
    let finalized_slot =
        read_latest_finalized_header(&store.connection, ratspeak_eth_verifier::SEPOLIA_CHAIN_ID)
            .unwrap()
            .map_or(derived_slot, |latest| {
                derived_slot.max(latest.finalized_slot().saturating_add(1))
            });
    let header = FinalizedHeaderValues {
        chain_id: ratspeak_eth_verifier::SEPOLIA_CHAIN_ID,
        network: ratspeak_eth_verifier::SEPOLIA_NETWORK.to_owned(),
        finalized_slot,
        execution_block_number,
        execution_block_hash,
        state_root,
        receipts_root,
        beacon_transactions_root: [0xee; 32],
        checkpoint_root,
        provenance: ExecutionHeaderProvenance::CheckpointAnchor,
        proof_bundle_hash: Sha256::digest(&consensus_bundle).into(),
        canonical_bundle: consensus_bundle,
    };
    let _ = store
        .record_finalized_header_values(header.clone())
        .unwrap();
    let mut execution_bundle = b"test execution evidence:".to_vec();
    execution_bundle.extend_from_slice(&execution_block_hash);
    let block = ExecutionBlockValues {
        chain_id: header.chain_id,
        network: header.network,
        execution_block_number,
        execution_block_hash,
        state_root,
        receipts_root,
        transactions_root,
        checkpoint_root,
        provenance: header.provenance,
        consensus_bundle_hash: header.proof_bundle_hash,
        proof_bundle_hash: Sha256::digest(&execution_bundle).into(),
        canonical_bundle: execution_bundle,
    };
    let stored = block.as_stored();
    let _ = store.record_execution_block_values(block).unwrap();
    stored
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::{
        CheckpointApproval, CheckpointApprovalBasis, CheckpointSourceAttestation,
        CheckpointSourceKind,
    };
    use ratspeak_eth_verifier::{SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};

    fn approved_store() -> (tempfile::TempDir, EthereumNodeStore, [u8; 32]) {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let checkpoint_root = [0x11; 32];
        let approval = CheckpointApproval::sepolia(
            checkpoint_root,
            CheckpointApprovalBasis::ProviderAgreement,
            1_780_000_000,
            vec![CheckpointSourceAttestation::new(
                CheckpointSourceKind::BeaconApi,
                [0x12; 32],
                [0x13; 32],
                1_779_999_900,
            )],
        );
        store.record_checkpoint_approval(&approval).unwrap();
        (profile, store, checkpoint_root)
    }

    fn finalized_values(checkpoint_root: [u8; 32], canonical: &[u8]) -> FinalizedHeaderValues {
        FinalizedHeaderValues {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            finalized_slot: 100,
            execution_block_number: 200,
            execution_block_hash: [0x21; 32],
            state_root: [0x22; 32],
            receipts_root: [0x23; 32],
            beacon_transactions_root: [0x24; 32],
            checkpoint_root,
            provenance: ExecutionHeaderProvenance::CheckpointAnchor,
            proof_bundle_hash: Sha256::digest(canonical).into(),
            canonical_bundle: canonical.to_vec(),
        }
    }

    fn execution_values(header: &FinalizedHeaderValues, canonical: &[u8]) -> ExecutionBlockValues {
        ExecutionBlockValues {
            chain_id: header.chain_id,
            network: header.network.clone(),
            execution_block_number: header.execution_block_number,
            execution_block_hash: header.execution_block_hash,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            transactions_root: [0x31; 32],
            checkpoint_root: header.checkpoint_root,
            provenance: header.provenance,
            consensus_bundle_hash: header.proof_bundle_hash,
            proof_bundle_hash: Sha256::digest(canonical).into(),
            canonical_bundle: canonical.to_vec(),
        }
    }

    fn shifted_header(
        header: &FinalizedHeaderValues,
        slot_delta: i64,
        block_delta: i64,
        block_hash: [u8; 32],
        canonical_bundle: Vec<u8>,
    ) -> FinalizedHeaderValues {
        let finalized_slot = if slot_delta >= 0 {
            header.finalized_slot + slot_delta as u64
        } else {
            header.finalized_slot - (-slot_delta) as u64
        };
        let execution_block_number = if block_delta >= 0 {
            header.execution_block_number + block_delta as u64
        } else {
            header.execution_block_number - (-block_delta) as u64
        };
        FinalizedHeaderValues {
            chain_id: header.chain_id,
            network: header.network.clone(),
            finalized_slot,
            execution_block_number,
            execution_block_hash: block_hash,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            beacon_transactions_root: header.beacon_transactions_root,
            checkpoint_root: header.checkpoint_root,
            provenance: header.provenance,
            proof_bundle_hash: Sha256::digest(&canonical_bundle).into(),
            canonical_bundle,
        }
    }

    #[test]
    fn persists_canonical_consensus_and_execution_evidence_across_reopen() {
        let (profile, mut store, root) = approved_store();
        let header = finalized_values(root, b"canonical consensus evidence");
        let block = execution_values(&header, b"canonical execution header evidence");
        assert_eq!(
            store
                .record_finalized_header_values(header.clone())
                .unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store
                .record_finalized_header_values(header.clone())
                .unwrap(),
            RecordOutcome::Replay
        );
        assert_eq!(
            store.record_execution_block_values(block.clone()).unwrap(),
            RecordOutcome::Inserted
        );
        assert_eq!(
            store.record_execution_block_values(block.clone()).unwrap(),
            RecordOutcome::Replay
        );
        drop(store);

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let latest = store
            .latest_finalized_header(SEPOLIA_CHAIN_ID)
            .unwrap()
            .unwrap();
        assert_eq!(latest.finalized_slot(), 100);
        assert_eq!(latest.canonical_bundle(), header.canonical_bundle);
        let stored_block = store
            .execution_block(SEPOLIA_CHAIN_ID, block.execution_block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored_block.transactions_root(), [0x31; 32]);
        assert_eq!(stored_block.canonical_bundle(), block.canonical_bundle);
        assert!(
            store
                .replay_record(
                    SEPOLIA_CHAIN_ID,
                    EvidenceKind::ConsensusBootstrap,
                    header.proof_bundle_hash,
                )
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .replay_record(
                    SEPOLIA_CHAIN_ID,
                    EvidenceKind::ExecutionHeader,
                    block.proof_bundle_hash,
                )
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rejects_unapproved_checkpoint_and_mismatched_canonical_hash() {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let header = finalized_values([0x41; 32], b"consensus evidence");
        assert!(
            store
                .record_finalized_header_values(header.clone())
                .unwrap_err()
                .to_string()
                .contains("unapproved checkpoint")
        );

        let approval = CheckpointApproval::sepolia(
            [0x41; 32],
            CheckpointApprovalBasis::ExplicitUserApproval,
            1_780_000_000,
            Vec::new(),
        );
        store.record_checkpoint_approval(&approval).unwrap();
        let mut bad_hash = header;
        bad_hash.proof_bundle_hash = [0x42; 32];
        assert!(
            store
                .record_finalized_header_values(bad_hash)
                .unwrap_err()
                .to_string()
                .contains("evidence hash does not match")
        );
        assert!(
            store
                .latest_finalized_header(SEPOLIA_CHAIN_ID)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_finalized_rollback_without_partial_replay_state() {
        let (_profile, mut store, root) = approved_store();
        let header = finalized_values(root, b"current consensus");
        store
            .record_finalized_header_values(header.clone())
            .unwrap();
        let rollback = shifted_header(&header, -1, -1, [0x51; 32], b"rollback consensus".to_vec());
        assert!(
            store
                .record_finalized_header_values(rollback.clone())
                .unwrap_err()
                .to_string()
                .contains("roll back finalized state")
        );
        assert!(
            store
                .replay_record(
                    SEPOLIA_CHAIN_ID,
                    EvidenceKind::ConsensusBootstrap,
                    rollback.proof_bundle_hash,
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .latest_finalized_header(SEPOLIA_CHAIN_ID)
                .unwrap()
                .unwrap()
                .finalized_slot(),
            header.finalized_slot
        );
    }

    #[test]
    fn rejects_conflicting_finalized_subject_and_execution_link() {
        let (_profile, mut store, root) = approved_store();
        let header = finalized_values(root, b"consensus subject");
        let block = execution_values(&header, b"execution subject");
        assert!(
            store
                .record_execution_block_values(block.clone())
                .unwrap_err()
                .to_string()
                .contains("no persisted consensus evidence")
        );
        store
            .record_finalized_header_values(header.clone())
            .unwrap();

        let conflicting = shifted_header(
            &header,
            0,
            1,
            [0x61; 32],
            b"conflicting consensus subject".to_vec(),
        );
        assert!(
            store
                .record_finalized_header_values(conflicting)
                .unwrap_err()
                .to_string()
                .contains("immutable verified state")
        );

        let mut bad_block = block;
        bad_block.receipts_root = [0x62; 32];
        assert!(
            store
                .record_execution_block_values(bad_block)
                .unwrap_err()
                .to_string()
                .contains("persisted consensus commitments")
        );
    }

    #[test]
    fn concurrent_consensus_record_is_exactly_once() {
        let (profile, store, root) = approved_store();
        drop(store);
        let first_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let second_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let values = finalized_values(root, b"concurrent consensus");
        let barrier = Arc::new(Barrier::new(2));
        let run =
            |mut store: EthereumNodeStore, values: FinalizedHeaderValues, barrier: Arc<Barrier>| {
                std::thread::spawn(move || {
                    barrier.wait();
                    store.record_finalized_header_values(values)
                })
            };
        let first = run(first_store, values.clone(), Arc::clone(&barrier));
        let second = run(second_store, values, Arc::clone(&barrier));
        let outcomes = [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RecordOutcome::Inserted)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RecordOutcome::Replay)
                .count(),
            1
        );
    }

    #[test]
    fn fails_closed_on_corrupted_canonical_consensus_bytes() {
        let (_profile, mut store, root) = approved_store();
        let header = finalized_values(root, b"uncorrupted consensus");
        store.record_finalized_header_values(header).unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_verified_finalized_headers SET canonical_bundle = x'00'",
                [],
            )
            .unwrap();
        assert!(
            store
                .latest_finalized_header(SEPOLIA_CHAIN_ID)
                .unwrap_err()
                .to_string()
                .contains("evidence hash does not match")
        );
    }
}
