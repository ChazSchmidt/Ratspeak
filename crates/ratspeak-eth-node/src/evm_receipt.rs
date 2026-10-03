use ratspeak_eth_verifier::{AnchorAssurance, VerifiedEvmTxReceipt, chain_definition};
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::evidence::{EvidenceKind, record_replay, validate_canonical_bundle};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvmReceiptRecord {
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
    assurance: AnchorAssurance,
    anchor_evidence_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
    canonical_bundle: Vec<u8>,
}

impl StoredEvmReceiptRecord {
    pub fn chain_id(&self) -> u64 { self.chain_id }
    pub fn network(&self) -> &str { &self.network }
    pub fn block_number(&self) -> u64 { self.block_number }
    pub fn block_hash(&self) -> [u8; 32] { self.block_hash }
    pub fn tx_hash(&self) -> [u8; 32] { self.tx_hash }
    pub fn tx_index(&self) -> u64 { self.tx_index }
    pub fn succeeded(&self) -> bool { self.succeeded }
    pub fn cumulative_gas_used(&self) -> u64 { self.cumulative_gas_used }
    pub fn logs_count(&self) -> u64 { self.logs_count }
    pub fn verified_at_unix(&self) -> u64 { self.verified_at_unix }
    pub fn assurance(&self) -> AnchorAssurance { self.assurance }
    pub fn anchor_evidence_hash(&self) -> [u8; 32] { self.anchor_evidence_hash }
    pub fn proof_bundle_hash(&self) -> [u8; 32] { self.proof_bundle_hash }
    pub fn canonical_bundle(&self) -> &[u8] { &self.canonical_bundle }
}

impl EthereumNodeStore {
    pub fn record_verified_evm_receipt(
        &mut self,
        receipt: &VerifiedEvmTxReceipt,
        canonical_bundle: &[u8],
        verified_at_unix: u64,
    ) -> Result<(RecordOutcome, StoredEvmReceiptRecord)> {
        let definition = chain_definition(receipt.chain_id()).ok_or_else(|| {
            NodeStoreError::new(format!("unsupported Ethereum chain {}", receipt.chain_id()))
        })?;
        if definition.network != receipt.network() || verified_at_unix == 0 {
            return Err(NodeStoreError::new(
                "verified EVM receipt uses an unsupported network or verification time",
            ));
        }
        validate_canonical_bundle(
            canonical_bundle,
            receipt.proof_bundle_hash(),
            "generic EVM receipt proof",
        )?;

        let stored = StoredEvmReceiptRecord {
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
            assurance: receipt.assurance(),
            anchor_evidence_hash: receipt.anchor_evidence_hash(),
            proof_bundle_hash: receipt.proof_bundle_hash(),
            canonical_bundle: canonical_bundle.to_vec(),
        };

        let digest = receipt_digest(&stored);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let changed = transaction
            .execute(
                "INSERT INTO eth_verified_evm_receipts (
                    chain_id, network, block_number, block_hash, tx_hash, tx_index,
                    succeeded, cumulative_gas_used, logs_count, verified_at_unix,
                    assurance, anchor_evidence_hash, proof_bundle_hash,
                    canonical_bundle, record_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                 ON CONFLICT(chain_id, network, tx_hash) DO NOTHING",
                rusqlite::params![
                    stored.chain_id.to_string(),
                    stored.network,
                    stored.block_number.to_string(),
                    stored.block_hash.as_slice(),
                    stored.tx_hash.as_slice(),
                    stored.tx_index.to_string(),
                    if stored.succeeded { 1_i64 } else { 0_i64 },
                    stored.cumulative_gas_used.to_string(),
                    stored.logs_count.to_string(),
                    stored.verified_at_unix.to_string(),
                    assurance_i64(stored.assurance),
                    stored.anchor_evidence_hash.as_slice(),
                    stored.proof_bundle_hash.as_slice(),
                    stored.canonical_bundle,
                    digest.as_slice(),
                ],
            )
            .map_err(NodeStoreError::sqlite)?;

        if changed == 0 {
            let existing = read_evm_receipt_by_tx_hash(
                &transaction,
                stored.chain_id,
                &stored.network,
                stored.tx_hash,
            )?
            .ok_or_else(|| NodeStoreError::new("EVM receipt replay has no stored row"))?;
            if existing != stored {
                return Err(NodeStoreError::new(
                    "verified EVM receipt conflicts with immutable stored evidence",
                ));
            }
        }

        let replay = record_replay(
            &transaction,
            stored.chain_id,
            &stored.network,
            EvidenceKind::ReceiptProof,
            stored.proof_bundle_hash,
            stored.tx_hash,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;

        let outcome = if changed == 1 || replay == RecordOutcome::Inserted {
            RecordOutcome::Inserted
        } else {
            RecordOutcome::Replay
        };
        Ok((outcome, stored))
    }

    pub fn verified_evm_receipt(
        &self,
        chain_id: u64,
        tx_hash: [u8; 32],
    ) -> Result<Option<StoredEvmReceiptRecord>> {
        let definition = chain_definition(chain_id).ok_or_else(|| {
            NodeStoreError::new(format!("unsupported Ethereum chain {chain_id}"))
        })?;
        read_evm_receipt_by_tx_hash(
            &self.connection,
            chain_id,
            definition.network,
            tx_hash,
        )
    }
}

pub(crate) fn read_evm_receipt_by_tx_hash(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    tx_hash: [u8; 32],
) -> Result<Option<StoredEvmReceiptRecord>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, block_number, block_hash, tx_hash, tx_index,
                    succeeded, cumulative_gas_used, logs_count, verified_at_unix,
                    assurance, anchor_evidence_hash, proof_bundle_hash,
                    canonical_bundle, record_digest
             FROM eth_verified_evm_receipts
             WHERE chain_id = ?1 AND network = ?2 AND tx_hash = ?3",
            rusqlite::params![chain_id.to_string(), network, tx_hash.as_slice()],
            |row| {
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
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

    let stored = StoredEvmReceiptRecord {
        chain_id: parse_stored_u64(&row.0, "EVM receipt chain id")?,
        network: row.1,
        block_number: parse_stored_u64(&row.2, "EVM receipt block number")?,
        block_hash: stored_array(&row.3, "EVM receipt block hash")?,
        tx_hash: stored_array(&row.4, "EVM receipt transaction hash")?,
        tx_index: parse_stored_u64(&row.5, "EVM receipt transaction index")?,
        succeeded: match row.6 {
            0 => false,
            1 => true,
            _ => return Err(NodeStoreError::new("invalid EVM receipt success value")),
        },
        cumulative_gas_used: parse_stored_u64(&row.7, "EVM receipt cumulative gas")?,
        logs_count: parse_stored_u64(&row.8, "EVM receipt logs count")?,
        verified_at_unix: parse_stored_u64(&row.9, "EVM receipt verification time")?,
        assurance: assurance_from_i64(row.10)?,
        anchor_evidence_hash: stored_array(&row.11, "EVM receipt anchor evidence hash")?,
        proof_bundle_hash: stored_array(&row.12, "EVM receipt proof hash")?,
        canonical_bundle: row.13,
    };

    let definition = chain_definition(stored.chain_id)
        .ok_or_else(|| NodeStoreError::new("stored EVM receipt uses unsupported chain"))?;
    if definition.network != stored.network
        || stored.tx_hash != tx_hash
        || stored.verified_at_unix == 0
        || stored_array::<32>(&row.14, "EVM receipt record digest")? != receipt_digest(&stored)
    {
        return Err(NodeStoreError::new(
            "stored EVM receipt digest does not match its values",
        ));
    }

    validate_canonical_bundle(
        &stored.canonical_bundle,
        stored.proof_bundle_hash,
        "stored generic EVM receipt proof",
    )?;
    Ok(Some(stored))
}

fn assurance_i64(assurance: AnchorAssurance) -> i64 {
    match assurance {
        AnchorAssurance::EthereumFinalized => 1,
        AnchorAssurance::SequencerAuthenticated => 2,
        AnchorAssurance::RollupConfirmed => 3,
    }
}

fn assurance_from_i64(value: i64) -> Result<AnchorAssurance> {
    match value {
        1 => Ok(AnchorAssurance::EthereumFinalized),
        2 => Ok(AnchorAssurance::SequencerAuthenticated),
        3 => Ok(AnchorAssurance::RollupConfirmed),
        _ => Err(NodeStoreError::new("invalid stored EVM receipt assurance")),
    }
}

fn receipt_digest(receipt: &StoredEvmReceiptRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-verified-evm-receipt-v1");
    hasher.update(receipt.chain_id.to_le_bytes());
    hasher.update((receipt.network.len() as u16).to_le_bytes());
    hasher.update(receipt.network.as_bytes());
    hasher.update(receipt.block_number.to_le_bytes());
    hasher.update(receipt.block_hash);
    hasher.update(receipt.tx_hash);
    hasher.update(receipt.tx_index.to_le_bytes());
    hasher.update([u8::from(receipt.succeeded)]);
    hasher.update(receipt.cumulative_gas_used.to_le_bytes());
    hasher.update(receipt.logs_count.to_le_bytes());
    hasher.update(receipt.verified_at_unix.to_le_bytes());
    hasher.update(assurance_i64(receipt.assurance).to_le_bytes());
    hasher.update(receipt.anchor_evidence_hash);
    hasher.update(receipt.proof_bundle_hash);
    hasher.finalize().into()
}
