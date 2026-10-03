use rusqlite::{OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::checkpoint::ensure_supported_network;
use crate::{EthereumNodeStore, NodeStoreError, RecordOutcome, Result, stored_array};
use ratspeak_eth_verifier::{MAX_BUNDLE_BYTES, SEPOLIA_NETWORK};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    ConsensusBootstrap,
    ExecutionHeader,
    AccountProof,
    SignedTransaction,
    ReceiptProof,
}

impl EvidenceKind {
    pub(crate) fn as_i64(self) -> i64 {
        match self {
            Self::ConsensusBootstrap => 1,
            Self::ExecutionHeader => 2,
            Self::AccountProof => 3,
            Self::SignedTransaction => 4,
            Self::ReceiptProof => 5,
        }
    }

    pub(crate) fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::ConsensusBootstrap),
            2 => Ok(Self::ExecutionHeader),
            3 => Ok(Self::AccountProof),
            4 => Ok(Self::SignedTransaction),
            5 => Ok(Self::ReceiptProof),
            _ => Err(NodeStoreError::new("invalid stored evidence kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReplayRecord {
    chain_id: u64,
    network: String,
    evidence_kind: EvidenceKind,
    replay_key: [u8; 32],
    subject_key: [u8; 32],
}

impl StoredReplayRecord {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn evidence_kind(&self) -> EvidenceKind {
        self.evidence_kind
    }

    pub fn replay_key(&self) -> [u8; 32] {
        self.replay_key
    }

    pub fn subject_key(&self) -> [u8; 32] {
        self.subject_key
    }
}

impl EthereumNodeStore {
    pub fn replay_record(
        &self,
        chain_id: u64,
        evidence_kind: EvidenceKind,
        replay_key: [u8; 32],
    ) -> Result<Option<StoredReplayRecord>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_replay(
            &self.connection,
            chain_id,
            SEPOLIA_NETWORK,
            evidence_kind,
            replay_key,
        )
    }
}

pub(crate) fn record_replay(
    transaction: &Transaction<'_>,
    chain_id: u64,
    network: &str,
    evidence_kind: EvidenceKind,
    replay_key: [u8; 32],
    subject_key: [u8; 32],
) -> Result<RecordOutcome> {
    let digest = replay_digest(chain_id, network, evidence_kind, replay_key, subject_key);
    let changed = transaction
        .execute(
            "INSERT INTO eth_replay_records (
                chain_id, network, evidence_kind, replay_key, subject_key, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chain_id, network, evidence_kind, replay_key) DO NOTHING",
            rusqlite::params![
                chain_id.to_string(),
                network,
                evidence_kind.as_i64(),
                replay_key.as_slice(),
                subject_key.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed == 1 {
        return Ok(RecordOutcome::Inserted);
    }

    let stored = read_replay(transaction, chain_id, network, evidence_kind, replay_key)?
        .ok_or_else(|| NodeStoreError::new("replay conflict has no corresponding record"))?;
    if stored.subject_key != subject_key {
        return Err(NodeStoreError::new(
            "replay key conflicts with an immutable evidence subject",
        ));
    }
    Ok(RecordOutcome::Replay)
}

pub(crate) fn read_replay(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    evidence_kind: EvidenceKind,
    replay_key: [u8; 32],
) -> Result<Option<StoredReplayRecord>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, evidence_kind, replay_key, subject_key, record_digest
             FROM eth_replay_records
             WHERE chain_id = ?1 AND network = ?2 AND evidence_kind = ?3 AND replay_key = ?4",
            rusqlite::params![
                chain_id.to_string(),
                network,
                evidence_kind.as_i64(),
                replay_key.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((chain_id, network, kind, replay_key, subject_key, digest)) = row else {
        return Ok(None);
    };
    let stored = StoredReplayRecord {
        chain_id: chain_id
            .parse()
            .map_err(|_| NodeStoreError::new("invalid stored replay chain id"))?,
        network,
        evidence_kind: EvidenceKind::from_i64(kind)?,
        replay_key: stored_array(&replay_key, "replay key")?,
        subject_key: stored_array(&subject_key, "replay subject key")?,
    };
    if stored_array::<32>(&digest, "replay record digest")?
        != replay_digest(
            stored.chain_id,
            &stored.network,
            stored.evidence_kind,
            stored.replay_key,
            stored.subject_key,
        )
    {
        return Err(NodeStoreError::new(
            "stored replay record digest does not match its values",
        ));
    }
    Ok(Some(stored))
}

pub(crate) fn validate_canonical_bundle(
    canonical_bundle: &[u8],
    expected_hash: [u8; 32],
    evidence_name: &'static str,
) -> Result<()> {
    if canonical_bundle.is_empty() {
        return Err(NodeStoreError::new(format!(
            "canonical {evidence_name} evidence is empty"
        )));
    }
    if canonical_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(NodeStoreError::new(format!(
            "canonical {evidence_name} evidence exceeds the verifier limit"
        )));
    }
    let actual: [u8; 32] = Sha256::digest(canonical_bundle).into();
    if actual != expected_hash {
        return Err(NodeStoreError::new(format!(
            "canonical {evidence_name} evidence hash does not match the verified value"
        )));
    }
    Ok(())
}

fn replay_digest(
    chain_id: u64,
    network: &str,
    evidence_kind: EvidenceKind,
    replay_key: [u8; 32],
    subject_key: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-replay-record-v1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update((network.len() as u16).to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.update(evidence_kind.as_i64().to_le_bytes());
    hasher.update(replay_key);
    hasher.update(subject_key);
    hasher.finalize().into()
}
