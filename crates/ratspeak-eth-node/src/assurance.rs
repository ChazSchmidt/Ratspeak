use ratspeak_eth_verifier::SEPOLIA_NETWORK;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::checkpoint::{ensure_supported_network, read_checkpoint};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceSubjectKind {
    Checkpoint,
    Transaction,
}

impl AssuranceSubjectKind {
    fn as_i64(self) -> i64 {
        match self {
            Self::Checkpoint => 1,
            Self::Transaction => 2,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Checkpoint),
            2 => Ok(Self::Transaction),
            _ => Err(NodeStoreError::new("invalid stored assurance subject kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceEventKind {
    CheckpointApproved,
    CheckpointSourceAttested,
    CheckpointRevoked,
    LocalSignatureRecorded,
    TransportDelivered,
    GatewayAcknowledged,
    RpcAccepted,
    FinalizedReceiptSucceeded,
    FinalizedReceiptFailed,
}

impl AssuranceEventKind {
    fn as_i64(self) -> i64 {
        match self {
            Self::CheckpointApproved => 1,
            Self::CheckpointSourceAttested => 2,
            Self::CheckpointRevoked => 3,
            Self::LocalSignatureRecorded => 4,
            Self::TransportDelivered => 5,
            Self::GatewayAcknowledged => 6,
            Self::RpcAccepted => 7,
            Self::FinalizedReceiptSucceeded => 8,
            Self::FinalizedReceiptFailed => 9,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::CheckpointApproved),
            2 => Ok(Self::CheckpointSourceAttested),
            3 => Ok(Self::CheckpointRevoked),
            4 => Ok(Self::LocalSignatureRecorded),
            5 => Ok(Self::TransportDelivered),
            6 => Ok(Self::GatewayAcknowledged),
            7 => Ok(Self::RpcAccepted),
            8 => Ok(Self::FinalizedReceiptSucceeded),
            9 => Ok(Self::FinalizedReceiptFailed),
            _ => Err(NodeStoreError::new("invalid stored assurance event kind")),
        }
    }
}

/// Events that can be stored as observations but never as Ethereum confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonAuthoritativeTransactionObservation {
    TransportDelivered,
    GatewayAcknowledged,
    RpcAccepted,
}

impl From<NonAuthoritativeTransactionObservation> for AssuranceEventKind {
    fn from(value: NonAuthoritativeTransactionObservation) -> Self {
        match value {
            NonAuthoritativeTransactionObservation::TransportDelivered => Self::TransportDelivered,
            NonAuthoritativeTransactionObservation::GatewayAcknowledged => {
                Self::GatewayAcknowledged
            }
            NonAuthoritativeTransactionObservation::RpcAccepted => Self::RpcAccepted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAssuranceEvent {
    chain_id: u64,
    network: String,
    subject_kind: AssuranceSubjectKind,
    subject_key: [u8; 32],
    event_kind: AssuranceEventKind,
    evidence_hash: [u8; 32],
    observed_at_unix: u64,
}

pub(crate) struct AssuranceEventInput<'a> {
    pub(crate) chain_id: u64,
    pub(crate) network: &'a str,
    pub(crate) subject_kind: AssuranceSubjectKind,
    pub(crate) subject_key: [u8; 32],
    pub(crate) event_kind: AssuranceEventKind,
    pub(crate) evidence_hash: [u8; 32],
    pub(crate) observed_at_unix: u64,
}

impl StoredAssuranceEvent {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn subject_kind(&self) -> AssuranceSubjectKind {
        self.subject_kind
    }

    pub fn subject_key(&self) -> [u8; 32] {
        self.subject_key
    }

    pub fn event_kind(&self) -> AssuranceEventKind {
        self.event_kind
    }

    pub fn evidence_hash(&self) -> [u8; 32] {
        self.evidence_hash
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }
}

impl EthereumNodeStore {
    /// Appends a revocation observation without deleting historical approval evidence.
    ///
    /// The bootstrap policy treats this durable event as immediately
    /// disqualifying the checkpoint from current use.
    pub fn record_checkpoint_revocation(
        &mut self,
        chain_id: u64,
        checkpoint_root: [u8; 32],
        revocation_evidence_hash: [u8; 32],
        observed_at_unix: u64,
    ) -> Result<RecordOutcome> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        if revocation_evidence_hash == [0; 32] || observed_at_unix == 0 {
            return Err(NodeStoreError::new(
                "checkpoint revocation is missing public evidence",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        if read_checkpoint(&transaction, chain_id, checkpoint_root)?.is_none() {
            return Err(NodeStoreError::new(
                "checkpoint revocation has no approved checkpoint record",
            ));
        }
        let outcome = record_assurance(
            &transaction,
            AssuranceEventInput {
                chain_id,
                network: SEPOLIA_NETWORK,
                subject_kind: AssuranceSubjectKind::Checkpoint,
                subject_key: checkpoint_root,
                event_kind: AssuranceEventKind::CheckpointRevoked,
                evidence_hash: revocation_evidence_hash,
                observed_at_unix,
            },
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    /// Records a non-authoritative delivery or relay observation for a local transaction.
    pub fn record_non_authoritative_transaction_observation(
        &mut self,
        chain_id: u64,
        tx_hash: [u8; 32],
        observation: NonAuthoritativeTransactionObservation,
        evidence_hash: [u8; 32],
        observed_at_unix: u64,
    ) -> Result<RecordOutcome> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        if evidence_hash == [0; 32] || observed_at_unix == 0 {
            return Err(NodeStoreError::new(
                "transaction observation is missing public evidence",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        if crate::transaction::read_signed_transaction(
            &transaction,
            chain_id,
            SEPOLIA_NETWORK,
            tx_hash,
        )?
        .is_none()
        {
            return Err(NodeStoreError::new(
                "transaction observation has no locally signed transaction",
            ));
        }
        let outcome = record_assurance(
            &transaction,
            AssuranceEventInput {
                chain_id,
                network: SEPOLIA_NETWORK,
                subject_kind: AssuranceSubjectKind::Transaction,
                subject_key: tx_hash,
                event_kind: observation.into(),
                evidence_hash,
                observed_at_unix,
            },
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn checkpoint_assurance_history(
        &self,
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> Result<Vec<StoredAssuranceEvent>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_assurance_history(
            &self.connection,
            chain_id,
            SEPOLIA_NETWORK,
            AssuranceSubjectKind::Checkpoint,
            checkpoint_root,
        )
    }

    pub fn transaction_assurance_history(
        &self,
        chain_id: u64,
        tx_hash: [u8; 32],
    ) -> Result<Vec<StoredAssuranceEvent>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_assurance_history(
            &self.connection,
            chain_id,
            SEPOLIA_NETWORK,
            AssuranceSubjectKind::Transaction,
            tx_hash,
        )
    }
}

pub(crate) fn record_assurance(
    transaction: &Transaction<'_>,
    input: AssuranceEventInput<'_>,
) -> Result<RecordOutcome> {
    let event_key = assurance_event_key(
        input.chain_id,
        input.network,
        input.subject_kind,
        input.subject_key,
        input.event_kind,
        input.evidence_hash,
        input.observed_at_unix,
    );
    let record_digest = assurance_record_digest(event_key);
    let changed = transaction
        .execute(
            "INSERT INTO eth_assurance_history (
                event_key, chain_id, network, subject_kind, subject_key,
                event_kind, evidence_hash, observed_at_unix, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(event_key) DO NOTHING",
            rusqlite::params![
                event_key.as_slice(),
                input.chain_id.to_string(),
                input.network,
                input.subject_kind.as_i64(),
                input.subject_key.as_slice(),
                input.event_kind.as_i64(),
                input.evidence_hash.as_slice(),
                input.observed_at_unix.to_string(),
                record_digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed == 1 {
        return Ok(RecordOutcome::Inserted);
    }
    let stored = read_assurance_by_key(transaction, event_key)?
        .ok_or_else(|| NodeStoreError::new("assurance replay has no corresponding record"))?;
    if stored.chain_id != input.chain_id
        || stored.network != input.network
        || stored.subject_kind != input.subject_kind
        || stored.subject_key != input.subject_key
        || stored.event_kind != input.event_kind
        || stored.evidence_hash != input.evidence_hash
        || stored.observed_at_unix != input.observed_at_unix
    {
        return Err(NodeStoreError::new(
            "assurance event conflicts with an immutable history record",
        ));
    }
    Ok(RecordOutcome::Replay)
}

pub(crate) fn read_assurance_history(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    subject_kind: AssuranceSubjectKind,
    subject_key: [u8; 32],
) -> Result<Vec<StoredAssuranceEvent>> {
    let mut statement = connection
        .prepare(
            "SELECT event_key, chain_id, network, subject_kind, subject_key,
                    event_kind, evidence_hash, observed_at_unix, record_digest
             FROM eth_assurance_history
             WHERE chain_id = ?1 AND network = ?2
                AND subject_kind = ?3 AND subject_key = ?4",
        )
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map(
            rusqlite::params![
                chain_id.to_string(),
                network,
                subject_kind.as_i64(),
                subject_key.as_slice()
            ],
            read_assurance_row,
        )
        .map_err(NodeStoreError::sqlite)?;
    let mut history = Vec::new();
    for row in rows {
        history.push(validate_assurance_row(
            row.map_err(NodeStoreError::sqlite)?,
        )?);
    }
    history.sort_by_key(|event| (event.observed_at_unix, event.event_kind.as_i64()));
    Ok(history)
}

fn read_assurance_by_key(
    connection: &rusqlite::Connection,
    event_key: [u8; 32],
) -> Result<Option<StoredAssuranceEvent>> {
    let row = connection
        .query_row(
            "SELECT event_key, chain_id, network, subject_kind, subject_key,
                    event_kind, evidence_hash, observed_at_unix, record_digest
             FROM eth_assurance_history WHERE event_key = ?1",
            [event_key.as_slice()],
            read_assurance_row,
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    row.map(validate_assurance_row).transpose()
}

type AssuranceRow = (
    Vec<u8>,
    String,
    String,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    String,
    Vec<u8>,
);

fn read_assurance_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssuranceRow> {
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
    ))
}

fn validate_assurance_row(row: AssuranceRow) -> Result<StoredAssuranceEvent> {
    let event_key = stored_array::<32>(&row.0, "assurance event key")?;
    let stored = StoredAssuranceEvent {
        chain_id: parse_stored_u64(&row.1, "assurance chain id")?,
        network: row.2,
        subject_kind: AssuranceSubjectKind::from_i64(row.3)?,
        subject_key: stored_array(&row.4, "assurance subject key")?,
        event_kind: AssuranceEventKind::from_i64(row.5)?,
        evidence_hash: stored_array(&row.6, "assurance evidence hash")?,
        observed_at_unix: parse_stored_u64(&row.7, "assurance observation time")?,
    };
    if event_key
        != assurance_event_key(
            stored.chain_id,
            &stored.network,
            stored.subject_kind,
            stored.subject_key,
            stored.event_kind,
            stored.evidence_hash,
            stored.observed_at_unix,
        )
        || stored_array::<32>(&row.8, "assurance record digest")?
            != assurance_record_digest(event_key)
    {
        return Err(NodeStoreError::new(
            "stored assurance record digest does not match its values",
        ));
    }
    Ok(stored)
}

fn assurance_event_key(
    chain_id: u64,
    network: &str,
    subject_kind: AssuranceSubjectKind,
    subject_key: [u8; 32],
    event_kind: AssuranceEventKind,
    evidence_hash: [u8; 32],
    observed_at_unix: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-assurance-event-v1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update((network.len() as u16).to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.update(subject_kind.as_i64().to_le_bytes());
    hasher.update(subject_key);
    hasher.update(event_kind.as_i64().to_le_bytes());
    hasher.update(evidence_hash);
    hasher.update(observed_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn assurance_record_digest(event_key: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-assurance-record-v1");
    hasher.update(event_key);
    hasher.finalize().into()
}
