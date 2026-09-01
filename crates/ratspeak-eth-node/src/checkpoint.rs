use std::collections::HashMap;

use ratspeak_eth_verifier::{SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{
    AssuranceEventInput, AssuranceEventKind, AssuranceSubjectKind, record_assurance,
};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

/// The already-evaluated basis recorded for a checkpoint approval.
///
/// The bootstrap policy evaluates observations before this decision is
/// constructed; the store only persists and revalidates the resulting record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointApprovalBasis {
    ProviderAgreement,
    ExplicitUserApproval,
}

impl CheckpointApprovalBasis {
    fn as_i64(self) -> i64 {
        match self {
            Self::ProviderAgreement => 1,
            Self::ExplicitUserApproval => 2,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::ProviderAgreement),
            2 => Ok(Self::ExplicitUserApproval),
            _ => Err(NodeStoreError::new(
                "invalid stored checkpoint approval basis",
            )),
        }
    }
}

/// Kind of public source whose observation contributed to a checkpoint decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointSourceKind {
    BeaconApi,
    AuthenticatedRatspeakIdentity,
    ExplicitUser,
    ManualUrl,
    ManualFile,
    ManualQr,
}

impl CheckpointSourceKind {
    fn as_i64(self) -> i64 {
        match self {
            Self::BeaconApi => 1,
            Self::AuthenticatedRatspeakIdentity => 2,
            Self::ExplicitUser => 3,
            Self::ManualUrl => 4,
            Self::ManualFile => 5,
            Self::ManualQr => 6,
        }
    }

    fn from_i64(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::BeaconApi),
            2 => Ok(Self::AuthenticatedRatspeakIdentity),
            3 => Ok(Self::ExplicitUser),
            4 => Ok(Self::ManualUrl),
            5 => Ok(Self::ManualFile),
            6 => Ok(Self::ManualQr),
            _ => Err(NodeStoreError::new("invalid stored checkpoint source kind")),
        }
    }
}

/// Secret-free provenance for one source observation.
///
/// Fingerprints identify the configured public source without retaining URLs,
/// headers, credentials, or response bodies. `observation_hash` identifies the
/// canonical public observation that the checkpoint manager evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSourceAttestation {
    source_kind: CheckpointSourceKind,
    source_fingerprint: [u8; 32],
    operator_fingerprint: [u8; 32],
    observation_hash: [u8; 32],
    observed_at_unix: u64,
}

impl CheckpointSourceAttestation {
    pub fn new(
        source_kind: CheckpointSourceKind,
        source_fingerprint: [u8; 32],
        observation_hash: [u8; 32],
        observed_at_unix: u64,
    ) -> Self {
        Self {
            source_kind,
            source_fingerprint,
            operator_fingerprint: source_fingerprint,
            observation_hash,
            observed_at_unix,
        }
    }

    pub(crate) fn with_operator(
        source_kind: CheckpointSourceKind,
        source_fingerprint: [u8; 32],
        operator_fingerprint: [u8; 32],
        observation_hash: [u8; 32],
        observed_at_unix: u64,
    ) -> Self {
        Self {
            source_kind,
            source_fingerprint,
            operator_fingerprint,
            observation_hash,
            observed_at_unix,
        }
    }

    pub fn source_kind(&self) -> CheckpointSourceKind {
        self.source_kind
    }

    pub fn source_fingerprint(&self) -> [u8; 32] {
        self.source_fingerprint
    }

    pub fn observation_hash(&self) -> [u8; 32] {
        self.observation_hash
    }

    pub fn operator_fingerprint(&self) -> [u8; 32] {
        self.operator_fingerprint
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }
}

/// A checkpoint approval decision supplied by this crate's bootstrap policy.
///
/// Construction stays crate-private. Public callers cannot turn an assertion
/// into installed checkpoint trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointApproval {
    chain_id: u64,
    network: String,
    checkpoint_root: [u8; 32],
    approval_basis: CheckpointApprovalBasis,
    approved_at_unix: u64,
    checkpoint_epoch: u64,
    valid_until_unix: u64,
    attestations: Vec<CheckpointSourceAttestation>,
}

pub(crate) struct CheckpointApprovalWindow {
    pub(crate) checkpoint_epoch: u64,
    pub(crate) valid_until_unix: u64,
}

impl CheckpointApproval {
    pub(crate) fn new(
        chain_id: u64,
        network: impl Into<String>,
        checkpoint_root: [u8; 32],
        approval_basis: CheckpointApprovalBasis,
        approved_at_unix: u64,
        window: CheckpointApprovalWindow,
        attestations: Vec<CheckpointSourceAttestation>,
    ) -> Self {
        Self {
            chain_id,
            network: network.into(),
            checkpoint_root,
            approval_basis,
            approved_at_unix,
            checkpoint_epoch: window.checkpoint_epoch,
            valid_until_unix: window.valid_until_unix,
            attestations,
        }
    }

    #[cfg(test)]
    pub(crate) fn sepolia(
        checkpoint_root: [u8; 32],
        approval_basis: CheckpointApprovalBasis,
        approved_at_unix: u64,
        attestations: Vec<CheckpointSourceAttestation>,
    ) -> Self {
        Self::new(
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            checkpoint_root,
            approval_basis,
            approved_at_unix,
            CheckpointApprovalWindow {
                checkpoint_epoch: 1,
                valid_until_unix: approved_at_unix.saturating_add(1),
            },
            attestations,
        )
    }
}

/// A stored checkpoint decision and its source fingerprints.
///
/// This snapshot is not a `BeaconCheckpointRoot` and cannot be passed to the
/// verifier without an explicit policy-layer conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCheckpointApproval {
    chain_id: u64,
    network: String,
    checkpoint_root: [u8; 32],
    approval_basis: CheckpointApprovalBasis,
    approved_at_unix: u64,
    checkpoint_epoch: u64,
    valid_until_unix: u64,
    attestations: Vec<CheckpointSourceAttestation>,
}

impl StoredCheckpointApproval {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn approval_basis(&self) -> CheckpointApprovalBasis {
        self.approval_basis
    }

    pub fn approved_at_unix(&self) -> u64 {
        self.approved_at_unix
    }

    pub fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }

    pub fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    pub fn attestations(&self) -> &[CheckpointSourceAttestation] {
        &self.attestations
    }
}

impl EthereumNodeStore {
    /// Atomically records an externally evaluated approval and its attestations.
    pub fn record_checkpoint_approval(
        &mut self,
        approval: &CheckpointApproval,
    ) -> Result<RecordOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let outcome = record_checkpoint_approval_monotonic_in(&transaction, approval)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(outcome)
    }

    pub fn checkpoint_approval(
        &self,
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> Result<Option<StoredCheckpointApproval>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_checkpoint(&self.connection, chain_id, checkpoint_root)
    }

    pub(crate) fn latest_checkpoint_approval(&self) -> Result<Option<StoredCheckpointApproval>> {
        latest_checkpoint_approval(&self.connection)
    }
}

pub(crate) fn record_checkpoint_approval_in(
    transaction: &rusqlite::Transaction<'_>,
    approval: &CheckpointApproval,
) -> Result<RecordOutcome> {
    ensure_supported_network(approval.chain_id, &approval.network)?;
    if approval.checkpoint_root == [0; 32]
        || approval.approved_at_unix == 0
        || approval.checkpoint_epoch == 0
        || approval.valid_until_unix <= approval.approved_at_unix
    {
        return Err(NodeStoreError::new(
            "checkpoint approval is missing a root, epoch, or valid lifetime",
        ));
    }
    if approval.attestations.iter().any(|attestation| {
        attestation.source_fingerprint == [0; 32]
            || attestation.operator_fingerprint == [0; 32]
            || attestation.observation_hash == [0; 32]
            || attestation.observed_at_unix == 0
    }) {
        return Err(NodeStoreError::new(
            "checkpoint attestation is missing public provenance",
        ));
    }
    let digest = checkpoint_digest(approval);
    let mut inserted = transaction
        .execute(
            "INSERT INTO eth_checkpoint_approvals (
                    chain_id, network, checkpoint_root, approval_basis,
                    approved_at_unix, checkpoint_epoch, valid_until_unix, record_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(chain_id, network, checkpoint_root) DO NOTHING",
            rusqlite::params![
                approval.chain_id.to_string(),
                approval.network,
                approval.checkpoint_root.as_slice(),
                approval.approval_basis.as_i64(),
                approval.approved_at_unix.to_string(),
                approval.checkpoint_epoch.to_string(),
                approval.valid_until_unix.to_string(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?
        == 1;

    if !inserted {
        let stored = read_checkpoint(transaction, approval.chain_id, approval.checkpoint_root)?
            .ok_or_else(|| {
                NodeStoreError::new("checkpoint conflict has no corresponding record")
            })?;
        if stored.network != approval.network
            || stored.approval_basis != approval.approval_basis
            || stored.approved_at_unix != approval.approved_at_unix
            || stored.checkpoint_epoch != approval.checkpoint_epoch
            || stored.valid_until_unix != approval.valid_until_unix
        {
            return Err(NodeStoreError::new(
                "checkpoint approval conflicts with an immutable decision",
            ));
        }
    }
    inserted |= record_assurance(
        transaction,
        AssuranceEventInput {
            chain_id: approval.chain_id,
            network: &approval.network,
            subject_kind: AssuranceSubjectKind::Checkpoint,
            subject_key: approval.checkpoint_root,
            event_kind: AssuranceEventKind::CheckpointApproved,
            evidence_hash: digest,
            observed_at_unix: approval.approved_at_unix,
        },
    )? == RecordOutcome::Inserted;

    for attestation in &approval.attestations {
        let key = attestation_key(approval, attestation);
        let record_digest = attestation_digest(approval, attestation);
        let changed = transaction
            .execute(
                "INSERT INTO eth_checkpoint_attestations (
                        attestation_key, chain_id, network, checkpoint_root, source_kind,
                        source_fingerprint, operator_fingerprint, observation_hash,
                        observed_at_unix, record_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                     ON CONFLICT(attestation_key) DO NOTHING",
                rusqlite::params![
                    key.as_slice(),
                    approval.chain_id.to_string(),
                    approval.network,
                    approval.checkpoint_root.as_slice(),
                    attestation.source_kind.as_i64(),
                    attestation.source_fingerprint.as_slice(),
                    attestation.operator_fingerprint.as_slice(),
                    attestation.observation_hash.as_slice(),
                    attestation.observed_at_unix.to_string(),
                    record_digest.as_slice(),
                ],
            )
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    NodeStoreError::new("checkpoint source conflicts with an immutable observation")
                } else {
                    NodeStoreError::sqlite(error)
                }
            })?;
        inserted |= changed == 1;
        if changed == 0 {
            validate_attestation_by_key(transaction, key, approval, attestation)?;
        }
        inserted |= record_assurance(
            transaction,
            AssuranceEventInput {
                chain_id: approval.chain_id,
                network: &approval.network,
                subject_kind: AssuranceSubjectKind::Checkpoint,
                subject_key: approval.checkpoint_root,
                event_kind: AssuranceEventKind::CheckpointSourceAttested,
                evidence_hash: attestation.observation_hash,
                observed_at_unix: attestation.observed_at_unix,
            },
        )? == RecordOutcome::Inserted;
    }

    Ok(if inserted {
        RecordOutcome::Inserted
    } else {
        RecordOutcome::Replay
    })
}

/// Checks the current durable head and records one approval under the same
/// immediate transaction. The epoch uniqueness index is the final backstop
/// against a second writer selecting another root for the same epoch.
pub(crate) fn record_checkpoint_approval_monotonic_in(
    transaction: &rusqlite::Transaction<'_>,
    approval: &CheckpointApproval,
) -> Result<RecordOutcome> {
    if let Some(latest) = latest_checkpoint_approval(transaction)? {
        if latest.checkpoint_root == approval.checkpoint_root
            && latest.checkpoint_epoch != approval.checkpoint_epoch
        {
            return Err(NodeStoreError::new(
                "checkpoint root is already bound to a different epoch",
            ));
        }
        if latest.checkpoint_epoch == approval.checkpoint_epoch
            && latest.checkpoint_root != approval.checkpoint_root
        {
            return Err(NodeStoreError::new(
                "checkpoint epoch is already bound to a different root",
            ));
        }
        if approval.checkpoint_epoch < latest.checkpoint_epoch {
            return Err(NodeStoreError::new(
                "checkpoint approval would roll back the latest installed epoch",
            ));
        }
    }
    record_checkpoint_approval_in(transaction, approval)
}

pub(crate) fn latest_checkpoint_approval(
    connection: &rusqlite::Connection,
) -> Result<Option<StoredCheckpointApproval>> {
    let mut statement = connection
        .prepare(
            "SELECT checkpoint_root FROM eth_checkpoint_approvals
                 WHERE chain_id = ?1 AND network = ?2",
        )
        .map_err(NodeStoreError::sqlite)?;
    let roots = statement
        .query_map(
            rusqlite::params![SEPOLIA_CHAIN_ID.to_string(), SEPOLIA_NETWORK],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    let mut roots_by_epoch = HashMap::new();
    let mut latest: Option<StoredCheckpointApproval> = None;
    for root in roots {
        let root = stored_array::<32>(&root.map_err(NodeStoreError::sqlite)?, "checkpoint root")?;
        let approval = read_checkpoint(connection, SEPOLIA_CHAIN_ID, root)?
            .ok_or_else(|| NodeStoreError::new("checkpoint row disappeared during lookup"))?;
        if roots_by_epoch
            .insert(approval.checkpoint_epoch, approval.checkpoint_root)
            .is_some_and(|existing| existing != approval.checkpoint_root)
        {
            return Err(NodeStoreError::new(
                "multiple checkpoint roots are stored for one epoch",
            ));
        }
        match latest.as_ref() {
            Some(current) if approval.checkpoint_epoch <= current.checkpoint_epoch => {}
            _ => latest = Some(approval),
        }
    }
    Ok(latest)
}

pub(crate) fn read_checkpoint(
    connection: &rusqlite::Connection,
    chain_id: u64,
    checkpoint_root: [u8; 32],
) -> Result<Option<StoredCheckpointApproval>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, checkpoint_root, approval_basis,
                    approved_at_unix, checkpoint_epoch, valid_until_unix, record_digest
             FROM eth_checkpoint_approvals
             WHERE chain_id = ?1 AND checkpoint_root = ?2",
            rusqlite::params![chain_id.to_string(), checkpoint_root.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((stored_chain, network, root, basis, approved_at, epoch, valid_until, digest)) = row
    else {
        return Ok(None);
    };
    let epoch = epoch.ok_or_else(|| {
        NodeStoreError::new("stored checkpoint predates bootstrap policy and cannot be trusted")
    })?;
    let valid_until = valid_until.ok_or_else(|| {
        NodeStoreError::new("stored checkpoint predates bootstrap policy and cannot be trusted")
    })?;
    let mut stored = StoredCheckpointApproval {
        chain_id: parse_stored_u64(&stored_chain, "checkpoint chain id")?,
        network,
        checkpoint_root: stored_array(&root, "checkpoint root")?,
        approval_basis: CheckpointApprovalBasis::from_i64(basis)?,
        approved_at_unix: parse_stored_u64(&approved_at, "checkpoint approval time")?,
        checkpoint_epoch: parse_stored_u64(&epoch, "checkpoint epoch")?,
        valid_until_unix: parse_stored_u64(&valid_until, "checkpoint validity")?,
        attestations: Vec::new(),
    };
    if stored.checkpoint_root == [0; 32]
        || stored.approved_at_unix == 0
        || stored.checkpoint_epoch == 0
        || stored.valid_until_unix <= stored.approved_at_unix
    {
        return Err(NodeStoreError::new(
            "stored checkpoint has an invalid root, epoch, or lifetime",
        ));
    }
    let expected = checkpoint_stored_digest(&stored);
    if stored_array::<32>(&digest, "checkpoint record digest")? != expected {
        return Err(NodeStoreError::new(
            "stored checkpoint record digest does not match its values",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT attestation_key, source_kind, source_fingerprint,
                    operator_fingerprint, observation_hash, observed_at_unix, record_digest
             FROM eth_checkpoint_attestations
             WHERE chain_id = ?1 AND network = ?2 AND checkpoint_root = ?3
             ORDER BY observed_at_unix, attestation_key",
        )
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map(
            rusqlite::params![
                stored.chain_id.to_string(),
                stored.network,
                stored.checkpoint_root.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(NodeStoreError::sqlite)?;
    for row in rows {
        let (
            key,
            source_kind,
            source_fingerprint,
            operator_fingerprint,
            observation_hash,
            observed_at,
            digest,
        ) = row.map_err(NodeStoreError::sqlite)?;
        let attestation = CheckpointSourceAttestation {
            source_kind: CheckpointSourceKind::from_i64(source_kind)?,
            source_fingerprint: stored_array(&source_fingerprint, "source fingerprint")?,
            operator_fingerprint: stored_array(
                &operator_fingerprint.ok_or_else(|| {
                    NodeStoreError::new("stored checkpoint attestation predates operator policy")
                })?,
                "operator fingerprint",
            )?,
            observation_hash: stored_array(&observation_hash, "observation hash")?,
            observed_at_unix: parse_stored_u64(&observed_at, "observation time")?,
        };
        let approval = checkpoint_input(&stored);
        if stored_array::<32>(&key, "checkpoint attestation key")?
            != attestation_key(&approval, &attestation)
            || stored_array::<32>(&digest, "checkpoint attestation digest")?
                != attestation_digest(&approval, &attestation)
        {
            return Err(NodeStoreError::new(
                "stored checkpoint attestation digest does not match its values",
            ));
        }
        stored.attestations.push(attestation);
    }
    Ok(Some(stored))
}

fn validate_attestation_by_key(
    connection: &rusqlite::Connection,
    key: [u8; 32],
    approval: &CheckpointApproval,
    expected: &CheckpointSourceAttestation,
) -> Result<()> {
    let stored = connection
        .query_row(
            "SELECT source_kind, source_fingerprint, operator_fingerprint,
                    observation_hash, observed_at_unix, record_digest
             FROM eth_checkpoint_attestations WHERE attestation_key = ?1",
            [key.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .ok_or_else(|| NodeStoreError::new("attestation replay has no corresponding record"))?;
    if CheckpointSourceKind::from_i64(stored.0)? != expected.source_kind
        || stored_array::<32>(&stored.1, "source fingerprint")? != expected.source_fingerprint
        || stored_array::<32>(&stored.2, "operator fingerprint")? != expected.operator_fingerprint
        || stored_array::<32>(&stored.3, "observation hash")? != expected.observation_hash
        || parse_stored_u64(&stored.4, "observation time")? != expected.observed_at_unix
        || stored_array::<32>(&stored.5, "checkpoint attestation digest")?
            != attestation_digest(approval, expected)
    {
        return Err(NodeStoreError::new(
            "checkpoint attestation replay conflicts with stored values",
        ));
    }
    Ok(())
}

fn checkpoint_input(stored: &StoredCheckpointApproval) -> CheckpointApproval {
    CheckpointApproval::new(
        stored.chain_id,
        stored.network.clone(),
        stored.checkpoint_root,
        stored.approval_basis,
        stored.approved_at_unix,
        CheckpointApprovalWindow {
            checkpoint_epoch: stored.checkpoint_epoch,
            valid_until_unix: stored.valid_until_unix,
        },
        Vec::new(),
    )
}

pub(crate) fn ensure_supported_network(chain_id: u64, network: &str) -> Result<()> {
    if chain_id != SEPOLIA_CHAIN_ID || network != SEPOLIA_NETWORK {
        return Err(NodeStoreError::new(format!(
            "unsupported Ethereum store network {chain_id}/{network}"
        )));
    }
    Ok(())
}

fn checkpoint_digest(approval: &CheckpointApproval) -> [u8; 32] {
    checkpoint_values_digest(
        approval.chain_id,
        &approval.network,
        approval.checkpoint_root,
        approval.approval_basis,
        approval.approved_at_unix,
        approval.checkpoint_epoch,
        approval.valid_until_unix,
    )
}

fn checkpoint_stored_digest(stored: &StoredCheckpointApproval) -> [u8; 32] {
    checkpoint_values_digest(
        stored.chain_id,
        &stored.network,
        stored.checkpoint_root,
        stored.approval_basis,
        stored.approved_at_unix,
        stored.checkpoint_epoch,
        stored.valid_until_unix,
    )
}

fn checkpoint_values_digest(
    chain_id: u64,
    network: &str,
    root: [u8; 32],
    basis: CheckpointApprovalBasis,
    approved_at_unix: u64,
    checkpoint_epoch: u64,
    valid_until_unix: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-approval-v2");
    hasher.update(chain_id.to_le_bytes());
    hasher.update((network.len() as u16).to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.update(root);
    hasher.update(basis.as_i64().to_le_bytes());
    hasher.update(approved_at_unix.to_le_bytes());
    hasher.update(checkpoint_epoch.to_le_bytes());
    hasher.update(valid_until_unix.to_le_bytes());
    hasher.finalize().into()
}

fn attestation_key(
    approval: &CheckpointApproval,
    attestation: &CheckpointSourceAttestation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-attestation-key-v1");
    hasher.update(approval.chain_id.to_le_bytes());
    hasher.update((approval.network.len() as u16).to_le_bytes());
    hasher.update(approval.network.as_bytes());
    hasher.update(approval.checkpoint_root);
    hasher.update(attestation.source_kind.as_i64().to_le_bytes());
    hasher.update(attestation.source_fingerprint);
    hasher.update(attestation.operator_fingerprint);
    hasher.update(attestation.observation_hash);
    hasher.update(attestation.observed_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn attestation_digest(
    approval: &CheckpointApproval,
    attestation: &CheckpointSourceAttestation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-attestation-record-v1");
    hasher.update(attestation_key(approval, attestation));
    hasher.finalize().into()
}
