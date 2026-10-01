use std::collections::HashSet;
use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, ffi, params};
use sha2::{Digest, Sha256};

use super::{AcceptedBulkApproval, GatewayMessageOutcome};
use super::{
    AuthenticatedGatewayEnvelope, GatewayMessageError, GatewayRateLimit, Message,
    MessagingEvidenceKind, RelayObservation, TransactionPresence, decode,
};
use crate::{GatewayBundle, GatewayBundleKind};

const SCHEMA_VERSION: i64 = 5;
const ADMISSION_ONLY_SCHEMA_VERSION: i64 = 1;
const RESPONSE_ONLY_SCHEMA_VERSION: i64 = 2;
const STATE_PENDING: i64 = 0;
const STATE_LEASED: i64 = 1;
const STATE_COMPLETED: i64 = 2;
const STATE_EXPIRED: i64 = 3;
const KIND_EVIDENCE: i64 = 1;
const KIND_RELAY: i64 = 2;
const MAX_LEASE_SECONDS: u64 = 60 * 60;
const MAX_REQUEST_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const MIN_REPLAY_RETENTION_SECONDS: u64 = 60 * 60;
const MAX_REPLAY_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_STORED_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RESULT_RELEASE_ATTEMPTS: i64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayReleasePhase {
    BulkManifest = 1,
    Evidence = 2,
    Relay = 3,
}

impl GatewayReleasePhase {
    fn as_sql(self) -> i64 {
        self as i64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GatewayReleaseLease {
    pub token: [u8; 32],
}

/// A redacted error from the durable gateway admission boundary.
///
/// SQL text, paths, request bytes, and RPC details must remain in the service's
/// protected diagnostic context rather than crossing its protocol boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayAdmissionError {
    #[error("gateway message was rejected")]
    Message(#[from] GatewayMessageError),
    #[error("gateway admission store is unavailable")]
    Storage,
    #[error("gateway request identifier conflicts with retained work")]
    ReplayConflict,
    #[error("gateway admission state is invalid")]
    InvalidState,
}

fn sqlite_storage_error(stage: &'static str, error: rusqlite::Error) -> GatewayAdmissionError {
    tracing::error!(
        stage,
        code = ?error.sqlite_error_code(),
        extended_code = error.sqlite_error().map(|value| value.extended_code),
        "Ethereum gateway durable SQLite operation failed"
    );
    GatewayAdmissionError::Storage
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayJobKind {
    Evidence,
    SignedRelay,
    /// Stored in the existing bounded control-job lane. The exact retained
    /// attachment determines this subtype when records are read back.
    TransactionStatus,
}

impl GatewayJobKind {
    fn as_sql(self) -> i64 {
        match self {
            Self::Evidence => KIND_EVIDENCE,
            Self::SignedRelay => KIND_RELAY,
            Self::TransactionStatus => KIND_RELAY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayJobState {
    Pending,
    Leased,
    Completed,
    Expired,
}

/// The durable disposition of one exact leased request.
///
/// Relay observations describe only provider transport. Evidence bytes have
/// already passed the gateway verifier, but remain untrusted by the receiving
/// field node until it independently verifies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayResultKind {
    Evidence,
    RelayAccepted,
    RelayRejected,
    /// A non-authoritative transaction presence/head sample. It uses the
    /// retained control-result SQL lane and is distinguished by revalidating
    /// the exact request attachment on every read.
    TransactionStatus,
    PermanentFailure,
}

impl GatewayResultKind {
    fn from_sql(value: i64) -> Result<Self, GatewayAdmissionError> {
        match value {
            1 => Ok(Self::Evidence),
            2 => Ok(Self::RelayAccepted),
            3 => Ok(Self::RelayRejected),
            4 => Ok(Self::PermanentFailure),
            _ => Err(GatewayAdmissionError::InvalidState),
        }
    }

    fn as_sql(self) -> i64 {
        match self {
            Self::Evidence => 1,
            Self::RelayAccepted => 2,
            Self::RelayRejected => 3,
            Self::TransactionStatus => 2,
            Self::PermanentFailure => 4,
        }
    }
}

/// A result bound to the attachment digest and lease generation that produced
/// it. Debug output deliberately omits requester, identifiers, and bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayStoredResult {
    requester_source_hash: [u8; 16],
    request_id: [u8; 16],
    attachment_digest: [u8; 32],
    lease_generation: u64,
    kind: GatewayResultKind,
    manifest_digest: [u8; 32],
    manifest: Vec<u8>,
    response_digest: [u8; 32],
    response: Vec<u8>,
    completed_at_unix: u64,
}

impl std::fmt::Debug for GatewayStoredResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayStoredResult")
            .field("lease_generation", &self.lease_generation)
            .field("kind", &self.kind)
            .field("manifest_len", &self.manifest.len())
            .field("response_len", &self.response.len())
            .field("completed_at_unix", &self.completed_at_unix)
            .finish()
    }
}

impl GatewayStoredResult {
    pub fn requester_source_hash(&self) -> [u8; 16] {
        self.requester_source_hash
    }

    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn attachment_digest(&self) -> [u8; 32] {
        self.attachment_digest
    }

    pub fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub fn kind(&self) -> GatewayResultKind {
        self.kind
    }

    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Evidence manifest bytes that must be delivered before `response`.
    /// Relay and permanent-failure results have no manifest.
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    pub fn response_digest(&self) -> [u8; 32] {
        self.response_digest
    }

    /// Exact response bytes for a separately authenticated transport adapter.
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    pub fn completed_at_unix(&self) -> u64 {
        self.completed_at_unix
    }
}

impl GatewayJobState {
    fn from_sql(value: i64) -> Result<Self, GatewayAdmissionError> {
        match value {
            STATE_PENDING => Ok(Self::Pending),
            STATE_LEASED => Ok(Self::Leased),
            STATE_COMPLETED => Ok(Self::Completed),
            STATE_EXPIRED => Ok(Self::Expired),
            _ => Err(GatewayAdmissionError::InvalidState),
        }
    }
}

/// Exact authenticated work retained for the gateway service.
///
/// The attachment contains public request or signed-transaction bytes, never
/// wallet secrets. The service must decode it again before execution rather
/// than trusting columns reconstructed from an earlier process.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayJob {
    requester_source_hash: [u8; 16],
    request_id: [u8; 16],
    attachment_digest: [u8; 32],
    attachment: Vec<u8>,
    kind: GatewayJobKind,
    state: GatewayJobState,
    expires_at_unix: u64,
}

impl std::fmt::Debug for GatewayJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayJob")
            .field("attachment_len", &self.attachment.len())
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl GatewayJob {
    pub fn requester_source_hash(&self) -> [u8; 16] {
        self.requester_source_hash
    }

    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn attachment_digest(&self) -> [u8; 32] {
        self.attachment_digest
    }

    pub fn attachment_len(&self) -> usize {
        self.attachment.len()
    }

    pub fn kind(&self) -> GatewayJobKind {
        self.kind
    }

    pub fn state(&self) -> GatewayJobState {
        self.state
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableGatewayOutcome {
    IgnoredUnauthenticated,
    Queued(GatewayJob),
    Duplicate(GatewayJobState),
    BulkApproved(GatewayStoredResult),
}

/// One exact ownership generation for a leased gateway job.
///
/// Callers pass this value back to `complete` or `release`. A stale worker
/// cannot transition work reclaimed under a newer generation.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayLease {
    job: GatewayJob,
    generation: u64,
}

impl std::fmt::Debug for GatewayLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayLease")
            .field("job", &self.job)
            .field("generation", &self.generation)
            .finish()
    }
}

impl GatewayLease {
    pub fn job(&self) -> &GatewayJob {
        &self.job
    }

    /// Decode the exact bytes revalidated when this lease was acquired.
    ///
    /// This is the executable gateway input. The returned relay or evidence
    /// request remains non-authoritative, and any RPC result must still be
    /// converted to a locally verified bundle before it is sent.
    pub fn validated_message(&self) -> Result<GatewayMessageOutcome, GatewayMessageError> {
        match decode(&self.job.attachment)? {
            Message::EvidenceRequest(request) => {
                Ok(GatewayMessageOutcome::EvidenceRequest(request))
            }
            Message::SignedRelay(relay) => Ok(GatewayMessageOutcome::SignedRelay(relay)),
            Message::TransactionStatus(request) => {
                Ok(GatewayMessageOutcome::TransactionStatus(request))
            }
            Message::BulkApproval(_) => Err(GatewayMessageError::UnsupportedKind),
            Message::Other => Err(GatewayMessageError::UnsupportedKind),
        }
    }
}

/// Restart-safe admission and work leasing for a dedicated gateway service.
///
/// This type does not perform RPC calls or send LXMF responses. It preserves
/// the security-relevant boundary between authenticated delivery and those
/// side effects so a Rathole-managed sidecar and a standalone daemon can share
/// identical behavior.
pub struct DurableGatewayAdmission {
    connection: Connection,
    configured_requesters: HashSet<[u8; 16]>,
    limit: GatewayRateLimit,
}

impl DurableGatewayAdmission {
    pub fn open(
        path: &Path,
        configured_requesters: impl IntoIterator<Item = [u8; 16]>,
        limit: GatewayRateLimit,
    ) -> Result<Self, GatewayAdmissionError> {
        let configured_requesters: HashSet<_> = configured_requesters.into_iter().collect();
        validate_configuration(&configured_requesters, limit)?;
        // The daemon's SQLite store needs a real pathname so WAL can create
        // same-directory sidecars. Ask SQLite itself to reject a final
        // symlink instead of routing the database through `/proc/self/fd`,
        // where WAL writes cannot succeed.
        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::from_bits_retain(ffi::SQLITE_OPEN_NOFOLLOW);
        let connection = Connection::open_with_flags(path, open_flags)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| GatewayAdmissionError::Storage)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 CREATE TABLE IF NOT EXISTS gateway_schema (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    version INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS gateway_rate_windows (
                    requester BLOB PRIMARY KEY CHECK (length(requester) = 16),
                    window_started_unix INTEGER NOT NULL CHECK (window_started_unix >= 0),
                    request_count INTEGER NOT NULL CHECK (request_count >= 0),
                    requested_bytes INTEGER NOT NULL CHECK (requested_bytes >= 0)
                 );
                 CREATE TABLE IF NOT EXISTS gateway_jobs (
                    requester BLOB NOT NULL CHECK (length(requester) = 16),
                    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                    attachment_digest BLOB NOT NULL CHECK (length(attachment_digest) = 32),
                    attachment BLOB NOT NULL,
                    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
                    state INTEGER NOT NULL CHECK (state IN (0, 1, 2, 3)),
                    first_seen_unix INTEGER NOT NULL CHECK (first_seen_unix >= 0),
                    expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix > 0),
                    lease_until_unix INTEGER,
                    lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
                    PRIMARY KEY (requester, request_id)
                 );
                 CREATE INDEX IF NOT EXISTS gateway_jobs_ready
                    ON gateway_jobs (state, lease_until_unix, first_seen_unix);",
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        match connection
            .query_row(
                "SELECT version FROM gateway_schema WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?
        {
            None => connection
                .execute(
                    "INSERT INTO gateway_schema (singleton, version) VALUES (1, ?1)",
                    [SCHEMA_VERSION],
                )
                .map_err(|_| GatewayAdmissionError::Storage)
                .map(|_| ())?,
            Some(SCHEMA_VERSION) => {}
            Some(4) | Some(3) => connection
                .execute(
                    "UPDATE gateway_schema SET version = 5
                       WHERE singleton = 1 AND version IN (3, 4)",
                    [],
                )
                .map_err(|_| GatewayAdmissionError::Storage)
                .map(|_| ())?,
            Some(ADMISSION_ONLY_SCHEMA_VERSION) => connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     DROP TABLE IF EXISTS gateway_job_results;
                     UPDATE gateway_schema SET version = 5
                       WHERE singleton = 1 AND version = 1;
                     COMMIT;",
                )
                .map_err(|_| GatewayAdmissionError::Storage)?,
            Some(RESPONSE_ONLY_SCHEMA_VERSION) => connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     UPDATE gateway_jobs
                        SET state = 0, lease_until_unix = NULL
                      WHERE state = 2
                        AND EXISTS (
                            SELECT 1 FROM gateway_job_results r
                             WHERE r.requester = gateway_jobs.requester
                               AND r.request_id = gateway_jobs.request_id
                        );
                     DROP TABLE gateway_job_results;
                     UPDATE gateway_schema SET version = 5
                       WHERE singleton = 1 AND version = 2;
                     COMMIT;",
                )
                .map_err(|_| GatewayAdmissionError::Storage)?,
            Some(_) => return Err(GatewayAdmissionError::InvalidState),
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS gateway_job_results (
                    requester BLOB NOT NULL CHECK (length(requester) = 16),
                    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                    attachment_digest BLOB NOT NULL CHECK (length(attachment_digest) = 32),
                    lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                    kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3, 4)),
                    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
                    manifest BLOB NOT NULL,
                    response_digest BLOB NOT NULL CHECK (length(response_digest) = 32),
                    response BLOB NOT NULL,
                    completed_at_unix INTEGER NOT NULL CHECK (completed_at_unix >= 0),
                    PRIMARY KEY (requester, request_id),
                    FOREIGN KEY (requester, request_id)
                        REFERENCES gateway_jobs (requester, request_id) ON DELETE CASCADE
                 );",
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS gateway_result_releases (
                    requester BLOB NOT NULL CHECK (length(requester) = 16),
                    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                    phase INTEGER NOT NULL CHECK (phase IN (1, 2, 3)),
                    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 3),
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    current_token BLOB CHECK (
                        current_token IS NULL OR length(current_token) = 32),
                    acknowledged INTEGER NOT NULL DEFAULT 0
                        CHECK (acknowledged IN (0, 1)),
                    last_attempt_unix INTEGER CHECK (last_attempt_unix >= 0),
                    PRIMARY KEY (requester, request_id, phase),
                    FOREIGN KEY (requester, request_id)
                        REFERENCES gateway_job_results (requester, request_id)
                        ON DELETE CASCADE
                 );",
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS gateway_bulk_approvals (
                    requester BLOB NOT NULL CHECK (length(requester) = 16),
                    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                    approval_digest BLOB NOT NULL CHECK (length(approval_digest) = 32),
                    approval_attachment BLOB NOT NULL
                        CHECK (length(approval_attachment) > 0
                           AND length(approval_attachment) <= 4096),
                    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
                    encoded_size INTEGER NOT NULL CHECK (encoded_size > 4096),
                    approved_at_unix INTEGER NOT NULL CHECK (approved_at_unix >= 0),
                    PRIMARY KEY (requester, request_id),
                    FOREIGN KEY (requester, request_id)
                        REFERENCES gateway_job_results (requester, request_id)
                        ON DELETE CASCADE
                 );",
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        validate_result_schema(&connection)?;
        Ok(Self {
            connection,
            configured_requesters,
            limit,
        })
    }

    pub fn admit_persisted_attachment(
        &mut self,
        envelope: AuthenticatedGatewayEnvelope<'_>,
        now_unix: u64,
    ) -> Result<DurableGatewayOutcome, GatewayAdmissionError> {
        if !self
            .configured_requesters
            .contains(&envelope.sender_source_hash)
        {
            return Ok(DurableGatewayOutcome::IgnoredUnauthenticated);
        }
        let requester = envelope.sender_source_hash;
        self.charge_attempt(requester, now_unix)?;
        if envelope
            .persisted_attachment
            .get(super::MAGIC.len() + 1 + std::mem::size_of::<u64>())
            == Some(&super::KIND_BULK_APPROVAL)
        {
            self.charge_approval_bytes(requester, envelope.persisted_attachment.len() as u64)?;
        }

        let decoded = decode(envelope.persisted_attachment)?;
        if let Message::BulkApproval(approval) = decoded {
            return self.approve_bulk_result(
                requester,
                approval,
                envelope.persisted_attachment,
                now_unix,
            );
        }
        let (request_id, kind, expires_at_unix, requested_bytes) = match decoded {
            Message::EvidenceRequest(request) => (
                request.request_id,
                GatewayJobKind::Evidence,
                request.expires_at_unix,
                u64::from(request.maximum_response_bytes),
            ),
            Message::SignedRelay(relay) => (
                relay.request_id,
                GatewayJobKind::SignedRelay,
                relay.expires_at_unix,
                relay.raw_transaction.len() as u64,
            ),
            Message::TransactionStatus(request) => (
                request.request_id,
                GatewayJobKind::TransactionStatus,
                request.expires_at_unix,
                226,
            ),
            Message::BulkApproval(_) => unreachable!("handled above"),
            Message::Other => {
                return Err(GatewayAdmissionError::Message(
                    GatewayMessageError::UnsupportedKind,
                ));
            }
        };
        if now_unix >= expires_at_unix {
            return Err(GatewayAdmissionError::Message(GatewayMessageError::Expired));
        }
        if expires_at_unix.saturating_sub(now_unix) > MAX_REQUEST_LIFETIME_SECONDS {
            return Err(GatewayAdmissionError::Message(
                GatewayMessageError::InvalidMessage,
            ));
        }
        let digest: [u8; 32] = Sha256::digest(envelope.persisted_attachment).into();
        let job = self.insert_or_find(
            requester,
            request_id,
            digest,
            envelope.persisted_attachment,
            kind,
            expires_at_unix,
            requested_bytes,
            now_unix,
        )?;
        match job {
            InsertResult::Queued(job) => Ok(DurableGatewayOutcome::Queued(job)),
            InsertResult::Duplicate(state) => Ok(DurableGatewayOutcome::Duplicate(state)),
        }
    }

    fn approve_bulk_result(
        &mut self,
        requester: [u8; 16],
        approval: AcceptedBulkApproval,
        authenticated_attachment: &[u8],
        now_unix: u64,
    ) -> Result<DurableGatewayOutcome, GatewayAdmissionError> {
        if now_unix >= approval.expires_at_unix()
            || approval.expires_at_unix().saturating_sub(now_unix) > MAX_REQUEST_LIFETIME_SECONDS
        {
            return Err(GatewayAdmissionError::Message(GatewayMessageError::Expired));
        }
        let result = self
            .completed_result(requester, approval.request_id())?
            .ok_or(GatewayAdmissionError::InvalidState)?;
        if result.kind() != GatewayResultKind::Evidence {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let expires_at_unix = self
            .connection
            .query_row(
                "SELECT expires_at_unix FROM gateway_jobs
                 WHERE requester = ?1 AND request_id = ?2 AND state = ?3",
                params![
                    requester.as_slice(),
                    approval.request_id().as_slice(),
                    STATE_COMPLETED
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let expires_at_unix =
            u64::try_from(expires_at_unix).map_err(|_| GatewayAdmissionError::InvalidState)?;
        let (_, manifest_kind, manifest_context, manifest_digest, manifest_size) =
            decode_manifest_frame(result.manifest())?;
        let response = decode_evidence_frame(result.response())?;
        if approval.expires_at_unix() != expires_at_unix
            || approval.evidence_kind() != manifest_kind
            || approval.checkpoint_context() != manifest_context
            || approval.digest() != manifest_digest
            || approval.encoded_size() != manifest_size
            || response.kind != manifest_kind
            || response.checkpoint_context != manifest_context
            || response.digest != manifest_digest
            || response.bundle.len() != manifest_size as usize
            || manifest_size as usize <= super::MAX_CONTROL_BYTES
        {
            return Err(GatewayAdmissionError::ReplayConflict);
        }

        let approval_digest: [u8; 32] = Sha256::digest(authenticated_attachment).into();
        let existing = self
            .connection
            .query_row(
                "SELECT approval_digest, approval_attachment, manifest_digest, encoded_size
                 FROM gateway_bulk_approvals
                 WHERE requester = ?1 AND request_id = ?2",
                params![requester.as_slice(), approval.request_id().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if let Some((stored_approval, stored_attachment, stored_manifest, stored_size)) = existing {
            if fixed::<32>(stored_approval).map_err(|_| GatewayAdmissionError::Storage)?
                != approval_digest
                || <[u8; 32]>::from(Sha256::digest(&stored_attachment)) != approval_digest
                || stored_attachment != authenticated_attachment
                || fixed::<32>(stored_manifest).map_err(|_| GatewayAdmissionError::Storage)?
                    != manifest_digest
                || u64::try_from(stored_size).map_err(|_| GatewayAdmissionError::InvalidState)?
                    != u64::from(manifest_size)
            {
                return Err(GatewayAdmissionError::ReplayConflict);
            }
            return Ok(DurableGatewayOutcome::BulkApproved(result));
        }
        self.connection
            .execute(
                "INSERT INTO gateway_bulk_approvals
                    (requester, request_id, approval_digest, approval_attachment,
                     manifest_digest, encoded_size, approved_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    requester.as_slice(),
                    approval.request_id().as_slice(),
                    approval_digest.as_slice(),
                    authenticated_attachment,
                    manifest_digest.as_slice(),
                    i64::from(manifest_size),
                    to_sql_time(now_unix)?,
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        Ok(DurableGatewayOutcome::BulkApproved(result))
    }

    pub(crate) fn bulk_result_is_approved(
        &self,
        result: &GatewayStoredResult,
    ) -> Result<bool, GatewayAdmissionError> {
        let stored = self
            .connection
            .query_row(
                "SELECT approval_digest, approval_attachment, manifest_digest, encoded_size
                   FROM gateway_bulk_approvals
                  WHERE requester = ?1 AND request_id = ?2",
                params![
                    result.requester_source_hash().as_slice(),
                    result.request_id().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let Some((approval_digest, attachment, manifest_digest, encoded_size)) = stored else {
            return Ok(false);
        };
        let Ok((_, manifest_kind, manifest_context, expected_manifest_digest, expected_size)) =
            decode_manifest_frame(result.manifest())
        else {
            return Err(GatewayAdmissionError::InvalidState);
        };
        let approval_matches = matches!(
            decode(&attachment),
            Ok(Message::BulkApproval(approval))
                if approval.request_id() == result.request_id()
                    && approval.evidence_kind() == manifest_kind
                    && approval.checkpoint_context() == manifest_context
                    && approval.digest() == expected_manifest_digest
                    && approval.encoded_size() == expected_size
        );
        Ok(
            fixed::<32>(approval_digest).map_err(|_| GatewayAdmissionError::Storage)?
                == <[u8; 32]>::from(Sha256::digest(&attachment))
                && fixed::<32>(manifest_digest).map_err(|_| GatewayAdmissionError::Storage)?
                    == expected_manifest_digest
                && encoded_size == i64::from(expected_size)
                && encoded_size > super::MAX_CONTROL_BYTES as i64
                && approval_matches,
        )
    }

    /// Consume one bounded response handoff attempt before bytes leave durable
    /// custody. A crash can lose an attempt, but can never reset the cap.
    pub(crate) fn lease_result_release(
        &mut self,
        result: &GatewayStoredResult,
        phase: GatewayReleasePhase,
        now_unix: u64,
    ) -> Result<Option<GatewayReleaseLease>, GatewayAdmissionError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_storage_error("lease_begin", error))?;
        let existing = transaction
            .query_row(
                "SELECT attempts, generation, acknowledged
                   FROM gateway_result_releases
                  WHERE requester = ?1 AND request_id = ?2 AND phase = ?3",
                params![
                    result.requester_source_hash().as_slice(),
                    result.request_id().as_slice(),
                    phase.as_sql(),
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?
            .unwrap_or((0, 0, 0));
        if existing.2 != 0 || existing.0 >= MAX_RESULT_RELEASE_ATTEMPTS {
            transaction
                .commit()
                .map_err(|_| GatewayAdmissionError::Storage)?;
            return Ok(None);
        }
        let attempts = existing.0 + 1;
        let generation = existing.1 + 1;
        let mut hasher = Sha256::new();
        hasher.update(b"ratspeak-gateway-release-v1");
        hasher.update(result.requester_source_hash());
        hasher.update(result.request_id());
        hasher.update(result.response_digest());
        hasher.update(phase.as_sql().to_be_bytes());
        hasher.update(generation.to_be_bytes());
        let token: [u8; 32] = hasher.finalize().into();
        transaction
            .execute(
                "INSERT INTO gateway_result_releases
                    (requester, request_id, phase, attempts, generation,
                     current_token, acknowledged, last_attempt_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
                 ON CONFLICT(requester, request_id, phase) DO UPDATE SET
                    attempts = excluded.attempts,
                    generation = excluded.generation,
                    current_token = excluded.current_token,
                    last_attempt_unix = excluded.last_attempt_unix",
                params![
                    result.requester_source_hash().as_slice(),
                    result.request_id().as_slice(),
                    phase.as_sql(),
                    attempts,
                    generation,
                    token.as_slice(),
                    to_sql_time(now_unix)?,
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .commit()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        Ok(Some(GatewayReleaseLease { token }))
    }

    pub(crate) fn acknowledge_result_release(
        &mut self,
        token: [u8; 32],
    ) -> Result<(), GatewayAdmissionError> {
        let changed = self
            .connection
            .execute(
                "UPDATE gateway_result_releases
                    SET acknowledged = 1
                  WHERE current_token = ?1 AND acknowledged = 0",
                [token.as_slice()],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if changed <= 1 {
            Ok(())
        } else {
            Err(GatewayAdmissionError::InvalidState)
        }
    }

    /// Lease the oldest unexpired pending job, or reclaim an expired lease.
    ///
    /// A service crash after an RPC side effect may cause the exact job to be
    /// leased again. Signed transaction relay is safe only because callers
    /// submit the exact retained bytes and correlate the exact transaction
    /// hash; an RPC acknowledgement remains non-authoritative.
    pub fn lease_next(
        &mut self,
        requester: [u8; 16],
        now_unix: u64,
        lease_seconds: u64,
    ) -> Result<Option<GatewayLease>, GatewayAdmissionError> {
        if !self.configured_requesters.contains(&requester)
            || lease_seconds == 0
            || lease_seconds > MAX_LEASE_SECONDS
        {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let now = to_sql_time(now_unix)?;
        let lease_until = to_sql_time(
            now_unix
                .checked_add(lease_seconds)
                .ok_or(GatewayAdmissionError::InvalidState)?,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let row = transaction
            .query_row(
                "SELECT requester, request_id, attachment_digest, attachment, kind, state,
                        expires_at_unix, lease_generation
                   FROM gateway_jobs
                  WHERE requester = ?1 AND expires_at_unix > ?2
                    AND ((state = 0 AND (lease_until_unix IS NULL OR lease_until_unix <= ?2))
                         OR (state = 1 AND lease_until_unix <= ?2))
                  ORDER BY first_seen_unix ASC, requester ASC, request_id ASC
                  LIMIT 1",
                params![requester.as_slice(), now],
                read_job,
            )
            .optional()
            .map_err(|error| sqlite_storage_error("lease_read", error))?;
        let Some(mut job) = row else {
            transaction
                .commit()
                .map_err(|error| sqlite_storage_error("lease_empty_commit", error))?;
            return Ok(None);
        };
        let next_generation = job
            .lease_generation
            .checked_add(1)
            .ok_or(GatewayAdmissionError::InvalidState)?;
        let changed = transaction
            .execute(
                "UPDATE gateway_jobs
                    SET state = 1, lease_until_unix = ?1, lease_generation = ?2
                  WHERE requester = ?3 AND request_id = ?4
                    AND lease_generation = ?5
                    AND ((state = 0 AND (lease_until_unix IS NULL OR lease_until_unix <= ?6))
                         OR (state = 1 AND lease_until_unix <= ?6))",
                params![
                    lease_until,
                    to_sql_time(next_generation)?,
                    job.public.requester_source_hash.as_slice(),
                    job.public.request_id.as_slice(),
                    to_sql_time(job.lease_generation)?,
                    now
                ],
            )
            .map_err(|error| sqlite_storage_error("lease_update", error))?;
        if changed != 1 {
            return Err(GatewayAdmissionError::InvalidState);
        }
        transaction
            .commit()
            .map_err(|error| sqlite_storage_error("lease_commit", error))?;
        job.public.state = GatewayJobState::Leased;
        job.lease_generation = next_generation;
        Ok(Some(GatewayLease {
            job: job.into_public(),
            generation: next_generation,
        }))
    }

    pub fn complete(&mut self, lease: &GatewayLease) -> Result<(), GatewayAdmissionError> {
        self.transition(lease, STATE_COMPLETED)
    }

    pub fn release(&mut self, lease: &GatewayLease) -> Result<(), GatewayAdmissionError> {
        self.transition(lease, STATE_PENDING)
    }

    /// Requeue an exact lease without making it eligible before `retry_at_unix`.
    pub(crate) fn defer_until(
        &mut self,
        lease: &GatewayLease,
        retry_at_unix: u64,
    ) -> Result<(), GatewayAdmissionError> {
        if !self
            .configured_requesters
            .contains(&lease.job.requester_source_hash)
            || retry_at_unix == 0
            || retry_at_unix >= lease.job.expires_at_unix
        {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE gateway_jobs
                    SET state = ?1, lease_until_unix = ?2
                  WHERE requester = ?3 AND request_id = ?4
                    AND attachment_digest = ?5 AND state = ?6
                    AND lease_generation = ?7",
                params![
                    STATE_PENDING,
                    to_sql_time(retry_at_unix)?,
                    lease.job.requester_source_hash.as_slice(),
                    lease.job.request_id.as_slice(),
                    lease.job.attachment_digest.as_slice(),
                    STATE_LEASED,
                    to_sql_time(lease.generation)?
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(GatewayAdmissionError::InvalidState)
        }
    }

    /// Atomically persist response bytes and complete the exact lease.
    pub(crate) fn complete_with_result(
        &mut self,
        lease: &GatewayLease,
        kind: GatewayResultKind,
        manifest: &[u8],
        response: &[u8],
        completed_at_unix: u64,
    ) -> Result<GatewayStoredResult, GatewayAdmissionError> {
        if !self
            .configured_requesters
            .contains(&lease.job.requester_source_hash)
            || manifest.len().saturating_add(response.len()) > MAX_STORED_RESULT_BYTES
            || !matches!(
                (lease.job.kind, kind),
                (GatewayJobKind::Evidence, GatewayResultKind::Evidence)
                    | (
                        GatewayJobKind::Evidence,
                        GatewayResultKind::PermanentFailure
                    )
                    | (
                        GatewayJobKind::SignedRelay,
                        GatewayResultKind::RelayAccepted
                    )
                    | (
                        GatewayJobKind::SignedRelay,
                        GatewayResultKind::RelayRejected
                    )
                    | (
                        GatewayJobKind::SignedRelay,
                        GatewayResultKind::PermanentFailure
                    )
                    | (
                        GatewayJobKind::TransactionStatus,
                        GatewayResultKind::TransactionStatus
                    )
                    | (
                        GatewayJobKind::TransactionStatus,
                        GatewayResultKind::PermanentFailure
                    )
            )
            || (kind == GatewayResultKind::Evidence && manifest.is_empty())
            || (kind != GatewayResultKind::Evidence && !manifest.is_empty())
            || (kind == GatewayResultKind::PermanentFailure && !response.is_empty())
            || (kind != GatewayResultKind::PermanentFailure && response.is_empty())
            || !stored_frames_match_request(
                lease.job.kind,
                kind,
                &lease.job.attachment,
                manifest,
                response,
            )
        {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let manifest_digest: [u8; 32] = Sha256::digest(manifest).into();
        let response_digest: [u8; 32] = Sha256::digest(response).into();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE gateway_jobs
                    SET state = ?1, lease_until_unix = NULL
                  WHERE requester = ?2 AND request_id = ?3
                    AND attachment_digest = ?4 AND state = ?5
                    AND lease_generation = ?6",
                params![
                    STATE_COMPLETED,
                    lease.job.requester_source_hash.as_slice(),
                    lease.job.request_id.as_slice(),
                    lease.job.attachment_digest.as_slice(),
                    STATE_LEASED,
                    to_sql_time(lease.generation)?
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if changed != 1 {
            return Err(GatewayAdmissionError::InvalidState);
        }
        transaction
            .execute(
                "INSERT INTO gateway_job_results
                    (requester, request_id, attachment_digest, lease_generation, kind,
                     manifest_digest, manifest, response_digest, response, completed_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    lease.job.requester_source_hash.as_slice(),
                    lease.job.request_id.as_slice(),
                    lease.job.attachment_digest.as_slice(),
                    to_sql_time(lease.generation)?,
                    kind.as_sql(),
                    manifest_digest.as_slice(),
                    manifest,
                    response_digest.as_slice(),
                    response,
                    to_sql_time(completed_at_unix)?
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .commit()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        Ok(GatewayStoredResult {
            requester_source_hash: lease.job.requester_source_hash,
            request_id: lease.job.request_id,
            attachment_digest: lease.job.attachment_digest,
            lease_generation: lease.generation,
            kind,
            manifest_digest,
            manifest: manifest.to_vec(),
            response_digest,
            response: response.to_vec(),
            completed_at_unix,
        })
    }

    /// Load a completed result only if it is still bound to the exact retained
    /// request and current completion generation.
    pub fn completed_result(
        &self,
        requester: [u8; 16],
        request_id: [u8; 16],
    ) -> Result<Option<GatewayStoredResult>, GatewayAdmissionError> {
        if !self.configured_requesters.contains(&requester) {
            return Err(GatewayAdmissionError::InvalidState);
        }
        self.connection
            .query_row(
                "SELECT r.requester, r.request_id, r.attachment_digest,
                        r.lease_generation, r.kind, r.manifest_digest, r.manifest,
                        r.response_digest, r.response, r.completed_at_unix, j.kind,
                        j.attachment
                   FROM gateway_job_results r
                   JOIN gateway_jobs j
                     ON j.requester = r.requester AND j.request_id = r.request_id
                  WHERE r.requester = ?1 AND r.request_id = ?2
                    AND j.state = ?3
                    AND j.attachment_digest = r.attachment_digest
                    AND j.lease_generation = r.lease_generation",
                params![requester.as_slice(), request_id.as_slice(), STATE_COMPLETED],
                read_result,
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)
    }

    /// Return the next retained completed result in SQLite insertion order.
    ///
    /// This supports a service adapter replaying an intent once after process
    /// restart. The cursor is process-local: transport acknowledgements never
    /// delete a result or change its Ethereum meaning.
    pub(crate) fn completed_result_after(
        &self,
        mut rowid_cursor: i64,
        now_unix: u64,
    ) -> Result<(i64, Option<GatewayStoredResult>), GatewayAdmissionError> {
        if rowid_cursor < 0 {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let now = to_sql_time(now_unix)?;
        loop {
            let next = self
                .connection
                .query_row(
                    "SELECT r.requester, r.request_id, r.attachment_digest,
                            r.lease_generation, r.kind, r.manifest_digest, r.manifest,
                            r.response_digest, r.response, r.completed_at_unix, j.kind,
                            j.attachment, r.rowid
                       FROM gateway_job_results r
                       JOIN gateway_jobs j
                         ON j.requester = r.requester AND j.request_id = r.request_id
                      WHERE r.rowid > ?1 AND j.state = ?2 AND j.expires_at_unix > ?3
                        AND j.attachment_digest = r.attachment_digest
                        AND j.lease_generation = r.lease_generation
                      ORDER BY r.rowid ASC
                      LIMIT 1",
                    params![rowid_cursor, STATE_COMPLETED, now],
                    |row| Ok((row.get::<_, i64>(12)?, read_result(row)?)),
                )
                .optional()
                .map_err(|error| sqlite_storage_error("completed_result_after", error))?;
            let Some((rowid, result)) = next else {
                return Ok((rowid_cursor, None));
            };
            if rowid <= rowid_cursor {
                return Err(GatewayAdmissionError::InvalidState);
            }
            rowid_cursor = rowid;
            if self
                .configured_requesters
                .contains(&result.requester_source_hash())
            {
                return Ok((rowid, Some(result)));
            }
        }
    }

    fn transition(&mut self, lease: &GatewayLease, to: i64) -> Result<(), GatewayAdmissionError> {
        if !self
            .configured_requesters
            .contains(&lease.job.requester_source_hash)
        {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE gateway_jobs
                    SET state = ?1, lease_until_unix = NULL
                  WHERE requester = ?2 AND request_id = ?3
                    AND attachment_digest = ?4 AND state = ?5
                    AND lease_generation = ?6",
                params![
                    to,
                    lease.job.requester_source_hash.as_slice(),
                    lease.job.request_id.as_slice(),
                    lease.job.attachment_digest.as_slice(),
                    STATE_LEASED,
                    to_sql_time(lease.generation)?
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(GatewayAdmissionError::InvalidState)
        }
    }

    /// Redact expired attachments and retain only a bounded replay tombstone.
    ///
    /// Services should call this periodically. It never changes unexpired
    /// work and cannot make delivery or RPC observations authoritative.
    pub fn prune_expired(
        &mut self,
        now_unix: u64,
        replay_retention_seconds: u64,
    ) -> Result<(), GatewayAdmissionError> {
        if !(MIN_REPLAY_RETENTION_SECONDS..=MAX_REPLAY_RETENTION_SECONDS)
            .contains(&replay_retention_seconds)
        {
            return Err(GatewayAdmissionError::InvalidState);
        }
        let now = to_sql_time(now_unix)?;
        let cutoff = to_sql_time(now_unix.saturating_sub(replay_retention_seconds))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .execute(
                "DELETE FROM gateway_job_results
                  WHERE (requester, request_id) IN
                        (SELECT requester, request_id FROM gateway_jobs
                          WHERE expires_at_unix <= ?1)",
                [now],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .execute(
                "UPDATE gateway_jobs
                    SET attachment = X'', state = 3, lease_until_unix = NULL
                  WHERE expires_at_unix <= ?1 AND state != 3",
                [now],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .execute(
                "DELETE FROM gateway_jobs WHERE state = 3 AND expires_at_unix <= ?1",
                [cutoff],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .commit()
            .map_err(|_| GatewayAdmissionError::Storage)
    }

    fn charge_attempt(
        &mut self,
        requester: [u8; 16],
        now_unix: u64,
    ) -> Result<(), GatewayAdmissionError> {
        let now = to_sql_time(now_unix)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let current = transaction
            .query_row(
                "SELECT window_started_unix, request_count, requested_bytes
                   FROM gateway_rate_windows WHERE requester = ?1",
                [requester.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let (started, count, bytes) = match current {
            Some((started, count, bytes))
                if now.saturating_sub(started)
                    < i64::try_from(self.limit.window_seconds)
                        .map_err(|_| GatewayAdmissionError::InvalidState)? =>
            {
                (started, count, bytes)
            }
            _ => (now, 0, 0),
        };
        let next = count.checked_add(1).ok_or(GatewayAdmissionError::Message(
            GatewayMessageError::RateLimited,
        ))?;
        if next > i64::from(self.limit.maximum_requests) {
            return Err(GatewayAdmissionError::Message(
                GatewayMessageError::RateLimited,
            ));
        }
        transaction
            .execute(
                "INSERT INTO gateway_rate_windows
                    (requester, window_started_unix, request_count, requested_bytes)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(requester) DO UPDATE SET
                    window_started_unix = excluded.window_started_unix,
                    request_count = excluded.request_count,
                    requested_bytes = excluded.requested_bytes",
                params![requester.as_slice(), started, next, bytes],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .commit()
            .map_err(|_| GatewayAdmissionError::Storage)
    }

    fn charge_approval_bytes(
        &mut self,
        requester: [u8; 16],
        wire_bytes: u64,
    ) -> Result<(), GatewayAdmissionError> {
        let wire_bytes =
            i64::try_from(wire_bytes).map_err(|_| GatewayAdmissionError::InvalidState)?;
        let changed = self
            .connection
            .execute(
                "UPDATE gateway_rate_windows
                    SET requested_bytes = requested_bytes + ?1
                  WHERE requester = ?2
                    AND requested_bytes <= ?3 - ?1",
                params![
                    wire_bytes,
                    requester.as_slice(),
                    i64::try_from(self.limit.maximum_requested_bytes)
                        .map_err(|_| GatewayAdmissionError::InvalidState)?,
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(GatewayAdmissionError::Message(
                GatewayMessageError::RateLimited,
            ))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_or_find(
        &mut self,
        requester: [u8; 16],
        request_id: [u8; 16],
        digest: [u8; 32],
        attachment: &[u8],
        kind: GatewayJobKind,
        expires_at_unix: u64,
        requested_bytes: u64,
        now_unix: u64,
    ) -> Result<InsertResult, GatewayAdmissionError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let existing = transaction
            .query_row(
                "SELECT attachment_digest, state FROM gateway_jobs
                  WHERE requester = ?1 AND request_id = ?2",
                params![requester.as_slice(), request_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        if let Some((existing_digest, state)) = existing {
            if existing_digest.as_slice() != digest {
                return Err(GatewayAdmissionError::ReplayConflict);
            }
            let state = GatewayJobState::from_sql(state)?;
            transaction
                .commit()
                .map_err(|_| GatewayAdmissionError::Storage)?;
            return Ok(InsertResult::Duplicate(state));
        }

        let current_bytes = transaction
            .query_row(
                "SELECT requested_bytes FROM gateway_rate_windows WHERE requester = ?1",
                [requester.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        let requested_bytes =
            i64::try_from(requested_bytes).map_err(|_| GatewayAdmissionError::InvalidState)?;
        let next_bytes =
            current_bytes
                .checked_add(requested_bytes)
                .ok_or(GatewayAdmissionError::Message(
                    GatewayMessageError::RateLimited,
                ))?;
        if next_bytes
            > i64::try_from(self.limit.maximum_requested_bytes)
                .map_err(|_| GatewayAdmissionError::InvalidState)?
        {
            return Err(GatewayAdmissionError::Message(
                GatewayMessageError::RateLimited,
            ));
        }
        transaction
            .execute(
                "UPDATE gateway_rate_windows SET requested_bytes = ?1 WHERE requester = ?2",
                params![next_bytes, requester.as_slice()],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .execute(
                "INSERT INTO gateway_jobs
                    (requester, request_id, attachment_digest, attachment, kind, state,
                     first_seen_unix, expires_at_unix, lease_until_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, NULL)",
                params![
                    requester.as_slice(),
                    request_id.as_slice(),
                    digest.as_slice(),
                    attachment,
                    kind.as_sql(),
                    to_sql_time(now_unix)?,
                    to_sql_time(expires_at_unix)?
                ],
            )
            .map_err(|_| GatewayAdmissionError::Storage)?;
        transaction
            .commit()
            .map_err(|_| GatewayAdmissionError::Storage)?;
        Ok(InsertResult::Queued(GatewayJob {
            requester_source_hash: requester,
            request_id,
            attachment_digest: digest,
            attachment: attachment.to_vec(),
            kind,
            state: GatewayJobState::Pending,
            expires_at_unix,
        }))
    }
}

enum InsertResult {
    Queued(GatewayJob),
    Duplicate(GatewayJobState),
}

fn validate_configuration(
    configured: &HashSet<[u8; 16]>,
    limit: GatewayRateLimit,
) -> Result<(), GatewayAdmissionError> {
    if configured.is_empty()
        || configured.contains(&[0; 16])
        || limit.window_seconds == 0
        || limit.maximum_requests == 0
        || limit.maximum_requested_bytes == 0
        || limit.maximum_requested_bytes > 64 * 1024 * 1024
        || i64::try_from(limit.window_seconds).is_err()
        || i64::try_from(limit.maximum_requested_bytes).is_err()
    {
        return Err(GatewayAdmissionError::InvalidState);
    }
    Ok(())
}

fn validate_result_schema(connection: &Connection) -> Result<(), GatewayAdmissionError> {
    const EXPECTED: &[&str] = &[
        "requester",
        "request_id",
        "attachment_digest",
        "lease_generation",
        "kind",
        "manifest_digest",
        "manifest",
        "response_digest",
        "response",
        "completed_at_unix",
    ];
    let mut statement = connection
        .prepare("PRAGMA table_info(gateway_job_results)")
        .map_err(|_| GatewayAdmissionError::Storage)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| GatewayAdmissionError::Storage)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| GatewayAdmissionError::Storage)?;
    if columns
        .iter()
        .map(String::as_str)
        .eq(EXPECTED.iter().copied())
    {
        Ok(())
    } else {
        Err(GatewayAdmissionError::InvalidState)
    }
}

fn to_sql_time(value: u64) -> Result<i64, GatewayAdmissionError> {
    i64::try_from(value).map_err(|_| GatewayAdmissionError::InvalidState)
}

struct StoredGatewayJob {
    public: GatewayJob,
    lease_generation: u64,
}

impl StoredGatewayJob {
    fn into_public(self) -> GatewayJob {
        self.public
    }
}

fn read_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredGatewayJob> {
    let requester = fixed::<16>(row.get(0)?)?;
    let request_id = fixed::<16>(row.get(1)?)?;
    let digest = fixed::<32>(row.get(2)?)?;
    let attachment: Vec<u8> = row.get(3)?;
    let kind_value: i64 = row.get(4)?;
    let state_value: i64 = row.get(5)?;
    let expires: i64 = row.get(6)?;
    let lease_generation = u64::try_from(row.get::<_, i64>(7)?).map_err(|_| invalid_sql_state())?;
    if <[u8; 32]>::from(Sha256::digest(&attachment)) != digest {
        return Err(invalid_sql_state());
    }
    let expires_at_unix = u64::try_from(expires).map_err(|_| invalid_sql_state())?;
    let kind = match decode(&attachment).map_err(|_| invalid_sql_state())? {
        Message::EvidenceRequest(request) => (kind_value == KIND_EVIDENCE
            && request.request_id == request_id
            && request.expires_at_unix == expires_at_unix)
            .then_some(GatewayJobKind::Evidence),
        Message::SignedRelay(relay) => (kind_value == KIND_RELAY
            && relay.request_id == request_id
            && relay.expires_at_unix == expires_at_unix)
            .then_some(GatewayJobKind::SignedRelay),
        Message::TransactionStatus(request) => (kind_value == KIND_RELAY
            && request.request_id == request_id
            && request.expires_at_unix == expires_at_unix)
            .then_some(GatewayJobKind::TransactionStatus),
        Message::BulkApproval(_) | Message::Other => None,
    };
    let kind = kind.ok_or_else(invalid_sql_state)?;
    Ok(StoredGatewayJob {
        public: GatewayJob {
            requester_source_hash: requester,
            request_id,
            attachment_digest: digest,
            attachment,
            kind,
            state: GatewayJobState::from_sql(state_value).map_err(|_| invalid_sql_state())?,
            expires_at_unix,
        },
        lease_generation,
    })
}

fn read_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<GatewayStoredResult> {
    let requester_source_hash = fixed::<16>(row.get(0)?)?;
    let request_id = fixed::<16>(row.get(1)?)?;
    let attachment_digest = fixed::<32>(row.get(2)?)?;
    let lease_generation = u64::try_from(row.get::<_, i64>(3)?).map_err(|_| invalid_sql_state())?;
    let result_kind_value: i64 = row.get(4)?;
    let manifest_digest = fixed::<32>(row.get(5)?)?;
    let manifest: Vec<u8> = row.get(6)?;
    let response_digest = fixed::<32>(row.get(7)?)?;
    let response: Vec<u8> = row.get(8)?;
    let completed_at_unix =
        u64::try_from(row.get::<_, i64>(9)?).map_err(|_| invalid_sql_state())?;
    let job_kind_value: i64 = row.get(10)?;
    let retained_attachment: Vec<u8> = row.get(11)?;
    let job_kind = match decode(&retained_attachment).map_err(|_| invalid_sql_state())? {
        Message::EvidenceRequest(_) if job_kind_value == KIND_EVIDENCE => GatewayJobKind::Evidence,
        Message::SignedRelay(_) if job_kind_value == KIND_RELAY => GatewayJobKind::SignedRelay,
        Message::TransactionStatus(_) if job_kind_value == KIND_RELAY => {
            GatewayJobKind::TransactionStatus
        }
        _ => return Err(invalid_sql_state()),
    };
    let kind = match job_kind {
        GatewayJobKind::TransactionStatus if result_kind_value == 2 => {
            GatewayResultKind::TransactionStatus
        }
        GatewayJobKind::TransactionStatus if result_kind_value == 4 => {
            GatewayResultKind::PermanentFailure
        }
        GatewayJobKind::TransactionStatus => return Err(invalid_sql_state()),
        _ => GatewayResultKind::from_sql(result_kind_value).map_err(|_| invalid_sql_state())?,
    };
    if manifest.len().saturating_add(response.len()) > MAX_STORED_RESULT_BYTES
        || <[u8; 32]>::from(Sha256::digest(&retained_attachment)) != attachment_digest
        || <[u8; 32]>::from(Sha256::digest(&manifest)) != manifest_digest
        || <[u8; 32]>::from(Sha256::digest(&response)) != response_digest
        || !matches!(
            (job_kind, kind),
            (GatewayJobKind::Evidence, GatewayResultKind::Evidence)
                | (
                    GatewayJobKind::Evidence,
                    GatewayResultKind::PermanentFailure
                )
                | (
                    GatewayJobKind::SignedRelay,
                    GatewayResultKind::RelayAccepted
                )
                | (
                    GatewayJobKind::SignedRelay,
                    GatewayResultKind::RelayRejected
                )
                | (
                    GatewayJobKind::SignedRelay,
                    GatewayResultKind::PermanentFailure
                )
                | (
                    GatewayJobKind::TransactionStatus,
                    GatewayResultKind::TransactionStatus
                )
                | (
                    GatewayJobKind::TransactionStatus,
                    GatewayResultKind::PermanentFailure
                )
        )
        || (kind == GatewayResultKind::Evidence && manifest.is_empty())
        || (kind != GatewayResultKind::Evidence && !manifest.is_empty())
        || (kind == GatewayResultKind::PermanentFailure && !response.is_empty())
        || (kind != GatewayResultKind::PermanentFailure && response.is_empty())
        || !stored_frames_match_request(job_kind, kind, &retained_attachment, &manifest, &response)
    {
        return Err(invalid_sql_state());
    }
    Ok(GatewayStoredResult {
        requester_source_hash,
        request_id,
        attachment_digest,
        lease_generation,
        kind,
        manifest_digest,
        manifest,
        response_digest,
        response,
        completed_at_unix,
    })
}

fn stored_frames_match_request(
    job_kind: GatewayJobKind,
    result_kind: GatewayResultKind,
    retained_attachment: &[u8],
    manifest: &[u8],
    response: &[u8],
) -> bool {
    match (decode(retained_attachment), job_kind, result_kind) {
        (
            Ok(Message::EvidenceRequest(request)),
            GatewayJobKind::Evidence,
            GatewayResultKind::Evidence,
        ) => evidence_frames_match(&request, manifest, response),
        (
            Ok(Message::EvidenceRequest(_)),
            GatewayJobKind::Evidence,
            GatewayResultKind::PermanentFailure,
        )
        | (
            Ok(Message::SignedRelay(_)),
            GatewayJobKind::SignedRelay,
            GatewayResultKind::PermanentFailure,
        ) => manifest.is_empty() && response.is_empty(),
        (
            Ok(Message::TransactionStatus(_)),
            GatewayJobKind::TransactionStatus,
            GatewayResultKind::PermanentFailure,
        ) => manifest.is_empty() && response.is_empty(),
        (
            Ok(Message::SignedRelay(relay)),
            GatewayJobKind::SignedRelay,
            GatewayResultKind::RelayAccepted,
        ) => relay_frame_matches(&relay, response, RelayObservation::RpcAccepted),
        (
            Ok(Message::SignedRelay(relay)),
            GatewayJobKind::SignedRelay,
            GatewayResultKind::RelayRejected,
        ) => relay_frame_matches(&relay, response, RelayObservation::RpcRejected),
        (
            Ok(Message::TransactionStatus(request)),
            GatewayJobKind::TransactionStatus,
            GatewayResultKind::TransactionStatus,
        ) => transaction_status_frame_matches(&request, response),
        _ => false,
    }
}

fn transaction_status_frame_matches(
    request: &super::AcceptedTransactionStatusRequest,
    bytes: &[u8],
) -> bool {
    let Ok(mut cursor) = result_cursor(bytes, super::KIND_TRANSACTION_STATUS_OBSERVATION) else {
        return false;
    };
    let parsed = (|| {
        let request_id = cursor.array::<16>()?;
        let tx_hash = cursor.array::<32>()?;
        let presence = TransactionPresence::from_wire(cursor.u8()?)?;
        let included_number = cursor.u64()?;
        let included_hash = cursor.array::<32>()?;
        let latest = super::TransactionStatusHead::new(cursor.u64()?, cursor.array()?)?;
        let safe = super::TransactionStatusHead::new(cursor.u64()?, cursor.array()?)?;
        let finalized = super::TransactionStatusHead::new(cursor.u64()?, cursor.array()?)?;
        cursor.finish()?;
        super::TransactionStatusObservation::new(
            tx_hash,
            presence,
            included_number,
            included_hash,
            latest,
            safe,
            finalized,
        )?;
        Ok::<_, GatewayMessageError>(request_id == request.request_id && tx_hash == request.tx_hash)
    })();
    parsed == Ok(true)
}

fn evidence_frames_match(
    request: &super::AcceptedEvidenceRequest,
    manifest: &[u8],
    response: &[u8],
) -> bool {
    let Ok((manifest_request, manifest_kind, manifest_context, manifest_digest, manifest_size)) =
        decode_manifest_frame(manifest)
    else {
        return false;
    };
    let Ok(decoded_response) = decode_evidence_frame(response) else {
        return false;
    };
    if manifest_request != request.request_id
        || decoded_response.request_id != request.request_id
        || manifest_kind != request.evidence_kind
        || manifest_context != request.checkpoint_context
        || decoded_response.kind != request.evidence_kind
        || decoded_response.checkpoint_context != request.checkpoint_context
        || manifest_digest != decoded_response.digest
        || usize::try_from(manifest_size).ok() != Some(decoded_response.bundle.len())
        || <[u8; 32]>::from(Sha256::digest(decoded_response.bundle)) != decoded_response.digest
    {
        return false;
    }
    let kind = match request.evidence_kind {
        MessagingEvidenceKind::Consensus => GatewayBundleKind::ConsensusBootstrap,
        MessagingEvidenceKind::ExecutionHeader => GatewayBundleKind::ExecutionHeader,
        MessagingEvidenceKind::AccountProof => GatewayBundleKind::AccountProof,
        MessagingEvidenceKind::ReceiptProof => GatewayBundleKind::TxReceiptProof,
        MessagingEvidenceKind::AccountStatePackage => GatewayBundleKind::AccountStateEvidence,
        MessagingEvidenceKind::FinalizedReceiptPackage => {
            GatewayBundleKind::FinalizedReceiptEvidence
        }
    };
    super::validate_bundle_for_request(
        request,
        &GatewayBundle {
            kind,
            bytes: decoded_response.bundle.to_vec(),
        },
        false,
    )
    .is_ok()
}

type DecodedManifestFrame = (
    [u8; 16],
    MessagingEvidenceKind,
    Option<super::EvidenceCheckpointContext>,
    [u8; 32],
    u32,
);

fn decode_manifest_frame(bytes: &[u8]) -> Result<DecodedManifestFrame, GatewayMessageError> {
    let mut cursor = result_cursor(bytes, super::KIND_EVIDENCE_MANIFEST)?;
    let request_id = cursor.array()?;
    let kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
    let checkpoint_context = super::decode_checkpoint_context(&mut cursor, kind)?;
    let digest = cursor.array()?;
    let size = cursor.u32()?;
    cursor.finish()?;
    Ok((request_id, kind, checkpoint_context, digest, size))
}

fn decode_evidence_frame(bytes: &[u8]) -> Result<DecodedEvidenceFrame<'_>, GatewayMessageError> {
    let mut cursor = result_cursor(bytes, super::KIND_EVIDENCE_RESPONSE)?;
    let request_id = cursor.array()?;
    let kind = MessagingEvidenceKind::from_wire(cursor.u8()?)?;
    let checkpoint_context = super::decode_checkpoint_context(&mut cursor, kind)?;
    let digest = cursor.array()?;
    let size = cursor.u32()? as usize;
    let bundle = cursor.take(size)?;
    cursor.finish()?;
    Ok(DecodedEvidenceFrame {
        request_id,
        kind,
        checkpoint_context,
        digest,
        bundle,
    })
}

struct DecodedEvidenceFrame<'a> {
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    checkpoint_context: Option<super::EvidenceCheckpointContext>,
    digest: [u8; 32],
    bundle: &'a [u8],
}

fn relay_frame_matches(
    relay: &super::AcceptedSignedRelay,
    bytes: &[u8],
    expected: RelayObservation,
) -> bool {
    let Ok(mut cursor) = result_cursor(bytes, super::KIND_RELAY_OBSERVATION) else {
        return false;
    };
    matches!(
        (cursor.array::<16>(), cursor.array::<32>(), cursor.u8(), cursor.finish()),
        (Ok(request_id), Ok(tx_hash), Ok(observation), Ok(()))
            if request_id == relay.request_id
                && tx_hash == relay.tx_hash
                && observation == expected.wire()
    )
}

fn result_cursor(
    bytes: &[u8],
    expected_kind: u8,
) -> Result<super::Cursor<'_>, GatewayMessageError> {
    let mut cursor = super::Cursor::new(bytes);
    if cursor.take(7)? != super::MAGIC
        || cursor.u8()? != super::VERSION
        || cursor.u64()? != ratspeak_eth_verifier::SEPOLIA_CHAIN_ID
        || cursor.u8()? != expected_kind
    {
        return Err(GatewayMessageError::InvalidMessage);
    }
    Ok(cursor)
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| invalid_sql_state())
}

fn invalid_sql_state() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::{
        AuthenticatedGatewayEnvelope, MessagingEvidenceKind, encode_test_evidence_request,
    };

    fn open(
        directory: &tempfile::TempDir,
        requester: [u8; 16],
        limit: GatewayRateLimit,
    ) -> DurableGatewayAdmission {
        DurableGatewayAdmission::open(&directory.path().join("gateway.sqlite"), [requester], limit)
            .unwrap()
    }

    fn request(id: [u8; 16], budget: u32) -> Vec<u8> {
        encode_test_evidence_request(
            id,
            MessagingEvidenceKind::ReceiptProof,
            [4; 32],
            budget,
            true,
            1_000,
        )
    }

    #[test]
    fn configured_identity_check_precedes_storage_and_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let mut store =
            DurableGatewayAdmission::open(&path, [[1; 16]], GatewayRateLimit::conservative())
                .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf([2; 16], b"garbage"),
                    10,
                )
                .unwrap(),
            DurableGatewayOutcome::IgnoredUnauthenticated
        );
    }

    #[test]
    fn malformed_attempt_limit_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 1,
            maximum_requested_bytes: 100,
        };
        let mut first = open(&directory, requester, limit);
        assert_eq!(
            first
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, b"garbage"),
                    10,
                )
                .unwrap_err(),
            GatewayAdmissionError::Message(GatewayMessageError::InvalidMessage)
        );
        drop(first);
        let mut reopened = open(&directory, requester, limit);
        assert_eq!(
            reopened
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(
                        requester,
                        &request([3; 16], 100)
                    ),
                    11,
                )
                .unwrap_err(),
            GatewayAdmissionError::Message(GatewayMessageError::RateLimited)
        );
    }

    #[test]
    fn exact_duplicate_is_idempotent_but_conflict_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let limit = GatewayRateLimit::conservative();
        let mut store = open(&directory, requester, limit);
        let first = request([3; 16], 100);
        assert!(matches!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &first),
                    10,
                )
                .unwrap(),
            DurableGatewayOutcome::Queued(_)
        ));
        drop(store);
        let mut store = open(&directory, requester, limit);
        assert_eq!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &first),
                    11,
                )
                .unwrap(),
            DurableGatewayOutcome::Duplicate(GatewayJobState::Pending)
        );
        let conflict = request([3; 16], 101);
        assert_eq!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &conflict),
                    12,
                )
                .unwrap_err(),
            GatewayAdmissionError::ReplayConflict
        );
    }

    #[test]
    fn removed_requester_cannot_recover_or_mutate_retained_work() {
        let directory = tempfile::tempdir().unwrap();
        let first_requester = [1; 16];
        let second_requester = [2; 16];
        let limit = GatewayRateLimit::conservative();
        let mut first = open(&directory, first_requester, limit);
        match first
            .admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(
                    first_requester,
                    &request([3; 16], 100),
                ),
                10,
            )
            .unwrap()
        {
            DurableGatewayOutcome::Queued(_) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
        let lease = first.lease_next(first_requester, 11, 30).unwrap().unwrap();
        drop(first);

        let mut reopened = open(&directory, second_requester, limit);
        assert_eq!(
            reopened.lease_next(first_requester, 11, 30).unwrap_err(),
            GatewayAdmissionError::InvalidState
        );
        assert!(
            reopened
                .lease_next(second_requester, 11, 30)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened.complete(&lease).unwrap_err(),
            GatewayAdmissionError::InvalidState
        );
    }

    #[test]
    fn pending_work_is_leased_completed_and_remains_durable() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let limit = GatewayRateLimit::conservative();
        let mut store = open(&directory, requester, limit);
        let bytes = request([3; 16], 100);
        let queued = match store
            .admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                10,
            )
            .unwrap()
        {
            DurableGatewayOutcome::Queued(job) => job,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let leased = store.lease_next(requester, 11, 30).unwrap().unwrap();
        assert_eq!(leased.job().attachment_len(), bytes.len());
        assert_eq!(leased.job().state(), GatewayJobState::Leased);
        assert!(matches!(
            leased.validated_message().unwrap(),
            GatewayMessageOutcome::EvidenceRequest(_)
        ));
        assert!(store.lease_next(requester, 12, 30).unwrap().is_none());
        drop(store);

        let mut reopened = open(&directory, requester, limit);
        assert!(reopened.lease_next(requester, 20, 30).unwrap().is_none());
        let reclaimed = reopened.lease_next(requester, 42, 30).unwrap().unwrap();
        assert_eq!(
            reclaimed.job().attachment_digest(),
            queued.attachment_digest()
        );
        reopened.complete(&reclaimed).unwrap();
        assert!(reopened.lease_next(requester, 43, 30).unwrap().is_none());
        assert_eq!(
            reopened
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                    44,
                )
                .unwrap(),
            DurableGatewayOutcome::Duplicate(GatewayJobState::Completed)
        );
    }

    #[test]
    fn reclaimed_lease_rejects_stale_owner_and_release_requeues() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let bytes = request([3; 16], 100);
        match store
            .admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                10,
            )
            .unwrap()
        {
            DurableGatewayOutcome::Queued(_) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
        let stale = store.lease_next(requester, 11, 1).unwrap().unwrap();
        let current = store.lease_next(requester, 13, 30).unwrap().unwrap();
        assert_eq!(
            store.release(&stale).unwrap_err(),
            GatewayAdmissionError::InvalidState
        );
        store.release(&current).unwrap();
        assert!(store.lease_next(requester, 14, 30).unwrap().is_some());
    }

    #[test]
    fn stale_lease_cannot_persist_or_replace_a_generation_bound_result() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let bytes = request([3; 16], 100);
        assert!(matches!(
            store.admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                10,
            ),
            Ok(DurableGatewayOutcome::Queued(_))
        ));
        let stale = store.lease_next(requester, 11, 1).unwrap().unwrap();
        let current = store.lease_next(requester, 13, 30).unwrap().unwrap();
        assert_eq!(
            store
                .complete_with_result(&stale, GatewayResultKind::PermanentFailure, &[], &[], 13,)
                .unwrap_err(),
            GatewayAdmissionError::InvalidState
        );
        let stored = store
            .complete_with_result(&current, GatewayResultKind::PermanentFailure, &[], &[], 13)
            .unwrap();
        assert_eq!(stored.lease_generation(), 2);
        assert!(stored.response().is_empty());
        assert!(stored.manifest().is_empty());
        let rendered = format!("{stored:?}");
        assert!(!rendered.contains(&alloy_primitives::hex::encode([3; 16])));
        assert_eq!(
            store.completed_result(requester, [3; 16]).unwrap().unwrap(),
            stored
        );
    }

    #[test]
    fn deferred_work_and_result_integrity_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let bytes = request([3; 16], 100);
        assert!(matches!(
            store.admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                10,
            ),
            Ok(DurableGatewayOutcome::Queued(_))
        ));
        let lease = store.lease_next(requester, 11, 30).unwrap().unwrap();
        store.defer_until(&lease, 20).unwrap();
        drop(store);

        let mut reopened =
            DurableGatewayAdmission::open(&path, [requester], GatewayRateLimit::conservative())
                .unwrap();
        assert!(reopened.lease_next(requester, 19, 30).unwrap().is_none());
        let lease = reopened.lease_next(requester, 20, 30).unwrap().unwrap();
        reopened
            .complete_with_result(&lease, GatewayResultKind::PermanentFailure, &[], &[], 20)
            .unwrap();
        reopened
            .connection
            .execute(
                "UPDATE gateway_job_results SET response = X'00' WHERE request_id = ?1",
                [[3; 16].as_slice()],
            )
            .unwrap();
        assert_eq!(
            reopened.completed_result(requester, [3; 16]).unwrap_err(),
            GatewayAdmissionError::Storage
        );
    }

    #[test]
    fn schema_one_store_is_migrated_without_losing_admitted_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let requester = [1; 16];
        {
            let mut store = open(&directory, requester, GatewayRateLimit::conservative());
            let bytes = request([3; 16], 100);
            assert!(matches!(
                store.admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                    10,
                ),
                Ok(DurableGatewayOutcome::Queued(_))
            ));
            store
                .connection
                .execute("UPDATE gateway_schema SET version = 1", [])
                .unwrap();
            store
                .connection
                .execute("DROP TABLE gateway_job_results", [])
                .unwrap();
        }
        let mut migrated =
            DurableGatewayAdmission::open(&path, [requester], GatewayRateLimit::conservative())
                .unwrap();
        assert!(migrated.lease_next(requester, 11, 30).unwrap().is_some());
        let version: i64 = migrated
            .connection
            .query_row("SELECT version FROM gateway_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn response_only_schema_two_requeues_exact_completed_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let requester = [1; 16];
        let request_id = [3; 16];
        let attachment = request(request_id, 100);
        let attachment_digest: [u8; 32] = Sha256::digest(&attachment).into();
        let old_response = b"response-without-required-manifest";
        let old_response_digest: [u8; 32] = Sha256::digest(old_response).into();
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE gateway_schema (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        version INTEGER NOT NULL
                     );
                     INSERT INTO gateway_schema VALUES (1, 2);
                     CREATE TABLE gateway_jobs (
                        requester BLOB NOT NULL CHECK (length(requester) = 16),
                        request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                        attachment_digest BLOB NOT NULL CHECK (length(attachment_digest) = 32),
                        attachment BLOB NOT NULL,
                        kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
                        state INTEGER NOT NULL CHECK (state IN (0, 1, 2, 3)),
                        first_seen_unix INTEGER NOT NULL CHECK (first_seen_unix >= 0),
                        expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix > 0),
                        lease_until_unix INTEGER,
                        lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
                        PRIMARY KEY (requester, request_id)
                     );
                     CREATE TABLE gateway_job_results (
                        requester BLOB NOT NULL CHECK (length(requester) = 16),
                        request_id BLOB NOT NULL CHECK (length(request_id) = 16),
                        attachment_digest BLOB NOT NULL CHECK (length(attachment_digest) = 32),
                        lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                        kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3, 4)),
                        response_digest BLOB NOT NULL CHECK (length(response_digest) = 32),
                        response BLOB NOT NULL,
                        completed_at_unix INTEGER NOT NULL CHECK (completed_at_unix >= 0),
                        PRIMARY KEY (requester, request_id),
                        FOREIGN KEY (requester, request_id)
                            REFERENCES gateway_jobs (requester, request_id) ON DELETE CASCADE
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO gateway_jobs
                        (requester, request_id, attachment_digest, attachment, kind, state,
                         first_seen_unix, expires_at_unix, lease_until_unix, lease_generation)
                     VALUES (?1, ?2, ?3, ?4, 1, 2, 10, 1000, NULL, 1)",
                    params![
                        requester.as_slice(),
                        request_id.as_slice(),
                        attachment_digest.as_slice(),
                        attachment.as_slice()
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO gateway_job_results
                        (requester, request_id, attachment_digest, lease_generation, kind,
                         response_digest, response, completed_at_unix)
                     VALUES (?1, ?2, ?3, 1, 1, ?4, ?5, 11)",
                    params![
                        requester.as_slice(),
                        request_id.as_slice(),
                        attachment_digest.as_slice(),
                        old_response_digest.as_slice(),
                        old_response.as_slice()
                    ],
                )
                .unwrap();
        }

        let mut migrated =
            DurableGatewayAdmission::open(&path, [requester], GatewayRateLimit::conservative())
                .unwrap();
        assert!(
            migrated
                .completed_result(requester, request_id)
                .unwrap()
                .is_none()
        );
        let lease = migrated.lease_next(requester, 12, 30).unwrap().unwrap();
        assert_eq!(lease.job().attachment_digest(), attachment_digest);
        assert_eq!(lease.generation, 2);
    }

    #[test]
    fn lease_revalidates_retained_authenticated_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let bytes = request([3; 16], 100);
        assert!(matches!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                    10,
                )
                .unwrap(),
            DurableGatewayOutcome::Queued(_)
        ));
        let mut corrupted = bytes;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        store
            .connection
            .execute(
                "UPDATE gateway_jobs SET attachment = ?1",
                [corrupted.as_slice()],
            )
            .unwrap();
        assert_eq!(
            store.lease_next(requester, 11, 30).unwrap_err(),
            GatewayAdmissionError::Storage
        );
    }

    #[test]
    fn debug_output_redacts_exact_attachment_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let bytes = request([3; 16], 100);
        let job = match store
            .admit_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &bytes),
                10,
            )
            .unwrap()
        {
            DurableGatewayOutcome::Queued(job) => job,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let rendered = format!("{job:?}");
        assert!(rendered.contains("attachment_len"));
        assert!(!rendered.contains(&alloy_primitives::hex::encode(bytes)));
    }

    #[test]
    fn future_lifetime_is_bounded_and_expired_bytes_are_pruned() {
        let directory = tempfile::tempdir().unwrap();
        let requester = [1; 16];
        let mut store = open(&directory, requester, GatewayRateLimit::conservative());
        let too_far = encode_test_evidence_request(
            [3; 16],
            MessagingEvidenceKind::ReceiptProof,
            [4; 32],
            100,
            true,
            10 + MAX_REQUEST_LIFETIME_SECONDS + 1,
        );
        assert_eq!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &too_far),
                    10,
                )
                .unwrap_err(),
            GatewayAdmissionError::Message(GatewayMessageError::InvalidMessage)
        );

        let valid = request([5; 16], 100);
        assert!(matches!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(requester, &valid),
                    11,
                )
                .unwrap(),
            DurableGatewayOutcome::Queued(_)
        ));
        store
            .prune_expired(1_000, MIN_REPLAY_RETENTION_SECONDS)
            .unwrap();
        let (state, attachment_len): (i64, i64) = store
            .connection
            .query_row(
                "SELECT state, length(attachment) FROM gateway_jobs WHERE request_id = ?1",
                [[5; 16].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, STATE_EXPIRED);
        assert_eq!(attachment_len, 0);
        store
            .prune_expired(
                1_000 + MIN_REPLAY_RETENTION_SECONDS,
                MIN_REPLAY_RETENTION_SECONDS,
            )
            .unwrap();
        let retained: i64 = store
            .connection
            .query_row("SELECT count(*) FROM gateway_jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(retained, 0);
    }
}
