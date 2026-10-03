use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ratspeak_eth_verifier::{
    BeaconCheckpointRoot, MAX_BUNDLE_BYTES, ManualCheckpointFile, SEPOLIA_CHAIN_ID,
    SEPOLIA_NETWORK, VerifiedExecutionHeader, Verifier, manual_checkpoint_file_fingerprint,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{AssuranceSubjectKind, read_assurance_history};
use crate::checkpoint::{
    CheckpointApprovalWindow, latest_checkpoint_approval, read_checkpoint,
    record_checkpoint_approval_monotonic_in,
};
use crate::{
    AssuranceEventKind, CheckpointApproval, CheckpointApprovalBasis, CheckpointSourceAttestation,
    CheckpointSourceKind, EthereumNodeStore, NodeStoreError, StoredCheckpointApproval,
};

const SEPOLIA_GENESIS_TIME: u64 = 1_655_733_600;
const SECONDS_PER_SLOT: u64 = 12;
const SLOTS_PER_EPOCH: u64 = 32;
const MAX_CHECKPOINT_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
const MAX_OBSERVATION_AGE_SECONDS: u64 = 60 * 60;
const MAX_FUTURE_SKEW_SECONDS: u64 = 5 * 60;
const MAX_PROVIDER_CANDIDATES: usize = 16;
const MAX_PENDING_MANUAL_CHECKPOINT_REVIEWS: usize = 16;
const MAX_MANUAL_REVIEW_SECONDS: u64 = 10 * 60;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointPolicyError {
    #[error("checkpoint policy requires a valid local clock")]
    InvalidLocalClock,
    #[error("checkpoint source fingerprints must be nonzero and unique")]
    InvalidProviderConfiguration,
    #[error("checkpoint candidate is malformed or exceeds its bound")]
    InvalidCandidate,
    #[error("checkpoint observation is newer than the trusted local clock")]
    FutureObservation,
    #[error("checkpoint observation is too old for automated or manual approval")]
    StaleObservation,
    #[error("checkpoint epoch is newer than the trusted local clock")]
    FutureCheckpoint,
    #[error("checkpoint epoch exceeds the 14-day weak-subjectivity policy")]
    StaleCheckpoint,
    #[error("checkpoint candidate was not produced by a configured provider source")]
    UnconfiguredProvider,
    #[error("provider agreement requires two distinct configured operator identities")]
    InsufficientOperatorAgreement,
    #[error("provider observations disagree on exact checkpoint epoch/root")]
    ProviderMismatch,
    #[error("one configured provider source appears more than once")]
    DuplicateProviderObservation,
    #[error("checkpoint bootstrap must contain only the canonical bootstrap, not updates")]
    BootstrapContainsUpdates,
    #[error("checkpoint epoch does not match the Helios-verified bootstrap slot")]
    BootstrapEpochMismatch,
    #[error("checkpoint would roll back the latest installed epoch")]
    CheckpointRollback,
    #[error("checkpoint root is already bound to a different epoch")]
    RootEpochConflict,
    #[error("checkpoint epoch is already bound to a different root")]
    EpochRootConflict,
    #[error("checkpoint is already installed and cannot be relabelled by manual approval")]
    CheckpointAlreadyInstalled,
    #[error("manual checkpoint review is already pending or was already consumed")]
    ReviewAlreadyExists,
    #[error("too many manual checkpoint reviews are awaiting native decisions")]
    ReviewQueueFull,
    #[error("manual checkpoint review is unknown or was already consumed")]
    ReviewUnavailable,
    #[error("manual checkpoint review no longer matches its durable candidate")]
    ReviewChanged,
    #[error("manual checkpoint review expired before approval completed")]
    ReviewExpired,
    #[error("checkpoint authority changed while native review was pending")]
    ReviewSuperseded,
    #[error("latest approved checkpoint has been revoked")]
    RevokedCheckpoint,
    #[error("no policy-approved checkpoint is installed")]
    NoApprovedCheckpoint,
    #[error("stored checkpoint does not satisfy its recorded approval policy")]
    CorruptApprovalPolicy,
    #[error("checkpoint bootstrap verification failed: {0}")]
    Verification(#[from] ratspeak_eth_verifier::VerifyError),
    #[error(transparent)]
    Store(#[from] NodeStoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum ManualCheckpointInstallError<E> {
    #[error(transparent)]
    Policy(#[from] CheckpointPolicyError),
    #[error("native checkpoint approval failed")]
    NativeApproval(E),
    #[error("native checkpoint approval was cancelled")]
    Cancelled,
}

impl<E> From<NodeStoreError> for ManualCheckpointInstallError<E> {
    fn from(error: NodeStoreError) -> Self {
        Self::Policy(CheckpointPolicyError::Store(error))
    }
}

/// Terminal outcome from one durable native checkpoint review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManualCheckpointReviewResolution {
    Approved,
    Denied,
}

/// One configured endpoint and the independently operated entity behind it.
///
/// The endpoint fingerprint identifies a specific configured source without
/// retaining its URL or credentials. Agreement counts distinct operator
/// fingerprints, never endpoint count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConfiguredCheckpointProvider {
    operator_fingerprint: [u8; 32],
    source_fingerprint: [u8; 32],
}

impl ConfiguredCheckpointProvider {
    pub fn new(
        operator_fingerprint: [u8; 32],
        source_fingerprint: [u8; 32],
    ) -> Result<Self, CheckpointPolicyError> {
        if operator_fingerprint == [0; 32] || source_fingerprint == [0; 32] {
            return Err(CheckpointPolicyError::InvalidProviderConfiguration);
        }
        Ok(Self {
            operator_fingerprint,
            source_fingerprint,
        })
    }

    pub fn operator_fingerprint(self) -> [u8; 32] {
        self.operator_fingerprint
    }

    pub fn source_fingerprint(self) -> [u8; 32] {
        self.source_fingerprint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManualCheckpointSource {
    Url,
    File,
    Qr,
}

impl ManualCheckpointSource {
    fn stored_kind(self) -> CheckpointSourceKind {
        match self {
            Self::Url => CheckpointSourceKind::ManualUrl,
            Self::File => CheckpointSourceKind::ManualFile,
            Self::Qr => CheckpointSourceKind::ManualQr,
        }
    }

    fn as_i64(self) -> i64 {
        match self {
            Self::Url => 1,
            Self::File => 2,
            Self::Qr => 3,
        }
    }

    fn from_i64(value: i64) -> Result<Self, NodeStoreError> {
        match value {
            1 => Ok(Self::Url),
            2 => Ok(Self::File),
            3 => Ok(Self::Qr),
            _ => Err(NodeStoreError::new(
                "invalid stored manual checkpoint source",
            )),
        }
    }
}

enum CandidateSource {
    Provider(ConfiguredCheckpointProvider),
    Manual {
        kind: ManualCheckpointSource,
        source_fingerprint: [u8; 32],
    },
}

/// Untrusted external observation. Constructing this value does not approve it.
///
/// Fetching a URL and scanning a QR code belong to native adapters; this type
/// carries their bounded bytes and secret-free source fingerprint only.
pub struct CheckpointCandidate {
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    bootstrap_bundle: Vec<u8>,
    observed_at_unix: u64,
    source: CandidateSource,
}

/// One independently sourced checkpoint-root observation. Bootstrap bytes are
/// deliberately absent: they may be downloaded from any untrusted Beacon API
/// after the independently operated sources agree on this exact epoch/root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointProviderObservation {
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    observed_at_unix: u64,
    provider: ConfiguredCheckpointProvider,
}

impl CheckpointProviderObservation {
    pub fn new(
        provider: ConfiguredCheckpointProvider,
        checkpoint_epoch: u64,
        checkpoint_root: [u8; 32],
        observed_at_unix: u64,
    ) -> Self {
        Self {
            checkpoint_epoch,
            checkpoint_root,
            observed_at_unix,
            provider,
        }
    }
}

impl CheckpointCandidate {
    /// Records bytes returned directly by a configured native provider adapter.
    ///
    /// Provider fingerprints are provenance labels, not response
    /// authentication. An incoming Ratspeak or gateway bundle must never be
    /// routed through this constructor; the application adapter is responsible
    /// for preserving that source boundary.
    pub fn from_provider(
        provider: ConfiguredCheckpointProvider,
        checkpoint_epoch: u64,
        checkpoint_root: [u8; 32],
        bootstrap_bundle: Vec<u8>,
        observed_at_unix: u64,
    ) -> Self {
        Self {
            checkpoint_epoch,
            checkpoint_root,
            bootstrap_bundle,
            observed_at_unix,
            source: CandidateSource::Provider(provider),
        }
    }

    pub fn from_manual_source(
        source: ManualCheckpointSource,
        source_fingerprint: [u8; 32],
        checkpoint_epoch: u64,
        checkpoint_root: [u8; 32],
        bootstrap_bundle: Vec<u8>,
        observed_at_unix: u64,
    ) -> Self {
        Self {
            checkpoint_epoch,
            checkpoint_root,
            bootstrap_bundle,
            observed_at_unix,
            source: CandidateSource::Manual {
                kind: source,
                source_fingerprint,
            },
        }
    }
}

impl fmt::Debug for CheckpointCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointCandidate")
            .field("checkpoint_epoch", &self.checkpoint_epoch)
            .field("checkpoint_root", &self.checkpoint_root)
            .field("bootstrap_bytes", &self.bootstrap_bundle.len())
            .field("observed_at_unix", &self.observed_at_unix)
            .finish_non_exhaustive()
    }
}

/// Exact validated values shown by the native manual-approval surface.
///
/// This is a borrowed review, not an approval token. It cannot be constructed
/// or retained to install another checkpoint.
pub struct ManualCheckpointReview<'a> {
    candidate: &'a CheckpointCandidate,
    source: ManualCheckpointSource,
    canonical_bootstrap_hash: [u8; 32],
    valid_until_unix: u64,
}

impl ManualCheckpointReview<'_> {
    pub fn checkpoint_epoch(&self) -> u64 {
        self.candidate.checkpoint_epoch
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.candidate.checkpoint_root
    }

    pub fn source(&self) -> ManualCheckpointSource {
        self.source
    }

    pub fn source_fingerprint(&self) -> [u8; 32] {
        match self.candidate.source {
            CandidateSource::Manual {
                source_fingerprint, ..
            } => source_fingerprint,
            CandidateSource::Provider(_) => unreachable!("manual reviews have a manual source"),
        }
    }

    pub fn canonical_bootstrap_hash(&self) -> [u8; 32] {
        self.canonical_bootstrap_hash
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.candidate.observed_at_unix
    }

    pub fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }
}

/// Redacted, profile-bound snapshot of one validated candidate awaiting a
/// native decision. All fields are private so application callers can select
/// a review, but cannot manufacture authoritative checkpoint or provenance
/// values for resolution.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingManualCheckpointReview {
    review_id: [u8; 32],
    profile_binding: [u8; 32],
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    source: ManualCheckpointSource,
    source_fingerprint: [u8; 32],
    canonical_bootstrap_hash: [u8; 32],
    observed_at_unix: u64,
    valid_until_unix: u64,
    expires_at_unix: u64,
    authority_binding: [u8; 32],
    candidate_digest: [u8; 32],
    binding_digest: [u8; 32],
}

impl PendingManualCheckpointReview {
    pub fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn source(&self) -> ManualCheckpointSource {
        self.source
    }

    pub fn source_fingerprint(&self) -> [u8; 32] {
        self.source_fingerprint
    }

    pub fn canonical_bootstrap_hash(&self) -> [u8; 32] {
        self.canonical_bootstrap_hash
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl fmt::Debug for PendingManualCheckpointReview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingManualCheckpointReview")
            .field("checkpoint_epoch", &self.checkpoint_epoch)
            .field("source", &self.source)
            .field("observed_at_unix", &self.observed_at_unix)
            .field("valid_until_unix", &self.valid_until_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

/// Synchronous native-only approval boundary. Returning `true` approves only
/// the borrowed review in this call; no reusable approval capability exists.
pub trait NativeCheckpointApproval {
    type Error;

    fn review_and_approve(
        &mut self,
        review: &ManualCheckpointReview<'_>,
    ) -> Result<bool, Self::Error>;
}

#[derive(Debug)]
pub struct CheckpointBootstrapPolicy {
    providers: Vec<ConfiguredCheckpointProvider>,
}

impl CheckpointBootstrapPolicy {
    pub fn new(
        providers: Vec<ConfiguredCheckpointProvider>,
    ) -> Result<Self, CheckpointPolicyError> {
        if providers.len() > MAX_PROVIDER_CANDIDATES {
            return Err(CheckpointPolicyError::InvalidProviderConfiguration);
        }
        let mut sources = HashSet::with_capacity(providers.len());
        if providers
            .iter()
            .any(|provider| !sources.insert(provider.source_fingerprint))
        {
            return Err(CheckpointPolicyError::InvalidProviderConfiguration);
        }
        Ok(Self { providers })
    }

    pub fn install_provider_agreement<'a>(
        &self,
        store: &'a mut EthereumNodeStore,
        candidates: &[CheckpointCandidate],
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        let now = trusted_now_unix()?;
        self.install_provider_agreement_with(store, candidates, now, &HeliosBootstrapValidator)
    }

    /// Installs a checkpoint only after independent sources agree on the root
    /// and a separately acquired light-client bootstrap verifies against it.
    /// The bootstrap transport is intentionally non-authoritative.
    pub fn install_provider_observation_agreement<'a>(
        &self,
        store: &'a mut EthereumNodeStore,
        observations: &[CheckpointProviderObservation],
        bootstrap_bundle: Vec<u8>,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        let now = trusted_now_unix()?;
        self.install_provider_observation_agreement_with(
            store,
            observations,
            bootstrap_bundle,
            now,
            &HeliosBootstrapValidator,
        )
    }

    /// Performs an immediate native-only decision for adapters that do not
    /// need restart persistence. Applications with an asynchronous UI should
    /// use `stage_manual_candidate` and `resolve_manual_checkpoint_review`.
    pub fn install_manual_candidate<'a, A: NativeCheckpointApproval>(
        &self,
        store: &'a mut EthereumNodeStore,
        candidate: &CheckpointCandidate,
        approver: &mut A,
    ) -> Result<ApprovedCheckpointAnchor<'a>, ManualCheckpointInstallError<A::Error>> {
        let now = trusted_now_unix()?;
        self.install_manual_with(store, candidate, approver, now, &HeliosBootstrapValidator)
    }

    /// Validates and durably stages one manual candidate for a later native
    /// decision. Provider observations are deliberately ineligible for this
    /// path and continue through provider-agreement policy only.
    pub fn stage_manual_candidate(
        &self,
        store: &mut EthereumNodeStore,
        candidate: &CheckpointCandidate,
    ) -> Result<PendingManualCheckpointReview, CheckpointPolicyError> {
        let now = trusted_now_unix()?;
        self.stage_manual_candidate_with(store, candidate, now, &HeliosBootstrapValidator)
    }

    /// Parses and stages a native-selected manual checkpoint card.
    ///
    /// The card bytes are the only caller input. The source fingerprint is a
    /// domain-separated integrity/provenance identifier for those exact
    /// bytes; it is not source authentication. The trusted local clock,
    /// candidate construction, and Helios validation remain inside this
    /// policy boundary.
    pub fn stage_manual_checkpoint_file(
        &self,
        store: &mut EthereumNodeStore,
        bytes: &[u8],
    ) -> Result<PendingManualCheckpointReview, CheckpointPolicyError> {
        let now = trusted_now_unix()?;
        self.stage_manual_checkpoint_file_with(store, bytes, now, &HeliosBootstrapValidator)
    }

    fn stage_manual_checkpoint_file_with(
        &self,
        store: &mut EthereumNodeStore,
        bytes: &[u8],
        now_unix: u64,
        validator: &impl BootstrapValidator,
    ) -> Result<PendingManualCheckpointReview, CheckpointPolicyError> {
        let file = ManualCheckpointFile::parse(bytes)?;
        let source_fingerprint = manual_checkpoint_file_fingerprint(bytes);
        let candidate = CheckpointCandidate::from_manual_source(
            ManualCheckpointSource::File,
            source_fingerprint,
            file.checkpoint_epoch(),
            file.checkpoint_root(),
            file.bootstrap_bundle().to_vec(),
            now_unix,
        );
        self.stage_manual_candidate_with(store, &candidate, now_unix, validator)
    }

    /// Returns a stable bounded page of validated, unexpired native reviews.
    /// Canonical bundle bytes and opaque binding values never leave this crate.
    pub fn pending_manual_checkpoint_reviews(
        &self,
        store: &mut EthereumNodeStore,
    ) -> Result<Vec<PendingManualCheckpointReview>, CheckpointPolicyError> {
        self.pending_manual_checkpoint_reviews_at(store, trusted_now_unix()?)
    }

    /// Reports whether an unexpired manual review exists without expiring
    /// stale rows. This read-only view is used by frequent application status
    /// polling; native review entry points perform durable expiry recovery.
    pub fn has_pending_manual_checkpoint_review(
        &self,
        store: &mut EthereumNodeStore,
    ) -> Result<bool, CheckpointPolicyError> {
        let now_unix = trusted_now_unix()?;
        let expected_profile = profile_binding(store);
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(NodeStoreError::sqlite)?;
        let review_id = transaction
            .query_row(
                "SELECT review_id FROM eth_pending_checkpoint_reviews
                 WHERE review_state = 1 AND CAST(expires_at_unix AS INTEGER) > ?1
                 ORDER BY recorded_at_unix, rowid LIMIT 1",
                [now_unix.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?
            .map(|bytes| crate::stored_array::<32>(&bytes, "manual checkpoint review identifier"))
            .transpose()?;
        if let Some(review_id) = review_id {
            let durable = read_manual_review(&transaction, review_id)?
                .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
            durable.pending_snapshot(expected_profile)?;
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(review_id.is_some())
    }

    /// Consumes exactly one durable review through the synchronous native-only
    /// approval boundary. The caller supplies no checkpoint, provenance, or
    /// approval fields; those are re-read from the profile database.
    pub fn resolve_manual_checkpoint_review<A: NativeCheckpointApproval>(
        &self,
        store: &mut EthereumNodeStore,
        review: &PendingManualCheckpointReview,
        approver: &mut A,
    ) -> Result<ManualCheckpointReviewResolution, ManualCheckpointInstallError<A::Error>> {
        let now = trusted_now_unix()?;
        self.resolve_manual_checkpoint_review_with(
            store,
            review,
            approver,
            now,
            None,
            &HeliosBootstrapValidator,
        )
    }

    pub fn active_anchor<'a>(
        &self,
        store: &'a EthereumNodeStore,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        self.active_anchor_at(store, trusted_now_unix()?)
    }

    /// Returns the currently installed checkpoint only after applying the
    /// same freshness, provenance, and revocation checks used for importing
    /// evidence.  This is a public, read-only display snapshot; it cannot be
    /// converted into verifier trust by callers.
    pub fn active_checkpoint_details(
        &self,
        store: &EthereumNodeStore,
    ) -> Result<StoredCheckpointApproval, CheckpointPolicyError> {
        let now_unix = trusted_now_unix()?;
        let approval = store
            .latest_checkpoint_approval()?
            .ok_or(CheckpointPolicyError::NoApprovedCheckpoint)?;
        validate_stored_approval(&store.connection, &approval, now_unix)?;
        Ok(approval)
    }

    fn stage_manual_candidate_with(
        &self,
        store: &mut EthereumNodeStore,
        candidate: &CheckpointCandidate,
        now_unix: u64,
        validator: &impl BootstrapValidator,
    ) -> Result<PendingManualCheckpointReview, CheckpointPolicyError> {
        let CandidateSource::Manual {
            kind,
            source_fingerprint,
        } = candidate.source
        else {
            return Err(CheckpointPolicyError::InvalidCandidate);
        };
        if source_fingerprint == [0; 32] {
            return Err(CheckpointPolicyError::InvalidCandidate);
        }
        let validated = validate_candidate(candidate, now_unix, validator)?;
        let valid_until_unix = checkpoint_valid_until(candidate.checkpoint_epoch)?;
        let expires_at_unix = now_unix
            .checked_add(MAX_MANUAL_REVIEW_SECONDS)
            .ok_or(CheckpointPolicyError::InvalidLocalClock)?
            .min(
                candidate
                    .observed_at_unix
                    .checked_add(MAX_OBSERVATION_AGE_SECONDS)
                    .ok_or(CheckpointPolicyError::InvalidCandidate)?,
            )
            .min(valid_until_unix);
        if expires_at_unix <= now_unix {
            return Err(CheckpointPolicyError::ReviewExpired);
        }

        let profile_binding = profile_binding(store);
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        expire_manual_reviews(&transaction, profile_binding, now_unix)?;
        enforce_monotonic_connection(&transaction, candidate)?;
        if is_exact_replay_connection(&transaction, candidate)? {
            return Err(CheckpointPolicyError::CheckpointAlreadyInstalled);
        }
        let authority_binding = checkpoint_authority_binding(&transaction)?;
        let active_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM eth_pending_checkpoint_reviews
                 WHERE review_state IN (1, 2)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(NodeStoreError::sqlite)?;
        if active_count
            >= i64::try_from(MAX_PENDING_MANUAL_CHECKPOINT_REVIEWS)
                .map_err(|_| CheckpointPolicyError::InvalidCandidate)?
        {
            return Err(CheckpointPolicyError::ReviewQueueFull);
        }
        let candidate_digest = manual_candidate_digest(
            profile_binding,
            candidate,
            kind,
            source_fingerprint,
            validated.canonical_bootstrap_hash,
        );
        let review_id = random_review_id(&transaction)?;
        let binding_digest = manual_review_binding_digest(
            review_id,
            candidate_digest,
            valid_until_unix,
            expires_at_unix,
            authority_binding,
        );
        transaction
            .execute(
                "INSERT INTO eth_pending_checkpoint_reviews (
                    review_id, profile_binding, checkpoint_epoch, checkpoint_root,
                    bootstrap_bundle, source_kind, source_fingerprint,
                    canonical_bootstrap_hash, observed_at_unix, valid_until_unix,
                    expires_at_unix, authority_binding, candidate_digest,
                    binding_digest, review_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1)",
                rusqlite::params![
                    review_id.as_slice(),
                    profile_binding.as_slice(),
                    candidate.checkpoint_epoch.to_string(),
                    candidate.checkpoint_root.as_slice(),
                    candidate.bootstrap_bundle.as_slice(),
                    kind.as_i64(),
                    source_fingerprint.as_slice(),
                    validated.canonical_bootstrap_hash.as_slice(),
                    candidate.observed_at_unix.to_string(),
                    valid_until_unix.to_string(),
                    expires_at_unix.to_string(),
                    authority_binding.as_slice(),
                    candidate_digest.as_slice(),
                    binding_digest.as_slice(),
                ],
            )
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    CheckpointPolicyError::ReviewAlreadyExists
                } else {
                    CheckpointPolicyError::Store(NodeStoreError::sqlite(error))
                }
            })?;
        let durable = read_manual_review(&transaction, review_id)?
            .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
        let review = durable.pending_snapshot(profile_binding)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(review)
    }

    fn pending_manual_checkpoint_reviews_at(
        &self,
        store: &mut EthereumNodeStore,
        now_unix: u64,
    ) -> Result<Vec<PendingManualCheckpointReview>, CheckpointPolicyError> {
        if now_unix == 0 {
            return Err(CheckpointPolicyError::InvalidLocalClock);
        }
        let expected_profile = profile_binding(store);
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        expire_manual_reviews(&transaction, expected_profile, now_unix)?;
        let review_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT review_id FROM eth_pending_checkpoint_reviews
                     WHERE review_state = 1 AND CAST(expires_at_unix AS INTEGER) > ?1
                     ORDER BY recorded_at_unix, rowid LIMIT ?2",
                )
                .map_err(NodeStoreError::sqlite)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        now_unix.to_string(),
                        i64::try_from(MAX_PENDING_MANUAL_CHECKPOINT_REVIEWS)
                            .map_err(|_| CheckpointPolicyError::InvalidCandidate)?,
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(NodeStoreError::sqlite)?;
            rows.map(|row| {
                let bytes = row.map_err(NodeStoreError::sqlite)?;
                crate::stored_array(&bytes, "manual checkpoint review identifier")
            })
            .collect::<Result<Vec<[u8; 32]>, NodeStoreError>>()?
        };
        let mut reviews = Vec::with_capacity(review_ids.len());
        for review_id in review_ids {
            let durable = read_manual_review(&transaction, review_id)?
                .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
            reviews.push(durable.pending_snapshot(expected_profile)?);
        }
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(reviews)
    }

    fn resolve_manual_checkpoint_review_with<A: NativeCheckpointApproval>(
        &self,
        store: &mut EthereumNodeStore,
        review: &PendingManualCheckpointReview,
        approver: &mut A,
        now_unix: u64,
        approval_time_override: Option<u64>,
        validator: &impl BootstrapValidator,
    ) -> Result<ManualCheckpointReviewResolution, ManualCheckpointInstallError<A::Error>> {
        let expected_profile = profile_binding(store);
        let durable = {
            let transaction = store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(NodeStoreError::sqlite)?;
            expire_manual_reviews(&transaction, expected_profile, now_unix)?;
            let durable = read_manual_review(&transaction, review.review_id)?
                .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
            if durable.state != ManualReviewState::Pending {
                return Err(CheckpointPolicyError::ReviewUnavailable.into());
            }
            let exact = durable.pending_snapshot(expected_profile)?;
            if exact != *review {
                return Err(CheckpointPolicyError::ReviewChanged.into());
            }
            if checkpoint_authority_binding(&transaction)? != durable.authority_binding {
                consume_manual_review(
                    &transaction,
                    durable.review_id,
                    ManualReviewState::Superseded,
                    now_unix,
                )?;
                transaction.commit().map_err(NodeStoreError::sqlite)?;
                return Err(CheckpointPolicyError::ReviewSuperseded.into());
            }
            transaction
                .execute(
                    "UPDATE eth_pending_checkpoint_reviews
                     SET review_state = 2 WHERE review_id = ?1 AND review_state = 1",
                    [durable.review_id.as_slice()],
                )
                .map_err(NodeStoreError::sqlite)?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            let mut authorizing = durable;
            authorizing.state = ManualReviewState::Authorizing;
            authorizing
        };

        let candidate = durable.candidate()?;
        let native_review = ManualCheckpointReview {
            candidate: &candidate,
            source: durable.source,
            canonical_bootstrap_hash: durable.canonical_bootstrap_hash,
            valid_until_unix: durable.valid_until_unix,
        };
        let approved = match approver.review_and_approve(&native_review) {
            Ok(approved) => approved,
            Err(error) => {
                consume_authorizing_review(
                    store,
                    &durable,
                    ManualReviewState::Interrupted,
                    now_unix,
                )?;
                return Err(ManualCheckpointInstallError::NativeApproval(error));
            }
        };
        if !approved {
            consume_authorizing_review(store, &durable, ManualReviewState::Denied, now_unix)?;
            return Ok(ManualCheckpointReviewResolution::Denied);
        }

        let approval_time = match approval_time_override {
            Some(approval_time) => approval_time,
            None => trusted_now_unix()?,
        };
        match validate_candidate(&candidate, approval_time, validator) {
            Ok(validated)
                if validated.canonical_bootstrap_hash == durable.canonical_bootstrap_hash => {}
            Ok(_) => {
                consume_authorizing_review(
                    store,
                    &durable,
                    ManualReviewState::Interrupted,
                    approval_time,
                )?;
                return Err(CheckpointPolicyError::ReviewChanged.into());
            }
            Err(error) => {
                let terminal = if matches!(
                    error,
                    CheckpointPolicyError::StaleObservation
                        | CheckpointPolicyError::StaleCheckpoint
                ) {
                    ManualReviewState::Expired
                } else {
                    ManualReviewState::Interrupted
                };
                consume_authorizing_review(store, &durable, terminal, approval_time)?;
                return Err(error.into());
            }
        }

        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let current = read_manual_review(&transaction, durable.review_id)?
            .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
        if current != durable || current.state != ManualReviewState::Authorizing {
            return Err(CheckpointPolicyError::ReviewChanged.into());
        }
        if approval_time >= current.expires_at_unix {
            consume_manual_review(
                &transaction,
                current.review_id,
                ManualReviewState::Expired,
                approval_time,
            )?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Err(CheckpointPolicyError::ReviewExpired.into());
        }
        if checkpoint_authority_binding(&transaction)? != current.authority_binding {
            consume_manual_review(
                &transaction,
                current.review_id,
                ManualReviewState::Superseded,
                approval_time,
            )?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Err(CheckpointPolicyError::ReviewSuperseded.into());
        }
        enforce_monotonic_connection(&transaction, &candidate)?;
        let attestation = CheckpointSourceAttestation::with_operator(
            current.source.stored_kind(),
            current.source_fingerprint,
            current.source_fingerprint,
            observation_hash(&candidate, current.canonical_bootstrap_hash),
            current.observed_at_unix,
        );
        let approval = CheckpointApproval::new(
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            current.checkpoint_root,
            CheckpointApprovalBasis::ExplicitUserApproval,
            approval_time,
            CheckpointApprovalWindow {
                checkpoint_epoch: current.checkpoint_epoch,
                valid_until_unix: current.valid_until_unix,
            },
            vec![attestation],
        );
        record_checkpoint_approval_monotonic_in(&transaction, &approval)?;
        consume_manual_review(
            &transaction,
            current.review_id,
            ManualReviewState::Approved,
            approval_time,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(ManualCheckpointReviewResolution::Approved)
    }

    fn install_provider_agreement_with<'a>(
        &self,
        store: &'a mut EthereumNodeStore,
        candidates: &[CheckpointCandidate],
        now_unix: u64,
        validator: &impl BootstrapValidator,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        if !(2..=MAX_PROVIDER_CANDIDATES).contains(&candidates.len()) {
            return Err(CheckpointPolicyError::InsufficientOperatorAgreement);
        }
        let first = &candidates[0];
        if candidates.iter().any(|candidate| {
            candidate.checkpoint_epoch != first.checkpoint_epoch
                || candidate.checkpoint_root != first.checkpoint_root
        }) {
            return Err(CheckpointPolicyError::ProviderMismatch);
        }

        let mut sources = HashSet::with_capacity(candidates.len());
        let mut operators = HashSet::with_capacity(candidates.len());
        let mut attestations = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let CandidateSource::Provider(provider) = candidate.source else {
                return Err(CheckpointPolicyError::UnconfiguredProvider);
            };
            if !self.providers.contains(&provider) {
                return Err(CheckpointPolicyError::UnconfiguredProvider);
            }
            if !sources.insert(provider.source_fingerprint) {
                return Err(CheckpointPolicyError::DuplicateProviderObservation);
            }
            operators.insert(provider.operator_fingerprint);
            let validated = validate_candidate(candidate, now_unix, validator)?;
            attestations.push(CheckpointSourceAttestation::with_operator(
                CheckpointSourceKind::BeaconApi,
                provider.source_fingerprint,
                provider.operator_fingerprint,
                observation_hash(candidate, validated.canonical_bootstrap_hash),
                candidate.observed_at_unix,
            ));
        }
        if operators.len() < 2 {
            return Err(CheckpointPolicyError::InsufficientOperatorAgreement);
        }
        if is_exact_replay(store, first)? {
            return self.active_anchor_at(store, now_unix);
        }
        self.install_validated(
            store,
            first,
            CheckpointApprovalBasis::ProviderAgreement,
            attestations,
            now_unix,
        )
    }

    fn install_provider_observation_agreement_with<'a>(
        &self,
        store: &'a mut EthereumNodeStore,
        observations: &[CheckpointProviderObservation],
        bootstrap_bundle: Vec<u8>,
        now_unix: u64,
        validator: &impl BootstrapValidator,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        if !(2..=MAX_PROVIDER_CANDIDATES).contains(&observations.len()) {
            return Err(CheckpointPolicyError::InsufficientOperatorAgreement);
        }
        let first = observations[0];
        if observations.iter().any(|observation| {
            observation.checkpoint_epoch != first.checkpoint_epoch
                || observation.checkpoint_root != first.checkpoint_root
        }) {
            return Err(CheckpointPolicyError::ProviderMismatch);
        }

        let candidate = CheckpointCandidate::from_provider(
            first.provider,
            first.checkpoint_epoch,
            first.checkpoint_root,
            bootstrap_bundle,
            first.observed_at_unix,
        );
        let validated = validate_candidate(&candidate, now_unix, validator)?;
        let mut sources = HashSet::with_capacity(observations.len());
        let mut operators = HashSet::with_capacity(observations.len());
        let mut attestations = Vec::with_capacity(observations.len());
        for observation in observations {
            if !self.providers.contains(&observation.provider) {
                return Err(CheckpointPolicyError::UnconfiguredProvider);
            }
            if !sources.insert(observation.provider.source_fingerprint) {
                return Err(CheckpointPolicyError::DuplicateProviderObservation);
            }
            operators.insert(observation.provider.operator_fingerprint);
            validate_checkpoint_observation(
                observation.checkpoint_epoch,
                observation.checkpoint_root,
                observation.observed_at_unix,
                now_unix,
            )?;
            attestations.push(CheckpointSourceAttestation::with_operator(
                CheckpointSourceKind::BeaconApi,
                observation.provider.source_fingerprint,
                observation.provider.operator_fingerprint,
                provider_observation_hash(observation),
                observation.observed_at_unix,
            ));
        }
        if operators.len() < 2 {
            return Err(CheckpointPolicyError::InsufficientOperatorAgreement);
        }
        if is_exact_replay(store, &candidate)? {
            return self.active_anchor_at(store, now_unix);
        }
        debug_assert_ne!(validated.canonical_bootstrap_hash, [0; 32]);
        self.install_validated(
            store,
            &candidate,
            CheckpointApprovalBasis::ProviderAgreement,
            attestations,
            now_unix,
        )
    }

    fn install_manual_with<'a, A: NativeCheckpointApproval>(
        &self,
        store: &'a mut EthereumNodeStore,
        candidate: &CheckpointCandidate,
        approver: &mut A,
        now_unix: u64,
        validator: &impl BootstrapValidator,
    ) -> Result<ApprovedCheckpointAnchor<'a>, ManualCheckpointInstallError<A::Error>> {
        let CandidateSource::Manual {
            kind,
            source_fingerprint,
        } = candidate.source
        else {
            return Err(CheckpointPolicyError::InvalidCandidate.into());
        };
        if source_fingerprint == [0; 32] {
            return Err(CheckpointPolicyError::InvalidCandidate.into());
        }
        let validated = validate_candidate(candidate, now_unix, validator)?;

        if is_exact_replay(store, candidate)? {
            return self.active_anchor_at(store, now_unix).map_err(Into::into);
        }

        let valid_until_unix = checkpoint_valid_until(candidate.checkpoint_epoch)?;
        let review = ManualCheckpointReview {
            candidate,
            source: kind,
            canonical_bootstrap_hash: validated.canonical_bootstrap_hash,
            valid_until_unix,
        };
        if !approver
            .review_and_approve(&review)
            .map_err(ManualCheckpointInstallError::NativeApproval)?
        {
            return Err(ManualCheckpointInstallError::Cancelled);
        }
        let attestation = CheckpointSourceAttestation::with_operator(
            kind.stored_kind(),
            source_fingerprint,
            source_fingerprint,
            observation_hash(candidate, validated.canonical_bootstrap_hash),
            candidate.observed_at_unix,
        );
        self.install_validated(
            store,
            candidate,
            CheckpointApprovalBasis::ExplicitUserApproval,
            vec![attestation],
            now_unix,
        )
        .map_err(Into::into)
    }

    fn install_validated<'a>(
        &self,
        store: &'a mut EthereumNodeStore,
        candidate: &CheckpointCandidate,
        basis: CheckpointApprovalBasis,
        attestations: Vec<CheckpointSourceAttestation>,
        now_unix: u64,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        enforce_monotonic(store, candidate)?;
        let approval = CheckpointApproval::new(
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            candidate.checkpoint_root,
            basis,
            now_unix,
            CheckpointApprovalWindow {
                checkpoint_epoch: candidate.checkpoint_epoch,
                valid_until_unix: checkpoint_valid_until(candidate.checkpoint_epoch)?,
            },
            attestations,
        );
        store.record_checkpoint_approval(&approval)?;
        self.active_anchor_at(store, now_unix)
    }

    fn active_anchor_at<'a>(
        &self,
        store: &'a EthereumNodeStore,
        now_unix: u64,
    ) -> Result<ApprovedCheckpointAnchor<'a>, CheckpointPolicyError> {
        let approval = store
            .latest_checkpoint_approval()?
            .ok_or(CheckpointPolicyError::NoApprovedCheckpoint)?;
        validate_stored_approval(&store.connection, &approval, now_unix)?;
        Ok(ApprovedCheckpointAnchor {
            store,
            checkpoint_root: approval.checkpoint_root(),
            checkpoint_epoch: approval.checkpoint_epoch(),
            valid_until_unix: approval.valid_until_unix(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManualReviewState {
    Pending = 1,
    Authorizing = 2,
    Approved = 3,
    Denied = 4,
    Expired = 5,
    Superseded = 6,
    Interrupted = 7,
}

impl ManualReviewState {
    fn from_i64(value: i64) -> Result<Self, NodeStoreError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Authorizing),
            3 => Ok(Self::Approved),
            4 => Ok(Self::Denied),
            5 => Ok(Self::Expired),
            6 => Ok(Self::Superseded),
            7 => Ok(Self::Interrupted),
            _ => Err(NodeStoreError::new(
                "invalid stored manual checkpoint review state",
            )),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Denied | Self::Expired | Self::Superseded | Self::Interrupted
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredManualCheckpointReview {
    review_id: [u8; 32],
    profile_binding: [u8; 32],
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    bootstrap_bundle: Option<Vec<u8>>,
    source: ManualCheckpointSource,
    source_fingerprint: [u8; 32],
    canonical_bootstrap_hash: [u8; 32],
    observed_at_unix: u64,
    valid_until_unix: u64,
    expires_at_unix: u64,
    authority_binding: [u8; 32],
    candidate_digest: [u8; 32],
    binding_digest: [u8; 32],
    state: ManualReviewState,
}

impl StoredManualCheckpointReview {
    fn candidate(&self) -> Result<CheckpointCandidate, CheckpointPolicyError> {
        let bootstrap_bundle = self
            .bootstrap_bundle
            .clone()
            .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
        Ok(CheckpointCandidate::from_manual_source(
            self.source,
            self.source_fingerprint,
            self.checkpoint_epoch,
            self.checkpoint_root,
            bootstrap_bundle,
            self.observed_at_unix,
        ))
    }

    fn pending_snapshot(
        &self,
        expected_profile: [u8; 32],
    ) -> Result<PendingManualCheckpointReview, CheckpointPolicyError> {
        if self.state != ManualReviewState::Pending {
            return Err(CheckpointPolicyError::ReviewUnavailable);
        }
        self.validate_active_integrity(expected_profile)?;
        Ok(PendingManualCheckpointReview {
            review_id: self.review_id,
            profile_binding: self.profile_binding,
            checkpoint_epoch: self.checkpoint_epoch,
            checkpoint_root: self.checkpoint_root,
            source: self.source,
            source_fingerprint: self.source_fingerprint,
            canonical_bootstrap_hash: self.canonical_bootstrap_hash,
            observed_at_unix: self.observed_at_unix,
            valid_until_unix: self.valid_until_unix,
            expires_at_unix: self.expires_at_unix,
            authority_binding: self.authority_binding,
            candidate_digest: self.candidate_digest,
            binding_digest: self.binding_digest,
        })
    }

    fn validate_active_integrity(
        &self,
        expected_profile: [u8; 32],
    ) -> Result<(), CheckpointPolicyError> {
        if !matches!(
            self.state,
            ManualReviewState::Pending | ManualReviewState::Authorizing
        ) || self.profile_binding != expected_profile
        {
            return Err(CheckpointPolicyError::ReviewUnavailable);
        }
        let candidate = self.candidate()?;
        let candidate_digest = manual_candidate_digest(
            self.profile_binding,
            &candidate,
            self.source,
            self.source_fingerprint,
            self.canonical_bootstrap_hash,
        );
        let expected = manual_review_binding_digest(
            self.review_id,
            candidate_digest,
            self.valid_until_unix,
            self.expires_at_unix,
            self.authority_binding,
        );
        if candidate_digest != self.candidate_digest || expected != self.binding_digest {
            return Err(CheckpointPolicyError::ReviewChanged);
        }
        Ok(())
    }
}

pub(super) fn create_schema(transaction: &Transaction<'_>) -> Result<(), NodeStoreError> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_pending_checkpoint_reviews (
                review_id BLOB PRIMARY KEY NOT NULL CHECK(length(review_id) = 32),
                profile_binding BLOB NOT NULL CHECK(length(profile_binding) = 32),
                checkpoint_epoch TEXT NOT NULL,
                checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                bootstrap_bundle BLOB,
                source_kind INTEGER NOT NULL CHECK(source_kind IN (1, 2, 3)),
                source_fingerprint BLOB NOT NULL CHECK(length(source_fingerprint) = 32),
                canonical_bootstrap_hash BLOB NOT NULL
                    CHECK(length(canonical_bootstrap_hash) = 32),
                observed_at_unix TEXT NOT NULL,
                valid_until_unix TEXT NOT NULL,
                expires_at_unix TEXT NOT NULL,
                authority_binding BLOB NOT NULL CHECK(length(authority_binding) = 32),
                candidate_digest BLOB NOT NULL UNIQUE CHECK(length(candidate_digest) = 32),
                binding_digest BLOB NOT NULL UNIQUE CHECK(length(binding_digest) = 32),
                review_state INTEGER NOT NULL CHECK(review_state BETWEEN 1 AND 7),
                resolved_at_unix TEXT,
                recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                CHECK(
                    (review_state IN (1, 2) AND bootstrap_bundle IS NOT NULL
                        AND length(bootstrap_bundle) > 0 AND resolved_at_unix IS NULL)
                    OR
                    (review_state BETWEEN 3 AND 7 AND bootstrap_bundle IS NULL
                        AND resolved_at_unix IS NOT NULL)
                )
            );",
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn read_manual_review(
    connection: &rusqlite::Connection,
    review_id: [u8; 32],
) -> Result<Option<StoredManualCheckpointReview>, NodeStoreError> {
    let row = connection
        .query_row(
            "SELECT review_id, profile_binding, checkpoint_epoch, checkpoint_root,
                    bootstrap_bundle, source_kind, source_fingerprint,
                    canonical_bootstrap_hash, observed_at_unix, valid_until_unix,
                    expires_at_unix, authority_binding, candidate_digest,
                    binding_digest, review_state
             FROM eth_pending_checkpoint_reviews WHERE review_id = ?1",
            [review_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, i64>(14)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored = StoredManualCheckpointReview {
        review_id: crate::stored_array(&row.0, "manual checkpoint review identifier")?,
        profile_binding: crate::stored_array(&row.1, "manual checkpoint profile binding")?,
        checkpoint_epoch: crate::parse_stored_u64(&row.2, "manual checkpoint epoch")?,
        checkpoint_root: crate::stored_array(&row.3, "manual checkpoint root")?,
        bootstrap_bundle: row.4,
        source: ManualCheckpointSource::from_i64(row.5)?,
        source_fingerprint: crate::stored_array(&row.6, "manual checkpoint source fingerprint")?,
        canonical_bootstrap_hash: crate::stored_array(&row.7, "manual checkpoint bootstrap hash")?,
        observed_at_unix: crate::parse_stored_u64(&row.8, "manual checkpoint observation")?,
        valid_until_unix: crate::parse_stored_u64(&row.9, "manual checkpoint validity")?,
        expires_at_unix: crate::parse_stored_u64(&row.10, "manual checkpoint review expiry")?,
        authority_binding: crate::stored_array(&row.11, "manual checkpoint authority binding")?,
        candidate_digest: crate::stored_array(&row.12, "manual checkpoint candidate binding")?,
        binding_digest: crate::stored_array(&row.13, "manual checkpoint review binding")?,
        state: ManualReviewState::from_i64(row.14)?,
    };
    if stored.review_id == [0; 32]
        || stored.profile_binding == [0; 32]
        || stored.checkpoint_epoch == 0
        || stored.checkpoint_root == [0; 32]
        || stored.source_fingerprint == [0; 32]
        || stored.canonical_bootstrap_hash == [0; 32]
        || stored.observed_at_unix == 0
        || stored.valid_until_unix == 0
        || stored.expires_at_unix == 0
        || stored.expires_at_unix > stored.valid_until_unix
        || stored.expires_at_unix
            > stored
                .observed_at_unix
                .saturating_add(MAX_OBSERVATION_AGE_SECONDS)
        || stored.authority_binding == [0; 32]
        || stored.candidate_digest == [0; 32]
        || stored.binding_digest == [0; 32]
        || (stored.state.is_terminal() != stored.bootstrap_bundle.is_none())
    {
        return Err(NodeStoreError::new(
            "stored manual checkpoint review failed validation",
        ));
    }
    Ok(Some(stored))
}

fn consume_manual_review(
    transaction: &Transaction<'_>,
    review_id: [u8; 32],
    terminal: ManualReviewState,
    now_unix: u64,
) -> Result<(), NodeStoreError> {
    if !terminal.is_terminal() || now_unix == 0 {
        return Err(NodeStoreError::new(
            "invalid terminal manual checkpoint review transition",
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE eth_pending_checkpoint_reviews
             SET review_state = ?1, bootstrap_bundle = NULL, resolved_at_unix = ?2
             WHERE review_id = ?3 AND review_state IN (1, 2)",
            rusqlite::params![terminal as i64, now_unix.to_string(), review_id.as_slice(),],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed != 1 {
        return Err(NodeStoreError::new(
            "manual checkpoint review was already consumed",
        ));
    }
    Ok(())
}

fn consume_authorizing_review(
    store: &mut EthereumNodeStore,
    expected: &StoredManualCheckpointReview,
    terminal: ManualReviewState,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(NodeStoreError::sqlite)?;
    let current = read_manual_review(&transaction, expected.review_id)?
        .ok_or(CheckpointPolicyError::ReviewUnavailable)?;
    if current != *expected || current.state != ManualReviewState::Authorizing {
        return Err(CheckpointPolicyError::ReviewChanged);
    }
    consume_manual_review(&transaction, current.review_id, terminal, now_unix)?;
    transaction.commit().map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn expire_manual_reviews(
    transaction: &Transaction<'_>,
    expected_profile: [u8; 32],
    now_unix: u64,
) -> Result<(), NodeStoreError> {
    let expired = active_review_ids(transaction, now_unix, false)?;
    for review_id in expired {
        let review = read_manual_review(transaction, review_id)?
            .ok_or_else(|| NodeStoreError::new("manual checkpoint review disappeared"))?;
        review
            .validate_active_integrity(expected_profile)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        consume_manual_review(transaction, review_id, ManualReviewState::Expired, now_unix)?;
    }
    Ok(())
}

fn active_review_ids(
    connection: &rusqlite::Connection,
    now_unix: u64,
    authorizing_only: bool,
) -> Result<Vec<[u8; 32]>, NodeStoreError> {
    let predicate = if authorizing_only {
        "review_state = 2 AND CAST(?1 AS INTEGER) >= 0"
    } else {
        "review_state = 1 AND CAST(expires_at_unix AS INTEGER) <= ?1"
    };
    let sql = format!(
        "SELECT review_id FROM eth_pending_checkpoint_reviews
         WHERE {predicate} ORDER BY recorded_at_unix, rowid LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql).map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map(
            rusqlite::params![
                now_unix.to_string(),
                i64::try_from(MAX_PENDING_MANUAL_CHECKPOINT_REVIEWS + 1)
                    .map_err(|_| NodeStoreError::new("invalid manual review bound"))?,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    let ids = rows
        .map(|row| {
            crate::stored_array(
                &row.map_err(NodeStoreError::sqlite)?,
                "manual checkpoint review identifier",
            )
        })
        .collect::<Result<Vec<_>, NodeStoreError>>()?;
    if ids.len() > MAX_PENDING_MANUAL_CHECKPOINT_REVIEWS {
        return Err(NodeStoreError::new(
            "stored manual checkpoint review bound was exceeded",
        ));
    }
    Ok(ids)
}

pub(crate) fn recover_interrupted_manual_reviews(
    store: &mut EthereumNodeStore,
) -> Result<(), NodeStoreError> {
    let now_unix = trusted_now_unix().map_err(|error| NodeStoreError::new(error.to_string()))?;
    let expected_profile = profile_binding(store);
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(NodeStoreError::sqlite)?;
    for review_id in active_review_ids(&transaction, now_unix, true)? {
        let review = read_manual_review(&transaction, review_id)?
            .ok_or_else(|| NodeStoreError::new("manual checkpoint review disappeared"))?;
        review
            .validate_active_integrity(expected_profile)
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        consume_manual_review(
            &transaction,
            review_id,
            ManualReviewState::Interrupted,
            now_unix,
        )?;
    }
    transaction.commit().map_err(NodeStoreError::sqlite)
}

fn random_review_id(transaction: &Transaction<'_>) -> Result<[u8; 32], NodeStoreError> {
    let bytes = transaction
        .query_row("SELECT randomblob(32)", [], |row| row.get::<_, Vec<u8>>(0))
        .map_err(NodeStoreError::sqlite)?;
    let review_id = crate::stored_array(&bytes, "manual checkpoint review identifier")?;
    if review_id == [0; 32] {
        return Err(NodeStoreError::new(
            "failed to generate manual checkpoint review identifier",
        ));
    }
    Ok(review_id)
}

fn manual_candidate_digest(
    profile_binding: [u8; 32],
    candidate: &CheckpointCandidate,
    source: ManualCheckpointSource,
    source_fingerprint: [u8; 32],
    canonical_bootstrap_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-native-checkpoint-candidate-v1");
    hasher.update(profile_binding);
    hasher.update(candidate.checkpoint_epoch.to_le_bytes());
    hasher.update(candidate.checkpoint_root);
    hasher.update(Sha256::digest(&candidate.bootstrap_bundle));
    hasher.update([source as u8]);
    hasher.update(source_fingerprint);
    hasher.update(canonical_bootstrap_hash);
    hasher.update(candidate.observed_at_unix.to_le_bytes());
    hasher.finalize().into()
}

fn manual_review_binding_digest(
    review_id: [u8; 32],
    candidate_digest: [u8; 32],
    valid_until_unix: u64,
    expires_at_unix: u64,
    authority_binding: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-native-checkpoint-review-v1");
    hasher.update(review_id);
    hasher.update(candidate_digest);
    hasher.update(valid_until_unix.to_le_bytes());
    hasher.update(expires_at_unix.to_le_bytes());
    hasher.update(authority_binding);
    hasher.finalize().into()
}

fn profile_binding(store: &EthereumNodeStore) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-profile-binding-v1");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = store.path().as_os_str().as_bytes();
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let path = store.path().as_os_str().encode_wide().collect::<Vec<_>>();
        hasher.update((path.len() as u64).to_le_bytes());
        for unit in path {
            hasher.update(unit.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

fn checkpoint_authority_binding(
    connection: &rusqlite::Connection,
) -> Result<[u8; 32], NodeStoreError> {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-authority-binding-v1");
    let Some(latest) = latest_checkpoint_approval(connection)? else {
        hasher.update([0]);
        return Ok(hasher.finalize().into());
    };
    hasher.update([1]);
    hasher.update(latest.checkpoint_root());
    hasher.update(latest.checkpoint_epoch().to_le_bytes());
    hasher.update(latest.approved_at_unix().to_le_bytes());
    hasher.update(latest.valid_until_unix().to_le_bytes());
    hasher.update([match latest.approval_basis() {
        CheckpointApprovalBasis::ProviderAgreement => 1,
        CheckpointApprovalBasis::ExplicitUserApproval => 2,
    }]);
    for attestation in latest.attestations() {
        hasher.update([match attestation.source_kind() {
            CheckpointSourceKind::BeaconApi => 1,
            CheckpointSourceKind::AuthenticatedRatspeakIdentity => 2,
            CheckpointSourceKind::ExplicitUser => 3,
            CheckpointSourceKind::ManualUrl => 4,
            CheckpointSourceKind::ManualFile => 5,
            CheckpointSourceKind::ManualQr => 6,
        }]);
        hasher.update(attestation.source_fingerprint());
        hasher.update(attestation.operator_fingerprint());
        hasher.update(attestation.observation_hash());
        hasher.update(attestation.observed_at_unix().to_le_bytes());
    }
    for event in read_assurance_history(
        connection,
        SEPOLIA_CHAIN_ID,
        SEPOLIA_NETWORK,
        AssuranceSubjectKind::Checkpoint,
        latest.checkpoint_root(),
    )? {
        hasher.update([match event.event_kind() {
            AssuranceEventKind::CheckpointApproved => 1,
            AssuranceEventKind::CheckpointSourceAttested => 2,
            AssuranceEventKind::CheckpointRevoked => 3,
            AssuranceEventKind::LocalSignatureRecorded => 4,
            AssuranceEventKind::TransportDelivered => 5,
            AssuranceEventKind::GatewayAcknowledged => 6,
            AssuranceEventKind::RpcAccepted => 7,
            AssuranceEventKind::FinalizedReceiptSucceeded => 8,
            AssuranceEventKind::FinalizedReceiptFailed => 9,
        }]);
        hasher.update(event.evidence_hash());
        hasher.update(event.observed_at_unix().to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

fn enforce_monotonic_connection(
    connection: &rusqlite::Connection,
    candidate: &CheckpointCandidate,
) -> Result<(), CheckpointPolicyError> {
    let Some(latest) = latest_checkpoint_approval(connection)? else {
        return Ok(());
    };
    if latest.checkpoint_root() == candidate.checkpoint_root
        && latest.checkpoint_epoch() != candidate.checkpoint_epoch
    {
        return Err(CheckpointPolicyError::RootEpochConflict);
    }
    if latest.checkpoint_epoch() == candidate.checkpoint_epoch
        && latest.checkpoint_root() != candidate.checkpoint_root
    {
        return Err(CheckpointPolicyError::EpochRootConflict);
    }
    if candidate.checkpoint_epoch < latest.checkpoint_epoch() {
        return Err(CheckpointPolicyError::CheckpointRollback);
    }
    Ok(())
}

fn is_exact_replay_connection(
    connection: &rusqlite::Connection,
    candidate: &CheckpointCandidate,
) -> Result<bool, CheckpointPolicyError> {
    let Some(latest) = latest_checkpoint_approval(connection)? else {
        return Ok(false);
    };
    enforce_monotonic_connection(connection, candidate)?;
    Ok(latest.checkpoint_epoch() == candidate.checkpoint_epoch
        && latest.checkpoint_root() == candidate.checkpoint_root)
}

/// Borrowed capability for invoking consensus verification from the currently
/// usable installed checkpoint. It cannot be built from a database row or an
/// incoming bundle, and it rechecks revocation/expiry immediately before use.
pub struct ApprovedCheckpointAnchor<'a> {
    store: &'a EthereumNodeStore,
    checkpoint_root: [u8; 32],
    checkpoint_epoch: u64,
    valid_until_unix: u64,
}

impl ApprovedCheckpointAnchor<'_> {
    pub fn verify_consensus_bootstrap(
        &self,
        verifier: &Verifier,
        canonical_bundle: &[u8],
    ) -> Result<VerifiedExecutionHeader, CheckpointPolicyError> {
        let now = trusted_now_unix()?;
        let current = self
            .store
            .latest_checkpoint_approval()?
            .ok_or(CheckpointPolicyError::NoApprovedCheckpoint)?;
        validate_stored_approval(&self.store.connection, &current, now)?;
        if current.checkpoint_root() != self.checkpoint_root
            || current.checkpoint_epoch() != self.checkpoint_epoch
            || current.valid_until_unix() != self.valid_until_unix
        {
            return Err(CheckpointPolicyError::CheckpointRollback);
        }
        verifier
            .verify_consensus_bootstrap(
                canonical_bundle,
                &BeaconCheckpointRoot::sepolia(self.checkpoint_root),
            )
            .map_err(Into::into)
    }
}

pub(crate) fn active_checkpoint_available_at(
    store: &EthereumNodeStore,
    now_unix: u64,
) -> Result<bool, CheckpointPolicyError> {
    let Some(approval) = store.latest_checkpoint_approval()? else {
        return Ok(false);
    };
    match validate_stored_approval(&store.connection, &approval, now_unix) {
        Ok(()) => Ok(true),
        Err(CheckpointPolicyError::StaleCheckpoint)
        | Err(CheckpointPolicyError::RevokedCheckpoint)
        | Err(CheckpointPolicyError::NoApprovedCheckpoint) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_active_checkpoint_at(
    store: &EthereumNodeStore,
    checkpoint_root: [u8; 32],
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    ensure_active_checkpoint_at_connection(&store.connection, checkpoint_root, now_unix)
}

pub(crate) fn ensure_active_checkpoint_at_connection(
    connection: &rusqlite::Connection,
    checkpoint_root: [u8; 32],
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    let approval = latest_checkpoint_approval(connection)?
        .ok_or(CheckpointPolicyError::NoApprovedCheckpoint)?;
    validate_stored_approval(connection, &approval, now_unix)?;
    if approval.checkpoint_root() != checkpoint_root {
        return Err(CheckpointPolicyError::CheckpointRollback);
    }
    Ok(())
}

/// Validates the exact checkpoint approval that governed immutable finalized
/// evidence. A newer approval does not invalidate old cryptographic evidence,
/// but expiry at finalization, later revocation, corrupt provenance, and an
/// invalid local clock all fail closed.
pub(crate) fn ensure_checkpoint_approved_for_finalized_evidence_at(
    store: &EthereumNodeStore,
    checkpoint_root: [u8; 32],
    finalized_at_unix: u64,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    ensure_checkpoint_approved_for_finalized_evidence_at_connection(
        &store.connection,
        checkpoint_root,
        finalized_at_unix,
        now_unix,
    )
}

/// Transaction-scoped form used when verified historical evidence and its
/// request completion must commit as one durable operation.
pub(crate) fn ensure_checkpoint_approved_for_finalized_evidence_at_connection(
    connection: &rusqlite::Connection,
    checkpoint_root: [u8; 32],
    finalized_at_unix: u64,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    let approval = read_checkpoint(connection, SEPOLIA_CHAIN_ID, checkpoint_root)?
        .ok_or(CheckpointPolicyError::NoApprovedCheckpoint)?;
    validate_stored_approval_provenance(connection, &approval, now_unix)?;
    let future_limit = now_unix
        .checked_add(MAX_FUTURE_SKEW_SECONDS)
        .ok_or(CheckpointPolicyError::InvalidLocalClock)?;
    if finalized_at_unix > future_limit {
        return Err(CheckpointPolicyError::InvalidLocalClock);
    }
    if finalized_at_unix >= approval.valid_until_unix() {
        return Err(CheckpointPolicyError::StaleCheckpoint);
    }
    Ok(())
}

fn enforce_monotonic(
    store: &EthereumNodeStore,
    candidate: &CheckpointCandidate,
) -> Result<(), CheckpointPolicyError> {
    let Some(latest) = store.latest_checkpoint_approval()? else {
        return Ok(());
    };
    if latest.checkpoint_root() == candidate.checkpoint_root
        && latest.checkpoint_epoch() != candidate.checkpoint_epoch
    {
        return Err(CheckpointPolicyError::RootEpochConflict);
    }
    if latest.checkpoint_epoch() == candidate.checkpoint_epoch
        && latest.checkpoint_root() != candidate.checkpoint_root
    {
        return Err(CheckpointPolicyError::EpochRootConflict);
    }
    if candidate.checkpoint_epoch < latest.checkpoint_epoch() {
        return Err(CheckpointPolicyError::CheckpointRollback);
    }
    Ok(())
}

fn is_exact_replay(
    store: &EthereumNodeStore,
    candidate: &CheckpointCandidate,
) -> Result<bool, CheckpointPolicyError> {
    let Some(latest) = store.latest_checkpoint_approval()? else {
        return Ok(false);
    };
    enforce_monotonic(store, candidate)?;
    Ok(latest.checkpoint_epoch() == candidate.checkpoint_epoch
        && latest.checkpoint_root() == candidate.checkpoint_root)
}

fn validate_stored_approval(
    connection: &rusqlite::Connection,
    approval: &StoredCheckpointApproval,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    validate_stored_approval_provenance(connection, approval, now_unix)?;
    if now_unix >= approval.valid_until_unix() {
        return Err(CheckpointPolicyError::StaleCheckpoint);
    }
    Ok(())
}

fn validate_stored_approval_provenance(
    connection: &rusqlite::Connection,
    approval: &StoredCheckpointApproval,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    if approval.chain_id() != SEPOLIA_CHAIN_ID
        || approval.network() != SEPOLIA_NETWORK
        || approval.checkpoint_root() == [0; 32]
        || approval.approved_at_unix() > now_unix.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        || approval.valid_until_unix() != checkpoint_valid_until(approval.checkpoint_epoch())?
        || approval.approved_at_unix() >= approval.valid_until_unix()
    {
        return Err(CheckpointPolicyError::CorruptApprovalPolicy);
    }

    let attestations = approval.attestations();
    let policy_valid = match approval.approval_basis() {
        CheckpointApprovalBasis::ProviderAgreement => {
            let mut operators = HashSet::new();
            let mut sources = HashSet::new();
            attestations.len() >= 2
                && attestations.iter().all(|attestation| {
                    attestation.source_kind() == CheckpointSourceKind::BeaconApi
                        && sources.insert(attestation.source_fingerprint())
                        && {
                            operators.insert(attestation.operator_fingerprint());
                            valid_stored_observation(attestation, approval, now_unix)
                        }
                })
                && operators.len() >= 2
        }
        CheckpointApprovalBasis::ExplicitUserApproval => {
            attestations.len() == 1
                && matches!(
                    attestations[0].source_kind(),
                    CheckpointSourceKind::ManualUrl
                        | CheckpointSourceKind::ManualFile
                        | CheckpointSourceKind::ManualQr
                )
                && attestations[0].operator_fingerprint() == attestations[0].source_fingerprint()
                && valid_stored_observation(&attestations[0], approval, now_unix)
        }
    };
    if !policy_valid {
        return Err(CheckpointPolicyError::CorruptApprovalPolicy);
    }

    let history = read_assurance_history(
        connection,
        SEPOLIA_CHAIN_ID,
        SEPOLIA_NETWORK,
        AssuranceSubjectKind::Checkpoint,
        approval.checkpoint_root(),
    )?;
    if history
        .iter()
        .any(|event| event.event_kind() == AssuranceEventKind::CheckpointRevoked)
    {
        return Err(CheckpointPolicyError::RevokedCheckpoint);
    }
    Ok(())
}

fn valid_stored_observation(
    attestation: &CheckpointSourceAttestation,
    approval: &StoredCheckpointApproval,
    now_unix: u64,
) -> bool {
    attestation.observation_hash() != [0; 32]
        && attestation.observed_at_unix()
            <= approval
                .approved_at_unix()
                .saturating_add(MAX_FUTURE_SKEW_SECONDS)
        && attestation.observed_at_unix() <= now_unix.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        && approval
            .approved_at_unix()
            .saturating_sub(attestation.observed_at_unix())
            <= MAX_OBSERVATION_AGE_SECONDS
}

#[derive(Debug)]
struct ValidatedBootstrap {
    canonical_bootstrap_hash: [u8; 32],
    checkpoint_epoch: u64,
}

trait BootstrapValidator {
    fn validate(
        &self,
        checkpoint_root: [u8; 32],
        bootstrap_bundle: &[u8],
    ) -> Result<ValidatedBootstrap, CheckpointPolicyError>;
}

struct HeliosBootstrapValidator;

impl BootstrapValidator for HeliosBootstrapValidator {
    fn validate(
        &self,
        checkpoint_root: [u8; 32],
        bootstrap_bundle: &[u8],
    ) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
        let verifier = Verifier::sepolia();
        let parsed = verifier.parse_consensus_bootstrap(bootstrap_bundle)?;
        if !parsed.updates_ssz.is_empty() || parsed.finality_update_ssz.is_some() {
            return Err(CheckpointPolicyError::BootstrapContainsUpdates);
        }
        let verified = verifier.verify_consensus_bootstrap(
            bootstrap_bundle,
            &BeaconCheckpointRoot::sepolia(checkpoint_root),
        )?;
        Ok(ValidatedBootstrap {
            canonical_bootstrap_hash: verified.proof_bundle_hash(),
            checkpoint_epoch: verified.finalized_slot() / SLOTS_PER_EPOCH,
        })
    }
}

fn validate_candidate(
    candidate: &CheckpointCandidate,
    now_unix: u64,
    validator: &impl BootstrapValidator,
) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
    if candidate.bootstrap_bundle.is_empty() || candidate.bootstrap_bundle.len() > MAX_BUNDLE_BYTES
    {
        return Err(CheckpointPolicyError::InvalidCandidate);
    }
    validate_checkpoint_observation(
        candidate.checkpoint_epoch,
        candidate.checkpoint_root,
        candidate.observed_at_unix,
        now_unix,
    )?;
    let validated = validator.validate(candidate.checkpoint_root, &candidate.bootstrap_bundle)?;
    if validated.checkpoint_epoch != candidate.checkpoint_epoch {
        return Err(CheckpointPolicyError::BootstrapEpochMismatch);
    }
    Ok(validated)
}

fn validate_checkpoint_observation(
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    observed_at_unix: u64,
    now_unix: u64,
) -> Result<(), CheckpointPolicyError> {
    if checkpoint_epoch == 0 || checkpoint_root == [0; 32] || observed_at_unix == 0 {
        return Err(CheckpointPolicyError::InvalidCandidate);
    }
    let future_limit = now_unix
        .checked_add(MAX_FUTURE_SKEW_SECONDS)
        .ok_or(CheckpointPolicyError::InvalidLocalClock)?;
    if observed_at_unix > future_limit {
        return Err(CheckpointPolicyError::FutureObservation);
    }
    if now_unix.saturating_sub(observed_at_unix) > MAX_OBSERVATION_AGE_SECONDS {
        return Err(CheckpointPolicyError::StaleObservation);
    }
    let checkpoint_time = checkpoint_time(checkpoint_epoch)?;
    if checkpoint_time > future_limit {
        return Err(CheckpointPolicyError::FutureCheckpoint);
    }
    if now_unix >= checkpoint_valid_until(checkpoint_epoch)? {
        return Err(CheckpointPolicyError::StaleCheckpoint);
    }
    if observed_at_unix.saturating_add(MAX_FUTURE_SKEW_SECONDS) < checkpoint_time {
        return Err(CheckpointPolicyError::InvalidCandidate);
    }
    Ok(())
}

fn checkpoint_time(epoch: u64) -> Result<u64, CheckpointPolicyError> {
    epoch
        .checked_mul(SLOTS_PER_EPOCH)
        .and_then(|slots| slots.checked_mul(SECONDS_PER_SLOT))
        .and_then(|seconds| SEPOLIA_GENESIS_TIME.checked_add(seconds))
        .ok_or(CheckpointPolicyError::InvalidCandidate)
}

fn checkpoint_valid_until(epoch: u64) -> Result<u64, CheckpointPolicyError> {
    checkpoint_time(epoch)?
        .checked_add(MAX_CHECKPOINT_AGE_SECONDS)
        .ok_or(CheckpointPolicyError::InvalidCandidate)
}

fn observation_hash(
    candidate: &CheckpointCandidate,
    canonical_bootstrap_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-observation-v1");
    hasher.update(candidate.checkpoint_epoch.to_le_bytes());
    hasher.update(candidate.checkpoint_root);
    hasher.update(canonical_bootstrap_hash);
    hasher.update(candidate.observed_at_unix.to_le_bytes());
    match candidate.source {
        CandidateSource::Provider(provider) => {
            hasher.update([1]);
            hasher.update(provider.operator_fingerprint);
            hasher.update(provider.source_fingerprint);
        }
        CandidateSource::Manual {
            kind,
            source_fingerprint,
        } => {
            hasher.update([2, kind as u8]);
            hasher.update(source_fingerprint);
        }
    }
    hasher.finalize().into()
}

fn provider_observation_hash(observation: &CheckpointProviderObservation) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-checkpoint-provider-observation-v1");
    hasher.update(observation.checkpoint_epoch.to_le_bytes());
    hasher.update(observation.checkpoint_root);
    hasher.update(observation.observed_at_unix.to_le_bytes());
    hasher.update(observation.provider.operator_fingerprint);
    hasher.update(observation.provider.source_fingerprint);
    hasher.finalize().into()
}

/// Identifies the exact selected file while keeping its provenance semantics
/// explicit: this digest does not authenticate the file's source.
pub(crate) fn trusted_now_unix() -> Result<u64, CheckpointPolicyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CheckpointPolicyError::InvalidLocalClock)
}

#[cfg(test)]
pub(crate) fn install_test_active_checkpoint(
    store: &mut EthereumNodeStore,
    checkpoint_root: [u8; 32],
    now_unix: u64,
) {
    if store
        .latest_checkpoint_approval()
        .unwrap()
        .is_some_and(|approval| approval.checkpoint_root() == checkpoint_root)
    {
        return;
    }
    let epoch =
        now_unix.checked_sub(SEPOLIA_GENESIS_TIME).unwrap() / (SECONDS_PER_SLOT * SLOTS_PER_EPOCH);
    let attestation = CheckpointSourceAttestation::with_operator(
        CheckpointSourceKind::ManualFile,
        [0xa1; 32],
        [0xa1; 32],
        [0xb2; 32],
        now_unix,
    );
    let approval = CheckpointApproval::new(
        SEPOLIA_CHAIN_ID,
        SEPOLIA_NETWORK,
        checkpoint_root,
        CheckpointApprovalBasis::ExplicitUserApproval,
        now_unix,
        CheckpointApprovalWindow {
            checkpoint_epoch: epoch,
            valid_until_unix: checkpoint_valid_until(epoch).unwrap(),
        },
        vec![attestation],
    );
    store.record_checkpoint_approval(&approval).unwrap();
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::{Arc, Barrier, mpsc};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    struct TestValidator;

    impl BootstrapValidator for TestValidator {
        fn validate(
            &self,
            _checkpoint_root: [u8; 32],
            bootstrap_bundle: &[u8],
        ) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
            if bootstrap_bundle != b"canonical-bootstrap" {
                return Err(CheckpointPolicyError::Verification(
                    ratspeak_eth_verifier::VerifyError::CheckpointMismatch,
                ));
            }
            Ok(ValidatedBootstrap {
                canonical_bootstrap_hash: Sha256::digest(bootstrap_bundle).into(),
                checkpoint_epoch: epoch_near(NOW),
            })
        }
    }

    struct FileTestValidator;

    impl BootstrapValidator for FileTestValidator {
        fn validate(
            &self,
            checkpoint_root: [u8; 32],
            bootstrap_bundle: &[u8],
        ) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
            if checkpoint_root != [0x42; 32] {
                return Err(CheckpointPolicyError::Verification(
                    ratspeak_eth_verifier::VerifyError::CheckpointMismatch,
                ));
            }
            let canonical_bootstrap_hash = Sha256::digest(bootstrap_bundle).into();
            Ok(ValidatedBootstrap {
                canonical_bootstrap_hash,
                checkpoint_epoch: epoch_near(NOW),
            })
        }
    }

    struct Approver {
        approvals: Vec<bool>,
        calls: Cell<usize>,
        reviewed_roots: Vec<[u8; 32]>,
    }

    struct PausingApprover {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl NativeCheckpointApproval for PausingApprover {
        type Error = ();

        fn review_and_approve(
            &mut self,
            _review: &ManualCheckpointReview<'_>,
        ) -> Result<bool, Self::Error> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(true)
        }
    }

    impl Approver {
        fn new(approvals: Vec<bool>) -> Self {
            Self {
                approvals,
                calls: Cell::new(0),
                reviewed_roots: Vec::new(),
            }
        }
    }

    impl NativeCheckpointApproval for Approver {
        type Error = ();

        fn review_and_approve(
            &mut self,
            review: &ManualCheckpointReview<'_>,
        ) -> Result<bool, Self::Error> {
            let index = self.calls.get();
            self.calls.set(index + 1);
            self.reviewed_roots.push(review.checkpoint_root());
            Ok(self.approvals.get(index).copied().unwrap_or(false))
        }
    }

    fn epoch_near(now: u64) -> u64 {
        (now - SEPOLIA_GENESIS_TIME) / (SECONDS_PER_SLOT * SLOTS_PER_EPOCH)
    }

    fn provider(operator: u8, source: u8) -> ConfiguredCheckpointProvider {
        ConfiguredCheckpointProvider::new([operator; 32], [source; 32]).unwrap()
    }

    fn provider_candidate(
        provider: ConfiguredCheckpointProvider,
        root: u8,
        epoch: u64,
        observed_at: u64,
    ) -> CheckpointCandidate {
        CheckpointCandidate::from_provider(
            provider,
            epoch,
            [root; 32],
            b"canonical-bootstrap".to_vec(),
            observed_at,
        )
    }

    fn provider_observation(
        provider: ConfiguredCheckpointProvider,
        root: u8,
        epoch: u64,
        observed_at: u64,
    ) -> CheckpointProviderObservation {
        CheckpointProviderObservation::new(provider, epoch, [root; 32], observed_at)
    }

    fn manual_candidate(root: u8, epoch: u64, observed_at: u64) -> CheckpointCandidate {
        CheckpointCandidate::from_manual_source(
            ManualCheckpointSource::Qr,
            [0xa1; 32],
            epoch,
            [root; 32],
            b"canonical-bootstrap".to_vec(),
            observed_at,
        )
    }

    fn store() -> (tempfile::TempDir, EthereumNodeStore) {
        let profile = tempfile::tempdir().unwrap();
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        (profile, store)
    }

    fn manual_checkpoint_file(epoch: u64, root: [u8; 32]) -> Vec<u8> {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        bundle.push(ratspeak_eth_verifier::VERSION);
        bundle.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bundle.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bundle.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bundle.push(ratspeak_eth_verifier::KIND_PINNED_CONSENSUS_BOOTSTRAP);
        bundle.extend_from_slice(&1u64.to_le_bytes());
        bundle.extend_from_slice(&1u32.to_le_bytes());
        bundle.push(0);
        bundle.extend_from_slice(&0u16.to_le_bytes());
        bundle.push(0);
        ratspeak_eth_verifier::encode_manual_checkpoint_file(epoch, root, &bundle).unwrap()
    }

    #[test]
    fn manual_checkpoint_file_stages_with_exact_domain_fingerprint() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let (_, mut store) = store();
        let epoch = epoch_near(NOW);
        let bytes = manual_checkpoint_file(epoch, [0x42; 32]);
        let pending = policy
            .stage_manual_checkpoint_file_with(&mut store, &bytes, NOW, &FileTestValidator)
            .unwrap();
        let expected = ratspeak_eth_verifier::manual_checkpoint_file_fingerprint(&bytes);
        assert_eq!(pending.source(), ManualCheckpointSource::File);
        assert_eq!(pending.source_fingerprint(), expected);
        assert_eq!(pending.checkpoint_epoch(), epoch);
        assert_eq!(pending.checkpoint_root(), [0x42; 32]);
        assert_eq!(
            policy
                .pending_manual_checkpoint_reviews_at(&mut store, NOW)
                .unwrap(),
            vec![pending]
        );
        assert!(matches!(
            policy.stage_manual_checkpoint_file_with(&mut store, &bytes, NOW, &FileTestValidator),
            Err(CheckpointPolicyError::ReviewAlreadyExists)
        ));
    }

    #[test]
    fn manual_checkpoint_file_uses_full_candidate_time_and_root_policy() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let (_, mut store) = store();
        let epoch = epoch_near(NOW);
        let bundle = manual_checkpoint_file(epoch, [0x42; 32]);

        let future = manual_checkpoint_file(epoch + 1_000, [0x42; 32]);
        assert!(matches!(
            policy.stage_manual_checkpoint_file_with(&mut store, &future, NOW, &FileTestValidator),
            Err(CheckpointPolicyError::FutureCheckpoint)
        ));
        let stale = manual_checkpoint_file(1, [0x42; 32]);
        assert!(matches!(
            policy.stage_manual_checkpoint_file_with(&mut store, &stale, NOW, &FileTestValidator),
            Err(CheckpointPolicyError::StaleCheckpoint)
        ));
        let wrong_root = manual_checkpoint_file(epoch, [0x43; 32]);
        assert!(matches!(
            policy.stage_manual_checkpoint_file_with(
                &mut store,
                &wrong_root,
                NOW,
                &FileTestValidator
            ),
            Err(CheckpointPolicyError::Verification(
                ratspeak_eth_verifier::VerifyError::CheckpointMismatch
            ))
        ));
        let wrong_epoch = manual_checkpoint_file(epoch + 1, [0x42; 32]);
        assert!(matches!(
            policy.stage_manual_checkpoint_file_with(
                &mut store,
                &wrong_epoch,
                NOW,
                &FileTestValidator
            ),
            Err(CheckpointPolicyError::BootstrapEpochMismatch)
        ));
        assert!(bundle.len() < ratspeak_eth_verifier::MAX_MANUAL_CHECKPOINT_FILE_BYTES);
    }

    #[test]
    fn provider_agreement_counts_distinct_operators_not_urls() {
        let p1 = provider(1, 11);
        let p1_other_url = provider(1, 12);
        let p2 = provider(2, 21);
        let policy = CheckpointBootstrapPolicy::new(vec![p1, p1_other_url, p2]).unwrap();
        let epoch = epoch_near(NOW);
        let (_, mut node_store) = store();
        let same_operator = [
            provider_candidate(p1, 3, epoch, NOW - 10),
            provider_candidate(p1_other_url, 3, epoch, NOW - 9),
        ];
        assert!(matches!(
            policy.install_provider_agreement_with(
                &mut node_store,
                &same_operator,
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::InsufficientOperatorAgreement)
        ));

        let independent = [
            provider_candidate(p1, 3, epoch, NOW - 10),
            provider_candidate(p2, 3, epoch, NOW - 9),
        ];
        {
            let anchor = policy
                .install_provider_agreement_with(&mut node_store, &independent, NOW, &TestValidator)
                .unwrap();
            assert_eq!(anchor.checkpoint_epoch, epoch);
        }
        {
            let _replay = policy
                .install_provider_agreement_with(&mut node_store, &independent, NOW, &TestValidator)
                .unwrap();
        }
        let stored = node_store
            .checkpoint_approval(SEPOLIA_CHAIN_ID, [3; 32])
            .unwrap()
            .unwrap();
        assert_eq!(stored.attestations().len(), 2);
        assert_ne!(
            stored.attestations()[0].operator_fingerprint(),
            stored.attestations()[1].operator_fingerprint()
        );
    }

    #[test]
    fn active_checkpoint_details_is_policy_gated() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let (_, node_store) = store();
        assert!(matches!(
            policy.active_checkpoint_details(&node_store),
            Err(CheckpointPolicyError::NoApprovedCheckpoint)
        ));
    }

    #[test]
    fn provider_root_agreement_is_separate_from_untrusted_bootstrap_transport() {
        let p1 = provider(1, 11);
        let p2 = provider(2, 21);
        let policy = CheckpointBootstrapPolicy::new(vec![p1, p2]).unwrap();
        let epoch = epoch_near(NOW);
        let observations = [
            provider_observation(p1, 3, epoch, NOW - 10),
            provider_observation(p2, 3, epoch, NOW - 9),
        ];
        let (_, mut node_store) = store();
        let anchor = policy
            .install_provider_observation_agreement_with(
                &mut node_store,
                &observations,
                b"canonical-bootstrap".to_vec(),
                NOW,
                &TestValidator,
            )
            .unwrap();
        assert_eq!(anchor.checkpoint_epoch, epoch);
        let stored = node_store
            .checkpoint_approval(SEPOLIA_CHAIN_ID, [3; 32])
            .unwrap()
            .unwrap();
        assert_eq!(stored.attestations().len(), 2);

        let (_, mut invalid_bootstrap_store) = store();
        assert!(matches!(
            policy.install_provider_observation_agreement_with(
                &mut invalid_bootstrap_store,
                &observations,
                b"gateway-supplied-root-and-bootstrap".to_vec(),
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::Verification(
                ratspeak_eth_verifier::VerifyError::CheckpointMismatch
            ))
        ));

        let mismatched = [
            provider_observation(p1, 3, epoch, NOW - 10),
            provider_observation(p2, 4, epoch, NOW - 9),
        ];
        let (_, mut mismatch_store) = store();
        assert!(matches!(
            policy.install_provider_observation_agreement_with(
                &mut mismatch_store,
                &mismatched,
                b"canonical-bootstrap".to_vec(),
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::ProviderMismatch)
        ));
    }

    #[test]
    fn rejects_provider_mismatch_duplicate_source_and_unconfigured_source() {
        let p1 = provider(1, 11);
        let p2 = provider(2, 21);
        let policy = CheckpointBootstrapPolicy::new(vec![p1, p2]).unwrap();
        let epoch = epoch_near(NOW);
        for candidates in [
            vec![
                provider_candidate(p1, 3, epoch, NOW - 10),
                provider_candidate(p2, 4, epoch, NOW - 9),
            ],
            vec![
                provider_candidate(p1, 3, epoch, NOW - 10),
                provider_candidate(p2, 3, epoch + 1, NOW - 9),
            ],
        ] {
            let (_, mut store) = store();
            assert!(matches!(
                policy.install_provider_agreement_with(
                    &mut store,
                    &candidates,
                    NOW,
                    &TestValidator,
                ),
                Err(CheckpointPolicyError::ProviderMismatch)
            ));
        }

        let (_, mut duplicate_store) = store();
        let duplicate = [
            provider_candidate(p1, 3, epoch, NOW - 10),
            provider_candidate(p1, 3, epoch, NOW - 9),
        ];
        assert!(matches!(
            policy.install_provider_agreement_with(
                &mut duplicate_store,
                &duplicate,
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::DuplicateProviderObservation)
        ));

        let (_, mut unconfigured_store) = store();
        let unconfigured = [
            provider_candidate(p1, 3, epoch, NOW - 10),
            provider_candidate(provider(9, 99), 3, epoch, NOW - 9),
        ];
        assert!(matches!(
            policy.install_provider_agreement_with(
                &mut unconfigured_store,
                &unconfigured,
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::UnconfiguredProvider)
        ));
    }

    #[test]
    fn rejects_future_stale_malformed_and_epoch_mismatched_candidates() {
        let p1 = provider(1, 11);
        let p2 = provider(2, 21);
        let policy = CheckpointBootstrapPolicy::new(vec![p1, p2]).unwrap();
        let epoch = epoch_near(NOW);
        let cases = [
            (
                provider_candidate(p1, 3, epoch, NOW + MAX_FUTURE_SKEW_SECONDS + 1),
                CheckpointPolicyError::FutureObservation,
            ),
            (
                provider_candidate(p1, 3, epoch, NOW - MAX_OBSERVATION_AGE_SECONDS - 1),
                CheckpointPolicyError::StaleObservation,
            ),
            (
                provider_candidate(p1, 3, epoch + 10_000, NOW),
                CheckpointPolicyError::FutureCheckpoint,
            ),
            (
                provider_candidate(p1, 3, 1, NOW),
                CheckpointPolicyError::StaleCheckpoint,
            ),
            (
                provider_candidate(p1, 3, epoch - 1, NOW),
                CheckpointPolicyError::BootstrapEpochMismatch,
            ),
        ];
        for (candidate, expected) in cases {
            let error = validate_candidate(&candidate, NOW, &TestValidator).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }

        let malformed = CheckpointCandidate::from_provider(p1, epoch, [3; 32], vec![], NOW);
        assert!(matches!(
            validate_candidate(&malformed, NOW, &TestValidator),
            Err(CheckpointPolicyError::InvalidCandidate)
        ));
        let invalid_bytes = CheckpointCandidate::from_provider(
            p1,
            epoch,
            [3; 32],
            b"incoming-bundle-asserts-root".to_vec(),
            NOW,
        );
        assert!(matches!(
            validate_candidate(&invalid_bytes, NOW, &TestValidator),
            Err(CheckpointPolicyError::Verification(_))
        ));
        let _ = policy;
    }

    #[test]
    fn manual_approval_is_synchronous_cancelled_without_token_and_not_reused() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW);
        let (_, mut store) = store();
        let first = manual_candidate(4, epoch, NOW - 10);
        let mut approver = Approver::new(vec![false, true]);
        assert!(matches!(
            policy.install_manual_with(&mut store, &first, &mut approver, NOW, &TestValidator),
            Err(ManualCheckpointInstallError::Cancelled)
        ));
        assert!(store.latest_checkpoint_approval().unwrap().is_none());

        {
            let _anchor = policy
                .install_manual_with(&mut store, &first, &mut approver, NOW, &TestValidator)
                .unwrap();
        }
        assert_eq!(approver.calls.get(), 2);

        // Exact installed replay is re-verified but does not consume another
        // native approval. A different root cannot reuse the earlier result.
        {
            let _replay = policy
                .install_manual_with(&mut store, &first, &mut approver, NOW, &TestValidator)
                .unwrap();
        }
        assert_eq!(approver.calls.get(), 2);
        let next = manual_candidate(5, epoch + 1, NOW - 5);
        assert!(matches!(
            policy.install_manual_with(
                &mut store,
                &next,
                &mut approver,
                NOW,
                &TestValidatorAt(epoch + 1),
            ),
            Err(ManualCheckpointInstallError::Cancelled)
        ));
        assert_eq!(approver.calls.get(), 3);
        assert!(
            store
                .checkpoint_approval(SEPOLIA_CHAIN_ID, [5; 32])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn monotonic_advancement_rejects_rollback_conflicts_and_revocation_fallback() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW) - 2;
        let (profile, mut store) = store();
        let mut approver = Approver::new(vec![true, true, true, true]);
        let first = manual_candidate(4, epoch, NOW - 10);
        {
            let _anchor = policy
                .install_manual_with(
                    &mut store,
                    &first,
                    &mut approver,
                    NOW,
                    &TestValidatorAt(epoch),
                )
                .unwrap();
        }

        let rollback = manual_candidate(3, epoch - 1, NOW - 5);
        assert!(matches!(
            policy.install_manual_with(
                &mut store,
                &rollback,
                &mut approver,
                NOW,
                &TestValidatorAt(epoch - 1),
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::CheckpointRollback
            ))
        ));
        let same_epoch = manual_candidate(5, epoch, NOW - 5);
        assert!(matches!(
            policy.install_manual_with(
                &mut store,
                &same_epoch,
                &mut approver,
                NOW,
                &TestValidatorAt(epoch),
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::EpochRootConflict
            ))
        ));
        let same_root = manual_candidate(4, epoch + 1, NOW - 5);
        assert!(matches!(
            policy.install_manual_with(
                &mut store,
                &same_root,
                &mut approver,
                NOW,
                &TestValidatorAt(epoch + 1),
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::RootEpochConflict
            ))
        ));

        store
            .record_checkpoint_revocation(SEPOLIA_CHAIN_ID, [4; 32], [0xf1; 32], NOW)
            .unwrap();
        assert!(matches!(
            policy.active_anchor_at(&store, NOW),
            Err(CheckpointPolicyError::RevokedCheckpoint)
        ));
        drop(store);
        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(matches!(
            policy.active_anchor_at(&reopened, NOW),
            Err(CheckpointPolicyError::RevokedCheckpoint)
        ));
    }

    struct TestValidatorAt(u64);

    impl BootstrapValidator for TestValidatorAt {
        fn validate(
            &self,
            _checkpoint_root: [u8; 32],
            bootstrap_bundle: &[u8],
        ) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
            Ok(ValidatedBootstrap {
                canonical_bootstrap_hash: Sha256::digest(bootstrap_bundle).into(),
                checkpoint_epoch: self.0,
            })
        }
    }

    #[test]
    fn durable_native_review_is_exact_one_shot_and_redacted() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW);
        let (_, mut store) = store();
        let candidate = manual_candidate(4, epoch, NOW - 10);
        let review = policy
            .stage_manual_candidate_with(&mut store, &candidate, NOW, &TestValidator)
            .unwrap();
        assert_eq!(
            policy
                .pending_manual_checkpoint_reviews_at(&mut store, NOW + 1)
                .unwrap(),
            vec![review.clone()]
        );
        let debug = format!("{review:?}");
        assert!(!debug.contains("review_id"));
        assert!(!debug.contains("checkpoint_root"));
        assert!(!debug.contains("bootstrap"));

        let mut forged = review.clone();
        forged.checkpoint_root = [9; 32];
        let mut approver = Approver::new(vec![true]);
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut store,
                &forged,
                &mut approver,
                NOW + 1,
                Some(NOW + 2),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewChanged
            ))
        ));
        assert_eq!(approver.calls.get(), 0);
        let mut forged_profile = review.clone();
        forged_profile.profile_binding = [8; 32];
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut store,
                &forged_profile,
                &mut approver,
                NOW + 1,
                Some(NOW + 2),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewChanged
            ))
        ));
        let mut forged_source = review.clone();
        forged_source.source = ManualCheckpointSource::Url;
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut store,
                &forged_source,
                &mut approver,
                NOW + 1,
                Some(NOW + 2),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewChanged
            ))
        ));
        assert_eq!(approver.calls.get(), 0);

        assert_eq!(
            policy
                .resolve_manual_checkpoint_review_with(
                    &mut store,
                    &review,
                    &mut approver,
                    NOW + 1,
                    Some(NOW + 2),
                    &TestValidator,
                )
                .unwrap(),
            ManualCheckpointReviewResolution::Approved
        );
        assert_eq!(approver.calls.get(), 1);
        let installed = store
            .checkpoint_approval(SEPOLIA_CHAIN_ID, [4; 32])
            .unwrap()
            .unwrap();
        assert_eq!(
            installed.approval_basis(),
            CheckpointApprovalBasis::ExplicitUserApproval
        );
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut store,
                &review,
                &mut approver,
                NOW + 3,
                Some(NOW + 3),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewUnavailable
            ))
        ));
        assert_eq!(approver.calls.get(), 1);
    }

    #[test]
    fn ordinary_two_handle_activity_never_interrupts_an_authorizing_review() {
        let profile = tempfile::tempdir().unwrap();
        let mut resolving_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        // Open both handles before Authorizing exists. Opening after a process
        // restart deliberately invokes crash recovery instead.
        let mut concurrent_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let epoch = epoch_near(NOW);
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let review = policy
            .stage_manual_candidate_with(
                &mut resolving_store,
                &manual_candidate(4, epoch, NOW - 10),
                NOW,
                &TestValidator,
            )
            .unwrap();
        let review_for_thread = review.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let resolver = std::thread::spawn(move || {
            let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
            let mut approver = PausingApprover {
                entered: entered_tx,
                release: release_rx,
            };
            policy
                .resolve_manual_checkpoint_review_with(
                    &mut resolving_store,
                    &review_for_thread,
                    &mut approver,
                    NOW + 1,
                    Some(NOW + 3),
                    &TestValidator,
                )
                .unwrap()
        });
        entered_rx.recv().unwrap();

        let concurrent_policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        assert!(
            concurrent_policy
                .pending_manual_checkpoint_reviews_at(&mut concurrent_store, NOW + 2)
                .unwrap()
                .is_empty()
        );
        let next = concurrent_policy
            .stage_manual_candidate_with(
                &mut concurrent_store,
                &manual_candidate(5, epoch + 1, NOW - 5),
                NOW + 2,
                &TestValidatorAt(epoch + 1),
            )
            .unwrap();
        assert_eq!(next.checkpoint_root(), [5; 32]);

        release_tx.send(()).unwrap();
        assert_eq!(
            resolver.join().unwrap(),
            ManualCheckpointReviewResolution::Approved
        );
        assert_eq!(
            concurrent_store
                .latest_checkpoint_approval()
                .unwrap()
                .unwrap()
                .checkpoint_root(),
            review.checkpoint_root()
        );
    }

    #[test]
    fn concurrent_install_paths_cannot_split_an_epoch_or_roll_back() {
        let profile = tempfile::tempdir().unwrap();
        let manual_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let provider_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let epoch = epoch_near(NOW) - 2;
        let start = Arc::new(Barrier::new(2));

        let manual_start = Arc::clone(&start);
        let manual = std::thread::spawn(move || {
            let mut store = manual_store;
            let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
            let mut approver = Approver::new(vec![true]);
            manual_start.wait();
            policy
                .install_manual_with(
                    &mut store,
                    &manual_candidate(4, epoch, NOW - 10),
                    &mut approver,
                    NOW,
                    &TestValidatorAt(epoch),
                )
                .is_ok()
        });
        let provider_start = Arc::clone(&start);
        let provider = std::thread::spawn(move || {
            let mut store = provider_store;
            let p1 = provider(1, 11);
            let p2 = provider(2, 22);
            let policy = CheckpointBootstrapPolicy::new(vec![p1, p2]).unwrap();
            provider_start.wait();
            policy
                .install_provider_agreement_with(
                    &mut store,
                    &[
                        provider_candidate(p1, 5, epoch, NOW - 10),
                        provider_candidate(p2, 5, epoch, NOW - 9),
                    ],
                    NOW,
                    &TestValidatorAt(epoch),
                )
                .is_ok()
        });
        let outcomes = [manual.join().unwrap(), provider.join().unwrap()];
        assert_eq!(
            outcomes.into_iter().filter(|installed| *installed).count(),
            1
        );

        let mut higher_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let lower_store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let installed_epoch = higher_store
            .latest_checkpoint_approval()
            .unwrap()
            .unwrap()
            .checkpoint_epoch();
        let higher_epoch = installed_epoch + 2;
        let mut higher_approver = Approver::new(vec![true]);
        CheckpointBootstrapPolicy::new(Vec::new())
            .unwrap()
            .install_manual_with(
                &mut higher_store,
                &manual_candidate(6, higher_epoch, NOW - 5),
                &mut higher_approver,
                NOW + 1,
                &TestValidatorAt(higher_epoch),
            )
            .unwrap();
        let lower = std::thread::spawn(move || {
            let mut store = lower_store;
            let mut approver = Approver::new(vec![true]);
            CheckpointBootstrapPolicy::new(Vec::new())
                .unwrap()
                .install_manual_with(
                    &mut store,
                    &manual_candidate(7, installed_epoch + 1, NOW - 4),
                    &mut approver,
                    NOW + 2,
                    &TestValidatorAt(installed_epoch + 1),
                )
                .is_ok()
        });
        assert!(!lower.join().unwrap());
        assert_eq!(
            higher_store
                .latest_checkpoint_approval()
                .unwrap()
                .unwrap()
                .checkpoint_epoch(),
            higher_epoch
        );
    }

    #[test]
    fn durable_native_denial_expiry_and_storage_mutation_fail_closed() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW);

        let (_, mut denied_store) = store();
        let denied = policy
            .stage_manual_candidate_with(
                &mut denied_store,
                &manual_candidate(4, epoch, NOW - 10),
                NOW,
                &TestValidator,
            )
            .unwrap();
        let mut deny = Approver::new(vec![false, true]);
        assert_eq!(
            policy
                .resolve_manual_checkpoint_review_with(
                    &mut denied_store,
                    &denied,
                    &mut deny,
                    NOW + 1,
                    Some(NOW + 2),
                    &TestValidator,
                )
                .unwrap(),
            ManualCheckpointReviewResolution::Denied
        );
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut denied_store,
                &denied,
                &mut deny,
                NOW + 3,
                Some(NOW + 3),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewUnavailable
            ))
        ));
        assert_eq!(deny.calls.get(), 1);

        let (_, mut expiring_store) = store();
        let expiring = policy
            .stage_manual_candidate_with(
                &mut expiring_store,
                &manual_candidate(5, epoch, NOW - 10),
                NOW,
                &TestValidator,
            )
            .unwrap();
        assert!(
            policy
                .pending_manual_checkpoint_reviews_at(
                    &mut expiring_store,
                    expiring.expires_at_unix(),
                )
                .unwrap()
                .is_empty()
        );
        let mut approve = Approver::new(vec![true]);
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut expiring_store,
                &expiring,
                &mut approve,
                expiring.expires_at_unix(),
                Some(expiring.expires_at_unix()),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewUnavailable
            ))
        ));
        assert_eq!(approve.calls.get(), 0);

        let (_, mut mutated_store) = store();
        let mutated = policy
            .stage_manual_candidate_with(
                &mut mutated_store,
                &manual_candidate(6, epoch, NOW - 10),
                NOW,
                &TestValidator,
            )
            .unwrap();
        mutated_store
            .connection
            .execute(
                "UPDATE eth_pending_checkpoint_reviews
                 SET checkpoint_root = ?1 WHERE review_id = ?2",
                rusqlite::params![[7_u8; 32].as_slice(), mutated.review_id.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            policy.pending_manual_checkpoint_reviews_at(&mut mutated_store, NOW + 1),
            Err(CheckpointPolicyError::ReviewChanged)
        ));
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut mutated_store,
                &mutated,
                &mut approve,
                NOW + 1,
                Some(NOW + 2),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewChanged
            ))
        ));
        assert_eq!(approve.calls.get(), 0);
    }

    #[test]
    fn authority_changes_and_reopen_never_relabel_or_replay_reviews() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW) - 2;

        for revoke in [false, true] {
            let (_, mut store) = store();
            let mut direct = Approver::new(vec![true, true]);
            policy
                .install_manual_with(
                    &mut store,
                    &manual_candidate(2, epoch, NOW - 20),
                    &mut direct,
                    NOW,
                    &TestValidatorAt(epoch),
                )
                .unwrap();
            let pending = policy
                .stage_manual_candidate_with(
                    &mut store,
                    &manual_candidate(3, epoch + 1, NOW - 10),
                    NOW,
                    &TestValidatorAt(epoch + 1),
                )
                .unwrap();
            if revoke {
                store
                    .record_checkpoint_revocation(SEPOLIA_CHAIN_ID, [2; 32], [0x71; 32], NOW + 1)
                    .unwrap();
            } else {
                policy
                    .install_manual_with(
                        &mut store,
                        &manual_candidate(4, epoch + 2, NOW - 5),
                        &mut direct,
                        NOW + 1,
                        &TestValidatorAt(epoch + 2),
                    )
                    .unwrap();
            }
            let mut native = Approver::new(vec![true]);
            assert!(matches!(
                policy.resolve_manual_checkpoint_review_with(
                    &mut store,
                    &pending,
                    &mut native,
                    NOW + 2,
                    Some(NOW + 2),
                    &TestValidatorAt(epoch + 1),
                ),
                Err(ManualCheckpointInstallError::Policy(
                    CheckpointPolicyError::ReviewSuperseded
                ))
            ));
            assert_eq!(native.calls.get(), 0);
            assert!(
                store
                    .checkpoint_approval(SEPOLIA_CHAIN_ID, [3; 32])
                    .unwrap()
                    .is_none()
            );
        }

        let (profile, mut store) = store();
        let pending = policy
            .stage_manual_candidate_with(
                &mut store,
                &manual_candidate(5, epoch_near(NOW), NOW - 10),
                NOW,
                &TestValidator,
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_pending_checkpoint_reviews SET review_state = 2
                 WHERE review_id = ?1",
                [pending.review_id.as_slice()],
            )
            .unwrap();
        drop(store);
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            policy
                .pending_manual_checkpoint_reviews_at(&mut reopened, NOW + 1)
                .unwrap()
                .is_empty()
        );
        let mut native = Approver::new(vec![true]);
        assert!(matches!(
            policy.resolve_manual_checkpoint_review_with(
                &mut reopened,
                &pending,
                &mut native,
                NOW + 1,
                Some(NOW + 2),
                &TestValidator,
            ),
            Err(ManualCheckpointInstallError::Policy(
                CheckpointPolicyError::ReviewUnavailable
            ))
        ));
        assert_eq!(native.calls.get(), 0);
    }

    #[test]
    fn manual_review_rejects_provider_routing_and_bundle_root_self_authentication() {
        struct RootBoundValidator(u64);
        impl BootstrapValidator for RootBoundValidator {
            fn validate(
                &self,
                checkpoint_root: [u8; 32],
                bootstrap_bundle: &[u8],
            ) -> Result<ValidatedBootstrap, CheckpointPolicyError> {
                if checkpoint_root != [4; 32] || bootstrap_bundle != b"proof-for-root-four" {
                    return Err(CheckpointPolicyError::Verification(
                        ratspeak_eth_verifier::VerifyError::CheckpointMismatch,
                    ));
                }
                Ok(ValidatedBootstrap {
                    canonical_bootstrap_hash: Sha256::digest(bootstrap_bundle).into(),
                    checkpoint_epoch: self.0,
                })
            }
        }

        let configured = provider(1, 11);
        let configured_two = provider(2, 22);
        let policy = CheckpointBootstrapPolicy::new(vec![configured, configured_two]).unwrap();
        let epoch = epoch_near(NOW);
        let (_, mut store) = store();
        assert!(matches!(
            policy.stage_manual_candidate_with(
                &mut store,
                &provider_candidate(configured, 4, epoch, NOW - 10),
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::InvalidCandidate)
        ));
        policy
            .install_provider_agreement_with(
                &mut store,
                &[
                    provider_candidate(configured, 4, epoch, NOW - 10),
                    provider_candidate(configured_two, 4, epoch, NOW - 9),
                ],
                NOW,
                &TestValidator,
            )
            .unwrap();
        assert!(matches!(
            policy.stage_manual_candidate_with(
                &mut store,
                &manual_candidate(4, epoch, NOW - 8),
                NOW,
                &TestValidator,
            ),
            Err(CheckpointPolicyError::CheckpointAlreadyInstalled)
        ));
        assert_eq!(
            store
                .checkpoint_approval(SEPOLIA_CHAIN_ID, [4; 32])
                .unwrap()
                .unwrap()
                .approval_basis(),
            CheckpointApprovalBasis::ProviderAgreement
        );

        let self_authenticated = CheckpointCandidate::from_manual_source(
            ManualCheckpointSource::File,
            [0xa1; 32],
            epoch,
            [5; 32],
            b"proof-for-root-four".to_vec(),
            NOW - 10,
        );
        assert!(matches!(
            policy.stage_manual_candidate_with(
                &mut store,
                &self_authenticated,
                NOW,
                &RootBoundValidator(epoch),
            ),
            Err(CheckpointPolicyError::Verification(
                ratspeak_eth_verifier::VerifyError::CheckpointMismatch
            ))
        ));
        assert!(
            policy
                .pending_manual_checkpoint_reviews_at(&mut store, NOW + 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn schema_v13_upgrade_adds_the_review_ledger_without_rewriting_authority() {
        let (profile, mut store) = store();
        install_test_active_checkpoint(&mut store, [0x31; 32], NOW);
        store
            .connection
            .execute_batch(
                "DROP TABLE eth_pending_checkpoint_reviews;
                 UPDATE eth_schema_version SET version = 13 WHERE singleton = 1;",
            )
            .unwrap();
        drop(store);

        let reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let table_exists = reopened
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'eth_pending_checkpoint_reviews'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap();
        assert!(table_exists);
        assert_eq!(
            reopened
                .latest_checkpoint_approval()
                .unwrap()
                .unwrap()
                .checkpoint_root(),
            [0x31; 32]
        );
    }

    #[test]
    fn schema_v14_upgrade_rejects_conflicting_epochs_without_rewriting_rows() {
        let (profile, mut store) = store();
        install_test_active_checkpoint(&mut store, [0x41; 32], NOW);
        let path = store.path().to_path_buf();
        store
            .connection
            .execute_batch(
                "DROP INDEX eth_checkpoint_approvals_by_epoch;
                 INSERT INTO eth_checkpoint_approvals (
                    chain_id, network, checkpoint_root, approval_basis,
                    approved_at_unix, checkpoint_epoch, valid_until_unix,
                    record_digest, recorded_at_unix
                 )
                 SELECT chain_id, network, zeroblob(32), approval_basis,
                    approved_at_unix, checkpoint_epoch, valid_until_unix,
                    record_digest, recorded_at_unix
                 FROM eth_checkpoint_approvals;
                 UPDATE eth_schema_version SET version = 14 WHERE singleton = 1;",
            )
            .unwrap();
        drop(store);

        assert!(EthereumNodeStore::open_in_profile(profile.path()).is_err());
        let connection = rusqlite::Connection::open(path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT version FROM eth_schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            14
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM eth_checkpoint_approvals", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            2
        );
    }

    #[test]
    fn approved_anchor_survives_reopen_but_stale_or_corrupt_rows_fail_closed() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let epoch = epoch_near(NOW);
        let (profile, mut store) = store();
        let candidate = manual_candidate(4, epoch, NOW - 10);
        let mut approver = Approver::new(vec![true]);
        {
            let _anchor = policy
                .install_manual_with(&mut store, &candidate, &mut approver, NOW, &TestValidator)
                .unwrap();
        }
        drop(store);

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(policy.active_anchor_at(&store, NOW).is_ok());
        assert!(matches!(
            policy.active_anchor_at(&store, checkpoint_valid_until(epoch).unwrap()),
            Err(CheckpointPolicyError::StaleCheckpoint)
        ));
        let path = store.path().to_path_buf();
        drop(store);
        rusqlite::Connection::open(path)
            .unwrap()
            .execute(
                "UPDATE eth_checkpoint_approvals SET checkpoint_epoch = '1'",
                [],
            )
            .unwrap();
        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(policy.active_anchor_at(&store, NOW).is_err());
    }

    #[test]
    fn historical_finalized_evidence_uses_its_exact_approved_checkpoint_after_rotation() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let old_epoch = epoch_near(NOW) - 2;
        let new_epoch = old_epoch + 1;
        let old_root = [0x41; 32];
        let (_, mut store) = store();
        let mut approver = Approver::new(vec![true, true]);
        {
            policy
                .install_manual_with(
                    &mut store,
                    &manual_candidate(0x41, old_epoch, NOW - 20),
                    &mut approver,
                    NOW,
                    &TestValidatorAt(old_epoch),
                )
                .unwrap();
        }
        {
            policy
                .install_manual_with(
                    &mut store,
                    &manual_candidate(0x42, new_epoch, NOW - 10),
                    &mut approver,
                    NOW,
                    &TestValidatorAt(new_epoch),
                )
                .unwrap();
        }

        assert!(matches!(
            ensure_active_checkpoint_at(&store, old_root, NOW),
            Err(CheckpointPolicyError::CheckpointRollback)
        ));
        let finalized_at = checkpoint_time(old_epoch).unwrap() + 60;
        let after_old_expiry = checkpoint_valid_until(old_epoch).unwrap() + 60;
        ensure_checkpoint_approved_for_finalized_evidence_at(
            &store,
            old_root,
            finalized_at,
            after_old_expiry,
        )
        .unwrap();
        assert!(matches!(
            ensure_checkpoint_approved_for_finalized_evidence_at(
                &store,
                old_root,
                after_old_expiry + MAX_FUTURE_SKEW_SECONDS + 1,
                after_old_expiry,
            ),
            Err(CheckpointPolicyError::InvalidLocalClock)
        ));
        assert!(matches!(
            ensure_checkpoint_approved_for_finalized_evidence_at(
                &store,
                old_root,
                checkpoint_valid_until(old_epoch).unwrap(),
                after_old_expiry,
            ),
            Err(CheckpointPolicyError::StaleCheckpoint)
        ));

        store
            .record_checkpoint_revocation(SEPOLIA_CHAIN_ID, old_root, [0x77; 32], after_old_expiry)
            .unwrap();
        assert!(matches!(
            ensure_checkpoint_approved_for_finalized_evidence_at(
                &store,
                old_root,
                finalized_at,
                after_old_expiry,
            ),
            Err(CheckpointPolicyError::RevokedCheckpoint)
        ));
    }

    #[test]
    fn real_validator_rejects_bundle_root_self_authentication_before_install() {
        let policy = CheckpointBootstrapPolicy::new(Vec::new()).unwrap();
        let (_, mut store) = store();
        let mut self_authenticated = Vec::new();
        self_authenticated.extend_from_slice(ratspeak_eth_verifier::MAGIC);
        self_authenticated.push(ratspeak_eth_verifier::VERSION);
        self_authenticated.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        self_authenticated.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        self_authenticated.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        self_authenticated.push(1); // legacy self-authenticated finalized-header kind
        let candidate = CheckpointCandidate::from_manual_source(
            ManualCheckpointSource::File,
            [1; 32],
            epoch_near(trusted_now_unix().unwrap()),
            [2; 32],
            self_authenticated,
            trusted_now_unix().unwrap(),
        );
        assert!(matches!(
            policy.stage_manual_candidate(&mut store, &candidate),
            Err(CheckpointPolicyError::Verification(
                ratspeak_eth_verifier::VerifyError::UntrustedHeader
            ))
        ));
        assert!(store.latest_checkpoint_approval().unwrap().is_none());
    }
}
