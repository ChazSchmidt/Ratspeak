use ratspeak_eth_verifier::{MAX_BUNDLE_BYTES, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::messaging::{
    CheckpointRequestContext, MessageRequestStatus, MessagingEvidenceKind,
    insert_planned_package_request, insert_planned_signed_relay, read_account_request_progress,
    validate_planned_package_request, validate_planned_signed_relay,
};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

const MAX_TRIGGER_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
pub const MAX_SYNC_TRANSACTIONS_PER_PLAN: usize = 16;

/// Durable, human-presentable progress for the account request in the newest
/// synchronization plan. These are protocol states, not estimated percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSyncStage {
    Queued,
    Sending,
    WaitingForGateway,
    AwaitingDownloadApproval,
    Verifying,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSyncProgress {
    stage: AccountSyncStage,
    created_at_unix: u64,
    expires_at_unix: u64,
    expected_gateway_source_hash: [u8; 16],
}

impl AccountSyncProgress {
    pub fn stage(self) -> AccountSyncStage {
        self.stage
    }

    pub fn created_at_unix(self) -> u64 {
        self.created_at_unix
    }

    pub fn expires_at_unix(self) -> u64 {
        self.expires_at_unix
    }

    /// Whether this progress belongs to the service currently selected by the
    /// caller. The destination itself remains native and is never serialized
    /// into the application WebView.
    pub fn belongs_to_gateway(self, gateway_source_hash: [u8; 16]) -> bool {
        self.expected_gateway_source_hash == gateway_source_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceSyncTrigger {
    trigger_id: [u8; 16],
    generation: u64,
    expected_gateway_source_hash: [u8; 16],
    maximum_response_bytes: u32,
    created_at_unix: u64,
    expires_at_unix: u64,
}

impl EvidenceSyncTrigger {
    pub fn new(
        trigger_id: [u8; 16],
        generation: u64,
        expected_gateway_source_hash: [u8; 16],
        maximum_response_bytes: u32,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        Self {
            trigger_id,
            generation,
            expected_gateway_source_hash,
            maximum_response_bytes,
            created_at_unix,
            expires_at_unix,
        }
    }

    pub(crate) fn expires_at_unix(self) -> u64 {
        self.expires_at_unix
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedEvidenceRequest {
    request_id: [u8; 16],
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
}

impl PlannedEvidenceRequest {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn kind(&self) -> MessagingEvidenceKind {
        self.kind
    }

    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSyncPlan {
    trigger_id: [u8; 16],
    generation: u64,
    account_request: PlannedEvidenceRequest,
    relay_requests: Vec<PlannedRelayRequest>,
    receipt_requests: Vec<PlannedEvidenceRequest>,
}

impl EvidenceSyncPlan {
    pub fn trigger_id(&self) -> [u8; 16] {
        self.trigger_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn account_request(&self) -> PlannedEvidenceRequest {
        self.account_request
    }

    pub fn receipt_requests(&self) -> &[PlannedEvidenceRequest] {
        &self.receipt_requests
    }

    pub fn relay_requests(&self) -> &[PlannedRelayRequest] {
        &self.relay_requests
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedRelayRequest {
    request_id: [u8; 16],
    tx_hash: [u8; 32],
}

impl PlannedRelayRequest {
    pub fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    pub fn tx_hash(self) -> [u8; 32] {
        self.tx_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSyncPlan {
    trigger: EvidenceSyncTrigger,
    wallet_address: [u8; 20],
    checkpoint_context: CheckpointRequestContext,
    request_set_digest: [u8; 32],
    request_count: u64,
}

pub(crate) fn create_schema(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_sync_plans (
                trigger_id BLOB PRIMARY KEY NOT NULL CHECK(length(trigger_id) = 16),
                generation TEXT NOT NULL UNIQUE,
                expected_gateway_source_hash BLOB NOT NULL
                    CHECK(length(expected_gateway_source_hash) = 16),
                wallet_address BLOB NOT NULL CHECK(length(wallet_address) = 20),
                checkpoint_epoch TEXT NOT NULL,
                checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                maximum_response_bytes TEXT NOT NULL,
                created_at_unix TEXT NOT NULL,
                expires_at_unix TEXT NOT NULL,
                request_count TEXT NOT NULL,
                request_set_digest BLOB NOT NULL CHECK(length(request_set_digest) = 32),
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE TABLE IF NOT EXISTS eth_sync_plan_requests (
                trigger_id BLOB NOT NULL CHECK(length(trigger_id) = 16),
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
                evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (5, 6)),
                subject BLOB NOT NULL CHECK(length(subject) = 32),
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                PRIMARY KEY(trigger_id, ordinal),
                FOREIGN KEY(trigger_id) REFERENCES eth_sync_plans(trigger_id),
                FOREIGN KEY(request_id) REFERENCES eth_message_requests(request_id)
             );
             CREATE TABLE IF NOT EXISTS eth_sync_plan_relays (
                trigger_id BLOB NOT NULL CHECK(length(trigger_id) = 16),
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                request_id BLOB NOT NULL UNIQUE CHECK(length(request_id) = 16),
                tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                PRIMARY KEY(trigger_id, ordinal),
                FOREIGN KEY(trigger_id) REFERENCES eth_sync_plans(trigger_id),
                FOREIGN KEY(request_id) REFERENCES eth_message_requests(request_id)
             );
             CREATE TABLE IF NOT EXISTS eth_sync_plan_relay_sets (
                trigger_id BLOB PRIMARY KEY NOT NULL CHECK(length(trigger_id) = 16),
                relay_count TEXT NOT NULL,
                relay_set_digest BLOB NOT NULL CHECK(length(relay_set_digest) = 32),
                record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                FOREIGN KEY(trigger_id) REFERENCES eth_sync_plans(trigger_id)
             );",
        )
        .map_err(NodeStoreError::sqlite)
}

impl EthereumNodeStore {
    /// Reads the newest durable account-check lifecycle without exposing its
    /// request identifier, gateway, checkpoint, or proof contents.
    pub fn latest_account_sync_progress(
        &mut self,
        now_unix: u64,
    ) -> Result<Option<AccountSyncProgress>> {
        if now_unix == 0 {
            return Err(NodeStoreError::new("invalid sync progress clock"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(NodeStoreError::sqlite)?;
        let trigger_id = transaction
            .query_row(
                "SELECT trigger_id FROM eth_sync_plans
                 ORDER BY CAST(generation AS INTEGER) DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?
            .map(|value| stored_array::<16>(&value, "sync progress trigger"))
            .transpose()?;
        let Some(trigger_id) = trigger_id else {
            return Ok(None);
        };
        let stored = read_sync_plan(&transaction, trigger_id)?
            .ok_or_else(|| NodeStoreError::new("sync progress plan disappeared"))?;
        let plan = read_and_validate_plan_requests(&transaction, &stored)?;
        let request_id = plan.account_request().request_id();
        let request = read_account_request_progress(&transaction, request_id)?
            .ok_or_else(|| NodeStoreError::new("sync progress request disappeared"))?;
        let stage = account_sync_stage(
            request.status,
            request.bulk_approved,
            request.outbox_state,
            stored.trigger.expires_at_unix,
            now_unix,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(Some(AccountSyncProgress {
            stage,
            created_at_unix: stored.trigger.created_at_unix,
            expires_at_unix: stored.trigger.expires_at_unix,
            expected_gateway_source_hash: stored.trigger.expected_gateway_source_hash,
        }))
    }

    pub fn next_evidence_sync_generation(&self) -> Result<u64> {
        latest_sync_generation(&self.connection)?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| NodeStoreError::new("sync generation exhausted"))
    }

    /// Plans a finite, explicitly triggered account/receipt synchronization.
    /// The active checkpoint is selected and validated from this profile; no
    /// checkpoint authority enters through this public API.
    pub fn plan_evidence_sync(
        &mut self,
        trigger: EvidenceSyncTrigger,
    ) -> Result<(RecordOutcome, EvidenceSyncPlan)> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        self.plan_evidence_sync_at_mode(trigger, now_unix, false)
    }

    /// Resumes the newest still-valid immutable plan when its gateway,
    /// checkpoint, wallet, response policy, and subjects still match. This is
    /// the application entry point: repeated commands and process restarts do
    /// not create parallel durable requests for the same finite work.
    pub fn plan_or_resume_evidence_sync(
        &mut self,
        trigger: EvidenceSyncTrigger,
    ) -> Result<(RecordOutcome, EvidenceSyncPlan)> {
        let now_unix = crate::bootstrap::trusted_now_unix()
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
        self.plan_evidence_sync_at_mode(trigger, now_unix, true)
    }

    #[cfg(test)]
    fn plan_evidence_sync_at(
        &mut self,
        trigger: EvidenceSyncTrigger,
        now_unix: u64,
    ) -> Result<(RecordOutcome, EvidenceSyncPlan)> {
        self.plan_evidence_sync_at_mode(trigger, now_unix, false)
    }

    fn plan_evidence_sync_at_mode(
        &mut self,
        trigger: EvidenceSyncTrigger,
        now_unix: u64,
        resume_compatible: bool,
    ) -> Result<(RecordOutcome, EvidenceSyncPlan)> {
        validate_trigger_shape(trigger, now_unix)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;

        if let Some(stored) = read_sync_plan(&transaction, trigger.trigger_id)? {
            if stored.trigger != trigger {
                return Err(NodeStoreError::new(
                    "sync trigger conflicts with an immutable plan",
                ));
            }
            crate::bootstrap::ensure_active_checkpoint_at_connection(
                &transaction,
                stored.checkpoint_context.checkpoint_root,
                now_unix,
            )
            .map_err(|error| NodeStoreError::new(error.to_string()))?;
            let plan = read_and_validate_plan_requests(&transaction, &stored)?;
            transaction.commit().map_err(NodeStoreError::sqlite)?;
            return Ok((RecordOutcome::Replay, plan));
        }
        validate_fresh_trigger(trigger, now_unix)?;

        let latest_generation = latest_sync_generation(&transaction)?;
        if !resume_compatible
            && latest_generation.is_some_and(|latest| trigger.generation <= latest)
        {
            return Err(NodeStoreError::new("sync generation did not advance"));
        }

        let checkpoint = crate::checkpoint::latest_checkpoint_approval(&transaction)?
            .ok_or_else(|| NodeStoreError::new("no policy-approved checkpoint"))?;
        crate::bootstrap::ensure_active_checkpoint_at_connection(
            &transaction,
            checkpoint.checkpoint_root(),
            now_unix,
        )
        .map_err(|error| NodeStoreError::new(error.to_string()))?;
        let checkpoint_context = CheckpointRequestContext {
            checkpoint_epoch: checkpoint.checkpoint_epoch(),
            checkpoint_root: checkpoint.checkpoint_root(),
        };
        let wallet = crate::read_wallet_account(&transaction)?
            .ok_or_else(|| NodeStoreError::new("Ethereum wallet account is not installed"))?;
        let wallet_address = *wallet.address().0;
        let mut account_subject = [0; 32];
        account_subject[12..].copy_from_slice(&wallet_address);
        let unconfirmed = crate::transaction::read_unconfirmed_signed_transactions(
            &transaction,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
        )?;
        if unconfirmed.len() > MAX_SYNC_TRANSACTIONS_PER_PLAN {
            return Err(NodeStoreError::new(format!(
                "unconfirmed transaction count exceeds finite sync plan limit of {MAX_SYNC_TRANSACTIONS_PER_PLAN}"
            )));
        }

        if resume_compatible {
            let mut active = Vec::new();
            for stored in unexpired_sync_plans(&transaction, now_unix)? {
                let existing = read_and_validate_plan_requests(&transaction, &stored)?;
                if sync_plan_has_outstanding_requests(&transaction, &existing)? {
                    active.push((stored, existing));
                }
            }
            for (stored, _) in &active {
                if stored.trigger.expected_gateway_source_hash
                    != trigger.expected_gateway_source_hash
                    || stored.trigger.maximum_response_bytes != trigger.maximum_response_bytes
                {
                    return Err(NodeStoreError::new(
                        "active sync plan conflicts with gateway or response policy",
                    ));
                }
                if stored.checkpoint_context != checkpoint_context {
                    return Err(NodeStoreError::new(
                        "active sync plan conflicts with checkpoint authority",
                    ));
                }
                if stored.wallet_address != wallet_address {
                    return Err(NodeStoreError::new(
                        "active sync plan conflicts with wallet account",
                    ));
                }
            }
            if active.len() > 1 {
                return Err(NodeStoreError::new(
                    "multiple active sync plans require recovery",
                ));
            }
            if let Some((_, existing)) = active.pop() {
                if !sync_plan_covers_subjects(&existing, account_subject, &unconfirmed) {
                    return Err(NodeStoreError::new(
                        "active sync plan conflicts with requested subjects",
                    ));
                }
                transaction.commit().map_err(NodeStoreError::sqlite)?;
                return Ok((RecordOutcome::Replay, existing));
            }
        }
        if latest_generation.is_some_and(|latest| trigger.generation <= latest) {
            return Err(NodeStoreError::new("sync generation did not advance"));
        }

        // A status report is only a scheduling hint, never proof.  It can
        // make a receipt request worthwhile once its claimed inclusion is at
        // or before its claimed finalized head; the receipt package itself
        // remains independently bound to the local checkpoint and verifier.
        let eligible_receipts = eligible_receipt_transactions(
            &transaction,
            &unconfirmed,
            trigger.expected_gateway_source_hash,
        )?;
        let mut requests = Vec::with_capacity(eligible_receipts.len().saturating_add(1));
        requests.push(PlannedEvidenceRequest {
            request_id: derive_request_id(
                trigger,
                checkpoint_context,
                MessagingEvidenceKind::AccountStatePackage,
                account_subject,
                0,
            ),
            kind: MessagingEvidenceKind::AccountStatePackage,
            subject: account_subject,
        });
        for (index, tx_hash) in &eligible_receipts {
            requests.push(PlannedEvidenceRequest {
                request_id: derive_request_id(
                    trigger,
                    checkpoint_context,
                    MessagingEvidenceKind::FinalizedReceiptPackage,
                    *tx_hash,
                    u64::try_from(*index)
                        .map_err(|_| NodeStoreError::new("too many unconfirmed transactions"))?
                        .saturating_add(1),
                ),
                kind: MessagingEvidenceKind::FinalizedReceiptPackage,
                subject: *tx_hash,
            });
        }
        let relay_requests = unconfirmed
            .iter()
            .enumerate()
            .map(|(index, transaction)| PlannedRelayRequest {
                request_id: derive_relay_request_id(
                    trigger,
                    checkpoint_context,
                    transaction.tx_hash(),
                    index as u64,
                ),
                tx_hash: transaction.tx_hash(),
            })
            .collect::<Vec<_>>();
        let request_set_digest = request_set_digest(&requests);
        let stored = StoredSyncPlan {
            trigger,
            wallet_address,
            checkpoint_context,
            request_set_digest,
            request_count: requests.len() as u64,
        };
        insert_sync_plan(&transaction, &stored)?;
        insert_planned_package_request(
            &transaction,
            requests[0].request_id,
            trigger.expected_gateway_source_hash,
            requests[0].kind,
            requests[0].subject,
            checkpoint_context,
            trigger.maximum_response_bytes,
            trigger.created_at_unix,
            trigger.expires_at_unix,
            now_unix,
        )?;
        insert_plan_request(&transaction, trigger.trigger_id, 0, requests[0])?;
        for (index, (signed, relay)) in unconfirmed.iter().zip(relay_requests.iter()).enumerate() {
            insert_planned_signed_relay(
                &transaction,
                relay.request_id,
                trigger.expected_gateway_source_hash,
                signed,
                trigger.created_at_unix,
                trigger.expires_at_unix,
            )?;
            insert_plan_relay(&transaction, trigger.trigger_id, index, relay)?;
        }
        insert_plan_relay_set(&transaction, trigger.trigger_id, &relay_requests)?;
        for (index, receipt) in requests.iter().skip(1).enumerate() {
            insert_planned_package_request(
                &transaction,
                receipt.request_id,
                trigger.expected_gateway_source_hash,
                receipt.kind,
                receipt.subject,
                checkpoint_context,
                trigger.maximum_response_bytes,
                trigger.created_at_unix,
                trigger.expires_at_unix,
                now_unix,
            )?;
            insert_plan_request(&transaction, trigger.trigger_id, index + 1, *receipt)?;
        }
        let plan = plan_from_requests(trigger, requests, relay_requests)?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok((RecordOutcome::Inserted, plan))
    }
}

fn account_sync_stage(
    request_status: MessageRequestStatus,
    bulk_approved: bool,
    outbox_state: Option<i64>,
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<AccountSyncStage> {
    if expires_at_unix <= now_unix || request_status == MessageRequestStatus::Expired {
        return Ok(AccountSyncStage::Failed);
    }
    match request_status {
        MessageRequestStatus::Pending => match outbox_state {
            None | Some(0) => Ok(AccountSyncStage::Queued),
            Some(1) => Ok(AccountSyncStage::Sending),
            Some(2) => Ok(AccountSyncStage::WaitingForGateway),
            _ => Err(NodeStoreError::new("sync progress outbox is invalid")),
        },
        MessageRequestStatus::AwaitingBulkApproval => {
            Ok(AccountSyncStage::AwaitingDownloadApproval)
        }
        MessageRequestStatus::Ready if !bulk_approved => Ok(AccountSyncStage::WaitingForGateway),
        MessageRequestStatus::Ready => match outbox_state {
            None | Some(0) => Ok(AccountSyncStage::Queued),
            Some(1) => Ok(AccountSyncStage::Sending),
            Some(2) => Ok(AccountSyncStage::WaitingForGateway),
            _ => Err(NodeStoreError::new(
                "sync progress approval outbox is invalid",
            )),
        },
        MessageRequestStatus::PendingVerification => Ok(AccountSyncStage::Verifying),
        MessageRequestStatus::Completed => Ok(AccountSyncStage::Completed),
        MessageRequestStatus::Cancelled | MessageRequestStatus::Expired => {
            Ok(AccountSyncStage::Failed)
        }
    }
}

fn validate_trigger_shape(trigger: EvidenceSyncTrigger, now_unix: u64) -> Result<()> {
    if trigger.trigger_id == [0; 16]
        || trigger.generation == 0
        || trigger.expected_gateway_source_hash == [0; 16]
        || trigger.maximum_response_bytes == 0
        || trigger.maximum_response_bytes as usize > MAX_BUNDLE_BYTES
        || trigger.created_at_unix == 0
        || trigger.expires_at_unix <= trigger.created_at_unix
        || now_unix >= trigger.expires_at_unix
    {
        return Err(NodeStoreError::new("invalid Ethereum sync trigger"));
    }
    Ok(())
}

fn validate_fresh_trigger(trigger: EvidenceSyncTrigger, now_unix: u64) -> Result<()> {
    if trigger.created_at_unix > now_unix.saturating_add(MAX_TRIGGER_CLOCK_SKEW_SECONDS)
        || now_unix.saturating_sub(trigger.created_at_unix) > MAX_TRIGGER_CLOCK_SKEW_SECONDS
    {
        return Err(NodeStoreError::new(
            "new Ethereum sync trigger does not match the trusted local clock",
        ));
    }
    Ok(())
}

fn latest_sync_generation(connection: &rusqlite::Connection) -> Result<Option<u64>> {
    let mut statement = connection
        .prepare("SELECT generation FROM eth_sync_plans")
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(NodeStoreError::sqlite)?;
    let mut latest = None;
    for row in rows {
        let value = row.map_err(NodeStoreError::sqlite)?;
        let generation = parse_stored_u64(&value, "sync generation")?;
        latest = Some(latest.map_or(generation, |current: u64| current.max(generation)));
    }
    Ok(latest)
}

fn unexpired_sync_plans(
    connection: &rusqlite::Connection,
    now_unix: u64,
) -> Result<Vec<StoredSyncPlan>> {
    let trigger_ids = {
        let mut statement = connection
            .prepare("SELECT trigger_id FROM eth_sync_plans")
            .map_err(NodeStoreError::sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(NodeStoreError::sqlite)?;
        rows.map(|row| {
            stored_array::<16>(
                &row.map_err(NodeStoreError::sqlite)?,
                "stored sync trigger identifier",
            )
        })
        .collect::<Result<Vec<_>>>()?
    };
    let mut unexpired = Vec::new();
    for trigger_id in trigger_ids {
        let stored = read_sync_plan(connection, trigger_id)?
            .ok_or_else(|| NodeStoreError::new("stored sync plan disappeared"))?;
        if stored.trigger.expires_at_unix > now_unix {
            unexpired.push(stored);
        }
    }
    unexpired.sort_unstable_by_key(|stored| stored.trigger.generation);
    Ok(unexpired)
}

fn sync_plan_covers_subjects(
    plan: &EvidenceSyncPlan,
    account_subject: [u8; 32],
    unconfirmed: &[crate::StoredSignedTransaction],
) -> bool {
    plan.account_request.subject == account_subject
        && plan.relay_requests.len() == unconfirmed.len()
        && receipt_requests_are_valid_snapshot(&plan.receipt_requests)
        && plan
            .relay_requests
            .iter()
            .zip(unconfirmed)
            .all(|(request, transaction)| request.tx_hash == transaction.tx_hash())
}

/// Receipt requests are a validated snapshot of status eligibility at plan
/// creation. A receipt may finish while related account work remains active,
/// and later status reports schedule their own proof work; neither should
/// make the original plan conflict on replay.
fn receipt_requests_are_valid_snapshot(requests: &[PlannedEvidenceRequest]) -> bool {
    requests.iter().enumerate().all(|(index, request)| {
        request.kind == MessagingEvidenceKind::FinalizedReceiptPackage
            && !requests[..index]
                .iter()
                .any(|earlier| earlier.subject == request.subject)
    })
}

/// Returns unconfirmed transaction indexes and hashes whose newest
/// authenticated report from this selected service claims inclusion no later
/// than its claimed finalized head.  This deliberately does not consult the
/// report's block hash or create an assurance result.
fn eligible_receipt_transactions(
    connection: &rusqlite::Connection,
    unconfirmed: &[crate::StoredSignedTransaction],
    expected_gateway_source_hash: [u8; 16],
) -> Result<Vec<(usize, [u8; 32])>> {
    let mut eligible = Vec::new();
    for (index, transaction) in unconfirmed.iter().enumerate() {
        let Some(observation) = crate::messaging::read_latest_transaction_status_observation(
            connection,
            transaction.tx_hash(),
        )?
        else {
            continue;
        };
        if observation.source_hash() == expected_gateway_source_hash
            && observation.status() == crate::messaging::TransactionStatus::Included
            && observation
                .included_block_number()
                .is_some_and(|number| number <= observation.finalized_head_number())
        {
            eligible.push((index, transaction.tx_hash()));
        }
    }
    Ok(eligible)
}

fn sync_plan_has_outstanding_requests(
    connection: &rusqlite::Connection,
    plan: &EvidenceSyncPlan,
) -> Result<bool> {
    let request_ids = std::iter::once(plan.account_request.request_id)
        .chain(
            plan.receipt_requests
                .iter()
                .map(|request| request.request_id),
        )
        .chain(plan.relay_requests.iter().map(|request| request.request_id));
    for request_id in request_ids {
        let status = connection
            .query_row(
                "SELECT status FROM eth_message_requests WHERE request_id = ?1",
                [request_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(NodeStoreError::sqlite)?;
        match status {
            // Pending, awaiting approval, ready, and pending verification all
            // retain finite work. Completed, cancelled, and expired do not.
            1 | 2 | 3 | 7 => return Ok(true),
            4..=6 => {}
            _ => return Err(NodeStoreError::new("invalid messaging request status")),
        }
    }
    Ok(false)
}

fn derive_request_id(
    trigger: EvidenceSyncTrigger,
    checkpoint: CheckpointRequestContext,
    kind: MessagingEvidenceKind,
    subject: [u8; 32],
    ordinal: u64,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-request.v1");
    hasher.update(trigger.trigger_id);
    hasher.update(trigger.generation.to_le_bytes());
    hasher.update([kind.wire()]);
    hasher.update(ordinal.to_le_bytes());
    hasher.update(subject);
    hasher.update(checkpoint.checkpoint_epoch.to_le_bytes());
    hasher.update(checkpoint.checkpoint_root);
    let digest = hasher.finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id[0] |= 0x80;
    request_id
}

fn derive_relay_request_id(
    trigger: EvidenceSyncTrigger,
    checkpoint: CheckpointRequestContext,
    tx_hash: [u8; 32],
    ordinal: u64,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-relay.v1");
    hasher.update(trigger.trigger_id);
    hasher.update(trigger.generation.to_le_bytes());
    hasher.update(ordinal.to_le_bytes());
    hasher.update(tx_hash);
    hasher.update(checkpoint.checkpoint_epoch.to_le_bytes());
    hasher.update(checkpoint.checkpoint_root);
    let digest = hasher.finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id[0] |= 0x80;
    request_id
}

fn insert_sync_plan(transaction: &Transaction<'_>, plan: &StoredSyncPlan) -> Result<()> {
    let digest = sync_plan_digest(plan);
    transaction
        .execute(
            "INSERT INTO eth_sync_plans (
                trigger_id, generation, expected_gateway_source_hash,
                wallet_address, checkpoint_epoch, checkpoint_root,
                maximum_response_bytes, created_at_unix, expires_at_unix,
                request_count, request_set_digest, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                plan.trigger.trigger_id.as_slice(),
                plan.trigger.generation.to_string(),
                plan.trigger.expected_gateway_source_hash.as_slice(),
                plan.wallet_address.as_slice(),
                plan.checkpoint_context.checkpoint_epoch.to_string(),
                plan.checkpoint_context.checkpoint_root.as_slice(),
                plan.trigger.maximum_response_bytes.to_string(),
                plan.trigger.created_at_unix.to_string(),
                plan.trigger.expires_at_unix.to_string(),
                plan.request_count.to_string(),
                plan.request_set_digest.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn insert_plan_request(
    transaction: &Transaction<'_>,
    trigger_id: [u8; 16],
    ordinal: usize,
    request: PlannedEvidenceRequest,
) -> Result<()> {
    let ordinal =
        u64::try_from(ordinal).map_err(|_| NodeStoreError::new("too many planned requests"))?;
    let digest = plan_request_digest(trigger_id, ordinal, request);
    transaction
        .execute(
            "INSERT INTO eth_sync_plan_requests (
                trigger_id, ordinal, request_id, evidence_kind, subject, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                trigger_id.as_slice(),
                ordinal,
                request.request_id.as_slice(),
                request.kind.wire(),
                request.subject.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn insert_plan_relay(
    transaction: &Transaction<'_>,
    trigger_id: [u8; 16],
    ordinal: usize,
    relay: &PlannedRelayRequest,
) -> Result<()> {
    let ordinal =
        u64::try_from(ordinal).map_err(|_| NodeStoreError::new("too many planned relays"))?;
    let digest = plan_relay_digest(trigger_id, ordinal, *relay);
    transaction
        .execute(
            "INSERT INTO eth_sync_plan_relays (
                trigger_id, ordinal, request_id, tx_hash, record_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                trigger_id.as_slice(),
                ordinal,
                relay.request_id.as_slice(),
                relay.tx_hash.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn insert_plan_relay_set(
    transaction: &Transaction<'_>,
    trigger_id: [u8; 16],
    relays: &[PlannedRelayRequest],
) -> Result<()> {
    let count =
        u64::try_from(relays.len()).map_err(|_| NodeStoreError::new("too many planned relays"))?;
    let set_digest = relay_set_digest(relays);
    let digest = relay_set_record_digest(trigger_id, count, set_digest);
    transaction
        .execute(
            "INSERT INTO eth_sync_plan_relay_sets (
                trigger_id, relay_count, relay_set_digest, record_digest
             ) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                trigger_id.as_slice(),
                count.to_string(),
                set_digest.as_slice(),
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn read_sync_plan(
    connection: &rusqlite::Connection,
    trigger_id: [u8; 16],
) -> Result<Option<StoredSyncPlan>> {
    let row = connection
        .query_row(
            "SELECT generation, expected_gateway_source_hash, wallet_address,
                    checkpoint_epoch, checkpoint_root, maximum_response_bytes,
                    created_at_unix, expires_at_unix, request_count,
                    request_set_digest, record_digest
               FROM eth_sync_plans WHERE trigger_id = ?1",
            [trigger_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let plan = StoredSyncPlan {
        trigger: EvidenceSyncTrigger {
            trigger_id,
            generation: parse_stored_u64(&row.0, "sync generation")?,
            expected_gateway_source_hash: stored_array(&row.1, "sync gateway")?,
            maximum_response_bytes: u32::try_from(parse_stored_u64(
                &row.5,
                "sync maximum response bytes",
            )?)
            .map_err(|_| NodeStoreError::new("invalid sync response limit"))?,
            created_at_unix: parse_stored_u64(&row.6, "sync creation time")?,
            expires_at_unix: parse_stored_u64(&row.7, "sync expiry time")?,
        },
        wallet_address: stored_array(&row.2, "sync wallet address")?,
        checkpoint_context: CheckpointRequestContext {
            checkpoint_epoch: parse_stored_u64(&row.3, "sync checkpoint epoch")?,
            checkpoint_root: stored_array(&row.4, "sync checkpoint root")?,
        },
        request_count: parse_stored_u64(&row.8, "sync request count")?,
        request_set_digest: stored_array(&row.9, "sync request set digest")?,
    };
    if plan.trigger.generation == 0
        || plan.trigger.expected_gateway_source_hash == [0; 16]
        || plan.wallet_address == [0; 20]
        || plan.checkpoint_context.checkpoint_epoch == 0
        || plan.checkpoint_context.checkpoint_root == [0; 32]
        || plan.trigger.maximum_response_bytes == 0
        || plan.trigger.maximum_response_bytes as usize > MAX_BUNDLE_BYTES
        || plan.trigger.created_at_unix == 0
        || plan.trigger.expires_at_unix <= plan.trigger.created_at_unix
        || plan.request_count == 0
        || stored_array::<32>(&row.10, "sync plan digest")? != sync_plan_digest(&plan)
    {
        return Err(NodeStoreError::new("stored sync plan failed validation"));
    }
    Ok(Some(plan))
}

fn read_and_validate_plan_requests(
    connection: &rusqlite::Connection,
    stored: &StoredSyncPlan,
) -> Result<EvidenceSyncPlan> {
    let mut statement = connection
        .prepare(
            "SELECT ordinal, request_id, evidence_kind, subject, record_digest
               FROM eth_sync_plan_requests
              WHERE trigger_id = ?1 ORDER BY ordinal",
        )
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map([stored.trigger.trigger_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u8>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(NodeStoreError::sqlite)?;
    let mut requests = Vec::new();
    for row in rows {
        let row = row.map_err(NodeStoreError::sqlite)?;
        let ordinal = u64::try_from(row.0)
            .map_err(|_| NodeStoreError::new("invalid sync request ordinal"))?;
        if ordinal != requests.len() as u64 {
            return Err(NodeStoreError::new(
                "sync request ordinals are not contiguous",
            ));
        }
        let request = PlannedEvidenceRequest {
            request_id: stored_array(&row.1, "planned request identifier")?,
            kind: MessagingEvidenceKind::from_wire(row.2)?,
            subject: stored_array(&row.3, "planned request subject")?,
        };
        if stored_array::<32>(&row.4, "planned request digest")?
            != plan_request_digest(stored.trigger.trigger_id, ordinal, request)
        {
            return Err(NodeStoreError::new("planned request failed validation"));
        }
        validate_planned_package_request(
            connection,
            request.request_id,
            stored.trigger.expected_gateway_source_hash,
            request.kind,
            request.subject,
            stored.checkpoint_context,
            stored.trigger.maximum_response_bytes,
            stored.trigger.created_at_unix,
            stored.trigger.expires_at_unix,
        )?;
        requests.push(request);
    }
    if requests.len() as u64 != stored.request_count
        || request_set_digest(&requests) != stored.request_set_digest
    {
        return Err(NodeStoreError::new("sync request set failed validation"));
    }
    let relay_requests = read_and_validate_plan_relays(connection, stored, &requests)?;
    plan_from_requests(stored.trigger, requests, relay_requests)
}

fn read_and_validate_plan_relays(
    connection: &rusqlite::Connection,
    stored: &StoredSyncPlan,
    requests: &[PlannedEvidenceRequest],
) -> Result<Vec<PlannedRelayRequest>> {
    let relay_set = connection
        .query_row(
            "SELECT relay_count, relay_set_digest, record_digest
               FROM eth_sync_plan_relay_sets WHERE trigger_id = ?1",
            [stored.trigger.trigger_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some((relay_count, relay_set_digest_bytes, record_digest)) = relay_set else {
        // Plans created before relay rows were made explicit used each receipt
        // request as its relay list. Retain that read-only legacy projection;
        // every new plan writes a dedicated, digest-bound relay set below.
        return read_and_validate_legacy_plan_relays(connection, stored, requests);
    };
    let relay_count = parse_stored_u64(&relay_count, "sync relay count")?;
    let stored_relay_set_digest =
        stored_array::<32>(&relay_set_digest_bytes, "sync relay set digest")?;
    if stored_array::<32>(&record_digest, "sync relay set record digest")?
        != relay_set_record_digest(
            stored.trigger.trigger_id,
            relay_count,
            stored_relay_set_digest,
        )
    {
        return Err(NodeStoreError::new("sync relay set failed validation"));
    }
    if relay_count as usize > MAX_SYNC_TRANSACTIONS_PER_PLAN {
        return Err(NodeStoreError::new(
            "sync relay set exceeds finite plan limit",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT ordinal, request_id, tx_hash, record_digest
               FROM eth_sync_plan_relays
              WHERE trigger_id = ?1 ORDER BY ordinal",
        )
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map([stored.trigger.trigger_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(NodeStoreError::sqlite)?;
    let mut relays = Vec::new();
    for row in rows {
        let row = row.map_err(NodeStoreError::sqlite)?;
        let ordinal =
            u64::try_from(row.0).map_err(|_| NodeStoreError::new("invalid sync relay ordinal"))?;
        if ordinal != relays.len() as u64 {
            return Err(NodeStoreError::new(
                "sync relay ordinals are not contiguous",
            ));
        }
        let relay = PlannedRelayRequest {
            request_id: stored_array(&row.1, "planned relay identifier")?,
            tx_hash: stored_array(&row.2, "planned relay transaction hash")?,
        };
        if stored_array::<32>(&row.3, "planned relay digest")?
            != plan_relay_digest(stored.trigger.trigger_id, ordinal, relay)
            || relay.request_id
                != derive_relay_request_id(
                    stored.trigger,
                    stored.checkpoint_context,
                    relay.tx_hash,
                    ordinal,
                )
        {
            return Err(NodeStoreError::new("planned relay failed validation"));
        }
        let signed = crate::transaction::read_signed_transaction(
            connection,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            relay.tx_hash,
        )?
        .ok_or_else(|| NodeStoreError::new("planned relay lost its signed transaction"))?;
        validate_planned_signed_relay(
            connection,
            relay.request_id,
            stored.trigger.expected_gateway_source_hash,
            &signed,
            stored.trigger.created_at_unix,
            stored.trigger.expires_at_unix,
        )?;
        relays.push(relay);
    }
    if relays.len() as u64 != relay_count || relay_set_digest(&relays) != stored_relay_set_digest {
        return Err(NodeStoreError::new("sync relay set failed validation"));
    }
    Ok(relays)
}

fn read_and_validate_legacy_plan_relays(
    connection: &rusqlite::Connection,
    stored: &StoredSyncPlan,
    requests: &[PlannedEvidenceRequest],
) -> Result<Vec<PlannedRelayRequest>> {
    let mut relay_requests = Vec::with_capacity(requests.len().saturating_sub(1));
    for (index, receipt) in requests.iter().skip(1).enumerate() {
        let signed = crate::transaction::read_signed_transaction(
            connection,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
            receipt.subject,
        )?
        .ok_or_else(|| NodeStoreError::new("planned relay lost its signed transaction"))?;
        let relay = PlannedRelayRequest {
            request_id: derive_relay_request_id(
                stored.trigger,
                stored.checkpoint_context,
                signed.tx_hash(),
                index as u64,
            ),
            tx_hash: signed.tx_hash(),
        };
        validate_planned_signed_relay(
            connection,
            relay.request_id,
            stored.trigger.expected_gateway_source_hash,
            &signed,
            stored.trigger.created_at_unix,
            stored.trigger.expires_at_unix,
        )?;
        relay_requests.push(relay);
    }
    Ok(relay_requests)
}

/// Returns the account request belonging to the newest fully validated sync
/// plan. Callers must keep their transaction open while using the result.
pub(crate) fn latest_account_sync_request(
    connection: &rusqlite::Connection,
) -> Result<Option<([u8; 16], EvidenceSyncTrigger)>> {
    let trigger_id = connection
        .query_row(
            "SELECT trigger_id FROM eth_sync_plans
             ORDER BY CAST(generation AS INTEGER) DESC LIMIT 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?
        .map(|value| stored_array::<16>(&value, "sync request trigger"))
        .transpose()?;
    let Some(trigger_id) = trigger_id else {
        return Ok(None);
    };
    let stored = read_sync_plan(connection, trigger_id)?
        .ok_or_else(|| NodeStoreError::new("sync request plan disappeared"))?;
    let plan = read_and_validate_plan_requests(connection, &stored)?;
    Ok(Some((plan.account_request().request_id(), stored.trigger)))
}

fn plan_from_requests(
    trigger: EvidenceSyncTrigger,
    mut requests: Vec<PlannedEvidenceRequest>,
    relay_requests: Vec<PlannedRelayRequest>,
) -> Result<EvidenceSyncPlan> {
    if requests.first().map(|request| request.kind)
        != Some(MessagingEvidenceKind::AccountStatePackage)
        || requests
            .iter()
            .skip(1)
            .any(|request| request.kind != MessagingEvidenceKind::FinalizedReceiptPackage)
    {
        return Err(NodeStoreError::new("invalid sync request sequence"));
    }
    let account_request = requests.remove(0);
    Ok(EvidenceSyncPlan {
        trigger_id: trigger.trigger_id,
        generation: trigger.generation,
        account_request,
        relay_requests,
        receipt_requests: requests,
    })
}

fn request_set_digest(requests: &[PlannedEvidenceRequest]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-request-set.v1");
    hasher.update((requests.len() as u64).to_le_bytes());
    for request in requests {
        hasher.update(request.request_id);
        hasher.update([request.kind.wire()]);
        hasher.update(request.subject);
    }
    hasher.finalize().into()
}

fn sync_plan_digest(plan: &StoredSyncPlan) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-plan.v1");
    hasher.update(plan.trigger.trigger_id);
    hasher.update(plan.trigger.generation.to_le_bytes());
    hasher.update(plan.trigger.expected_gateway_source_hash);
    hasher.update(plan.wallet_address);
    hasher.update(plan.checkpoint_context.checkpoint_epoch.to_le_bytes());
    hasher.update(plan.checkpoint_context.checkpoint_root);
    hasher.update(plan.trigger.maximum_response_bytes.to_le_bytes());
    hasher.update(plan.trigger.created_at_unix.to_le_bytes());
    hasher.update(plan.trigger.expires_at_unix.to_le_bytes());
    hasher.update(plan.request_count.to_le_bytes());
    hasher.update(plan.request_set_digest);
    hasher.finalize().into()
}

fn plan_request_digest(
    trigger_id: [u8; 16],
    ordinal: u64,
    request: PlannedEvidenceRequest,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-plan-request.v1");
    hasher.update(trigger_id);
    hasher.update(ordinal.to_le_bytes());
    hasher.update(request.request_id);
    hasher.update([request.kind.wire()]);
    hasher.update(request.subject);
    hasher.finalize().into()
}

fn plan_relay_digest(trigger_id: [u8; 16], ordinal: u64, relay: PlannedRelayRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-plan-relay.v1");
    hasher.update(trigger_id);
    hasher.update(ordinal.to_le_bytes());
    hasher.update(relay.request_id);
    hasher.update(relay.tx_hash);
    hasher.finalize().into()
}

fn relay_set_digest(relays: &[PlannedRelayRequest]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-plan-relay-set.v1");
    hasher.update((relays.len() as u64).to_le_bytes());
    for relay in relays {
        hasher.update(relay.request_id);
        hasher.update(relay.tx_hash);
    }
    hasher.finalize().into()
}

fn relay_set_record_digest(
    trigger_id: [u8; 16],
    relay_count: u64,
    relay_set_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak.ethereum.sync-plan-relay-set-record.v1");
    hasher.update(trigger_id);
    hasher.update(relay_count.to_le_bytes());
    hasher.update(relay_set_digest);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use ratspeak_eth_wallet::WalletAccount;

    use super::*;
    use crate::transaction::test_support::signed_fixture_with_nonce;
    use crate::{
        OutboundMessageBinding, OutboundMessageKind, OutboundTransactionStatusRequest,
        TransactionAssurance, TransactionStatus,
    };

    const NOW: u64 = 1_800_000_000;
    const ROOT: [u8; 32] = [0x41; 32];
    const GATEWAY: [u8; 16] = [0x42; 16];
    const SOURCE: [u8; 16] = [0x43; 16];
    const WALLET: [u8; 20] = [0x44; 20];

    #[test]
    fn account_sync_progress_uses_durable_request_and_outbox_states() {
        let cases = [
            (
                MessageRequestStatus::Pending,
                false,
                None,
                AccountSyncStage::Queued,
            ),
            (
                MessageRequestStatus::Pending,
                false,
                Some(0),
                AccountSyncStage::Queued,
            ),
            (
                MessageRequestStatus::Pending,
                false,
                Some(1),
                AccountSyncStage::Sending,
            ),
            (
                MessageRequestStatus::Pending,
                false,
                Some(2),
                AccountSyncStage::WaitingForGateway,
            ),
            (
                MessageRequestStatus::AwaitingBulkApproval,
                false,
                Some(2),
                AccountSyncStage::AwaitingDownloadApproval,
            ),
            (
                MessageRequestStatus::Ready,
                false,
                None,
                AccountSyncStage::WaitingForGateway,
            ),
            (
                MessageRequestStatus::Ready,
                true,
                None,
                AccountSyncStage::Queued,
            ),
            (
                MessageRequestStatus::Ready,
                true,
                Some(1),
                AccountSyncStage::Sending,
            ),
            (
                MessageRequestStatus::Ready,
                true,
                Some(2),
                AccountSyncStage::WaitingForGateway,
            ),
            (
                MessageRequestStatus::PendingVerification,
                false,
                Some(2),
                AccountSyncStage::Verifying,
            ),
            (
                MessageRequestStatus::Completed,
                false,
                Some(2),
                AccountSyncStage::Completed,
            ),
            (
                MessageRequestStatus::Cancelled,
                false,
                Some(2),
                AccountSyncStage::Failed,
            ),
        ];
        for (request, bulk_approved, outbox, expected) in cases {
            assert_eq!(
                account_sync_stage(request, bulk_approved, outbox, NOW + 100, NOW).unwrap(),
                expected
            );
        }
        assert_eq!(
            account_sync_stage(MessageRequestStatus::Pending, false, Some(2), NOW, NOW).unwrap(),
            AccountSyncStage::Failed
        );
        assert!(
            account_sync_stage(MessageRequestStatus::Pending, false, Some(9), NOW + 1, NOW)
                .is_err()
        );
    }

    fn trigger(id: u8, generation: u64, created_at_unix: u64) -> EvidenceSyncTrigger {
        EvidenceSyncTrigger::new(
            [id; 16],
            generation,
            GATEWAY,
            MAX_BUNDLE_BYTES as u32,
            created_at_unix,
            created_at_unix + 600,
        )
    }

    fn prepared_store() -> (tempfile::TempDir, EthereumNodeStore) {
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .install_wallet_account(WalletAccount::sepolia(Address::from(WALLET)))
            .unwrap();
        crate::bootstrap::install_test_active_checkpoint(&mut store, ROOT, NOW);
        (profile, store)
    }

    fn rpc_accepted_observation(request_id: [u8; 16], tx_hash: [u8; 32]) -> Vec<u8> {
        let mut bytes = b"RSETHM1".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.push(5);
        bytes.extend_from_slice(&request_id);
        bytes.extend_from_slice(&tx_hash);
        bytes.push(2);
        bytes
    }

    fn transaction_status_report(
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        status: TransactionStatus,
        included_number: u64,
        finalized_number: u64,
    ) -> Vec<u8> {
        let mut bytes = b"RSETHM1".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.push(9);
        bytes.extend_from_slice(&request_id);
        bytes.extend_from_slice(&tx_hash);
        bytes.push(match status {
            TransactionStatus::NotSeen => 1,
            TransactionStatus::Pending => 2,
            TransactionStatus::Included => 3,
        });
        let included_hash = if status == TransactionStatus::Included {
            [0x71; 32]
        } else {
            [0; 32]
        };
        bytes.extend_from_slice(&included_number.to_le_bytes());
        bytes.extend_from_slice(&included_hash);
        let safe_number = finalized_number.max(included_number).saturating_add(1);
        let latest_number = safe_number.saturating_add(1);
        for (number, hash) in [
            (latest_number, [0x72; 32]),
            (safe_number, [0x73; 32]),
            (finalized_number, [0x74; 32]),
        ] {
            bytes.extend_from_slice(&number.to_le_bytes());
            bytes.extend_from_slice(&hash);
        }
        assert_eq!(bytes.len(), 226);
        bytes
    }

    fn record_transaction_status(
        store: &mut EthereumNodeStore,
        request_id: [u8; 16],
        tx_hash: [u8; 32],
        status: TransactionStatus,
        included_number: u64,
        finalized_number: u64,
    ) {
        store
            .create_transaction_status_request(OutboundTransactionStatusRequest::new(
                request_id,
                GATEWAY,
                tx_hash,
                NOW.saturating_sub(1),
                NOW + 100,
            ))
            .unwrap();
        let report = transaction_status_report(
            request_id,
            tx_hash,
            status,
            included_number,
            finalized_number,
        );
        store
            .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &report, NOW)
            .unwrap();
    }

    #[test]
    fn fresh_signed_transactions_plan_account_and_relay_without_premature_receipts() {
        let (_profile, mut store) = prepared_store();
        let confirmed = signed_fixture_with_nonce(&mut store, 11);
        let first_unconfirmed = signed_fixture_with_nonce(&mut store, 12);
        let second_unconfirmed = signed_fixture_with_nonce(&mut store, 13);
        crate::receipt::install_test_receipt_for_transaction(&mut store, confirmed, true);

        let pending = store
            .unconfirmed_signed_transactions(SEPOLIA_CHAIN_ID)
            .unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|transaction| transaction.tx_hash())
                .collect::<Vec<_>>(),
            vec![first_unconfirmed, second_unconfirmed]
        );
        let assurance_before = store.transaction_assurance(first_unconfirmed).unwrap();
        let (outcome, plan) = store
            .plan_evidence_sync_at(trigger(1, 1, NOW), NOW)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Inserted);
        assert_eq!(
            plan.account_request().kind(),
            MessagingEvidenceKind::AccountStatePackage
        );
        assert_eq!(plan.account_request().subject()[..12], [0; 12]);
        assert_eq!(plan.account_request().subject()[12..], WALLET);
        assert!(plan.receipt_requests().is_empty());
        assert_eq!(
            plan.relay_requests()
                .iter()
                .map(|request| request.tx_hash())
                .collect::<Vec<_>>(),
            vec![first_unconfirmed, second_unconfirmed]
        );

        let binding = OutboundMessageBinding::new(GATEWAY, SOURCE, 1).unwrap();
        let account = store
            .lease_next_outbound_message(binding, NOW + 1, 10)
            .unwrap()
            .unwrap();
        assert_eq!(account.kind(), OutboundMessageKind::EvidenceRequest);
        let bytes = account.attachment();
        assert_eq!(bytes.len(), 119);
        assert_eq!(bytes[41], MessagingEvidenceKind::AccountStatePackage.wire());
        assert_eq!(&bytes[42..74], plan.account_request().subject());
        let checkpoint = store.latest_checkpoint_approval().unwrap().unwrap();
        assert_eq!(&bytes[74..82], &checkpoint.checkpoint_epoch().to_le_bytes());
        assert_eq!(&bytes[82..114], &ROOT);
        assert_eq!(&bytes[114..118], &(MAX_BUNDLE_BYTES as u32).to_le_bytes());
        assert_eq!(bytes[118], 0);
        let mut expected_request = b"RSETHM1".to_vec();
        expected_request.push(1);
        expected_request.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        expected_request.push(1);
        expected_request.extend_from_slice(&plan.account_request().request_id());
        expected_request.extend_from_slice(&(NOW + 600).to_le_bytes());
        expected_request.push(MessagingEvidenceKind::AccountStatePackage.wire());
        expected_request.extend_from_slice(&plan.account_request().subject());
        expected_request.extend_from_slice(&checkpoint.checkpoint_epoch().to_le_bytes());
        expected_request.extend_from_slice(&ROOT);
        expected_request.extend_from_slice(&(MAX_BUNDLE_BYTES as u32).to_le_bytes());
        expected_request.push(0);
        assert_eq!(bytes, expected_request.as_slice());
        store
            .settle_outbound_message_queued(binding, &account, NOW + 2)
            .unwrap();
        let relay = store
            .lease_next_outbound_message(binding, NOW + 3, 10)
            .unwrap()
            .unwrap();
        assert_eq!(relay.kind(), OutboundMessageKind::SignedTransactionRelay);
        assert_eq!(relay.request_id(), plan.relay_requests()[0].request_id());
        store
            .settle_outbound_message_queued(binding, &relay, NOW + 4)
            .unwrap();
        let second_relay = store
            .lease_next_outbound_message(binding, NOW + 5, 10)
            .unwrap()
            .unwrap();
        assert_eq!(
            second_relay.kind(),
            OutboundMessageKind::SignedTransactionRelay
        );
        assert_eq!(
            second_relay.request_id(),
            plan.relay_requests()[1].request_id()
        );
        store
            .settle_outbound_message_queued(binding, &second_relay, NOW + 6)
            .unwrap();
        assert!(
            store
                .lease_next_outbound_message(binding, NOW + 7, 10)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.transaction_assurance(first_unconfirmed).unwrap(),
            assurance_before
        );
        assert!(matches!(
            assurance_before,
            Some(TransactionAssurance::Signed { .. })
        ));
    }

    #[test]
    fn planner_includes_receipt_only_after_status_reports_finalized_inclusion() {
        let (_profile, mut store) = prepared_store();
        let tx_hash = signed_fixture_with_nonce(&mut store, 12);
        record_transaction_status(
            &mut store,
            [0x51; 16],
            tx_hash,
            TransactionStatus::Included,
            100,
            100,
        );

        let plan = store
            .plan_evidence_sync_at(trigger(2, 1, NOW), NOW)
            .unwrap()
            .1;
        assert_eq!(
            plan.receipt_requests()
                .iter()
                .map(PlannedEvidenceRequest::subject)
                .collect::<Vec<_>>(),
            vec![tx_hash]
        );
        assert!(
            plan.receipt_requests()
                .iter()
                .all(|request| request.kind() == MessagingEvidenceKind::FinalizedReceiptPackage)
        );
        assert_eq!(
            plan.relay_requests()
                .iter()
                .map(|request| request.tx_hash())
                .collect::<Vec<_>>(),
            vec![tx_hash]
        );
        assert!(matches!(
            store.transaction_assurance(tx_hash).unwrap(),
            Some(TransactionAssurance::Signed { .. })
        ));
    }

    #[test]
    fn planner_excludes_pending_and_not_yet_finalized_status_reports() {
        let (_profile, mut store) = prepared_store();
        let pending = signed_fixture_with_nonce(&mut store, 12);
        let not_finalized = signed_fixture_with_nonce(&mut store, 13);
        record_transaction_status(
            &mut store,
            [0x52; 16],
            pending,
            TransactionStatus::Pending,
            0,
            100,
        );
        record_transaction_status(
            &mut store,
            [0x53; 16],
            not_finalized,
            TransactionStatus::Included,
            101,
            100,
        );

        let plan = store
            .plan_evidence_sync_at(trigger(3, 1, NOW), NOW)
            .unwrap()
            .1;
        assert!(plan.receipt_requests().is_empty());
        assert_eq!(
            plan.relay_requests()
                .iter()
                .map(|request| request.tx_hash())
                .collect::<Vec<_>>(),
            vec![pending, not_finalized]
        );
    }

    #[test]
    fn user_retry_can_replace_only_a_validated_settled_account_request() {
        let (_profile, mut store) = prepared_store();
        let binding = OutboundMessageBinding::new(GATEWAY, SOURCE, 1).unwrap();
        let plan = store
            .plan_evidence_sync_at(trigger(9, 1, NOW), NOW)
            .unwrap()
            .1;
        let lease = store
            .lease_next_outbound_message(binding, NOW + 1, 10)
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id(), plan.account_request().request_id());
        store
            .settle_outbound_message_queued(binding, &lease, NOW + 2)
            .unwrap();
        store.rearm_latest_account_sync(binding, NOW + 3).unwrap();
        let retried = store
            .lease_next_outbound_message(binding, NOW + 4, 10)
            .unwrap()
            .unwrap();
        assert_eq!(retried.request_id(), lease.request_id());
        assert_eq!(retried.attachment(), lease.attachment());
        store
            .settle_outbound_message_queued(binding, &retried, NOW + 5)
            .unwrap();
        assert!(
            store
                .cancel_settled_account_sync_for_retry(binding, NOW + 6)
                .unwrap()
        );
        assert_eq!(
            store.message_request_status(lease.request_id()).unwrap(),
            Some(crate::messaging::MessageRequestStatus::Cancelled)
        );
        let replacement = store
            .plan_evidence_sync_at(trigger(10, 2, NOW + 7), NOW + 7)
            .unwrap()
            .1;
        assert_ne!(
            replacement.account_request().request_id(),
            lease.request_id()
        );
    }

    #[test]
    fn account_sync_progress_survives_restart_and_rejects_corrupt_outbox() {
        let (profile, mut store) = prepared_store();
        let plan = store
            .plan_evidence_sync_at(trigger(9, 1, NOW), NOW)
            .unwrap()
            .1;
        let queued = store
            .latest_account_sync_progress(NOW + 1)
            .unwrap()
            .unwrap();
        assert_eq!(queued.stage(), AccountSyncStage::Queued);
        assert!(queued.belongs_to_gateway(GATEWAY));
        assert!(!queued.belongs_to_gateway([0x44; 16]));

        let binding = OutboundMessageBinding::new(GATEWAY, SOURCE, 1).unwrap();
        let lease = store
            .lease_next_outbound_message(binding, NOW + 2, 10)
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id(), plan.account_request().request_id());
        assert_eq!(
            store
                .latest_account_sync_progress(NOW + 3)
                .unwrap()
                .unwrap()
                .stage(),
            AccountSyncStage::Sending
        );
        store
            .settle_outbound_message_queued(binding, &lease, NOW + 4)
            .unwrap();
        assert_eq!(
            store
                .latest_account_sync_progress(NOW + 5)
                .unwrap()
                .unwrap()
                .stage(),
            AccountSyncStage::WaitingForGateway
        );
        drop(store);

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened
                .latest_account_sync_progress(NOW + 6)
                .unwrap()
                .unwrap()
                .stage(),
            AccountSyncStage::WaitingForGateway
        );
        reopened
            .connection
            .execute(
                "UPDATE eth_message_outbox SET attachment_digest = ?1
                 WHERE request_id = ?2 AND item_kind = 1",
                rusqlite::params![
                    [0x7f_u8; 32].as_slice(),
                    plan.account_request().request_id().as_slice(),
                ],
            )
            .unwrap();
        assert!(reopened.latest_account_sync_progress(NOW + 7).is_err());
    }

    #[test]
    fn replay_is_restart_safe_and_generation_and_expiry_are_strict() {
        let (profile, mut store) = prepared_store();
        signed_fixture_with_nonce(&mut store, 21);
        let first_trigger = trigger(2, 7, NOW);
        let inserted = store.plan_evidence_sync_at(first_trigger, NOW).unwrap().1;
        drop(store);

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (outcome, replay) = reopened
            .plan_evidence_sync_at(first_trigger, NOW + 301)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Replay);
        assert_eq!(replay, inserted);
        assert_eq!(reopened.next_evidence_sync_generation().unwrap(), 8);
        assert!(
            reopened
                .plan_evidence_sync_at(trigger(3, 7, NOW + 1), NOW + 1)
                .unwrap_err()
                .to_string()
                .contains("generation")
        );
        assert!(
            reopened
                .plan_evidence_sync_at(first_trigger, NOW + 601)
                .unwrap_err()
                .to_string()
                .contains("invalid Ethereum sync trigger")
        );
        assert_eq!(
            reopened
                .plan_evidence_sync_at(trigger(4, 8, NOW + 2), NOW + 2)
                .unwrap()
                .0,
            RecordOutcome::Inserted
        );
    }

    #[test]
    fn application_planner_resumes_one_compatible_plan_across_spam_and_restart() {
        let (profile, mut store) = prepared_store();
        let tx_hash = signed_fixture_with_nonce(&mut store, 22);
        let inserted = store
            .plan_evidence_sync_at_mode(trigger(20, 1, NOW), NOW, true)
            .unwrap()
            .1;
        for id in 21..=100 {
            let candidate = trigger(id, 2, NOW + 1);
            let (outcome, resumed) = store
                .plan_evidence_sync_at_mode(candidate, NOW + 1, true)
                .unwrap();
            assert_eq!(outcome, RecordOutcome::Replay);
            assert_eq!(resumed, inserted);
            assert_eq!(resumed.relay_requests()[0].tx_hash(), tx_hash);
        }
        let counts: (u64, u64, u64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT count(*) FROM eth_sync_plans),
                    (SELECT count(*) FROM eth_sync_plan_requests),
                    (SELECT count(*) FROM eth_message_requests)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (1, 1, 2));
        drop(store);

        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (outcome, resumed) = reopened
            .plan_evidence_sync_at_mode(trigger(101, 2, NOW + 2), NOW + 2, true)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Replay);
        assert_eq!(resumed, inserted);
        assert_eq!(reopened.next_evidence_sync_generation().unwrap(), 2);
        assert!(
            reopened
                .plan_evidence_sync_at_mode(trigger(102, 2, NOW), NOW + 301, true)
                .unwrap_err()
                .to_string()
                .contains("trusted local clock")
        );
    }

    #[test]
    fn application_planner_requires_terminal_work_before_subjects_can_change() {
        let (_profile, mut store) = prepared_store();
        let first = store
            .plan_evidence_sync_at_mode(trigger(30, 1, NOW), NOW, true)
            .unwrap()
            .1;

        let conflicting_gateway = EvidenceSyncTrigger::new(
            [31; 16],
            2,
            [0x99; 16],
            MAX_BUNDLE_BYTES as u32,
            NOW + 1,
            NOW + 601,
        );
        assert!(
            store
                .plan_evidence_sync_at_mode(conflicting_gateway, NOW + 1, true)
                .unwrap_err()
                .to_string()
                .contains("gateway or response policy")
        );

        let (_checkpoint_profile, mut checkpoint_store) = prepared_store();
        checkpoint_store
            .plan_evidence_sync_at_mode(trigger(35, 1, NOW), NOW, true)
            .unwrap();
        let advanced_at = NOW + 384;
        crate::bootstrap::install_test_active_checkpoint(
            &mut checkpoint_store,
            [0xa5; 32],
            advanced_at,
        );
        assert!(
            checkpoint_store
                .plan_evidence_sync_at_mode(trigger(36, 2, advanced_at + 1), advanced_at + 1, true)
                .unwrap_err()
                .to_string()
                .contains("checkpoint authority")
        );

        signed_fixture_with_nonce(&mut store, 23);
        assert!(
            store
                .plan_evidence_sync_at_mode(trigger(32, 2, NOW + 2), NOW + 2, true)
                .unwrap_err()
                .to_string()
                .contains("requested subjects")
        );
        assert_eq!(store.next_evidence_sync_generation().unwrap(), 2);
        store
            .cancel_message_request(first.account_request().request_id())
            .unwrap();
        assert_eq!(
            store
                .plan_evidence_sync_at_mode(trigger(37, 2, NOW + 3), NOW + 3, true)
                .unwrap()
                .0,
            RecordOutcome::Inserted
        );
        assert_eq!(store.next_evidence_sync_generation().unwrap(), 3);

        let (_expired_profile, mut expired_store) = prepared_store();
        expired_store
            .plan_evidence_sync_at_mode(trigger(33, 1, NOW), NOW, true)
            .unwrap();
        assert_eq!(
            expired_store
                .plan_evidence_sync_at_mode(trigger(34, 2, NOW + 601), NOW + 601, true)
                .unwrap()
                .0,
            RecordOutcome::Inserted
        );
    }

    #[test]
    fn application_planner_resumes_mixed_pending_work_but_replaces_terminal_plan() {
        let (_profile, mut store) = prepared_store();
        let tx_hash = signed_fixture_with_nonce(&mut store, 24);
        let first = store
            .plan_evidence_sync_at_mode(trigger(40, 1, NOW), NOW, true)
            .unwrap()
            .1;
        let relay = first.relay_requests()[0];
        store
            .handle_attachment_from_trusted_lxmf_adapter(
                GATEWAY,
                GATEWAY,
                &rpc_accepted_observation(relay.request_id(), tx_hash),
                NOW + 1,
            )
            .unwrap();

        let (outcome, mixed) = store
            .plan_evidence_sync_at_mode(trigger(41, 2, NOW + 2), NOW + 2, true)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Replay);
        assert_eq!(mixed, first);

        store
            .cancel_message_request(first.account_request().request_id())
            .unwrap();
        for request in first.receipt_requests() {
            store.cancel_message_request(request.request_id()).unwrap();
        }
        let (outcome, replacement) = store
            .plan_evidence_sync_at_mode(trigger(42, 2, NOW + 3), NOW + 3, true)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Inserted);
        assert_eq!(replacement.generation(), 2);
        assert_ne!(replacement.trigger_id(), first.trigger_id());
        assert_eq!(store.next_evidence_sync_generation().unwrap(), 3);
    }

    #[test]
    fn gateway_replacement_rejects_active_sync_plan_requests() {
        let (_profile, mut store) = prepared_store();
        let plan = store
            .plan_evidence_sync_at_mode(trigger(90, 1, NOW), NOW, true)
            .unwrap()
            .1;
        assert_ne!(plan.account_request().request_id(), [0; 16]);
        store
            .ensure_gateway_replacement_allowed(GATEWAY, NOW + 1)
            .unwrap();
        assert!(
            store
                .ensure_gateway_replacement_allowed([0xfa; 16], NOW + 1)
                .is_err()
        );
    }

    #[test]
    fn application_planner_does_not_hide_older_active_work() {
        let (_profile, mut store) = prepared_store();
        let older = store
            .plan_evidence_sync_at(trigger(43, 1, NOW), NOW)
            .unwrap()
            .1;
        let newer = store
            .plan_evidence_sync_at(trigger(44, 2, NOW + 1), NOW + 1)
            .unwrap()
            .1;
        assert!(
            store
                .plan_evidence_sync_at_mode(trigger(45, 3, NOW + 2), NOW + 2, true)
                .unwrap_err()
                .to_string()
                .contains("multiple active sync plans")
        );

        store
            .cancel_message_request(newer.account_request().request_id())
            .unwrap();
        let (outcome, resumed) = store
            .plan_evidence_sync_at_mode(trigger(46, 3, NOW + 3), NOW + 3, true)
            .unwrap();
        assert_eq!(outcome, RecordOutcome::Replay);
        assert_eq!(resumed, older);
        assert_eq!(store.next_evidence_sync_generation().unwrap(), 3);
    }

    #[test]
    fn revoked_checkpoint_blocks_new_and_replayed_plans() {
        let (_profile, mut store) = prepared_store();
        let first_trigger = trigger(5, 1, NOW);
        store.plan_evidence_sync_at(first_trigger, NOW).unwrap();
        store
            .record_checkpoint_revocation(SEPOLIA_CHAIN_ID, ROOT, [0x51; 32], NOW + 1)
            .unwrap();
        for next in [first_trigger, trigger(6, 2, NOW + 2)] {
            assert!(
                store
                    .plan_evidence_sync_at(next, NOW + 2)
                    .unwrap_err()
                    .to_string()
                    .contains("revoked")
            );
        }
    }

    #[test]
    fn corrupted_signed_transaction_aborts_planning_atomically() {
        let (_profile, mut store) = prepared_store();
        let tx_hash = signed_fixture_with_nonce(&mut store, 31);
        store
            .connection
            .execute(
                "UPDATE eth_signed_transactions SET nonce = '999'
                 WHERE tx_hash = ?1",
                [tx_hash.as_slice()],
            )
            .unwrap();
        assert!(
            store
                .plan_evidence_sync_at(trigger(9, 1, NOW), NOW)
                .unwrap_err()
                .to_string()
                .contains("digest")
        );
        let counts: (u64, u64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT count(*) FROM eth_sync_plans),
                    (SELECT count(*) FROM eth_message_requests)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0));
    }

    #[test]
    fn request_context_is_digest_bound_and_legacy_public_api_cannot_inject_it() {
        let (_profile, mut store) = prepared_store();
        let legacy = store
            .create_evidence_request(crate::OutboundEvidenceRequest::new(
                [0x60; 16],
                GATEWAY,
                MessagingEvidenceKind::ReceiptProof,
                [0x63; 32],
                1024,
                NOW,
                NOW + 600,
            ))
            .unwrap();
        assert_eq!(legacy.len(), 79);
        assert!(
            store
                .create_evidence_request(crate::OutboundEvidenceRequest::new(
                    [0x61; 16],
                    GATEWAY,
                    MessagingEvidenceKind::AccountStatePackage,
                    [0x62; 32],
                    1024,
                    NOW,
                    NOW + 600,
                ))
                .unwrap_err()
                .to_string()
                .contains("durable sync planner")
        );
        let plan = store
            .plan_evidence_sync_at(trigger(7, 1, NOW), NOW)
            .unwrap()
            .1;
        store
            .connection
            .execute(
                "UPDATE eth_message_requests SET checkpoint_epoch = '9'
                 WHERE request_id = ?1",
                [plan.account_request().request_id().as_slice()],
            )
            .unwrap();
        assert!(
            store
                .message_request_status(plan.account_request().request_id())
                .unwrap_err()
                .to_string()
                .contains("failed validation")
        );
    }

    #[test]
    fn malformed_transport_correlated_package_never_enters_pending_state() {
        let (_profile, mut store) = prepared_store();
        let plan = store
            .plan_evidence_sync_at(trigger(8, 1, NOW), NOW)
            .unwrap()
            .1;
        let request = plan.account_request();
        let package = b"not verified composite evidence";
        let digest: [u8; 32] = Sha256::digest(package).into();
        let mut manifest = b"RSETHM1".to_vec();
        manifest.push(1);
        manifest.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        manifest.push(2);
        manifest.extend_from_slice(&request.request_id());
        manifest.push(request.kind().wire());
        let checkpoint = store.latest_checkpoint_approval().unwrap().unwrap();
        manifest.extend_from_slice(&checkpoint.checkpoint_epoch().to_le_bytes());
        manifest.extend_from_slice(&ROOT);
        manifest.extend_from_slice(&digest);
        manifest.extend_from_slice(&(package.len() as u32).to_le_bytes());
        store
            .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &manifest, NOW + 1)
            .unwrap();
        let mut response = b"RSETHM1".to_vec();
        response.push(1);
        response.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        response.push(3);
        response.extend_from_slice(&request.request_id());
        response.push(request.kind().wire());
        response.extend_from_slice(&checkpoint.checkpoint_epoch().to_le_bytes());
        response.extend_from_slice(&ROOT);
        response.extend_from_slice(&digest);
        response.extend_from_slice(&(package.len() as u32).to_le_bytes());
        response.extend_from_slice(package);
        assert!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &response, NOW + 2,)
                .unwrap_err()
                .to_string()
                .contains("malformed Ethereum evidence response")
        );
        assert_eq!(
            store.message_request_status(request.request_id()).unwrap(),
            Some(crate::MessageRequestStatus::Ready)
        );
        assert!(
            store
                .account_at_checkpoint(SEPOLIA_CHAIN_ID, ROOT, WALLET)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .pending_message_evidence(request.request_id())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn finite_plan_limit_fails_atomically() {
        let (_profile, mut store) = prepared_store();
        for nonce in 0..=MAX_SYNC_TRANSACTIONS_PER_PLAN {
            signed_fixture_with_nonce(&mut store, 100 + nonce as u64);
        }
        assert!(
            store
                .plan_evidence_sync_at(trigger(11, 1, NOW), NOW)
                .unwrap_err()
                .to_string()
                .contains("finite sync plan limit")
        );
        let counts: (u64, u64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT count(*) FROM eth_sync_plans),
                    (SELECT count(*) FROM eth_message_requests)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0));
    }

    #[test]
    fn composite_gateway_wire_echoes_exact_checkpoint_context() {
        let (_profile, mut store) = prepared_store();
        let plan = store
            .plan_evidence_sync_at(trigger(10, 1, NOW), NOW)
            .unwrap()
            .1;
        let request = plan.account_request();
        let checkpoint_epoch = store
            .latest_checkpoint_approval()
            .unwrap()
            .unwrap()
            .checkpoint_epoch();
        let package = vec![0x71; 4 * 1024 + 1];
        let digest: [u8; 32] = Sha256::digest(&package).into();

        let mut manifest = b"RSETHM1".to_vec();
        manifest.push(1);
        manifest.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        manifest.push(2);
        manifest.extend_from_slice(&request.request_id());
        manifest.push(request.kind().wire());
        manifest.extend_from_slice(&checkpoint_epoch.to_le_bytes());
        manifest.extend_from_slice(&ROOT);
        manifest.extend_from_slice(&digest);
        manifest.extend_from_slice(&(package.len() as u32).to_le_bytes());

        let context_offset = 7 + 1 + 8 + 1 + 16 + 1;
        let mut missing_context = manifest.clone();
        missing_context.drain(context_offset..context_offset + 40);
        assert!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(
                    GATEWAY,
                    GATEWAY,
                    &missing_context,
                    NOW + 1,
                )
                .is_err()
        );
        let mut zero_epoch = manifest.clone();
        zero_epoch[context_offset..context_offset + 8].fill(0);
        assert!(store
            .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &zero_epoch, NOW + 1,)
            .unwrap_err()
            .to_string()
            .contains("checkpoint context"));
        let mut wrong_root = manifest.clone();
        wrong_root[context_offset + 8] ^= 1;
        assert!(store
            .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &wrong_root, NOW + 1,)
            .unwrap_err()
            .to_string()
            .contains("does not match request"));
        assert!(matches!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &manifest, NOW + 1,)
                .unwrap(),
            crate::NodeMessageOutcome::BulkApprovalRequired(_)
        ));

        let approval = store
            .approve_bulk_evidence(request.request_id(), digest, package.len() as u32, NOW + 2)
            .unwrap();
        let mut expected_approval = b"RSETHM1".to_vec();
        expected_approval.push(1);
        expected_approval.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        expected_approval.push(6);
        expected_approval.extend_from_slice(&request.request_id());
        expected_approval.extend_from_slice(&(NOW + 600).to_le_bytes());
        expected_approval.push(request.kind().wire());
        expected_approval.extend_from_slice(&checkpoint_epoch.to_le_bytes());
        expected_approval.extend_from_slice(&ROOT);
        expected_approval.extend_from_slice(&digest);
        expected_approval.extend_from_slice(&(package.len() as u32).to_le_bytes());
        assert_eq!(approval, expected_approval);

        let mut response = b"RSETHM1".to_vec();
        response.push(1);
        response.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        response.push(3);
        response.extend_from_slice(&request.request_id());
        response.push(request.kind().wire());
        response.extend_from_slice(&checkpoint_epoch.to_le_bytes());
        response.extend_from_slice(&ROOT);
        response.extend_from_slice(&digest);
        response.extend_from_slice(&(package.len() as u32).to_le_bytes());
        response.extend_from_slice(&package);
        let mut wrong_response = response.clone();
        wrong_response[context_offset + 8] ^= 1;
        assert!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(
                    GATEWAY,
                    GATEWAY,
                    &wrong_response,
                    NOW + 3,
                )
                .unwrap_err()
                .to_string()
                .contains("does not match approved manifest")
        );
        assert!(
            store
                .handle_attachment_from_trusted_lxmf_adapter(GATEWAY, GATEWAY, &response, NOW + 3,)
                .unwrap_err()
                .to_string()
                .contains("malformed Ethereum evidence response")
        );
    }
}
