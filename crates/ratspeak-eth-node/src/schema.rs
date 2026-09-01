use ratspeak_eth_verifier::{SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};
use rusqlite::{OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::{NodeStoreError, Result};

pub(super) const ETHEREUM_STORE_SCHEMA_VERSION: i64 = 17;

pub(super) fn validate_current(connection: &rusqlite::Connection) -> Result<()> {
    let version = connection
        .query_row(
            "SELECT version FROM eth_schema_version WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if version != ETHEREUM_STORE_SCHEMA_VERSION {
        return Err(NodeStoreError::new(
            "Ethereum database schema requires initialization",
        ));
    }
    Ok(())
}

pub(super) fn initialize(connection: &mut rusqlite::Connection) -> Result<()> {
    let transaction = connection.transaction().map_err(NodeStoreError::sqlite)?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_schema_version (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                version INTEGER NOT NULL
            );",
        )
        .map_err(NodeStoreError::sqlite)?;
    let version: Option<i64> = transaction
        .query_row(
            "SELECT version FROM eth_schema_version WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;

    match version {
        None => {
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "INSERT INTO eth_schema_version (singleton, version) VALUES (1, ?1)",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(1) => {
            migrate_v1_to_v2(&transaction)?;
            migrate_v2_to_v3(&transaction)?;
            create_current_schema(&transaction)?;
            migrate_v3_to_v4(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(2) => {
            migrate_v2_to_v3(&transaction)?;
            create_current_schema(&transaction)?;
            migrate_v3_to_v4(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(3) => {
            create_current_schema(&transaction)?;
            migrate_v3_to_v4(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(4) => {
            // v4 established checkpoint policy. Creating the current schema
            // adds the field-operation table without rewriting trusted rows.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(5) => {
            // v6 adds only the durable authenticated-message correlation
            // ledger. Existing Ethereum authority records are unchanged.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(6) => {
            // v7 makes authenticated evidence import fail closed. Rebuild the
            // request ledger so PendingVerification is representable before
            // creating the durable evidence queue.
            crate::messaging::migrate_v6_to_v7(&transaction)?;
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(7) => {
            // v8 adds only public wallet-account metadata. Custody material
            // remains outside SQLite in the platform protector.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(8) => {
            create_current_schema(&transaction)?;
            migrate_v8_to_v9(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(9) => {
            create_current_schema(&transaction)?;
            migrate_v9_to_v10(&transaction)?;
            migrate_v10_to_v11(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(10) => {
            create_current_schema(&transaction)?;
            migrate_v9_to_v10(&transaction)?;
            migrate_v10_to_v11(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(11) => {
            // v12 adds only the node-owned outbound queue lease ledger.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(12) => {
            migrate_v12_to_v13(&transaction)?;
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(13) => {
            // v14 adds only the durable native checkpoint-review ledger.
            // Existing trust decisions and evidence remain unchanged.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(14) => {
            // v15 adds an epoch uniqueness backstop. Index creation and the
            // version bump share this transaction, so a legacy conflicting
            // database fails closed without rewriting either approval.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(15) => {
            // v16 reserves every active sender nonce durably. Creating the
            // partial unique index and recording the version share this
            // transaction, so a legacy conflict fails closed without freeing
            // either operation.
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(16) => {
            crate::messaging::migrate_v16_to_v17(&transaction)?;
            create_current_schema(&transaction)?;
            transaction
                .execute(
                    "UPDATE eth_schema_version SET version = ?1 WHERE singleton = 1",
                    [ETHEREUM_STORE_SCHEMA_VERSION],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
        Some(ETHEREUM_STORE_SCHEMA_VERSION) => create_current_schema(&transaction)?,
        Some(version) => {
            return Err(NodeStoreError::new(format!(
                "unsupported Ethereum store schema version {version}"
            )));
        }
    }

    migrate_v8_to_v9(&transaction)?;
    migrate_v9_to_v10(&transaction)?;
    migrate_v10_to_v11(&transaction)?;
    migrate_v12_to_v13(&transaction)?;
    crate::messaging::migrate_v16_to_v17(&transaction)?;
    install_checkpoint_epoch_index(&transaction)?;
    install_field_operation_nonce_reservation_index(&transaction)?;
    install_or_validate_network(&transaction)?;
    transaction.commit().map_err(NodeStoreError::sqlite)
}

fn migrate_v12_to_v13(transaction: &Transaction<'_>) -> Result<()> {
    let has_checkpoint_context = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('eth_message_requests')
                WHERE name = 'checkpoint_epoch'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if has_checkpoint_context {
        return Ok(());
    }

    transaction
        .execute_batch(
            "DROP TABLE IF EXISTS eth_sync_plan_requests;
             DROP TABLE IF EXISTS eth_sync_plans;
             ALTER TABLE eth_message_outbox RENAME TO eth_message_outbox_v12;
             ALTER TABLE eth_pending_message_evidence
                 RENAME TO eth_pending_message_evidence_v12;
             ALTER TABLE eth_message_requests RENAME TO eth_message_requests_v12;",
        )
        .map_err(NodeStoreError::sqlite)?;
    crate::messaging::create_schema(transaction)?;
    transaction
        .execute_batch(
            "INSERT INTO eth_message_requests (
                request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, checkpoint_epoch, checkpoint_root,
                maximum_response_bytes, bulk_approved, created_at_unix,
                expires_at_unix, status, manifest_digest, manifest_size,
                relay_observation, record_digest, recorded_at_unix
             )
             SELECT request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, NULL, NULL, maximum_response_bytes,
                bulk_approved, created_at_unix, expires_at_unix, status,
                manifest_digest, manifest_size, relay_observation,
                record_digest, recorded_at_unix
             FROM eth_message_requests_v12;
             INSERT INTO eth_pending_message_evidence
                 SELECT * FROM eth_pending_message_evidence_v12;
             INSERT INTO eth_message_outbox SELECT * FROM eth_message_outbox_v12;
             DROP TABLE eth_message_outbox_v12;
             DROP TABLE eth_pending_message_evidence_v12;
             DROP TABLE eth_message_requests_v12;",
        )
        .map_err(NodeStoreError::sqlite)?;
    crate::workflow::create_schema(transaction)
}

fn migrate_v10_to_v11(transaction: &Transaction<'_>) -> Result<()> {
    let request_sql = transaction
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'eth_message_requests'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let pending_sql = transaction
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'eth_pending_message_evidence'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    if request_sql
        .as_deref()
        .is_some_and(|sql| sql.contains("1, 2, 3, 4"))
        && pending_sql
            .as_deref()
            .is_some_and(|sql| sql.contains("1, 2, 3, 4"))
    {
        return Ok(());
    }
    if request_sql.is_none() || pending_sql.is_none() {
        return Ok(());
    }

    transaction
        .execute_batch(
            "DROP TABLE IF EXISTS eth_sync_plan_requests;
             DROP TABLE IF EXISTS eth_sync_plans;
             DROP TABLE IF EXISTS eth_message_outbox;
             ALTER TABLE eth_pending_message_evidence
                 RENAME TO eth_pending_message_evidence_v10;
             ALTER TABLE eth_message_requests RENAME TO eth_message_requests_v10;",
        )
        .map_err(NodeStoreError::sqlite)?;
    crate::messaging::create_schema(transaction)?;
    transaction
        .execute_batch(
            "INSERT INTO eth_message_requests (
                request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, checkpoint_epoch, checkpoint_root,
                maximum_response_bytes, bulk_approved, created_at_unix,
                expires_at_unix, status, manifest_digest, manifest_size,
                relay_observation, record_digest, recorded_at_unix
             )
             SELECT request_id, expected_gateway_source_hash, operation_kind,
                evidence_kind, subject, NULL, NULL, maximum_response_bytes,
                bulk_approved, created_at_unix, expires_at_unix, status,
                manifest_digest, manifest_size, relay_observation,
                record_digest, recorded_at_unix
             FROM eth_message_requests_v10;
             INSERT INTO eth_pending_message_evidence
                 SELECT * FROM eth_pending_message_evidence_v10;
             DROP TABLE eth_pending_message_evidence_v10;
             DROP TABLE eth_message_requests_v10;",
        )
        .map_err(NodeStoreError::sqlite)?;
    crate::workflow::create_schema(transaction)
}

fn migrate_v8_to_v9(transaction: &Transaction<'_>) -> Result<()> {
    let has_chain_time = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('eth_field_operations')
                WHERE name = 'chain_evidence_at_unix'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if !has_chain_time {
        transaction
            .execute(
                "ALTER TABLE eth_field_operations
                 ADD COLUMN chain_evidence_at_unix TEXT NOT NULL DEFAULT '0'",
                [],
            )
            .map_err(NodeStoreError::sqlite)?;
        // v8 operations derived freshness from local import time. They cannot
        // be safely authorized or reinterpreted, while their signed transaction
        // records remain independently preserved.
        transaction
            .execute("DELETE FROM eth_field_operations", [])
            .map_err(NodeStoreError::sqlite)?;
    }
    Ok(())
}

fn migrate_v9_to_v10(transaction: &Transaction<'_>) -> Result<()> {
    let references_receipt_targets = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_foreign_key_list('eth_verified_receipts')
                WHERE \"table\" = 'eth_verified_receipt_targets'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if references_receipt_targets {
        return Ok(());
    }

    crate::receipt::migrate_v9_receipt_targets(transaction)?;
    transaction
        .execute_batch(
            "CREATE TABLE eth_verified_receipts_v10 (
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
                FOREIGN KEY(
                    chain_id, network, block_hash, execution_header_proof_hash
                ) REFERENCES eth_verified_receipt_targets(
                    chain_id, network, block_hash, authority_bundle_hash
                ),
                UNIQUE(chain_id, network, tx_hash),
                UNIQUE(chain_id, network, proof_bundle_hash)
            );
             INSERT INTO eth_verified_receipts_v10 (
                chain_id, network, block_number, block_hash, tx_hash, tx_index,
                succeeded, cumulative_gas_used, logs_count, verified_at_unix,
                checkpoint_root, provenance, consensus_bundle_hash,
                execution_header_proof_hash, proof_bundle_hash, canonical_bundle,
                record_digest, recorded_at_unix
             ) SELECT
                chain_id, network, block_number, block_hash, tx_hash, tx_index,
                succeeded, cumulative_gas_used, logs_count, verified_at_unix,
                checkpoint_root, provenance, consensus_bundle_hash,
                execution_header_proof_hash, proof_bundle_hash, canonical_bundle,
                record_digest, recorded_at_unix
             FROM eth_verified_receipts;
             DROP TABLE eth_verified_receipts;
             ALTER TABLE eth_verified_receipts_v10 RENAME TO eth_verified_receipts;",
        )
        .map_err(NodeStoreError::sqlite)
}

fn migrate_v3_to_v4(transaction: &Transaction<'_>) -> Result<()> {
    add_column_if_missing(
        transaction,
        "eth_checkpoint_approvals",
        "checkpoint_epoch",
        "ALTER TABLE eth_checkpoint_approvals ADD COLUMN checkpoint_epoch TEXT",
    )?;
    add_column_if_missing(
        transaction,
        "eth_checkpoint_approvals",
        "valid_until_unix",
        "ALTER TABLE eth_checkpoint_approvals ADD COLUMN valid_until_unix TEXT",
    )?;
    add_column_if_missing(
        transaction,
        "eth_checkpoint_attestations",
        "operator_fingerprint",
        "ALTER TABLE eth_checkpoint_attestations ADD COLUMN operator_fingerprint BLOB
         CHECK(operator_fingerprint IS NULL OR length(operator_fingerprint) = 32)",
    )
}

fn add_column_if_missing(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
    sql: &str,
) -> Result<()> {
    let exists = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
            )",
            [table, column],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if !exists {
        transaction
            .execute(sql, [])
            .map_err(NodeStoreError::sqlite)?;
    }
    Ok(())
}

fn migrate_v2_to_v3(transaction: &Transaction<'_>) -> Result<()> {
    let has_receipts = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'eth_verified_receipts'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if has_receipts {
        let has_verified_at = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('eth_verified_receipts')
                    WHERE name = 'verified_at_unix'
                )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(NodeStoreError::sqlite)?;
        if !has_verified_at {
            transaction
                .execute(
                    "ALTER TABLE eth_verified_receipts
                     ADD COLUMN verified_at_unix TEXT NOT NULL DEFAULT '0'",
                    [],
                )
                .map_err(NodeStoreError::sqlite)?;
            // v2 did not retain a distinct verification time. Preserve its
            // local record time as migration metadata; this does not prove
            // when the receipt was cryptographically verified.
            transaction
                .execute(
                    "UPDATE eth_verified_receipts
                     SET verified_at_unix = CAST(recorded_at_unix AS TEXT)
                     WHERE verified_at_unix = '0'",
                    [],
                )
                .map_err(NodeStoreError::sqlite)?;
        }
    }
    Ok(())
}

fn migrate_v1_to_v2(transaction: &Transaction<'_>) -> Result<()> {
    let has_canonical_bundle = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('eth_verified_account_imports')
                WHERE name = 'canonical_bundle'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(NodeStoreError::sqlite)?;
    if !has_canonical_bundle {
        transaction
            .execute(
                "ALTER TABLE eth_verified_account_imports
                 ADD COLUMN canonical_bundle BLOB
                 CHECK(canonical_bundle IS NULL OR length(canonical_bundle) > 0)",
                [],
            )
            .map_err(NodeStoreError::sqlite)?;
    }
    Ok(())
}

fn create_current_schema(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS eth_network_profile (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32)
                );

             CREATE TABLE IF NOT EXISTS eth_wallet_profile (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    address BLOB NOT NULL CHECK(length(address) = 20),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32)
                );

             CREATE TABLE IF NOT EXISTS eth_verified_account_imports (
                    import_key BLOB PRIMARY KEY NOT NULL CHECK(length(import_key) = 32),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    block_number TEXT NOT NULL,
                    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                    address BLOB NOT NULL CHECK(length(address) = 20),
                    balance BLOB NOT NULL CHECK(length(balance) = 32),
                    nonce TEXT NOT NULL,
                    code_hash BLOB NOT NULL CHECK(length(code_hash) = 32),
                    storage_root BLOB NOT NULL CHECK(length(storage_root) = 32),
                    proof_bundle_hash BLOB NOT NULL CHECK(length(proof_bundle_hash) = 32),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    canonical_bundle BLOB
                        CHECK(canonical_bundle IS NULL OR length(canonical_bundle) > 0)
                );
             CREATE UNIQUE INDEX IF NOT EXISTS eth_verified_accounts_by_subject
                ON eth_verified_account_imports(chain_id, block_hash, address);

             CREATE TABLE IF NOT EXISTS eth_checkpoint_approvals (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    approval_basis INTEGER NOT NULL,
                    approved_at_unix TEXT NOT NULL,
                    checkpoint_epoch TEXT NOT NULL,
                    valid_until_unix TEXT NOT NULL,
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, checkpoint_root)
                );
             CREATE TABLE IF NOT EXISTS eth_checkpoint_attestations (
                    attestation_key BLOB PRIMARY KEY NOT NULL CHECK(length(attestation_key) = 32),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    source_kind INTEGER NOT NULL,
                    source_fingerprint BLOB NOT NULL CHECK(length(source_fingerprint) = 32),
                    operator_fingerprint BLOB NOT NULL CHECK(length(operator_fingerprint) = 32),
                    observation_hash BLOB NOT NULL CHECK(length(observation_hash) = 32),
                    observed_at_unix TEXT NOT NULL,
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    FOREIGN KEY(chain_id, network, checkpoint_root)
                        REFERENCES eth_checkpoint_approvals(chain_id, network, checkpoint_root),
                    UNIQUE(
                        chain_id, network, source_kind,
                        source_fingerprint, observed_at_unix
                    )
                );

             CREATE TABLE IF NOT EXISTS eth_verified_finalized_headers (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    finalized_slot TEXT NOT NULL,
                    execution_block_number TEXT NOT NULL,
                    execution_block_hash BLOB NOT NULL CHECK(length(execution_block_hash) = 32),
                    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                    receipts_root BLOB NOT NULL CHECK(length(receipts_root) = 32),
                    beacon_transactions_root BLOB NOT NULL
                        CHECK(length(beacon_transactions_root) = 32),
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    provenance INTEGER NOT NULL,
                    proof_bundle_hash BLOB NOT NULL CHECK(length(proof_bundle_hash) = 32),
                    canonical_bundle BLOB NOT NULL CHECK(length(canonical_bundle) > 0),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, finalized_slot),
                    FOREIGN KEY(chain_id, network, checkpoint_root)
                        REFERENCES eth_checkpoint_approvals(chain_id, network, checkpoint_root),
                    UNIQUE(chain_id, network, execution_block_hash),
                    UNIQUE(chain_id, network, proof_bundle_hash)
                );

             CREATE TABLE IF NOT EXISTS eth_latest_finalized_header (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    finalized_slot TEXT NOT NULL,
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    PRIMARY KEY(chain_id, network),
                    FOREIGN KEY(chain_id, network, finalized_slot)
                        REFERENCES eth_verified_finalized_headers(chain_id, network, finalized_slot)
                );

             CREATE TABLE IF NOT EXISTS eth_verified_execution_blocks (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    execution_block_number TEXT NOT NULL,
                    execution_block_hash BLOB NOT NULL CHECK(length(execution_block_hash) = 32),
                    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                    receipts_root BLOB NOT NULL CHECK(length(receipts_root) = 32),
                    transactions_root BLOB NOT NULL CHECK(length(transactions_root) = 32),
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    provenance INTEGER NOT NULL,
                    consensus_bundle_hash BLOB NOT NULL CHECK(length(consensus_bundle_hash) = 32),
                    proof_bundle_hash BLOB NOT NULL CHECK(length(proof_bundle_hash) = 32),
                    canonical_bundle BLOB NOT NULL CHECK(length(canonical_bundle) > 0),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, execution_block_hash),
                    FOREIGN KEY(chain_id, network, consensus_bundle_hash)
                        REFERENCES eth_verified_finalized_headers(chain_id, network, proof_bundle_hash),
                    UNIQUE(chain_id, network, proof_bundle_hash)
                );

             CREATE TABLE IF NOT EXISTS eth_replay_records (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    evidence_kind INTEGER NOT NULL,
                    replay_key BLOB NOT NULL CHECK(length(replay_key) = 32),
                    subject_key BLOB NOT NULL CHECK(length(subject_key) = 32),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, evidence_kind, replay_key)
                );

             CREATE TABLE IF NOT EXISTS eth_signed_transactions (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
                    signing_hash BLOB NOT NULL CHECK(length(signing_hash) = 32),
                    sender BLOB NOT NULL CHECK(length(sender) = 20),
                    nonce TEXT NOT NULL,
                    intent_review_digest BLOB NOT NULL CHECK(length(intent_review_digest) = 32),
                    signed_at_unix TEXT NOT NULL,
                    raw_transaction BLOB NOT NULL CHECK(length(raw_transaction) > 0),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, tx_hash)
                );

             CREATE TABLE IF NOT EXISTS eth_verified_receipt_targets (
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    block_number TEXT NOT NULL,
                    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                    parent_hash BLOB NOT NULL CHECK(length(parent_hash) = 32),
                    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                    receipts_root BLOB NOT NULL CHECK(length(receipts_root) = 32),
                    transactions_root BLOB NOT NULL CHECK(length(transactions_root) = 32),
                    anchor_block_hash BLOB NOT NULL CHECK(length(anchor_block_hash) = 32),
                    checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root) = 32),
                    provenance INTEGER NOT NULL,
                    consensus_bundle_hash BLOB NOT NULL CHECK(length(consensus_bundle_hash) = 32),
                    authority_kind INTEGER NOT NULL CHECK(authority_kind IN (1, 2)),
                    authority_bundle_hash BLOB NOT NULL CHECK(length(authority_bundle_hash) = 32),
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(chain_id, network, block_hash, authority_bundle_hash),
                    FOREIGN KEY(chain_id, network, anchor_block_hash)
                        REFERENCES eth_verified_execution_blocks(
                            chain_id, network, execution_block_hash
                        )
                );

             CREATE TABLE IF NOT EXISTS eth_verified_receipts (
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
                    FOREIGN KEY(
                        chain_id, network, block_hash, execution_header_proof_hash
                    ) REFERENCES eth_verified_receipt_targets(
                        chain_id, network, block_hash, authority_bundle_hash
                        ),
                    UNIQUE(chain_id, network, tx_hash),
                    UNIQUE(chain_id, network, proof_bundle_hash)
                );

             CREATE TABLE IF NOT EXISTS eth_assurance_history (
                    event_key BLOB PRIMARY KEY NOT NULL CHECK(length(event_key) = 32),
                    chain_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    subject_kind INTEGER NOT NULL,
                    subject_key BLOB NOT NULL CHECK(length(subject_key) = 32),
                    event_kind INTEGER NOT NULL,
                    evidence_hash BLOB NOT NULL CHECK(length(evidence_hash) = 32),
                    observed_at_unix TEXT NOT NULL,
                    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
                    recorded_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                    UNIQUE(
                        chain_id, network, subject_kind, subject_key,
                        event_kind, evidence_hash, observed_at_unix
                    )
                );",
        )
        .map_err(NodeStoreError::sqlite)?;
    crate::field_node::create_schema(transaction)?;
    crate::bootstrap::create_schema(transaction)?;
    crate::messaging::create_schema(transaction)?;
    crate::workflow::create_schema(transaction)
}

fn install_checkpoint_epoch_index(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS eth_checkpoint_approvals_by_epoch
             ON eth_checkpoint_approvals(chain_id, network, checkpoint_epoch)",
            [],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn install_field_operation_nonce_reservation_index(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS eth_field_operations_active_nonce
             ON eth_field_operations(chain_id, network, sender, nonce)
             WHERE state IN (1, 2, 4)",
            [],
        )
        .map_err(NodeStoreError::sqlite)?;
    Ok(())
}

fn install_or_validate_network(transaction: &Transaction<'_>) -> Result<()> {
    let expected_digest = network_digest(SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK);
    transaction
        .execute(
            "INSERT INTO eth_network_profile (
                singleton, chain_id, network, record_digest
             ) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO NOTHING",
            rusqlite::params![
                SEPOLIA_CHAIN_ID.to_string(),
                SEPOLIA_NETWORK,
                expected_digest.as_slice()
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    let stored = transaction
        .query_row(
            "SELECT chain_id, network, record_digest
             FROM eth_network_profile WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(NodeStoreError::sqlite)?;
    let chain_id = stored
        .0
        .parse::<u64>()
        .map_err(|_| NodeStoreError::new("invalid stored network chain id"))?;
    let digest: [u8; 32] = stored
        .2
        .as_slice()
        .try_into()
        .map_err(|_| NodeStoreError::new("invalid stored network digest"))?;
    if chain_id != SEPOLIA_CHAIN_ID
        || stored.1 != SEPOLIA_NETWORK
        || digest != network_digest(chain_id, &stored.1)
    {
        return Err(NodeStoreError::new(
            "Ethereum store is pinned to a different or corrupted network",
        ));
    }
    Ok(())
}

fn network_digest(chain_id: u64, network: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-network-profile-v1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update((network.len() as u16).to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v11_requests_survive_outbound_ledger_migration_and_reopen() {
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0x21; 16];
        {
            let mut store = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(crate::OutboundEvidenceRequest::new(
                    request_id,
                    [0x22; 16],
                    crate::MessagingEvidenceKind::ReceiptProof,
                    [0x23; 32],
                    1024,
                    100,
                    200,
                ))
                .unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE eth_message_outbox;
                     UPDATE eth_schema_version SET version = 11 WHERE singleton = 1;",
                )
                .unwrap();
        }
        let store = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (version, outbox_count): (i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'eth_message_outbox')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(outbox_count, 1);
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(crate::MessageRequestStatus::Pending)
        );
    }

    #[test]
    fn v12_requests_survive_checkpoint_context_migration() {
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0x29; 16];
        {
            let mut store = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(crate::OutboundEvidenceRequest::new(
                    request_id,
                    [0x2a; 16],
                    crate::MessagingEvidenceKind::ReceiptProof,
                    [0x2b; 32],
                    1024,
                    100,
                    200,
                ))
                .unwrap();
            store
                .connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     CREATE TABLE eth_message_requests_backup AS
                     SELECT request_id, expected_gateway_source_hash,
                        operation_kind, evidence_kind, subject,
                        maximum_response_bytes, bulk_approved, created_at_unix,
                        expires_at_unix, status, manifest_digest, manifest_size,
                        relay_observation, record_digest, recorded_at_unix
                     FROM eth_message_requests;
                     CREATE TABLE eth_pending_message_evidence_backup AS
                        SELECT * FROM eth_pending_message_evidence;
                     CREATE TABLE eth_message_outbox_backup AS
                        SELECT * FROM eth_message_outbox;
                     DROP TABLE eth_sync_plan_requests;
                     DROP TABLE eth_sync_plans;
                     DROP TABLE eth_message_outbox;
                     DROP TABLE eth_pending_message_evidence;
                     DROP TABLE eth_message_requests;
                     ALTER TABLE eth_message_requests_backup
                        RENAME TO eth_message_requests;
                     ALTER TABLE eth_pending_message_evidence_backup
                        RENAME TO eth_pending_message_evidence;
                     ALTER TABLE eth_message_outbox_backup
                        RENAME TO eth_message_outbox;
                     UPDATE eth_schema_version SET version = 12 WHERE singleton = 1;",
                )
                .unwrap();
        }
        let store = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            store.message_request_status(request_id).unwrap(),
            Some(crate::MessageRequestStatus::Pending)
        );
        let (version, context_columns, workflow_tables): (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM pragma_table_info('eth_message_requests')
                     WHERE name IN ('checkpoint_epoch', 'checkpoint_root')),
                    (SELECT count(*) FROM sqlite_master WHERE type = 'table'
                     AND name IN ('eth_sync_plans', 'eth_sync_plan_requests'))",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(context_columns, 2);
        assert_eq!(workflow_tables, 2);
    }

    #[test]
    fn v10_messaging_rows_survive_consensus_kind_migration_and_reopen() {
        let profile = tempfile::tempdir().unwrap();
        let request_id = [0x31; 16];
        {
            let mut store = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            store
                .create_evidence_request(crate::OutboundEvidenceRequest::new(
                    request_id,
                    [0x32; 16],
                    crate::MessagingEvidenceKind::ReceiptProof,
                    [0x33; 32],
                    1024,
                    100,
                    200,
                ))
                .unwrap();
            // Reproduce the v10 CHECK constraints without depending on a
            // historical binary. The temporary database is closed immediately
            // so SQLite reparses the edited schema on the migration reopen.
            store
                .connection
                .execute_batch(
                    "PRAGMA writable_schema=ON;
                     UPDATE sqlite_schema
                     SET sql = replace(sql, '1, 2, 3, 4', '1, 2, 3')
                     WHERE type = 'table'
                       AND name IN (
                         'eth_message_requests',
                         'eth_pending_message_evidence'
                       );
                     UPDATE eth_schema_version SET version = 10 WHERE singleton = 1;
                     PRAGMA writable_schema=OFF;",
                )
                .unwrap();
        }

        let mut reopened = crate::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            reopened.message_request_status(request_id).unwrap(),
            Some(crate::MessageRequestStatus::Pending)
        );
        let (version, request_sql, pending_sql): (i64, String, String) = reopened
            .connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT sql FROM sqlite_schema
                     WHERE type = 'table' AND name = 'eth_message_requests'),
                    (SELECT sql FROM sqlite_schema
                     WHERE type = 'table' AND name = 'eth_pending_message_evidence')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert!(request_sql.contains("1, 2, 3, 4"));
        assert!(pending_sql.contains("1, 2, 3, 4"));
        let workflow_request_target: String = reopened
            .connection
            .query_row(
                "SELECT \"table\" FROM pragma_foreign_key_list('eth_sync_plan_requests')
                 WHERE \"from\" = 'request_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(workflow_request_target, "eth_message_requests");
        let now = crate::bootstrap::trusted_now_unix().unwrap();
        reopened
            .install_wallet_account(ratspeak_eth_wallet::WalletAccount::sepolia(
                alloy_primitives::Address::repeat_byte(0x39),
            ))
            .unwrap();
        crate::bootstrap::install_test_active_checkpoint(&mut reopened, [0x3a; 32], now);
        let generation = reopened.next_evidence_sync_generation().unwrap();
        reopened
            .plan_evidence_sync(crate::EvidenceSyncTrigger::new(
                [0x3b; 16],
                generation,
                [0x3c; 16],
                1024,
                now,
                now + 600,
            ))
            .unwrap();
    }

    #[test]
    fn rejects_orphaned_v2_receipt_instead_of_manufacturing_target_authority() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE eth_schema_version (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    version INTEGER NOT NULL
                 );
                 INSERT INTO eth_schema_version (singleton, version) VALUES (1, 2);
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
                    UNIQUE(chain_id, network, tx_hash),
                    UNIQUE(chain_id, network, proof_bundle_hash)
                 );
                 INSERT INTO eth_verified_receipts (
                    chain_id, network, block_number, block_hash, tx_hash, tx_index,
                    succeeded, cumulative_gas_used, logs_count, checkpoint_root,
                    provenance, consensus_bundle_hash, execution_header_proof_hash,
                    proof_bundle_hash, canonical_bundle, record_digest, recorded_at_unix
                 ) VALUES (
                    '11155111', 'sepolia', '1', zeroblob(32), zeroblob(32), '0',
                    1, '1', '0', zeroblob(32), 1, zeroblob(32), zeroblob(32),
                    zeroblob(32), x'01', zeroblob(32), 123
                 );",
            )
            .unwrap();

        assert!(
            initialize(&mut connection)
                .unwrap_err()
                .to_string()
                .contains("lost its execution authority")
        );
        let version: i64 = connection
            .query_row(
                "SELECT version FROM eth_schema_version WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 2);
    }

    #[test]
    fn migrates_checkpoint_policy_v4_to_field_operations_v5() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP TABLE eth_field_operations;
                 UPDATE eth_schema_version SET version = 4 WHERE singleton = 1;",
            )
            .unwrap();

        initialize(&mut connection).unwrap();
        let (version, field_table, checkpoint_epoch): (i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'eth_field_operations'),
                    (SELECT count(*) FROM pragma_table_info('eth_checkpoint_approvals')
                     WHERE name = 'checkpoint_epoch')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(field_table, 1);
        assert_eq!(checkpoint_epoch, 1);
    }

    #[test]
    fn migrates_v7_to_public_wallet_profile_without_custody_columns() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP TABLE eth_wallet_profile;
                 UPDATE eth_schema_version SET version = 7 WHERE singleton = 1;",
            )
            .unwrap();

        initialize(&mut connection).unwrap();
        let (version, wallet_table, wallet_columns): (i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'eth_wallet_profile'),
                    (SELECT count(*) FROM pragma_table_info('eth_wallet_profile'))",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(wallet_table, 1);
        assert_eq!(wallet_columns, 5);
    }

    #[test]
    fn v8_migration_discards_operations_with_local_time_authority() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&mut connection).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE eth_field_operations DROP COLUMN chain_evidence_at_unix;
                 UPDATE eth_schema_version SET version = 8 WHERE singleton = 1;
                 INSERT INTO eth_field_operations (
                    operation_id, chain_id, network, sender, nonce, signing_hash,
                    review_context_digest, review_digest, prepared_at_unix, expires_at_unix,
                    account_block_number, account_block_hash, account_state_root,
                    checkpoint_root, account_proof_hash, evidence_verified_at_unix,
                    maximum_evidence_age_seconds, state, tx_hash, record_digest
                 ) VALUES (
                    x'01010101010101010101010101010101', '11155111', 'sepolia',
                    zeroblob(20), '1', zeroblob(32), zeroblob(32), zeroblob(32),
                    '100', '200', '1', zeroblob(32), zeroblob(32), zeroblob(32),
                    zeroblob(32), '100', '60', 3, NULL, zeroblob(32)
                 );",
            )
            .unwrap();

        initialize(&mut connection).unwrap();
        let (version, chain_time_column, operation_count): (i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM pragma_table_info('eth_field_operations')
                     WHERE name = 'chain_evidence_at_unix'),
                    (SELECT count(*) FROM eth_field_operations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(version, ETHEREUM_STORE_SCHEMA_VERSION);
        assert_eq!(chain_time_column, 1);
        assert_eq!(operation_count, 0);
    }

    #[test]
    fn v15_migration_rejects_conflicting_active_nonce_reservations() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP INDEX eth_field_operations_active_nonce;
                 UPDATE eth_schema_version SET version = 15 WHERE singleton = 1;
                 INSERT INTO eth_field_operations (
                    operation_id, chain_id, network, sender, nonce, signing_hash,
                    review_context_digest, review_digest, prepared_at_unix, expires_at_unix,
                    account_block_number, account_block_hash, account_state_root,
                    checkpoint_root, account_proof_hash, evidence_verified_at_unix,
                    chain_evidence_at_unix, maximum_evidence_age_seconds, state, tx_hash,
                    record_digest
                 ) VALUES
                    (x'01010101010101010101010101010101', '11155111', 'sepolia',
                     zeroblob(20), '7', zeroblob(32), zeroblob(32), zeroblob(32),
                     '100', '200', '42', zeroblob(32), zeroblob(32), zeroblob(32),
                     zeroblob(32), '100', '100', '60', 1, NULL, zeroblob(32)),
                    (x'02020202020202020202020202020202', '11155111', 'sepolia',
                     zeroblob(20), '7', zeroblob(32), zeroblob(32), zeroblob(32),
                     '100', '200', '42', zeroblob(32), zeroblob(32), zeroblob(32),
                     zeroblob(32), '100', '100', '60', 2, NULL, zeroblob(32));",
            )
            .unwrap();

        assert!(initialize(&mut connection).is_err());
        let (version, index_count): (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT version FROM eth_schema_version WHERE singleton = 1),
                    (SELECT count(*) FROM sqlite_master
                     WHERE type = 'index'
                       AND name = 'eth_field_operations_active_nonce')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 15);
        assert_eq!(index_count, 0);
    }
}
