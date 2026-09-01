use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{TxKind, U256};
use ratspeak_eth_verifier::{SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};
use rusqlite::{OptionalExtension, Transaction as SqliteTransaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::assurance::{
    AssuranceEventInput, AssuranceEventKind, AssuranceSubjectKind, record_assurance,
};
use crate::checkpoint::ensure_supported_network;
use crate::evidence::{EvidenceKind, record_replay};
use crate::{
    EthereumNodeStore, NodeStoreError, RecordOutcome, Result, parse_stored_u64, stored_array,
};

/// A plain native EIP-1559 transfer is well below this defense-in-depth limit.
const MAX_SIGNED_TRANSACTION_BYTES: usize = 256;
const NATIVE_TRANSFER_GAS_LIMIT: u64 = 21_000;

/// Public, locally signed transaction material read from SQLite.
///
/// Signed transaction bytes are public relay material. This type never contains
/// a seed, private key, mnemonic, passphrase, or platform-protection key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSignedTransaction {
    chain_id: u64,
    network: String,
    tx_hash: [u8; 32],
    signing_hash: [u8; 32],
    sender: [u8; 20],
    nonce: u64,
    intent_review_digest: [u8; 32],
    signed_at_unix: u64,
    raw_transaction: Vec<u8>,
}

impl StoredSignedTransaction {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        self.signing_hash
    }

    pub fn sender(&self) -> [u8; 20] {
        self.sender
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn intent_review_digest(&self) -> [u8; 32] {
        self.intent_review_digest
    }

    pub fn signed_at_unix(&self) -> u64 {
        self.signed_at_unix
    }

    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }
}

impl EthereumNodeStore {
    /// Validates and atomically stores an exact locally signed Sepolia EIP-1559 transaction.
    ///
    /// The signature is recovered from `raw_transaction` and must match
    /// `expected_sender`. `intent_review_digest` is a caller-supplied link to a
    /// custody-layer review record. This store preserves that link but cannot
    /// establish user authorization or the digest's review semantics by itself.
    #[allow(dead_code)]
    pub(crate) fn record_locally_signed_transaction(
        &mut self,
        raw_transaction: &[u8],
        expected_sender: [u8; 20],
        intent_review_digest: [u8; 32],
        signed_at_unix: u64,
    ) -> Result<(RecordOutcome, StoredSignedTransaction)> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(NodeStoreError::sqlite)?;
        let result = record_locally_signed_transaction_in(
            &transaction,
            raw_transaction,
            expected_sender,
            intent_review_digest,
            signed_at_unix,
        )?;
        transaction.commit().map_err(NodeStoreError::sqlite)?;
        Ok(result)
    }

    pub fn signed_transaction(
        &self,
        chain_id: u64,
        tx_hash: [u8; 32],
    ) -> Result<Option<StoredSignedTransaction>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_signed_transaction(&self.connection, chain_id, SEPOLIA_NETWORK, tx_hash)
    }

    /// Returns the most recently persisted locally signed transaction.
    ///
    /// SQLite's durable row sequence establishes insertion order without
    /// trusting either a caller-supplied signing time or the device clock. The
    /// selected row is then fully decoded and digest-checked before it crosses
    /// this boundary.
    pub fn latest_signed_transaction(
        &self,
        chain_id: u64,
    ) -> Result<Option<StoredSignedTransaction>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        let tx_hash = self
            .connection
            .query_row(
                "SELECT tx_hash
                 FROM eth_signed_transactions
                 WHERE chain_id = ?1 AND network = ?2
                 ORDER BY rowid DESC
                 LIMIT 1",
                rusqlite::params![chain_id.to_string(), SEPOLIA_NETWORK],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(NodeStoreError::sqlite)?
            .map(|value| stored_array(&value, "latest transaction hash"))
            .transpose()?;
        tx_hash
            .map(|hash| read_signed_transaction(&self.connection, chain_id, SEPOLIA_NETWORK, hash))
            .transpose()
            .map(Option::flatten)
    }

    /// Returns every locally signed transaction that does not yet have an
    /// exact verified receipt, in durable insertion order.
    pub fn unconfirmed_signed_transactions(
        &self,
        chain_id: u64,
    ) -> Result<Vec<StoredSignedTransaction>> {
        ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
        read_unconfirmed_signed_transactions(&self.connection, chain_id, SEPOLIA_NETWORK)
    }
}

pub(crate) fn read_unconfirmed_signed_transactions(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
) -> Result<Vec<StoredSignedTransaction>> {
    let mut statement = connection
        .prepare(
            "SELECT tx_hash FROM eth_signed_transactions
              WHERE chain_id = ?1 AND network = ?2 ORDER BY rowid",
        )
        .map_err(NodeStoreError::sqlite)?;
    let rows = statement
        .query_map(rusqlite::params![chain_id.to_string(), network], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(NodeStoreError::sqlite)?;
    let hashes = rows
        .map(|row| {
            stored_array(
                &row.map_err(NodeStoreError::sqlite)?,
                "unconfirmed transaction hash",
            )
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;
    let mut unconfirmed = Vec::new();
    for hash in hashes {
        let transaction = read_signed_transaction(connection, chain_id, network, hash)?
            .ok_or_else(|| NodeStoreError::new("unconfirmed signed transaction disappeared"))?;
        if crate::receipt::read_receipt_by_tx_hash(connection, chain_id, network, hash)?.is_none() {
            unconfirmed.push(transaction);
        }
    }
    Ok(unconfirmed)
}

pub(crate) fn record_locally_signed_transaction_in(
    transaction: &SqliteTransaction<'_>,
    raw_transaction: &[u8],
    expected_sender: [u8; 20],
    intent_review_digest: [u8; 32],
    signed_at_unix: u64,
) -> Result<(RecordOutcome, StoredSignedTransaction)> {
    if intent_review_digest == [0; 32] || signed_at_unix == 0 {
        return Err(NodeStoreError::new(
            "locally signed transaction is missing an intent review digest or signing time",
        ));
    }
    let decoded = decode_signed_transaction(raw_transaction)?;
    if decoded.sender != expected_sender {
        return Err(NodeStoreError::new(
            "locally signed transaction recovered an unexpected sender",
        ));
    }
    let stored = StoredSignedTransaction {
        chain_id: SEPOLIA_CHAIN_ID,
        network: SEPOLIA_NETWORK.to_owned(),
        tx_hash: decoded.tx_hash,
        signing_hash: decoded.signing_hash,
        sender: decoded.sender,
        nonce: decoded.nonce,
        intent_review_digest,
        signed_at_unix,
        raw_transaction: raw_transaction.to_vec(),
    };
    let digest = signed_transaction_digest(&stored);
    let changed = transaction
        .execute(
            "INSERT INTO eth_signed_transactions (
                    chain_id, network, tx_hash, signing_hash, sender, nonce,
                    intent_review_digest, signed_at_unix, raw_transaction, record_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(chain_id, network, tx_hash) DO NOTHING",
            rusqlite::params![
                stored.chain_id.to_string(),
                stored.network,
                stored.tx_hash.as_slice(),
                stored.signing_hash.as_slice(),
                stored.sender.as_slice(),
                stored.nonce.to_string(),
                stored.intent_review_digest.as_slice(),
                stored.signed_at_unix.to_string(),
                stored.raw_transaction,
                digest.as_slice(),
            ],
        )
        .map_err(NodeStoreError::sqlite)?;
    if changed == 0 {
        let existing = read_signed_transaction(
            transaction,
            stored.chain_id,
            &stored.network,
            stored.tx_hash,
        )?
        .ok_or_else(|| {
            NodeStoreError::new("signed transaction replay has no corresponding record")
        })?;
        if existing != stored {
            return Err(NodeStoreError::new(
                "transaction hash conflicts with immutable locally signed bytes",
            ));
        }
    }
    let replay = record_replay(
        transaction,
        stored.chain_id,
        &stored.network,
        EvidenceKind::SignedTransaction,
        stored.tx_hash,
        stored.tx_hash,
    )?;
    let assurance = record_assurance(
        transaction,
        AssuranceEventInput {
            chain_id: stored.chain_id,
            network: &stored.network,
            subject_kind: AssuranceSubjectKind::Transaction,
            subject_key: stored.tx_hash,
            event_kind: AssuranceEventKind::LocalSignatureRecorded,
            evidence_hash: stored.intent_review_digest,
            observed_at_unix: stored.signed_at_unix,
        },
    )?;
    let mut receipt_assurance = RecordOutcome::Replay;
    if let Some(receipt) = crate::receipt::read_receipt_by_tx_hash(
        transaction,
        stored.chain_id,
        &stored.network,
        stored.tx_hash,
    )? {
        receipt_assurance = record_assurance(
            transaction,
            AssuranceEventInput {
                chain_id: stored.chain_id,
                network: &stored.network,
                subject_kind: AssuranceSubjectKind::Transaction,
                subject_key: stored.tx_hash,
                event_kind: if receipt.succeeded() {
                    AssuranceEventKind::FinalizedReceiptSucceeded
                } else {
                    AssuranceEventKind::FinalizedReceiptFailed
                },
                evidence_hash: receipt.proof_bundle_hash(),
                observed_at_unix: receipt.verified_at_unix(),
            },
        )?;
    }
    let outcome = if changed == 1
        || replay == RecordOutcome::Inserted
        || assurance == RecordOutcome::Inserted
        || receipt_assurance == RecordOutcome::Inserted
    {
        RecordOutcome::Inserted
    } else {
        RecordOutcome::Replay
    };
    Ok((outcome, stored))
}

#[derive(Debug)]
struct DecodedSignedTransaction {
    tx_hash: [u8; 32],
    signing_hash: [u8; 32],
    sender: [u8; 20],
    nonce: u64,
}

fn decode_signed_transaction(raw_transaction: &[u8]) -> Result<DecodedSignedTransaction> {
    if raw_transaction.is_empty() {
        return Err(NodeStoreError::new("signed transaction bytes are empty"));
    }
    if raw_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES {
        return Err(NodeStoreError::new(
            "signed transaction exceeds the storage limit",
        ));
    }
    let mut remaining = raw_transaction;
    let envelope = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|error| NodeStoreError::new(format!("invalid signed transaction: {error}")))?;
    if !remaining.is_empty() {
        return Err(NodeStoreError::new(
            "signed transaction contains trailing bytes",
        ));
    }
    let TxEnvelope::Eip1559(signed) = &envelope else {
        return Err(NodeStoreError::new(
            "only EIP-1559 locally signed transactions are stored",
        ));
    };
    let transaction = signed.tx();
    if !matches!(transaction.to, TxKind::Call(_)) {
        return Err(NodeStoreError::new(
            "locally signed transaction must call an address",
        ));
    }
    if transaction.gas_limit != NATIVE_TRANSFER_GAS_LIMIT {
        return Err(NodeStoreError::new(
            "locally signed native transfer must use 21000 gas",
        ));
    }
    if transaction.value == U256::ZERO {
        return Err(NodeStoreError::new(
            "locally signed native transfer value must be nonzero",
        ));
    }
    if !transaction.input.is_empty() {
        return Err(NodeStoreError::new(
            "locally signed native transfer must have empty calldata",
        ));
    }
    if !transaction.access_list.is_empty() {
        return Err(NodeStoreError::new(
            "locally signed native transfer must have an empty access list",
        ));
    }
    let chain_id = envelope
        .chain_id()
        .ok_or_else(|| NodeStoreError::new("signed transaction has no chain id"))?;
    ensure_supported_network(chain_id, SEPOLIA_NETWORK)?;
    let sender = envelope
        .recover_signer()
        .map_err(|error| NodeStoreError::new(format!("invalid transaction signature: {error}")))?;
    Ok(DecodedSignedTransaction {
        tx_hash: envelope.tx_hash().0,
        signing_hash: envelope.signature_hash().0,
        sender: *sender.0,
        nonce: envelope.nonce(),
    })
}

pub(crate) fn read_signed_transaction(
    connection: &rusqlite::Connection,
    chain_id: u64,
    network: &str,
    tx_hash: [u8; 32],
) -> Result<Option<StoredSignedTransaction>> {
    let row = connection
        .query_row(
            "SELECT chain_id, network, tx_hash, signing_hash, sender, nonce,
                    intent_review_digest, signed_at_unix, raw_transaction, record_digest
             FROM eth_signed_transactions
             WHERE chain_id = ?1 AND network = ?2 AND tx_hash = ?3",
            rusqlite::params![chain_id.to_string(), network, tx_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(NodeStoreError::sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored = StoredSignedTransaction {
        chain_id: parse_stored_u64(&row.0, "signed transaction chain id")?,
        network: row.1,
        tx_hash: stored_array(&row.2, "transaction hash")?,
        signing_hash: stored_array(&row.3, "transaction signing hash")?,
        sender: stored_array(&row.4, "transaction sender")?,
        nonce: parse_stored_u64(&row.5, "transaction nonce")?,
        intent_review_digest: stored_array(&row.6, "intent review digest")?,
        signed_at_unix: parse_stored_u64(&row.7, "transaction signing time")?,
        raw_transaction: row.8,
    };
    let decoded = decode_signed_transaction(&stored.raw_transaction)?;
    if decoded.tx_hash != stored.tx_hash
        || decoded.signing_hash != stored.signing_hash
        || decoded.sender != stored.sender
        || decoded.nonce != stored.nonce
        || stored.chain_id != SEPOLIA_CHAIN_ID
        || stored.network != SEPOLIA_NETWORK
        || stored.intent_review_digest == [0; 32]
        || stored_array::<32>(&row.9, "signed transaction record digest")?
            != signed_transaction_digest(&stored)
    {
        return Err(NodeStoreError::new(
            "stored signed transaction digest does not match its bytes",
        ));
    }
    Ok(Some(stored))
}

fn signed_transaction_digest(transaction: &StoredSignedTransaction) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ratspeak-eth-signed-transaction-record-v1");
    hasher.update(transaction.chain_id.to_le_bytes());
    hasher.update((transaction.network.len() as u16).to_le_bytes());
    hasher.update(transaction.network.as_bytes());
    hasher.update(transaction.tx_hash);
    hasher.update(transaction.signing_hash);
    hasher.update(transaction.sender);
    hasher.update(transaction.nonce.to_le_bytes());
    hasher.update(transaction.intent_review_digest);
    hasher.update(transaction.signed_at_unix.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
pub(crate) mod test_support {
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Bytes, Signature};

    use super::*;

    fn raw_native_transfer() -> Vec<u8> {
        alloy_primitives::hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap()
    }

    pub(crate) fn signed_fixture_tx_hash() -> [u8; 32] {
        decode_signed_transaction(&raw_native_transfer())
            .unwrap()
            .tx_hash
    }

    pub(crate) fn signed_fixture(store: &mut EthereumNodeStore) -> ([u8; 20], [u8; 32], [u8; 32]) {
        let raw_transaction = raw_native_transfer();
        let decoded = decode_signed_transaction(&raw_transaction).unwrap();
        let review_digest = [0x7a; 32];
        store
            .record_locally_signed_transaction(&raw_transaction, decoded.sender, review_digest, 100)
            .unwrap();
        (decoded.sender, review_digest, decoded.tx_hash)
    }

    pub(crate) fn signed_fixture_with_nonce(store: &mut EthereumNodeStore, nonce: u64) -> [u8; 32] {
        let transaction = TxEip1559 {
            chain_id: SEPOLIA_CHAIN_ID,
            nonce,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            gas_limit: NATIVE_TRANSFER_GAS_LIMIT,
            to: Address::repeat_byte(0x11).into(),
            value: U256::from(1_000_000_000_000_000_u64),
            input: Bytes::new(),
            access_list: AccessList::default(),
        };
        let envelope = TxEnvelope::Eip1559(transaction.into_signed(Signature::test_signature()));
        let mut raw = Vec::new();
        envelope.encode_2718(&mut raw);
        let decoded = decode_signed_transaction(&raw).unwrap();
        store
            .record_locally_signed_transaction(
                &raw,
                decoded.sender,
                Sha256::digest(nonce.to_le_bytes()).into(),
                100 + nonce,
            )
            .unwrap();
        decoded.tx_hash
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::{Address, B256, Bytes, Signature, hex};

    use super::*;
    use crate::NonAuthoritativeTransactionObservation;

    fn sepolia_raw_transaction() -> Vec<u8> {
        hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap()
    }

    fn policy_transaction() -> TxEip1559 {
        TxEip1559 {
            chain_id: SEPOLIA_CHAIN_ID,
            nonce: 7,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            gas_limit: NATIVE_TRANSFER_GAS_LIMIT,
            to: Address::repeat_byte(0x11).into(),
            value: U256::from(1_000_000_000_000_000_u64),
            input: Bytes::new(),
            access_list: AccessList::default(),
        }
    }

    fn encoded_test_transaction(transaction: TxEip1559) -> Vec<u8> {
        let envelope = TxEnvelope::Eip1559(transaction.into_signed(Signature::test_signature()));
        let mut encoded = Vec::new();
        envelope.encode_2718(&mut encoded);
        encoded
    }

    #[test]
    fn persists_validated_signed_bytes_and_non_authoritative_history() {
        let raw = sepolia_raw_transaction();
        let decoded = decode_signed_transaction(&raw).unwrap();
        let profile = tempfile::tempdir().unwrap();
        let tx_hash = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            let (outcome, stored) = store
                .record_locally_signed_transaction(&raw, decoded.sender, [0x71; 32], 100)
                .unwrap();
            assert_eq!(outcome, RecordOutcome::Inserted);
            assert_eq!(
                store
                    .record_locally_signed_transaction(&raw, decoded.sender, [0x71; 32], 100)
                    .unwrap()
                    .0,
                RecordOutcome::Replay
            );
            assert_eq!(
                store
                    .record_non_authoritative_transaction_observation(
                        SEPOLIA_CHAIN_ID,
                        stored.tx_hash(),
                        NonAuthoritativeTransactionObservation::RpcAccepted,
                        [0x72; 32],
                        101,
                    )
                    .unwrap(),
                RecordOutcome::Inserted
            );
            stored.tx_hash()
        };

        let store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let stored = store
            .signed_transaction(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored.raw_transaction(), raw);
        assert_eq!(stored.sender(), decoded.sender);
        let history = store
            .transaction_assurance_history(SEPOLIA_CHAIN_ID, tx_hash)
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].event_kind(),
            AssuranceEventKind::LocalSignatureRecorded
        );
        assert_eq!(history[1].event_kind(), AssuranceEventKind::RpcAccepted);
        assert!(history.iter().all(|event| !matches!(
            event.event_kind(),
            AssuranceEventKind::FinalizedReceiptSucceeded
                | AssuranceEventKind::FinalizedReceiptFailed
        )));
    }

    #[test]
    fn latest_signed_transaction_is_durable_and_insertion_ordered() {
        let profile = tempfile::tempdir().unwrap();
        let mut first_transaction = policy_transaction();
        first_transaction.nonce = 8;
        let first_raw = encoded_test_transaction(first_transaction);
        let first = decode_signed_transaction(&first_raw).unwrap();
        let first_hash = {
            let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            assert!(
                store
                    .latest_signed_transaction(SEPOLIA_CHAIN_ID)
                    .unwrap()
                    .is_none()
            );
            let (_, stored) = store
                .record_locally_signed_transaction(&first_raw, first.sender, [0x61; 32], 200)
                .unwrap();
            stored.tx_hash()
        };

        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert_eq!(
            store
                .latest_signed_transaction(SEPOLIA_CHAIN_ID)
                .unwrap()
                .unwrap()
                .tx_hash(),
            first_hash
        );
        let mut second_transaction = policy_transaction();
        second_transaction.nonce = 9;
        let second_raw = encoded_test_transaction(second_transaction);
        let second = decode_signed_transaction(&second_raw).unwrap();
        let (_, second_stored) = store
            .record_locally_signed_transaction(&second_raw, second.sender, [0x62; 32], 199)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_signed_transactions
                 SET recorded_at_unix = CASE tx_hash WHEN ?1 THEN 300 WHEN ?2 THEN 100 END
                 WHERE tx_hash IN (?1, ?2)",
                rusqlite::params![first_hash.as_slice(), second_stored.tx_hash().as_slice()],
            )
            .unwrap();
        assert_eq!(
            store
                .latest_signed_transaction(SEPOLIA_CHAIN_ID)
                .unwrap()
                .unwrap()
                .tx_hash(),
            second_stored.tx_hash(),
            "durable insertion order must win over signing time and a backward device clock"
        );
        drop(store);

        assert_eq!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap()
                .latest_signed_transaction(SEPOLIA_CHAIN_ID)
                .unwrap()
                .unwrap()
                .tx_hash(),
            second_stored.tx_hash()
        );
    }

    #[test]
    fn rejects_wrong_sender_missing_review_and_trailing_bytes() {
        let raw = sepolia_raw_transaction();
        let decoded = decode_signed_transaction(&raw).unwrap();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        assert!(
            store
                .record_locally_signed_transaction(&raw, [0; 20], [0x81; 32], 100)
                .unwrap_err()
                .to_string()
                .contains("unexpected sender")
        );
        assert!(
            store
                .record_locally_signed_transaction(&raw, decoded.sender, [0; 32], 100)
                .unwrap_err()
                .to_string()
                .contains("missing an intent review digest")
        );
        let mut trailing = raw;
        trailing.push(0);
        assert!(
            store
                .record_locally_signed_transaction(&trailing, decoded.sender, [0x81; 32], 100)
                .unwrap_err()
                .to_string()
                .contains("trailing bytes")
        );
    }

    #[test]
    fn rejects_mainnet_and_non_eip1559_signed_transactions() {
        let mut mainnet_transaction = policy_transaction();
        mainnet_transaction.chain_id = 1;
        let mainnet = encoded_test_transaction(mainnet_transaction);
        assert!(
            decode_signed_transaction(&mainnet)
                .unwrap_err()
                .to_string()
                .contains("unsupported Ethereum store network 1/sepolia")
        );

        let mut sepolia = sepolia_raw_transaction();
        sepolia[0] = 1;
        assert!(decode_signed_transaction(&sepolia).is_err());
    }

    #[test]
    fn rejects_signed_bytes_outside_native_transfer_policy() {
        let mut creation = policy_transaction();
        creation.to = TxKind::Create;
        assert!(
            decode_signed_transaction(&encoded_test_transaction(creation))
                .unwrap_err()
                .to_string()
                .contains("must call an address")
        );

        let mut gas = policy_transaction();
        gas.gas_limit += 1;
        assert!(
            decode_signed_transaction(&encoded_test_transaction(gas))
                .unwrap_err()
                .to_string()
                .contains("21000 gas")
        );

        let mut zero_value = policy_transaction();
        zero_value.value = U256::ZERO;
        assert!(
            decode_signed_transaction(&encoded_test_transaction(zero_value))
                .unwrap_err()
                .to_string()
                .contains("value must be nonzero")
        );

        let mut calldata = policy_transaction();
        calldata.input = Bytes::from_static(&[1]);
        assert!(
            decode_signed_transaction(&encoded_test_transaction(calldata))
                .unwrap_err()
                .to_string()
                .contains("empty calldata")
        );

        let mut access_list = policy_transaction();
        access_list.access_list.0.push(AccessListItem {
            address: Address::repeat_byte(0x22),
            storage_keys: vec![B256::repeat_byte(0x33)],
        });
        assert!(
            decode_signed_transaction(&encoded_test_transaction(access_list))
                .unwrap_err()
                .to_string()
                .contains("empty access list")
        );

        assert!(
            decode_signed_transaction(&vec![0; MAX_SIGNED_TRANSACTION_BYTES + 1])
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
    }

    #[test]
    fn fails_closed_on_corrupted_signed_transaction_bytes() {
        let raw = sepolia_raw_transaction();
        let decoded = decode_signed_transaction(&raw).unwrap();
        let profile = tempfile::tempdir().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let (_, stored) = store
            .record_locally_signed_transaction(&raw, decoded.sender, [0x91; 32], 100)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE eth_signed_transactions SET raw_transaction = x'02'",
                [],
            )
            .unwrap();
        assert!(
            store
                .signed_transaction(SEPOLIA_CHAIN_ID, stored.tx_hash())
                .unwrap_err()
                .to_string()
                .contains("invalid signed transaction")
        );
    }
}
