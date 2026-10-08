use alloy_consensus::{ReceiptEnvelope, Transaction, TxEnvelope};
use alloy_eips::Typed2718;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Bytes};
use alloy_trie::Nibbles;
use alloy_trie::proof::verify_proof;

use super::{
    AnchorAssurance, Cursor, KIND_TX_RECEIPT_PROOF, MAX_PROOF_NODE_BYTES, MAX_PROOF_NODES, Result,
    VerifiedEvmAnchor, VerifiedExecutionBlock, Verifier, VerifyError, sha256,
};

const MAX_TRANSACTION_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_BYTES: usize = 512 * 1024;

/// An exact transaction and receipt inclusion proof for one execution block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceiptProofBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub tx_index: u64,
    pub raw_tx: Vec<u8>,
    pub receipt: Vec<u8>,
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub tx_proof: Vec<Vec<u8>>,
    pub receipt_proof: Vec<Vec<u8>>,
}

/// Exact receipt evidence verified relative to a consensus-authenticated execution block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTxReceipt {
    pub(super) chain_id: u64,
    pub(super) network: String,
    pub(super) block_number: u64,
    pub(super) block_hash: [u8; 32],
    pub(super) tx_hash: [u8; 32],
    pub(super) tx_index: u64,
    pub(super) succeeded: bool,
    pub(super) cumulative_gas_used: u64,
    pub(super) logs_count: u64,
    pub(super) checkpoint_root: [u8; 32],
    pub(super) provenance: crate::ExecutionHeaderProvenance,
    pub(super) consensus_bundle_hash: [u8; 32],
    pub(super) execution_header_proof_hash: [u8; 32],
    pub(super) proof_bundle_hash: [u8; 32],
}

impl VerifiedTxReceipt {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    pub fn tx_index(&self) -> u64 {
        self.tx_index
    }

    /// Whether execution succeeded. A false value still proves an included failed receipt.
    pub fn succeeded(&self) -> bool {
        self.succeeded
    }

    pub fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used
    }

    pub fn logs_count(&self) -> u64 {
        self.logs_count
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn provenance(&self) -> crate::ExecutionHeaderProvenance {
        self.provenance
    }

    pub fn consensus_bundle_hash(&self) -> [u8; 32] {
        self.consensus_bundle_hash
    }

    pub fn execution_header_proof_hash(&self) -> [u8; 32] {
        self.execution_header_proof_hash
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvmTxReceipt {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    tx_hash: [u8; 32],
    tx_index: u64,
    succeeded: bool,
    cumulative_gas_used: u64,
    logs_count: u64,
    assurance: AnchorAssurance,
    anchor_evidence_hash: [u8; 32],
    proof_bundle_hash: [u8; 32],
}

impl VerifiedEvmTxReceipt {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn block_number(&self) -> u64 {
        self.block_number
    }
    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    pub fn tx_index(&self) -> u64 {
        self.tx_index
    }
    pub fn succeeded(&self) -> bool {
        self.succeeded
    }
    pub fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used
    }
    pub fn logs_count(&self) -> u64 {
        self.logs_count
    }
    pub fn assurance(&self) -> AnchorAssurance {
        self.assurance
    }
    pub fn anchor_evidence_hash(&self) -> [u8; 32] {
        self.anchor_evidence_hash
    }
    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

impl Verifier {
    pub fn parse_tx_receipt_proof(&self, bytes: &[u8]) -> Result<TxReceiptProofBundle> {
        let canonical = self.canonical_bundle(bytes)?;
        parse_tx_receipt_proof(&canonical, self.chain_id, self.network)
    }

    /// Verifies exact transaction and receipt inclusion against a shared EVM
    /// anchor, regardless of the stack that authenticated that anchor.
    pub fn verify_tx_receipt_from_anchor(
        &self,
        bytes: &[u8],
        anchor: &VerifiedEvmAnchor,
    ) -> Result<VerifiedEvmTxReceipt> {
        if anchor.chain_id() != self.chain_id || anchor.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: anchor.chain_id(),
                network: anchor.network().to_owned(),
            });
        }

        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_tx_receipt_proof(&canonical, self.chain_id, self.network)?;
        let (succeeded, cumulative_gas_used, logs_count) = verify_tx_receipt_core(
            &bundle,
            anchor.chain_id(),
            anchor.block_number(),
            anchor.block_hash(),
            anchor.transactions_root(),
            anchor.receipts_root(),
        )?;

        Ok(VerifiedEvmTxReceipt {
            chain_id: bundle.chain_id,
            network: bundle.network,
            block_number: bundle.block_number,
            block_hash: bundle.block_hash,
            tx_hash: bundle.tx_hash,
            tx_index: bundle.tx_index,
            succeeded,
            cumulative_gas_used,
            logs_count,
            assurance: anchor.assurance(),
            anchor_evidence_hash: anchor.evidence_hash(),
            proof_bundle_hash: sha256(&canonical),
        })
    }

    /// Verifies exact inclusion against roots whose provenance is carried by `block`.
    pub fn verify_tx_receipt(
        &self,
        bytes: &[u8],
        block: &VerifiedExecutionBlock,
    ) -> Result<VerifiedTxReceipt> {
        if block.chain_id() != self.chain_id || block.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: block.chain_id(),
                network: block.network().to_owned(),
            });
        }
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_tx_receipt_proof(&canonical, self.chain_id, self.network)?;
        verify_tx_receipt(bundle, block, sha256(&canonical))
    }
}

pub(super) fn parse_tx_receipt_proof(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<TxReceiptProofBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_TX_RECEIPT_PROOF {
        return Err(VerifyError::UnsupportedKind(prelude.kind));
    }
    let created_at_unix = cursor.u64()?;
    let block_number = cursor.u64()?;
    let block_hash = cursor.array32()?;
    let tx_hash = cursor.array32()?;
    let tx_index = cursor.u64()?;
    let raw_tx = cursor.sized_bytes(MAX_TRANSACTION_BYTES, "transaction exceeds limit")?;
    let receipt = cursor.sized_bytes(MAX_RECEIPT_BYTES, "receipt exceeds limit")?;
    if raw_tx.is_empty() || receipt.is_empty() {
        return Err(VerifyError::Malformed("empty transaction or receipt"));
    }
    let transactions_root = cursor.array32()?;
    let receipts_root = cursor.array32()?;
    let tx_proof = proof_nodes(&mut cursor)?;
    let receipt_proof = proof_nodes(&mut cursor)?;
    cursor.finish()?;
    Ok(TxReceiptProofBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        block_number,
        block_hash,
        tx_hash,
        tx_index,
        raw_tx,
        receipt,
        transactions_root,
        receipts_root,
        tx_proof,
        receipt_proof,
    })
}

fn proof_nodes(cursor: &mut Cursor<'_>) -> Result<Vec<Vec<u8>>> {
    let count = cursor.u32()? as usize;
    if count == 0 {
        return Err(VerifyError::Malformed("receipt trie proof is empty"));
    }
    if count > MAX_PROOF_NODES {
        return Err(VerifyError::TooManyProofNodes);
    }
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = cursor.sized_bytes(MAX_PROOF_NODE_BYTES, "receipt proof node exceeds limit")?;
        if node.is_empty() {
            return Err(VerifyError::Malformed("receipt proof node is empty"));
        }
        nodes.push(node);
    }
    Ok(nodes)
}

pub(super) fn verify_tx_receipt(
    bundle: TxReceiptProofBundle,
    block: &VerifiedExecutionBlock,
    proof_bundle_hash: [u8; 32],
) -> Result<VerifiedTxReceipt> {
    let (succeeded, cumulative_gas_used, logs_count) = verify_tx_receipt_core(
        &bundle,
        block.chain_id(),
        block.execution_block_number(),
        block.execution_block_hash(),
        block.transactions_root(),
        block.receipts_root(),
    )?;

    Ok(VerifiedTxReceipt {
        chain_id: bundle.chain_id,
        network: bundle.network,
        block_number: bundle.block_number,
        block_hash: bundle.block_hash,
        tx_hash: bundle.tx_hash,
        tx_index: bundle.tx_index,
        succeeded,
        cumulative_gas_used,
        logs_count,
        checkpoint_root: block.checkpoint_root(),
        provenance: block.provenance(),
        consensus_bundle_hash: block.consensus_bundle_hash(),
        execution_header_proof_hash: block.proof_bundle_hash(),
        proof_bundle_hash,
    })
}

fn verify_tx_receipt_core(
    bundle: &TxReceiptProofBundle,
    expected_chain_id: u64,
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
    expected_transactions_root: [u8; 32],
    expected_receipts_root: [u8; 32],
) -> Result<(bool, u64, u64)> {
    if bundle.chain_id != expected_chain_id
        || bundle.block_number != expected_block_number
        || bundle.block_hash != expected_block_hash
        || bundle.transactions_root != expected_transactions_root
        || bundle.receipts_root != expected_receipts_root
    {
        return Err(VerifyError::ReceiptHeaderMismatch);
    }

    verify_trie_value(
        bundle.transactions_root,
        bundle.tx_index,
        &bundle.raw_tx,
        &bundle.tx_proof,
        "transaction proof",
    )?;
    verify_trie_value(
        bundle.receipts_root,
        bundle.tx_index,
        &bundle.receipt,
        &bundle.receipt_proof,
        "receipt proof",
    )?;

    let transaction = decode_transaction(&bundle.raw_tx)?;
    if transaction.chain_id() != Some(bundle.chain_id) {
        return Err(VerifyError::InvalidTransaction(format!(
            "transaction does not commit to expected chain id {}",
            bundle.chain_id
        )));
    }
    if transaction.tx_hash().0 != bundle.tx_hash {
        return Err(VerifyError::InvalidTransaction(
            "verified transaction bytes do not match transaction hash".to_owned(),
        ));
    }

    let receipt = decode_receipt(&bundle.receipt)?;
    if transaction.ty() != receipt.ty() {
        return Err(VerifyError::InvalidReceiptProof(
            "receipt envelope type does not match transaction type".to_owned(),
        ));
    }

    Ok((
        receipt.status(),
        receipt.cumulative_gas_used(),
        receipt.logs().len() as u64,
    ))
}

fn verify_trie_value(
    root: [u8; 32],
    index: u64,
    expected: &[u8],
    proof: &[Vec<u8>],
    label: &'static str,
) -> Result<()> {
    let nodes = proof
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect::<Vec<_>>();
    verify_proof(
        B256::from(root),
        Nibbles::unpack(alloy_rlp::encode(index)),
        Some(expected.to_vec()),
        nodes.iter(),
    )
    .map_err(|error| VerifyError::InvalidReceiptProof(format!("{label}: {error}")))
}

fn decode_transaction(bytes: &[u8]) -> Result<TxEnvelope> {
    let mut remaining = bytes;
    let transaction = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|error| VerifyError::InvalidTransaction(error.to_string()))?;
    if !remaining.is_empty() {
        return Err(VerifyError::Malformed("trailing transaction bytes"));
    }
    Ok(transaction)
}

fn decode_receipt(bytes: &[u8]) -> Result<ReceiptEnvelope> {
    let mut remaining = bytes;
    let receipt = ReceiptEnvelope::decode_2718(&mut remaining)
        .map_err(|error| VerifyError::InvalidReceiptProof(error.to_string()))?;
    if !remaining.is_empty() {
        return Err(VerifyError::Malformed("trailing receipt bytes"));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use crate::SEPOLIA_CHAIN_ID;
    use alloy_consensus::{Receipt, ReceiptWithBloom, SignableTransaction, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Signature, U256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{HashBuilder, Nibbles};

    use super::*;
    use crate::{MAGIC, MAX_BUNDLE_BYTES, SEPOLIA_NETWORK, VERSION};

    fn transaction_bytes_for_chain(nonce: u64, chain_id: u64) -> Vec<u8> {
        let envelope = TxEnvelope::Eip1559(
            TxEip1559 {
                chain_id,
                nonce,
                max_fee_per_gas: 3,
                max_priority_fee_per_gas: 2,
                gas_limit: 21_000,
                to: Address::repeat_byte(0x22).into(),
                value: U256::from(7_u64),
                input: Default::default(),
                access_list: Default::default(),
            }
            .into_signed(Signature::test_signature()),
        );
        let mut bytes = Vec::new();
        envelope.encode_2718(&mut bytes);
        bytes
    }

    fn receipt_bytes(status: bool, gas: u64) -> Vec<u8> {
        let receipt = ReceiptEnvelope::Eip1559(ReceiptWithBloom {
            receipt: Receipt {
                status: status.into(),
                cumulative_gas_used: gas,
                logs: vec![],
            },
            logs_bloom: [0; 256].into(),
        });
        let mut bytes = Vec::new();
        receipt.encode_2718(&mut bytes);
        bytes
    }

    fn trie_root_and_proof(values: &[Vec<u8>], target: u64) -> ([u8; 32], Vec<Vec<u8>>) {
        let target_key = Nibbles::unpack(alloy_rlp::encode(target));
        let mut entries = values
            .iter()
            .enumerate()
            .map(|(index, value)| (Nibbles::unpack(alloy_rlp::encode(index as u64)), value))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.0);
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([target_key]));
        for (key, value) in entries {
            builder.add_leaf(key, value);
        }
        let root = builder.root().into();
        let proof = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect();
        (root, proof)
    }

    fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    fn write_nodes(out: &mut Vec<u8>, nodes: &[Vec<u8>]) {
        out.extend_from_slice(&(nodes.len() as u32).to_le_bytes());
        for node in nodes {
            write_bytes(out, node);
        }
    }

    fn encode(bundle: &TxReceiptProofBundle) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&bundle.chain_id.to_le_bytes());
        bytes.extend_from_slice(&(bundle.network.len() as u16).to_le_bytes());
        bytes.extend_from_slice(bundle.network.as_bytes());
        bytes.push(KIND_TX_RECEIPT_PROOF);
        bytes.extend_from_slice(&bundle.created_at_unix.to_le_bytes());
        bytes.extend_from_slice(&bundle.block_number.to_le_bytes());
        bytes.extend_from_slice(&bundle.block_hash);
        bytes.extend_from_slice(&bundle.tx_hash);
        bytes.extend_from_slice(&bundle.tx_index.to_le_bytes());
        write_bytes(&mut bytes, &bundle.raw_tx);
        write_bytes(&mut bytes, &bundle.receipt);
        bytes.extend_from_slice(&bundle.transactions_root);
        bytes.extend_from_slice(&bundle.receipts_root);
        write_nodes(&mut bytes, &bundle.tx_proof);
        write_nodes(&mut bytes, &bundle.receipt_proof);
        assert!(bytes.len() <= MAX_BUNDLE_BYTES);
        bytes
    }

    fn fixture(index: u64) -> (Vec<u8>, VerifiedExecutionBlock) {
        fixture_for_chain(index, SEPOLIA_CHAIN_ID)
    }

    fn fixture_for_chain(index: u64, chain_id: u64) -> (Vec<u8>, VerifiedExecutionBlock) {
        let transactions = vec![
            transaction_bytes_for_chain(1, chain_id),
            transaction_bytes_for_chain(2, chain_id),
        ];
        let receipts = vec![receipt_bytes(true, 21_000), receipt_bytes(false, 42_000)];
        let (transactions_root, tx_proof) = trie_root_and_proof(&transactions, index);
        let (receipts_root, receipt_proof) = trie_root_and_proof(&receipts, index);
        let raw_tx = transactions[index as usize].clone();
        let transaction = decode_transaction(&raw_tx).unwrap();
        let bundle = TxReceiptProofBundle {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            created_at_unix: 123,
            block_number: 456,
            block_hash: [0x44; 32],
            tx_hash: transaction.tx_hash().0,
            tx_index: index,
            raw_tx,
            receipt: receipts[index as usize].clone(),
            transactions_root,
            receipts_root,
            tx_proof,
            receipt_proof,
        };
        let header = VerifiedExecutionBlock {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            execution_block_number: bundle.block_number,
            execution_block_hash: bundle.block_hash,
            parent_hash: [0x43; 32],
            state_root: [0x33; 32],
            receipts_root,
            transactions_root,
            checkpoint_root: [0x66; 32],
            provenance: crate::ExecutionHeaderProvenance::HeliosFinalityUpdate,
            consensus_bundle_hash: [0x55; 32],
            proof_bundle_hash: [0x55; 32],
        };
        (encode(&bundle), header)
    }

    fn shared_anchor_fixture(chain_id: u64) -> (Vec<u8>, VerifiedEvmAnchor) {
        let definition = crate::chain_definition(chain_id).unwrap();
        let transactions = vec![transaction_bytes_for_chain(1, chain_id)];
        let receipts = vec![receipt_bytes(true, 21_000)];
        let (transactions_root, tx_proof) = trie_root_and_proof(&transactions, 0);
        let (receipts_root, receipt_proof) = trie_root_and_proof(&receipts, 0);
        let raw_tx = transactions[0].clone();
        let transaction = decode_transaction(&raw_tx).unwrap();
        let bundle = TxReceiptProofBundle {
            chain_id,
            network: definition.network.to_owned(),
            created_at_unix: 123,
            block_number: 456,
            block_hash: [0x44; 32],
            tx_hash: transaction.tx_hash().0,
            tx_index: 0,
            raw_tx,
            receipt: receipts[0].clone(),
            transactions_root,
            receipts_root,
            tx_proof,
            receipt_proof,
        };
        let assurance = match definition.family {
            crate::VerificationFamily::EthereumBeacon => crate::AnchorAssurance::EthereumFinalized,
            crate::VerificationFamily::OpStack => crate::AnchorAssurance::SequencerAuthenticated,
            crate::VerificationFamily::Nitro => crate::AnchorAssurance::RollupConfirmed,
        };
        let anchor = VerifiedEvmAnchor::new(
            chain_id,
            definition.network,
            bundle.block_number,
            bundle.block_hash,
            [0x43; 32],
            [0x33; 32],
            transactions_root,
            receipts_root,
            1_800_000_000,
            assurance,
            [0x55; 32],
        );
        (encode(&bundle), anchor)
    }

    #[test]
    fn shared_receipt_verifier_accepts_all_five_poc_networks() {
        for chain_id in [
            crate::ETHEREUM_SEPOLIA_CHAIN_ID,
            crate::BASE_SEPOLIA_CHAIN_ID,
            crate::OP_SEPOLIA_CHAIN_ID,
            crate::ARBITRUM_SEPOLIA_CHAIN_ID,
            crate::ROBINHOOD_TESTNET_CHAIN_ID,
        ] {
            let (bytes, anchor) = shared_anchor_fixture(chain_id);
            let verified = Verifier::for_chain(chain_id)
                .unwrap()
                .verify_tx_receipt_from_anchor(&bytes, &anchor)
                .unwrap();
            assert_eq!(verified.chain_id(), chain_id);
            assert!(verified.succeeded());
            assert_eq!(verified.tx_index(), 0);
        }
    }

    #[test]
    fn verifies_exact_successful_receipt() {
        let (bytes, header) = fixture(0);
        let verified = Verifier::sepolia()
            .verify_tx_receipt(&bytes, &header)
            .unwrap();
        assert!(verified.succeeded());
        assert_eq!(verified.cumulative_gas_used(), 21_000);
        assert_eq!(verified.tx_index(), 0);
        assert_eq!(verified.checkpoint_root(), [0x66; 32]);
        assert_eq!(
            verified.provenance(),
            crate::ExecutionHeaderProvenance::HeliosFinalityUpdate
        );
        assert_eq!(verified.consensus_bundle_hash(), [0x55; 32]);
        assert_eq!(verified.execution_header_proof_hash(), [0x55; 32]);
    }

    #[test]
    fn confirms_failed_transaction_as_failed() {
        let (bytes, header) = fixture(1);
        let verified = Verifier::sepolia()
            .verify_tx_receipt(&bytes, &header)
            .unwrap();
        assert!(!verified.succeeded());
        assert_eq!(verified.cumulative_gas_used(), 42_000);
    }

    #[test]
    fn rejects_receipt_against_different_consensus_root() {
        let (bytes, mut header) = fixture(0);
        header.receipts_root = [0xee; 32];
        assert!(matches!(
            Verifier::sepolia().verify_tx_receipt(&bytes, &header),
            Err(VerifyError::ReceiptHeaderMismatch)
        ));
    }

    #[test]
    fn rejects_receipt_proof_from_another_index() {
        let (first_bytes, header) = fixture(0);
        let (second_bytes, _) = fixture(1);
        let mut first = Verifier::sepolia()
            .parse_tx_receipt_proof(&first_bytes)
            .unwrap();
        let second = Verifier::sepolia()
            .parse_tx_receipt_proof(&second_bytes)
            .unwrap();
        first.receipt = second.receipt;
        first.receipt_proof = second.receipt_proof;
        assert!(matches!(
            Verifier::sepolia().verify_tx_receipt(&encode(&first), &header),
            Err(VerifyError::InvalidReceiptProof(_))
        ));
    }

    #[test]
    fn rejects_transaction_hash_metadata_mismatch() {
        let (bytes, header) = fixture(0);
        let mut bundle = Verifier::sepolia().parse_tx_receipt_proof(&bytes).unwrap();
        bundle.tx_hash = [0xaa; 32];
        assert!(matches!(
            Verifier::sepolia().verify_tx_receipt(&encode(&bundle), &header),
            Err(VerifyError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn rejects_transaction_signed_for_another_chain() {
        let (bytes, header) = fixture_for_chain(0, 1);
        assert!(matches!(
            Verifier::sepolia().verify_tx_receipt(&bytes, &header),
            Err(VerifyError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn rejects_trailing_receipt_bundle_bytes() {
        let (mut bytes, header) = fixture(0);
        bytes.push(0);
        assert!(matches!(
            Verifier::sepolia().verify_tx_receipt(&bytes, &header),
            Err(VerifyError::Malformed("trailing bytes"))
        ));
    }
}
