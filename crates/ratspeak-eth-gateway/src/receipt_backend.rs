//! Complete-block transaction and receipt proof construction.
//!
//! Execution JSON-RPC is only an untrusted byte source. The backend fetches
//! the consensus-anchored block and every receipt, reconstructs both ordered
//! tries locally, and retains only the requested transaction's proof.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{B256, keccak256};
use alloy_rpc_types_eth::{Block, TransactionReceipt};
use alloy_trie::proof::{ProofRetainer, verify_proof};
use alloy_trie::{HashBuilder, Nibbles};
use serde_json::{Value, json};

use crate::provider::{
    GatewayHttpTransport, HttpTransportFailure, ProviderHttpPolicy, parse_rpc_result_bounded,
};
use crate::{
    ExactReceiptProofBackend, GatewayProviderFailure, UntrustedReceiptLocation,
    UntrustedTxReceiptProofRpcInput,
};
use ratspeak_eth_verifier::{
    MAX_PROOF_NODE_BYTES, MAX_PROOF_NODES, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, chain_definition,
};

const MAX_BLOCK_TRANSACTIONS: usize = 2_048;
const MAX_TRANSACTION_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_BYTES: usize = 512 * 1024;
const MAX_TOTAL_TRIE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_RPC_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSON_VALUES_PER_RESPONSE: usize = 131_072;
const MAX_TOTAL_FETCH_TIME: Duration = Duration::from_secs(120);

/// Complete-block proof backend using standard execution JSON-RPC methods.
pub struct CompleteBlockReceiptProofBackend<T> {
    transport: T,
    policy: ProviderHttpPolicy,
    chain_id: u64,
    network: &'static str,
    next_rpc_id: u64,
}

impl<T> std::fmt::Debug for CompleteBlockReceiptProofBackend<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompleteBlockReceiptProofBackend")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<T> CompleteBlockReceiptProofBackend<T> {
    pub fn new(
        transport: T,
        policy: ProviderHttpPolicy,
    ) -> Result<Self, crate::ProviderConfigurationError> {
        Self::new_for_chain(
            transport,
            policy,
            SEPOLIA_CHAIN_ID,
            SEPOLIA_NETWORK,
        )
    }

    pub fn new_for_chain(
        transport: T,
        policy: ProviderHttpPolicy,
        chain_id: u64,
        network: &str,
    ) -> Result<Self, crate::ProviderConfigurationError> {
        let definition = chain_definition(chain_id)
            .ok_or(crate::ProviderConfigurationError::InvalidPolicy)?;
        if definition.network != network {
            return Err(crate::ProviderConfigurationError::InvalidPolicy);
        }
        Ok(Self {
            transport,
            policy: policy.validate()?,
            chain_id,
            network: definition.network,
            next_rpc_id: 1,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: GatewayHttpTransport> ExactReceiptProofBackend for CompleteBlockReceiptProofBackend<T> {
    fn fetch_receipt_location(
        &mut self,
        tx_hash: [u8; 32],
        _captured_at_unix: u64,
    ) -> Result<UntrustedReceiptLocation, GatewayProviderFailure> {
        let started = Instant::now();
        let mut response_bytes = 0_usize;
        let value = self.rpc_result(
            "eth_getTransactionReceipt",
            json!([data_hex(&tx_hash)]),
            started,
            &mut response_bytes,
        )?;
        if value.is_null() {
            return Err(GatewayProviderFailure::Transient);
        }
        let receipt = serde_json::from_value::<TransactionReceipt>(value)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        if receipt.transaction_hash != B256::from(tx_hash)
            || receipt.inner.logs().iter().any(|log| log.removed)
        {
            return Err(GatewayProviderFailure::Permanent);
        }
        let block_number = receipt
            .block_number
            .ok_or(GatewayProviderFailure::Transient)?;
        let block_hash = receipt
            .block_hash
            .ok_or(GatewayProviderFailure::Transient)?
            .0;
        Ok(UntrustedReceiptLocation {
            block_number,
            block_hash,
        })
    }

    fn fetch_exact_receipt_proof(
        &mut self,
        tx_hash: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        captured_at_unix: u64,
    ) -> Result<UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
        let started = Instant::now();
        let mut response_bytes = 0_usize;
        let block_value = self.rpc_result(
            "eth_getBlockByHash",
            json!([data_hex(&execution_block_hash), true]),
            started,
            &mut response_bytes,
        )?;
        if block_value.is_null() {
            return Err(GatewayProviderFailure::Transient);
        }
        let block = serde_json::from_value::<Block>(block_value)
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        validate_header(&block, execution_block_number, execution_block_hash)?;
        let expected_gas_used = block.header.inner.gas_used;
        let expected_transactions_root = block.header.inner.transactions_root;
        let expected_receipts_root = block.header.inner.receipts_root;
        let transactions = block
            .try_into_transactions()
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        if transactions.is_empty() || transactions.len() > MAX_BLOCK_TRANSACTIONS {
            return Err(GatewayProviderFailure::Permanent);
        }

        let mut raw_transactions = Vec::with_capacity(transactions.len());
        let mut transaction_hashes = HashSet::with_capacity(transactions.len());
        let mut target_index = None;
        let mut total_trie_bytes = 0_usize;
        for (index, transaction) in transactions.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| GatewayProviderFailure::Permanent)?;
            if transaction.block_hash != Some(B256::from(execution_block_hash))
                || transaction.block_number != Some(execution_block_number)
                || transaction.transaction_index != Some(index)
            {
                return Err(GatewayProviderFailure::Permanent);
            }
            let raw = transaction.as_ref().encoded_2718();
            if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
                return Err(GatewayProviderFailure::Permanent);
            }
            let local_hash = keccak256(&raw).0;
            if transaction.as_ref().tx_hash().0 != local_hash {
                return Err(GatewayProviderFailure::Permanent);
            }
            if !transaction_hashes.insert(local_hash) {
                return Err(GatewayProviderFailure::Permanent);
            }
            if local_hash == tx_hash && target_index.replace(index).is_some() {
                return Err(GatewayProviderFailure::Permanent);
            }
            total_trie_bytes = bounded_add(total_trie_bytes, raw.len(), MAX_TOTAL_TRIE_BYTES)?;
            raw_transactions.push(raw);
        }
        let target_index = target_index.ok_or(GatewayProviderFailure::Permanent)?;

        let mut receipts = Vec::with_capacity(raw_transactions.len());
        let mut previous_cumulative_gas = 0_u64;
        for (index, raw_tx) in raw_transactions.iter().enumerate() {
            let index_u64 = u64::try_from(index).map_err(|_| GatewayProviderFailure::Permanent)?;
            let hash = keccak256(raw_tx);
            let receipt_value = self.rpc_result(
                "eth_getTransactionReceipt",
                json!([data_hex(hash.as_slice())]),
                started,
                &mut response_bytes,
            )?;
            if receipt_value.is_null() {
                return Err(GatewayProviderFailure::Transient);
            }
            let receipt = serde_json::from_value::<TransactionReceipt>(receipt_value)
                .map_err(|_| GatewayProviderFailure::Permanent)?;
            validate_receipt_metadata(
                &receipt,
                hash,
                index_u64,
                execution_block_number,
                execution_block_hash,
            )?;
            if receipt.inner.tx_type() != transactions[index].as_ref().tx_type() {
                return Err(GatewayProviderFailure::Permanent);
            }
            let cumulative_gas = receipt.inner.cumulative_gas_used();
            if cumulative_gas < previous_cumulative_gas || cumulative_gas > expected_gas_used {
                return Err(GatewayProviderFailure::Permanent);
            }
            previous_cumulative_gas = cumulative_gas;
            let raw = receipt.into_primitives_receipt().inner.encoded_2718();
            if raw.is_empty() || raw.len() > MAX_RECEIPT_BYTES {
                return Err(GatewayProviderFailure::Permanent);
            }
            total_trie_bytes = bounded_add(total_trie_bytes, raw.len(), MAX_TOTAL_TRIE_BYTES)?;
            receipts.push(raw);
        }
        if previous_cumulative_gas != expected_gas_used {
            return Err(GatewayProviderFailure::Permanent);
        }

        let (transactions_root, tx_proof) = trie_root_and_proof(&raw_transactions, target_index)?;
        let (receipts_root, receipt_proof) = trie_root_and_proof(&receipts, target_index)?;
        if transactions_root != expected_transactions_root.0
            || receipts_root != expected_receipts_root.0
        {
            return Err(GatewayProviderFailure::Permanent);
        }

        Ok(UntrustedTxReceiptProofRpcInput {
            chain_id: self.chain_id,
            network: self.network.to_owned(),
            captured_at_unix,
            block_number: execution_block_number,
            block_hash: execution_block_hash,
            tx_hash,
            tx_index: target_index,
            raw_tx: raw_transactions[target_index as usize].clone(),
            receipt: receipts[target_index as usize].clone(),
            transactions_root,
            receipts_root,
            tx_proof,
            receipt_proof,
        })
    }
}

impl<T: GatewayHttpTransport> CompleteBlockReceiptProofBackend<T> {
    fn rpc_result(
        &mut self,
        method: &'static str,
        params: Value,
        started: Instant,
        total_response_bytes: &mut usize,
    ) -> Result<Value, GatewayProviderFailure> {
        let remaining = MAX_TOTAL_FETCH_TIME
            .checked_sub(started.elapsed())
            .ok_or(GatewayProviderFailure::Transient)?;
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(1);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .transport
            .post_json(
                &body,
                self.policy.maximum_json_response_bytes,
                self.policy.request_timeout.min(remaining),
            )
            .map_err(map_transport_failure)?;
        if response.body().len() > self.policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        *total_response_bytes = bounded_add(
            *total_response_bytes,
            response.body().len(),
            MAX_TOTAL_RPC_RESPONSE_BYTES,
        )?;
        if started.elapsed() >= MAX_TOTAL_FETCH_TIME {
            return Err(GatewayProviderFailure::Transient);
        }
        match response.status() {
            200..=299 => {
                parse_rpc_result_bounded(response.body(), id, MAX_JSON_VALUES_PER_RESPONSE)
            }
            408 | 425 | 429 | 500..=599 => Err(GatewayProviderFailure::Transient),
            _ => Err(GatewayProviderFailure::Permanent),
        }
    }
}

fn validate_header(
    block: &Block,
    expected_number: u64,
    expected_hash: [u8; 32],
) -> Result<(), GatewayProviderFailure> {
    let expected_hash = B256::from(expected_hash);
    if block.header.hash != expected_hash
        || block.header.inner.hash_slow() != expected_hash
        || block.header.inner.number != expected_number
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn validate_receipt_metadata(
    receipt: &TransactionReceipt,
    expected_tx_hash: B256,
    expected_index: u64,
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
) -> Result<(), GatewayProviderFailure> {
    let expected_block_hash = B256::from(expected_block_hash);
    if receipt.transaction_hash != expected_tx_hash
        || receipt.transaction_index != Some(expected_index)
        || receipt.block_number != Some(expected_block_number)
        || receipt.block_hash != Some(expected_block_hash)
        || receipt.inner.logs().iter().any(|log| {
            log.removed
                || log
                    .block_hash
                    .is_some_and(|hash| hash != expected_block_hash)
                || log
                    .block_number
                    .is_some_and(|number| number != expected_block_number)
                || log
                    .transaction_hash
                    .is_some_and(|hash| hash != expected_tx_hash)
                || log
                    .transaction_index
                    .is_some_and(|index| index != expected_index)
        })
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn trie_root_and_proof(
    values: &[Vec<u8>],
    target_index: u64,
) -> Result<([u8; 32], Vec<Vec<u8>>), GatewayProviderFailure> {
    let target = Nibbles::unpack(alloy_rlp::encode(target_index));
    let mut entries = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let index = u64::try_from(index).map_err(|_| GatewayProviderFailure::Permanent)?;
            Ok((Nibbles::unpack(alloy_rlp::encode(index)), value.as_slice()))
        })
        .collect::<Result<Vec<_>, GatewayProviderFailure>>()?;
    entries.sort_unstable_by_key(|(key, _)| *key);
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![target]));
    for (key, value) in entries {
        builder.add_leaf(key, value);
    }
    let root = builder.root();
    let proof_nodes = builder
        .take_proof_nodes()
        .matching_nodes_sorted(&target)
        .into_iter()
        .map(|(_, node)| node)
        .collect::<Vec<_>>();
    if proof_nodes.is_empty()
        || proof_nodes.len() > MAX_PROOF_NODES
        || proof_nodes
            .iter()
            .any(|node| node.is_empty() || node.len() > MAX_PROOF_NODE_BYTES)
    {
        return Err(GatewayProviderFailure::Permanent);
    }
    verify_proof(
        root,
        target,
        Some(values[target_index as usize].clone()),
        proof_nodes.iter(),
    )
    .map_err(|_| GatewayProviderFailure::Permanent)?;
    let proof = proof_nodes.into_iter().map(|node| node.to_vec()).collect();
    Ok((root.0, proof))
}

fn bounded_add(
    current: usize,
    added: usize,
    maximum: usize,
) -> Result<usize, GatewayProviderFailure> {
    current
        .checked_add(added)
        .filter(|total| *total <= maximum)
        .ok_or(GatewayProviderFailure::Permanent)
}

fn map_transport_failure(failure: HttpTransportFailure) -> GatewayProviderFailure {
    match failure {
        HttpTransportFailure::Transient => GatewayProviderFailure::Transient,
        HttpTransportFailure::Permanent | HttpTransportFailure::Oversized => {
            GatewayProviderFailure::Permanent
        }
    }
}

fn data_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use alloy_consensus::transaction::{Recovered, SignerRecoverable};
    use alloy_consensus::{
        Receipt, ReceiptEnvelope, ReceiptWithBloom, SignableTransaction, TxEip1559, TxEnvelope,
    };
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::{Address, Signature, U256};
    use alloy_rpc_types_eth::{Header as RpcHeader, Transaction as RpcTransaction};

    use super::*;
    use crate::provider::GatewayHttpResponse;

    const BLOCK_NUMBER: u64 = 8_765_432;
    const CAPTURED_AT: u64 = 1_800_000_000;

    #[derive(Debug)]
    struct MockTransport {
        replies: VecDeque<GatewayHttpResponse>,
        methods: Vec<String>,
    }

    impl GatewayHttpTransport for MockTransport {
        fn post_json(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
            _timeout: Duration,
        ) -> Result<GatewayHttpResponse, HttpTransportFailure> {
            let request: Value = serde_json::from_slice(body).unwrap();
            self.methods
                .push(request["method"].as_str().unwrap().to_owned());
            self.replies
                .pop_front()
                .ok_or(HttpTransportFailure::Permanent)
        }
    }

    struct Fixture {
        block: Value,
        receipts: Vec<Value>,
        block_hash: [u8; 32],
        tx_hashes: Vec<[u8; 32]>,
    }

    impl Fixture {
        fn new(statuses: &[bool]) -> Self {
            let mut transactions = Vec::new();
            let mut receipt_objects = Vec::new();
            let mut raw_transactions = Vec::new();
            let mut raw_receipts = Vec::new();
            let mut cumulative_gas = 0_u64;

            for (index, status) in statuses.iter().copied().enumerate() {
                let envelope = TxEnvelope::Eip1559(
                    TxEip1559 {
                        chain_id: SEPOLIA_CHAIN_ID,
                        nonce: index as u64,
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
                let signer = envelope.recover_signer().unwrap();
                let raw_tx = envelope.encoded_2718();
                let tx_hash = keccak256(&raw_tx);
                raw_transactions.push(raw_tx);
                transactions.push(RpcTransaction {
                    inner: Recovered::new_unchecked(envelope, signer),
                    block_hash: None,
                    block_number: Some(BLOCK_NUMBER),
                    transaction_index: Some(index as u64),
                    effective_gas_price: Some(3),
                });

                cumulative_gas += 21_000;
                let inner = ReceiptEnvelope::Eip1559(ReceiptWithBloom {
                    receipt: Receipt {
                        status: status.into(),
                        cumulative_gas_used: cumulative_gas,
                        logs: vec![],
                    },
                    logs_bloom: [0; 256].into(),
                });
                raw_receipts.push(inner.encoded_2718());
                receipt_objects.push(TransactionReceipt {
                    inner,
                    transaction_hash: tx_hash,
                    transaction_index: Some(index as u64),
                    block_hash: None,
                    block_number: Some(BLOCK_NUMBER),
                    gas_used: 21_000,
                    effective_gas_price: 3,
                    blob_gas_used: None,
                    blob_gas_price: None,
                    from: signer,
                    to: Some(Address::repeat_byte(0x22)),
                    contract_address: None,
                });
            }
            let (transactions_root, _) = trie_root_and_proof(&raw_transactions, 0).unwrap();
            let (receipts_root, _) = trie_root_and_proof(&raw_receipts, 0).unwrap();
            let header = alloy_consensus::Header {
                transactions_root: transactions_root.into(),
                receipts_root: receipts_root.into(),
                number: BLOCK_NUMBER,
                gas_limit: 30_000_000,
                gas_used: cumulative_gas,
                base_fee_per_gas: Some(1),
                ..Default::default()
            };
            let block_hash = header.hash_slow();
            for transaction in &mut transactions {
                transaction.block_hash = Some(block_hash);
            }
            for receipt in &mut receipt_objects {
                receipt.block_hash = Some(block_hash);
            }
            let tx_hashes = raw_transactions
                .iter()
                .map(|raw| keccak256(raw).0)
                .collect();
            let block = Block::new(
                RpcHeader {
                    hash: block_hash,
                    inner: header,
                    total_difficulty: None,
                    size: None,
                },
                transactions.into(),
            );
            Self {
                block: serde_json::to_value(block).unwrap(),
                receipts: receipt_objects
                    .into_iter()
                    .map(|receipt| serde_json::to_value(receipt).unwrap())
                    .collect(),
                block_hash: block_hash.0,
                tx_hashes,
            }
        }

        fn backend(&self) -> CompleteBlockReceiptProofBackend<MockTransport> {
            let mut replies = VecDeque::new();
            replies.push_back(reply(1, self.block.clone()));
            for (offset, receipt) in self.receipts.iter().cloned().enumerate() {
                replies.push_back(reply((offset + 2) as u64, receipt));
            }
            CompleteBlockReceiptProofBackend::new(
                MockTransport {
                    replies,
                    methods: Vec::new(),
                },
                ProviderHttpPolicy::conservative(),
            )
            .unwrap()
        }

        fn fetch(
            &self,
            target: usize,
        ) -> Result<UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
            self.backend().fetch_exact_receipt_proof(
                self.tx_hashes[target],
                BLOCK_NUMBER,
                self.block_hash,
                CAPTURED_AT,
            )
        }
    }

    fn reply(id: u64, result: Value) -> GatewayHttpResponse {
        GatewayHttpResponse::new(
            200,
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap(),
        )
    }

    #[test]
    fn reconstructs_both_roots_and_exact_target_proof() {
        let fixture = Fixture::new(&[true, false]);
        let input = fixture.fetch(1).unwrap();
        assert_eq!(input.tx_hash, fixture.tx_hashes[1]);
        assert_eq!(input.tx_index, 1);
        assert_eq!(input.block_hash, fixture.block_hash);
        assert!(!input.tx_proof.is_empty());
        assert!(!input.receipt_proof.is_empty());
        let mut receipt = input.receipt.as_slice();
        let decoded = ReceiptEnvelope::decode_2718(&mut receipt).unwrap();
        assert!(!decoded.status());
        assert!(receipt.is_empty());
    }

    #[test]
    fn receipt_location_is_only_an_exact_hash_bound_hint() {
        let fixture = Fixture::new(&[true]);
        let mut backend = CompleteBlockReceiptProofBackend::new(
            MockTransport {
                replies: VecDeque::from([reply(1, fixture.receipts[0].clone())]),
                methods: Vec::new(),
            },
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let location = backend
            .fetch_receipt_location(fixture.tx_hashes[0], CAPTURED_AT)
            .unwrap();
        assert_eq!(location.block_number, BLOCK_NUMBER);
        assert_eq!(location.block_hash, fixture.block_hash);
        assert_eq!(
            backend.transport.methods,
            vec!["eth_getTransactionReceipt".to_owned()]
        );

        let mut wrong = fixture.receipts[0].clone();
        wrong["transactionHash"] = Value::String(data_hex(&[0x99; 32]));
        let mut backend = CompleteBlockReceiptProofBackend::new(
            MockTransport {
                replies: VecDeque::from([reply(1, wrong)]),
                methods: Vec::new(),
            },
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            backend.fetch_receipt_location(fixture.tx_hashes[0], CAPTURED_AT),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn successful_receipt_is_preserved_exactly() {
        let input = Fixture::new(&[true]).fetch(0).unwrap();
        let mut receipt = input.receipt.as_slice();
        assert!(ReceiptEnvelope::decode_2718(&mut receipt).unwrap().status());
    }

    #[test]
    fn rejects_receipt_for_another_transaction_or_reordered_reply() {
        let fixture = Fixture::new(&[true, false]);
        let mut backend = fixture.backend();
        backend.transport.replies.swap(1, 2);
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn rejects_missing_receipt_and_partial_full_block() {
        let fixture = Fixture::new(&[true, false]);
        let mut backend = fixture.backend();
        backend.transport.replies[1] = reply(2, Value::Null);
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Transient)
        );

        let mut fixture = Fixture::new(&[true, false]);
        fixture.block["transactions"].as_array_mut().unwrap().pop();
        assert_eq!(fixture.fetch(0), Err(GatewayProviderFailure::Permanent));
    }

    #[test]
    fn rejects_header_root_and_reorg_metadata_mismatches() {
        let mut fixture = Fixture::new(&[true]);
        fixture.block["transactionsRoot"] = Value::String(data_hex(&[0x44; 32]));
        assert_eq!(fixture.fetch(0), Err(GatewayProviderFailure::Permanent));

        let mut fixture = Fixture::new(&[true]);
        fixture.receipts[0]["blockHash"] = Value::String(data_hex(&[0x55; 32]));
        assert_eq!(fixture.fetch(0), Err(GatewayProviderFailure::Permanent));
    }

    #[test]
    fn rejects_wrong_response_correlation_and_duplicate_json_names() {
        let fixture = Fixture::new(&[true]);
        let mut backend = fixture.backend();
        backend.transport.replies[0] = reply(99, fixture.block.clone());
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Permanent)
        );

        let mut backend = fixture.backend();
        backend.transport.replies[0] = GatewayHttpResponse::new(
            200,
            br#"{"jsonrpc":"2.0","id":1,"id":1,"result":null}"#.to_vec(),
        );
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Transient)
        );
    }

    #[test]
    fn rejects_oversized_and_deeply_malformed_responses() {
        let fixture = Fixture::new(&[true]);
        let mut backend = fixture.backend();
        backend.policy.maximum_json_response_bytes = 8;
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Permanent)
        );

        let mut nested = Value::Null;
        for _ in 0..20 {
            nested = json!([nested]);
        }
        let mut backend = fixture.backend();
        backend.transport.replies[0] = reply(1, nested);
        assert_eq!(
            backend.fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            ),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn uses_only_fixed_rpc_methods() {
        let fixture = Fixture::new(&[true, true]);
        let mut backend = fixture.backend();
        backend
            .fetch_exact_receipt_proof(
                fixture.tx_hashes[0],
                BLOCK_NUMBER,
                fixture.block_hash,
                CAPTURED_AT,
            )
            .unwrap();
        assert_eq!(
            backend.transport.methods,
            [
                "eth_getBlockByHash",
                "eth_getTransactionReceipt",
                "eth_getTransactionReceipt"
            ]
        );
    }

    #[test]
    fn rejects_unsupported_transaction_and_receipt_envelopes() {
        let mut fixture = Fixture::new(&[true]);
        fixture.block["transactions"][0]["type"] = Value::String("0x7f".to_owned());
        assert_eq!(fixture.fetch(0), Err(GatewayProviderFailure::Permanent));

        let mut fixture = Fixture::new(&[true]);
        fixture.receipts[0]["type"] = Value::String("0x7f".to_owned());
        assert_eq!(fixture.fetch(0), Err(GatewayProviderFailure::Permanent));
    }

    #[test]
    fn aggregate_bounds_fail_closed() {
        assert_eq!(
            bounded_add(MAX_TOTAL_TRIE_BYTES, 1, MAX_TOTAL_TRIE_BYTES),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            bounded_add(usize::MAX, 1, usize::MAX),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn realistic_full_block_exceeding_shared_json_limit_is_supported() {
        let fixture = Fixture::new(&vec![true; 300]);
        let input = fixture.fetch(299).unwrap();
        assert_eq!(input.tx_index, 299);
        assert_eq!(input.tx_hash, fixture.tx_hashes[299]);
    }
}
