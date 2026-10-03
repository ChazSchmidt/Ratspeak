use alloy_consensus::{ReceiptEnvelope, TxReceipt};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, keccak256};

use super::{
    AnchorAssurance, ETHEREUM_SEPOLIA_CHAIN_ID, Result, StackConfig, VerifiedEvmAnchor,
    VerifyError, Verifier, chain_definition,
};
use crate::execution::decode_header;

const MAX_NITRO_ANCESTRY_HEADERS: usize = 8_192;

/// L2 block hash authenticated by an AssertionConfirmed event in a receipt
/// already proven against a finalized Ethereum Sepolia anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NitroConfirmedEndpoint {
    chain_id: u64,
    network: &'static str,
    assertion_hash: [u8; 32],
    block_hash: [u8; 32],
    send_root: [u8; 32],
    l1_receipt_proof_hash: [u8; 32],
}

impl NitroConfirmedEndpoint {
    pub fn from_l1_receipt_proof(
        l2_chain_id: u64,
        l1_receipt_proof: &[u8],
        l1_anchor: &VerifiedEvmAnchor,
    ) -> Result<Self> {
        let definition = chain_definition(l2_chain_id).ok_or_else(|| VerifyError::UnsupportedNetwork {
            chain_id: l2_chain_id,
            network: "unknown".to_owned(),
        })?;
        let StackConfig::Nitro(config) = definition.stack else {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: l2_chain_id,
                network: definition.network.to_owned(),
            });
        };
        if definition.parent_chain_id != Some(ETHEREUM_SEPOLIA_CHAIN_ID)
            || l1_anchor.chain_id() != ETHEREUM_SEPOLIA_CHAIN_ID
        {
            return Err(VerifyError::CheckpointMismatch);
        }

        let verifier = Verifier::sepolia();
        let verified = verifier.verify_tx_receipt_from_anchor(l1_receipt_proof, l1_anchor)?;
        let parsed = verifier.parse_tx_receipt_proof(l1_receipt_proof)?;

        let mut remaining = parsed.receipt.as_slice();
        let receipt = ReceiptEnvelope::decode_2718(&mut remaining)
            .map_err(|error| VerifyError::InvalidReceiptProof(error.to_string()))?;
        if !remaining.is_empty() {
            return Err(VerifyError::Malformed("trailing Nitro L1 receipt bytes"));
        }

        let event_topic = keccak256(b"AssertionConfirmed(bytes32,bytes32,bytes32)");
        for log in receipt.logs() {
            let topics = log.data.topics();
            if log.address != config.rollup
                || topics.len() != 2
                || topics[0] != event_topic
                || log.data.data.len() != 64
            {
                continue;
            }

            let mut assertion_hash = [0u8; 32];
            assertion_hash.copy_from_slice(topics[1].as_slice());
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&log.data.data[..32]);
            let mut send_root = [0u8; 32];
            send_root.copy_from_slice(&log.data.data[32..64]);

            return Ok(Self {
                chain_id: l2_chain_id,
                network: definition.network,
                assertion_hash,
                block_hash,
                send_root,
                l1_receipt_proof_hash: verified.proof_bundle_hash(),
            });
        }

        Err(VerifyError::InvalidReceiptProof(
            "verified L1 receipt does not contain the expected Nitro AssertionConfirmed event"
                .to_owned(),
        ))
    }

    pub fn chain_id(&self) -> u64 { self.chain_id }
    pub fn network(&self) -> &'static str { self.network }
    pub fn assertion_hash(&self) -> [u8; 32] { self.assertion_hash }
    pub fn block_hash(&self) -> [u8; 32] { self.block_hash }
    pub fn send_root(&self) -> [u8; 32] { self.send_root }
    pub fn l1_receipt_proof_hash(&self) -> [u8; 32] { self.l1_receipt_proof_hash }

    /// Authenticates the confirmed endpoint header and, optionally, walks
    /// contiguous parent headers down to an earlier target block.
    ///
    /// The header walk is deliberately simple for the PoC. BoLD history-root
    /// inclusion proofs can later replace long ancestry lists without changing
    /// the shared VerifiedEvmAnchor API.
    pub fn verify_target_header(
        &self,
        confirmed_header_rlp: &[u8],
        ancestry_headers: &[Vec<u8>],
    ) -> Result<VerifiedEvmAnchor> {
        if ancestry_headers.len() > MAX_NITRO_ANCESTRY_HEADERS {
            return Err(VerifyError::TooManyAncestryHeaders);
        }

        let confirmed = decode_header(confirmed_header_rlp)?;
        if confirmed.hash_slow().0 != self.block_hash {
            return Err(VerifyError::ExecutionHeaderMismatch);
        }

        let mut target = confirmed.clone();
        let mut expected_hash = confirmed.parent_hash.0;
        let mut expected_number = confirmed.number;

        for rlp in ancestry_headers {
            expected_number = expected_number
                .checked_sub(1)
                .ok_or(VerifyError::InvalidExecutionAncestry)?;
            let header = decode_header(rlp)?;
            if header.hash_slow().0 != expected_hash || header.number != expected_number {
                return Err(VerifyError::InvalidExecutionAncestry);
            }
            expected_hash = header.parent_hash.0;
            target = header;
        }

        let mut evidence = Vec::with_capacity(64 + ancestry_headers.len() * 32);
        evidence.extend_from_slice(&self.l1_receipt_proof_hash);
        evidence.extend_from_slice(&self.assertion_hash);
        evidence.extend_from_slice(&self.block_hash);
        for rlp in ancestry_headers {
            evidence.extend_from_slice(keccak256(rlp).as_slice());
        }

        Ok(VerifiedEvmAnchor::new(
            self.chain_id,
            self.network,
            target.number,
            target.hash_slow().0,
            target.parent_hash.0,
            target.state_root.0,
            target.transactions_root.0,
            target.receipts_root.0,
            target.timestamp,
            AnchorAssurance::RollupConfirmed,
            keccak256(evidence).0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ARBITRUM_SEPOLIA_CHAIN_ID, ROBINHOOD_TESTNET_CHAIN_ID};

    #[test]
    fn generic_nitro_backend_covers_both_poc_chains() {
        for chain_id in [ARBITRUM_SEPOLIA_CHAIN_ID, ROBINHOOD_TESTNET_CHAIN_ID] {
            let definition = chain_definition(chain_id).unwrap();
            assert!(matches!(definition.stack, StackConfig::Nitro(_)));
            assert_eq!(definition.parent_chain_id, Some(ETHEREUM_SEPOLIA_CHAIN_ID));
        }
    }
}
