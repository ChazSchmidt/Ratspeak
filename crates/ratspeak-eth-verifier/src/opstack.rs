use alloy_primitives::{Address, B256, b256, keccak256};
use helios_opstack::{SequencerCommitment, types::ExecutionPayload};

use super::{
    AnchorAssurance, ETHEREUM_SEPOLIA_CHAIN_ID, ETHEREUM_SEPOLIA, Result, StackConfig,
    VerifiedEvmAnchor, VerifiedStorageValue, VerifyError, chain_definition,
};
use crate::execution::decode_header;

const UNSAFE_SIGNER_SLOT: B256 =
    b256!("65a7ed542fb37fe237fdfbdd70b31598523fe5b32879e307bae27a0bd9581c08");

/// OP-Stack execution head authenticated by a sequencer signature whose signer
/// was independently proven from the chain's L1 SystemConfig storage.
///
/// This intentionally represents the fast unsafe/sequencer-authenticated path.
/// It must not be presented as L1-derived safe or finalized state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpStackSequencerAnchor {
    chain_id: u64,
    network: &'static str,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    timestamp: u64,
    sequencer_signer: [u8; 20],
    signer_storage_proof_hash: [u8; 32],
    sequencer_commitment_hash: [u8; 32],
}

impl OpStackSequencerAnchor {
    pub fn verify(
        chain_id: u64,
        compressed_commitment: &[u8],
        verified_signer_storage: &VerifiedStorageValue,
    ) -> Result<Self> {
        let definition = chain_definition(chain_id).ok_or_else(|| VerifyError::UnsupportedNetwork {
            chain_id,
            network: "unknown".to_owned(),
        })?;
        let StackConfig::OpStack(config) = definition.stack else {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id,
                network: definition.network.to_owned(),
            });
        };
        if definition.parent_chain_id != Some(ETHEREUM_SEPOLIA_CHAIN_ID)
            || verified_signer_storage.chain_id() != ETHEREUM_SEPOLIA_CHAIN_ID
            || verified_signer_storage.network() != ETHEREUM_SEPOLIA.network
            || verified_signer_storage.account_address() != config.system_config.0
            || B256::from(verified_signer_storage.key()) != UNSAFE_SIGNER_SLOT
        {
            return Err(VerifyError::CheckpointMismatch);
        }

        let signer_bytes = verified_signer_storage.value().to_be_bytes::<32>();
        let signer = Address::from_slice(&signer_bytes[12..]);
        if signer == Address::ZERO {
            return Err(VerifyError::Malformed("OP-Stack sequencer signer is zero"));
        }

        let commitment = SequencerCommitment::new(compressed_commitment)
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack sequencer commitment"))?;
        commitment
            .verify(signer, chain_id)
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack sequencer signature"))?;
        let payload = ExecutionPayload::try_from(&commitment)
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack execution payload"))?;

        Ok(Self {
            chain_id,
            network: definition.network,
            block_number: payload.block_number,
            block_hash: payload.block_hash.0,
            state_root: payload.state_root.0,
            receipts_root: payload.receipts_root.0,
            timestamp: payload.timestamp,
            sequencer_signer: signer.0,
            signer_storage_proof_hash: verified_signer_storage.proof_bundle_hash(),
            sequencer_commitment_hash: keccak256(compressed_commitment).0,
        })
    }

    pub fn chain_id(&self) -> u64 { self.chain_id }
    pub fn network(&self) -> &'static str { self.network }
    pub fn block_number(&self) -> u64 { self.block_number }
    pub fn block_hash(&self) -> [u8; 32] { self.block_hash }
    pub fn state_root(&self) -> [u8; 32] { self.state_root }
    pub fn receipts_root(&self) -> [u8; 32] { self.receipts_root }
    pub fn timestamp(&self) -> u64 { self.timestamp }
    pub fn sequencer_signer(&self) -> [u8; 20] { self.sequencer_signer }
    pub fn signer_storage_proof_hash(&self) -> [u8; 32] { self.signer_storage_proof_hash }
    pub fn sequencer_commitment_hash(&self) -> [u8; 32] { self.sequencer_commitment_hash }

    pub fn verify_rlp_header(&self, rlp_header: &[u8]) -> Result<VerifiedEvmAnchor> {
        let header = decode_header(rlp_header)?;
        if header.number != self.block_number
            || header.hash_slow().0 != self.block_hash
            || header.state_root.0 != self.state_root
            || header.receipts_root.0 != self.receipts_root
            || header.timestamp != self.timestamp
        {
            return Err(VerifyError::ExecutionHeaderMismatch);
        }

        Ok(VerifiedEvmAnchor::new(
            self.chain_id,
            self.network,
            header.number,
            self.block_hash,
            header.parent_hash.0,
            header.state_root.0,
            header.transactions_root.0,
            header.receipts_root.0,
            header.timestamp,
            AnchorAssurance::SequencerAuthenticated,
            self.sequencer_commitment_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BASE_SEPOLIA_CHAIN_ID, OP_SEPOLIA_CHAIN_ID};

    #[test]
    fn generic_backend_accepts_both_builtin_op_stack_chains() {
        for chain_id in [BASE_SEPOLIA_CHAIN_ID, OP_SEPOLIA_CHAIN_ID] {
            let definition = chain_definition(chain_id).unwrap();
            assert!(matches!(definition.stack, StackConfig::OpStack(_)));
            assert_eq!(definition.parent_chain_id, Some(ETHEREUM_SEPOLIA_CHAIN_ID));
        }
    }
}
