use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use ssz_derive::Decode;
use ssz::Decode as _;
use ssz_types::{FixedVector, VariableList};

use super::{
    AnchorAssurance, ETHEREUM_SEPOLIA_CHAIN_ID, ETHEREUM_SEPOLIA, Result, StackConfig,
    VerifiedEvmAnchor, VerifiedStorageValue, VerifyError, chain_definition,
};
use crate::execution::decode_header;

const UNSAFE_SIGNER_SLOT: B256 = B256::new([
    0x65, 0xa7, 0xed, 0x54, 0x2f, 0xb3, 0x7f, 0xe2,
    0x37, 0xfd, 0xfb, 0xdd, 0x70, 0xb3, 0x15, 0x98,
    0x52, 0x3f, 0xe5, 0xb3, 0x28, 0x79, 0xe3, 0x07,
    0xba, 0xe2, 0x7a, 0x0b, 0xd9, 0x58, 0x1c, 0x08,
]);

#[derive(Debug, Clone, Decode)]
struct OpExecutionPayload {
    parent_hash: B256,
    fee_recipient: Address,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: FixedVector<u8, typenum::U256>,
    prev_randao: B256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: VariableList<u8, typenum::U32>,
    base_fee_per_gas: U256,
    block_hash: B256,
    transactions: VariableList<VariableList<u8, typenum::U1073741824>, typenum::U1048576>,
    withdrawals: VariableList<OpWithdrawal, typenum::U16>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    withdrawals_root: B256,
}

#[derive(Debug, Clone, Decode)]
struct OpWithdrawal {
    index: u64,
    validator_index: u64,
    address: Address,
    amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpStackSignerProofQuery {
    pub parent_chain_id: u64,
    pub system_config: Address,
    pub storage_key: B256,
}

/// OP-Stack execution head authenticated by a sequencer signature whose signer
/// was independently proven from the chain's L1 SystemConfig storage.
///
/// The online agent may decompress the wire commitment before sending it over
/// RatSpeak. Decompression is not trusted: the phone verifies the sequencer
/// signature over the exact decompressed commitment data.
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
    pub fn signer_proof_query(chain_id: u64) -> Result<OpStackSignerProofQuery> {
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
        let parent_chain_id = definition
            .parent_chain_id
            .ok_or(VerifyError::CheckpointMismatch)?;
        Ok(OpStackSignerProofQuery {
            parent_chain_id,
            system_config: config.system_config,
            storage_key: UNSAFE_SIGNER_SLOT,
        })
    }

    /// Verifies a decompressed Helios-compatible OP Stack commitment:
    /// 65-byte ECDSA signature followed by signed data. The signed data begins
    /// with a 32-byte commitment prefix followed by the SSZ execution payload.
    pub fn verify(
        chain_id: u64,
        decompressed_commitment: &[u8],
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
        if decompressed_commitment.len() <= 65 + 32 {
            return Err(VerifyError::Malformed("OP-Stack sequencer commitment is too short"));
        }

        let signer_bytes = verified_signer_storage.value().to_be_bytes::<32>();
        let expected_signer = Address::from_slice(&signer_bytes[12..]);
        if expected_signer == Address::ZERO {
            return Err(VerifyError::Malformed("OP-Stack sequencer signer is zero"));
        }

        let signature = Signature::try_from(&decompressed_commitment[..65])
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack sequencer signature"))?;
        let signed_data = &decompressed_commitment[65..];
        let message_hash = op_signature_hash(signed_data, chain_id);
        let recovered = signature
            .recover_address_from_prehash(&message_hash)
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack sequencer signature"))?;
        if recovered != expected_signer {
            return Err(VerifyError::Malformed("OP-Stack sequencer signer mismatch"));
        }

        let payload = OpExecutionPayload::from_ssz_bytes(&signed_data[32..])
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack execution payload"))?;

        Ok(Self {
            chain_id,
            network: definition.network,
            block_number: payload.block_number,
            block_hash: payload.block_hash.0,
            state_root: payload.state_root.0,
            receipts_root: payload.receipts_root.0,
            timestamp: payload.timestamp,
            sequencer_signer: expected_signer.0,
            signer_storage_proof_hash: verified_signer_storage.proof_bundle_hash(),
            sequencer_commitment_hash: keccak256(decompressed_commitment).0,
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

fn op_signature_hash(data: &[u8], chain_id: u64) -> B256 {
    let mut chain_word = [0u8; 32];
    chain_word[24..].copy_from_slice(&chain_id.to_be_bytes());
    let payload_hash = keccak256(data);
    let mut bytes = [0u8; 96];
    // First 32 bytes are the zero domain used by the Helios OP Stack feed.
    bytes[32..64].copy_from_slice(&chain_word);
    bytes[64..96].copy_from_slice(payload_hash.as_slice());
    keccak256(bytes)
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

    #[test]
    fn op_signature_domain_commits_chain_id_and_data() {
        let data = b"op-stack-test";
        assert_ne!(
            op_signature_hash(data, BASE_SEPOLIA_CHAIN_ID),
            op_signature_hash(data, OP_SEPOLIA_CHAIN_ID)
        );
        assert_ne!(
            op_signature_hash(data, BASE_SEPOLIA_CHAIN_ID),
            op_signature_hash(b"op-stack-changed", BASE_SEPOLIA_CHAIN_ID)
        );
    }
}
