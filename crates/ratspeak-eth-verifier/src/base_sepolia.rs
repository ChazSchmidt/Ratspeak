use alloy_primitives::{Address, B256, address, b256, keccak256};
use helios_opstack::{SequencerCommitment, types::ExecutionPayload};

use super::{
    BASE_SEPOLIA_CHAIN_ID, BASE_SEPOLIA_NETWORK, PinnedCheckpoint, Result, VerifiedStorageValue,
    VerifyError,
};
use crate::execution::decode_header;

const BASE_SEPOLIA_SYSTEM_CONFIG: Address =
    address!("f272670eb55e895584501d564AfEB048bEd26194");
const UNSAFE_SIGNER_SLOT: B256 =
    b256!("65a7ed542fb37fe237fdfbdd70b31598523fe5b32879e307bae27a0bd9581c08");

/// Base Sepolia execution head authenticated by the sequencer signature whose
/// signer was independently proven from the L1 SystemConfig storage.
///
/// This is intentionally not called finalized or safe. It protects RatSpeak
/// from an untrusted agent/RPC inventing a Base state root, but it does not
/// protect against sequencer equivocation or a later L2 reorg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseSepoliaSequencerAnchor {
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    timestamp: u64,
    sequencer_signer: [u8; 20],
    signer_storage_proof_hash: [u8; 32],
    sequencer_commitment_hash: [u8; 32],
}

impl BaseSepoliaSequencerAnchor {
    /// Verifies a compressed Helios OP-Stack sequencer commitment using a
    /// signer value already authenticated from Ethereum Sepolia contract
    /// storage.
    pub fn verify(
        compressed_commitment: &[u8],
        verified_signer_storage: &VerifiedStorageValue,
    ) -> Result<Self> {
        if verified_signer_storage.chain_id() != super::SEPOLIA_CHAIN_ID
            || verified_signer_storage.network() != super::SEPOLIA_NETWORK
            || verified_signer_storage.account_address() != BASE_SEPOLIA_SYSTEM_CONFIG.0
            || B256::from(verified_signer_storage.key()) != UNSAFE_SIGNER_SLOT
        {
            return Err(VerifyError::CheckpointMismatch);
        }

        let signer_bytes = verified_signer_storage.value().to_be_bytes::<32>();
        let signer = Address::from_slice(&signer_bytes[12..]);
        if signer == Address::ZERO {
            return Err(VerifyError::Malformed("Base Sepolia sequencer signer is zero"));
        }

        let commitment = SequencerCommitment::new(compressed_commitment)
            .map_err(|_| VerifyError::Malformed("invalid OP-Stack sequencer commitment"))?;
        commitment
            .verify(signer, BASE_SEPOLIA_CHAIN_ID)
            .map_err(|_| VerifyError::Malformed("invalid Base Sepolia sequencer signature"))?;
        let payload = ExecutionPayload::try_from(&commitment)
            .map_err(|_| VerifyError::Malformed("invalid Base Sepolia execution payload"))?;

        Ok(Self {
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

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn sequencer_signer(&self) -> [u8; 20] {
        self.sequencer_signer
    }

    pub fn signer_storage_proof_hash(&self) -> [u8; 32] {
        self.signer_storage_proof_hash
    }

    pub fn sequencer_commitment_hash(&self) -> [u8; 32] {
        self.sequencer_commitment_hash
    }

    /// Supplies the authenticated state root to the existing Base Sepolia
    /// account/storage proof verifier.
    pub fn pinned_checkpoint(&self) -> PinnedCheckpoint {
        PinnedCheckpoint::base_sepolia(self.block_number, self.block_hash, self.state_root)
    }

    /// Checks an RPC-supplied RLP header against the sequencer-authenticated
    /// payload. This exposes the authenticated transactions root without
    /// trusting the RPC's header fields.
    pub fn verify_rlp_header(&self, rlp_header: &[u8]) -> Result<VerifiedBaseSepoliaHeader> {
        let header = decode_header(rlp_header)?;
        if header.number != self.block_number
            || header.hash_slow().0 != self.block_hash
            || header.state_root.0 != self.state_root
            || header.receipts_root.0 != self.receipts_root
            || header.timestamp != self.timestamp
        {
            return Err(VerifyError::ExecutionHeaderMismatch);
        }

        Ok(VerifiedBaseSepoliaHeader {
            block_number: header.number,
            block_hash: self.block_hash,
            parent_hash: header.parent_hash.0,
            state_root: header.state_root.0,
            transactions_root: header.transactions_root.0,
            receipts_root: header.receipts_root.0,
            timestamp: header.timestamp,
            sequencer_signer: self.sequencer_signer,
            anchor_hash: self.sequencer_commitment_hash,
        })
    }
}

/// Full L2 header whose hash and execution roots match a verified sequencer
/// commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBaseSepoliaHeader {
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    transactions_root: [u8; 32],
    receipts_root: [u8; 32],
    timestamp: u64,
    sequencer_signer: [u8; 20],
    anchor_hash: [u8; 32],
}

impl VerifiedBaseSepoliaHeader {
    pub fn chain_id(&self) -> u64 {
        BASE_SEPOLIA_CHAIN_ID
    }

    pub fn network(&self) -> &'static str {
        BASE_SEPOLIA_NETWORK
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn transactions_root(&self) -> [u8; 32] {
        self.transactions_root
    }

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn sequencer_signer(&self) -> [u8; 20] {
        self.sequencer_signer
    }

    pub fn anchor_hash(&self) -> [u8; 32] {
        self.anchor_hash
    }
}
