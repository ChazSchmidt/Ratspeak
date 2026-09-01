use alloy_consensus::Header;
use alloy_rlp::Decodable;

use super::{
    Cursor, ExecutionHeaderProvenance, KIND_EXECUTION_HEADER_PROOF, Result,
    VerifiedExecutionHeader, Verifier, VerifyError, sha256,
};

const MAX_EXECUTION_HEADER_BYTES: usize = 1024 * 1024;

/// An RLP execution header transported separately from Beacon consensus data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHeaderProofBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
    pub rlp_header: Vec<u8>,
}

/// Execution trie roots from an RLP header whose hash matches Helios consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExecutionBlock {
    pub(super) chain_id: u64,
    pub(super) network: String,
    pub(super) execution_block_number: u64,
    pub(super) execution_block_hash: [u8; 32],
    pub(super) parent_hash: [u8; 32],
    pub(super) state_root: [u8; 32],
    pub(super) receipts_root: [u8; 32],
    pub(super) transactions_root: [u8; 32],
    pub(super) checkpoint_root: [u8; 32],
    pub(super) provenance: ExecutionHeaderProvenance,
    pub(super) consensus_bundle_hash: [u8; 32],
    pub(super) proof_bundle_hash: [u8; 32],
}

impl VerifiedExecutionBlock {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn execution_block_number(&self) -> u64 {
        self.execution_block_number
    }

    pub fn execution_block_hash(&self) -> [u8; 32] {
        self.execution_block_hash
    }

    pub fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    /// Merkle-Patricia root from the hash-authenticated execution header.
    pub fn transactions_root(&self) -> [u8; 32] {
        self.transactions_root
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn provenance(&self) -> ExecutionHeaderProvenance {
        self.provenance
    }

    pub fn consensus_bundle_hash(&self) -> [u8; 32] {
        self.consensus_bundle_hash
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

impl Verifier {
    pub fn parse_execution_header_proof(&self, bytes: &[u8]) -> Result<ExecutionHeaderProofBundle> {
        let canonical = self.canonical_bundle(bytes)?;
        parse_execution_header_proof(&canonical, self.chain_id, self.network)
    }

    /// Authenticates execution trie roots using the Helios-verified block hash.
    pub fn verify_execution_header(
        &self,
        bytes: &[u8],
        consensus: &VerifiedExecutionHeader,
    ) -> Result<VerifiedExecutionBlock> {
        if consensus.chain_id() != self.chain_id || consensus.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: consensus.chain_id(),
                network: consensus.network().to_owned(),
            });
        }
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_execution_header_proof(&canonical, self.chain_id, self.network)?;
        let header = decode_header(&bundle.rlp_header)?;
        let block_hash = header.hash_slow().0;
        if header.number != consensus.execution_block_number()
            || block_hash != consensus.execution_block_hash()
            || header.state_root.0 != consensus.state_root()
            || header.receipts_root.0 != consensus.receipts_root()
        {
            return Err(VerifyError::ExecutionHeaderMismatch);
        }
        if header.timestamp != consensus.finalized_at_unix()? {
            return Err(VerifyError::ExecutionTimestampMismatch);
        }
        Ok(VerifiedExecutionBlock {
            chain_id: bundle.chain_id,
            network: bundle.network,
            execution_block_number: header.number,
            execution_block_hash: block_hash,
            parent_hash: header.parent_hash.0,
            state_root: header.state_root.0,
            receipts_root: header.receipts_root.0,
            transactions_root: header.transactions_root.0,
            checkpoint_root: consensus.checkpoint_root(),
            provenance: consensus.provenance(),
            consensus_bundle_hash: consensus.proof_bundle_hash(),
            proof_bundle_hash: sha256(&canonical),
        })
    }
}

fn parse_execution_header_proof(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<ExecutionHeaderProofBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_EXECUTION_HEADER_PROOF {
        return Err(VerifyError::UnsupportedKind(prelude.kind));
    }
    let created_at_unix = cursor.u64()?;
    let rlp_header =
        cursor.sized_bytes(MAX_EXECUTION_HEADER_BYTES, "execution header exceeds limit")?;
    if rlp_header.is_empty() {
        return Err(VerifyError::Malformed("empty execution header"));
    }
    cursor.finish()?;
    decode_header(&rlp_header)?;
    Ok(ExecutionHeaderProofBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        rlp_header,
    })
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<Header> {
    let mut remaining = bytes;
    let header = Header::decode(&mut remaining)
        .map_err(|error| VerifyError::InvalidExecutionHeader(error.to_string()))?;
    if !remaining.is_empty() {
        return Err(VerifyError::Malformed("trailing execution header bytes"));
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn real_header_bundle() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../tests/fixtures/sepolia-execution-header-11574048.rseth.b64")
                    .trim(),
            )
            .unwrap()
    }

    #[test]
    fn rejects_trailing_execution_bundle_bytes() {
        let mut bytes = real_header_bundle();
        bytes.push(0);
        assert!(matches!(
            Verifier::sepolia().parse_execution_header_proof(&bytes),
            Err(VerifyError::Malformed("trailing bytes"))
        ));
    }

    #[test]
    fn rejects_header_that_does_not_match_consensus_commitment() {
        let bytes = real_header_bundle();
        let bundle = Verifier::sepolia()
            .parse_execution_header_proof(&bytes)
            .unwrap();
        let header = decode_header(&bundle.rlp_header).unwrap();
        let consensus = VerifiedExecutionHeader {
            chain_id: crate::SEPOLIA_CHAIN_ID,
            network: crate::SEPOLIA_NETWORK.to_owned(),
            finalized_slot: 1,
            execution_block_number: header.number,
            execution_block_hash: [0xff; 32],
            state_root: header.state_root.0,
            receipts_root: header.receipts_root.0,
            beacon_transactions_root: [0x22; 32],
            checkpoint_root: [0x33; 32],
            provenance: ExecutionHeaderProvenance::CheckpointAnchor,
            proof_bundle_hash: [0x44; 32],
        };
        assert!(matches!(
            Verifier::sepolia().verify_execution_header(&bytes, &consensus),
            Err(VerifyError::ExecutionHeaderMismatch)
        ));
    }

    #[test]
    fn rejects_execution_timestamp_that_disagrees_with_consensus_slot() {
        let bytes = real_header_bundle();
        let bundle = Verifier::sepolia()
            .parse_execution_header_proof(&bytes)
            .unwrap();
        let header = decode_header(&bundle.rlp_header).unwrap();
        let correct_slot = crate::sepolia_slot_at_unix(header.timestamp).unwrap();
        let consensus = VerifiedExecutionHeader {
            chain_id: crate::SEPOLIA_CHAIN_ID,
            network: crate::SEPOLIA_NETWORK.to_owned(),
            finalized_slot: correct_slot + 1,
            execution_block_number: header.number,
            execution_block_hash: header.hash_slow().0,
            state_root: header.state_root.0,
            receipts_root: header.receipts_root.0,
            beacon_transactions_root: [0x22; 32],
            checkpoint_root: [0x33; 32],
            provenance: ExecutionHeaderProvenance::CheckpointAnchor,
            proof_bundle_hash: [0x44; 32],
        };
        assert!(matches!(
            Verifier::sepolia().verify_execution_header(&bytes, &consensus),
            Err(VerifyError::ExecutionTimestampMismatch)
        ));
    }
}
