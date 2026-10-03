use super::execution::decode_header;
use super::receipt::{parse_tx_receipt_proof, verify_tx_receipt};
use super::{
    Cursor, KIND_FINALIZED_TX_RECEIPT_PROOF, Result, TxReceiptProofBundle, VerifiedExecutionBlock,
    VerifiedTxReceipt, Verifier, VerifyError, sha256,
};

pub const MAX_ANCESTRY_HEADERS: usize = 256;
pub const MAX_ANCESTRY_HEADER_BYTES: usize = 2 * 1024;

/// Untrusted receipt material plus the exact execution parent chain from a
/// consensus-authenticated descendant to the transaction's block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedTxReceiptProofBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
    pub anchor_block_number: u64,
    pub anchor_block_hash: [u8; 32],
    pub target_block_number: u64,
    pub target_block_hash: [u8; 32],
    /// Descending headers: anchor parent first and target last.
    pub ancestry_headers: Vec<Vec<u8>>,
    pub receipt_proof: TxReceiptProofBundle,
    pub receipt_proof_bytes: Vec<u8>,
}

/// Exact receipt evidence and the execution block derived from finalized
/// consensus. Neither value can be constructed by a transport adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFinalizedTxReceipt {
    target_block: VerifiedExecutionBlock,
    receipt: VerifiedTxReceipt,
}

impl VerifiedFinalizedTxReceipt {
    pub fn target_block(&self) -> &VerifiedExecutionBlock {
        &self.target_block
    }

    pub fn receipt(&self) -> &VerifiedTxReceipt {
        &self.receipt
    }

    pub fn into_parts(self) -> (VerifiedExecutionBlock, VerifiedTxReceipt) {
        (self.target_block, self.receipt)
    }
}

impl Verifier {
    pub fn parse_finalized_tx_receipt_proof(
        &self,
        bytes: &[u8],
    ) -> Result<FinalizedTxReceiptProofBundle> {
        let canonical = self.canonical_bundle(bytes)?;
        parse_finalized_tx_receipt_proof(&canonical, self.chain_id, self.network)
    }

    /// Verifies a target block by walking exact parent hashes from an already
    /// consensus-authenticated descendant, then verifies both transaction and
    /// receipt inclusion against the target's authenticated trie roots.
    pub fn verify_finalized_tx_receipt(
        &self,
        bytes: &[u8],
        anchor: &VerifiedExecutionBlock,
    ) -> Result<VerifiedFinalizedTxReceipt> {
        if anchor.chain_id() != self.chain_id || anchor.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: anchor.chain_id(),
                network: anchor.network().to_owned(),
            });
        }
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_finalized_tx_receipt_proof(&canonical, self.chain_id, self.network)?;
        if bundle.anchor_block_number != anchor.execution_block_number()
            || bundle.anchor_block_hash != anchor.execution_block_hash()
        {
            return Err(VerifyError::InvalidExecutionAncestry);
        }
        let proof_hash = sha256(&canonical);
        let target_block = verify_ancestry(&bundle, anchor, proof_hash)?;
        let receipt = verify_tx_receipt(bundle.receipt_proof, &target_block, proof_hash)?;
        Ok(VerifiedFinalizedTxReceipt {
            target_block,
            receipt,
        })
    }
}

fn parse_finalized_tx_receipt_proof(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<FinalizedTxReceiptProofBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_FINALIZED_TX_RECEIPT_PROOF {
        return Err(VerifyError::UnsupportedKind(prelude.kind));
    }
    let created_at_unix = cursor.u64()?;
    let anchor_block_number = cursor.u64()?;
    let anchor_block_hash = cursor.array32()?;
    let target_block_number = cursor.u64()?;
    let target_block_hash = cursor.array32()?;
    let count = cursor.u16()? as usize;
    if count > MAX_ANCESTRY_HEADERS {
        return Err(VerifyError::TooManyAncestryHeaders);
    }
    let mut ancestry_headers = Vec::with_capacity(count);
    for _ in 0..count {
        let header_len = cursor.u32()? as usize;
        if header_len > MAX_ANCESTRY_HEADER_BYTES {
            return Err(VerifyError::OversizedAncestryHeader);
        }
        let header = cursor.take(header_len)?.to_vec();
        if header.is_empty() {
            return Err(VerifyError::Malformed("empty execution ancestry header"));
        }
        decode_header(&header)?;
        ancestry_headers.push(header);
    }
    let receipt_proof_bytes = cursor.sized_bytes(
        super::MAX_BUNDLE_BYTES,
        "finalized receipt proof exceeds limit",
    )?;
    if receipt_proof_bytes.is_empty() {
        return Err(VerifyError::Malformed("empty finalized receipt proof"));
    }
    cursor.finish()?;
    let receipt_proof =
        parse_tx_receipt_proof(&receipt_proof_bytes, expected_chain_id, expected_network)?;
    Ok(FinalizedTxReceiptProofBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        anchor_block_number,
        anchor_block_hash,
        target_block_number,
        target_block_hash,
        ancestry_headers,
        receipt_proof,
        receipt_proof_bytes,
    })
}

fn verify_ancestry(
    bundle: &FinalizedTxReceiptProofBundle,
    anchor: &VerifiedExecutionBlock,
    proof_bundle_hash: [u8; 32],
) -> Result<VerifiedExecutionBlock> {
    let distance = anchor
        .execution_block_number()
        .checked_sub(bundle.target_block_number)
        .ok_or(VerifyError::InvalidExecutionAncestry)?;
    if usize::try_from(distance).ok() != Some(bundle.ancestry_headers.len()) {
        return Err(VerifyError::InvalidExecutionAncestry);
    }
    if bundle.ancestry_headers.is_empty() {
        if bundle.target_block_number != anchor.execution_block_number()
            || bundle.target_block_hash != anchor.execution_block_hash()
        {
            return Err(VerifyError::InvalidExecutionAncestry);
        }
        return Ok(VerifiedExecutionBlock {
            chain_id: anchor.chain_id,
            network: anchor.network.clone(),
            execution_block_number: anchor.execution_block_number,
            execution_block_hash: anchor.execution_block_hash,
            parent_hash: anchor.parent_hash,
            state_root: anchor.state_root,
            receipts_root: anchor.receipts_root,
            transactions_root: anchor.transactions_root,
            checkpoint_root: anchor.checkpoint_root,
            provenance: anchor.provenance,
            consensus_bundle_hash: anchor.consensus_bundle_hash,
            proof_bundle_hash: anchor.proof_bundle_hash,
        });
    }

    let mut expected_hash = anchor.parent_hash();
    let mut expected_number = anchor.execution_block_number();
    let mut target = None;
    for rlp in &bundle.ancestry_headers {
        expected_number = expected_number
            .checked_sub(1)
            .ok_or(VerifyError::InvalidExecutionAncestry)?;
        let header = decode_header(rlp)?;
        if header.hash_slow().0 != expected_hash || header.number != expected_number {
            return Err(VerifyError::InvalidExecutionAncestry);
        }
        expected_hash = header.parent_hash.0;
        target = Some(header);
    }
    let target = target.ok_or(VerifyError::InvalidExecutionAncestry)?;
    let target_hash = target.hash_slow().0;
    if target.number != bundle.target_block_number
        || target_hash != bundle.target_block_hash
        || bundle.receipt_proof.block_number != target.number
        || bundle.receipt_proof.block_hash != target_hash
        || bundle.receipt_proof.transactions_root != target.transactions_root.0
        || bundle.receipt_proof.receipts_root != target.receipts_root.0
    {
        return Err(VerifyError::InvalidExecutionAncestry);
    }
    Ok(VerifiedExecutionBlock {
        chain_id: bundle.chain_id,
        network: bundle.network.clone(),
        execution_block_number: target.number,
        execution_block_hash: target_hash,
        parent_hash: target.parent_hash.0,
        state_root: target.state_root.0,
        receipts_root: target.receipts_root.0,
        transactions_root: target.transactions_root.0,
        checkpoint_root: anchor.checkpoint_root(),
        provenance: anchor.provenance(),
        consensus_bundle_hash: anchor.consensus_bundle_hash(),
        proof_bundle_hash,
    })
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use base64::Engine;

    use super::*;
    use crate::{ExecutionHeaderProvenance, MAGIC, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, VERSION};

    fn target_header_and_receipt() -> (Vec<u8>, Header, Vec<u8>) {
        let execution = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../tests/fixtures/sepolia-execution-header-11574048.rseth.b64")
                    .trim(),
            )
            .unwrap();
        let parsed = Verifier::sepolia()
            .parse_execution_header_proof(&execution)
            .unwrap();
        let header = decode_header(&parsed.rlp_header).unwrap();
        let receipt = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-receipt-11574048-0.rseth.b64").trim())
            .unwrap();
        (parsed.rlp_header, header, receipt)
    }

    fn verified_anchor(
        number: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
    ) -> VerifiedExecutionBlock {
        VerifiedExecutionBlock {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            execution_block_number: number,
            execution_block_hash: hash,
            parent_hash,
            state_root: [0x11; 32],
            receipts_root: [0x12; 32],
            transactions_root: [0x13; 32],
            checkpoint_root: [0x14; 32],
            provenance: ExecutionHeaderProvenance::HeliosFinalityUpdate,
            consensus_bundle_hash: [0x15; 32],
            proof_bundle_hash: [0x16; 32],
        }
    }

    fn encode(
        anchor: &VerifiedExecutionBlock,
        target: &Header,
        headers: &[Vec<u8>],
        receipt: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        out.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        out.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        out.push(KIND_FINALIZED_TX_RECEIPT_PROOF);
        out.extend_from_slice(&1_800_000_000_u64.to_le_bytes());
        out.extend_from_slice(&anchor.execution_block_number().to_le_bytes());
        out.extend_from_slice(&anchor.execution_block_hash());
        out.extend_from_slice(&target.number.to_le_bytes());
        out.extend_from_slice(&target.hash_slow().0);
        out.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        for header in headers {
            out.extend_from_slice(&(header.len() as u32).to_le_bytes());
            out.extend_from_slice(header);
        }
        out.extend_from_slice(&(receipt.len() as u32).to_le_bytes());
        out.extend_from_slice(receipt);
        out
    }

    fn two_header_fixture() -> (VerifiedExecutionBlock, Header, Vec<Vec<u8>>, Vec<u8>) {
        let (target_rlp, target, receipt) = target_header_and_receipt();
        let intermediate = Header {
            number: target.number + 1,
            parent_hash: target.hash_slow(),
            state_root: [0x21; 32].into(),
            receipts_root: [0x22; 32].into(),
            transactions_root: [0x23; 32].into(),
            ..Default::default()
        };
        let intermediate_rlp = alloy_rlp::encode(&intermediate);
        let anchor = verified_anchor(target.number + 2, [0x31; 32], intermediate.hash_slow().0);
        (anchor, target, vec![intermediate_rlp, target_rlp], receipt)
    }

    #[test]
    fn derives_target_and_verifies_exact_receipt_from_finalized_descendant() {
        let (anchor, target, headers, receipt) = two_header_fixture();
        let bytes = encode(&anchor, &target, &headers, &receipt);
        let verified = Verifier::sepolia()
            .verify_finalized_tx_receipt(&bytes, &anchor)
            .unwrap();
        assert_eq!(
            verified.target_block().execution_block_hash(),
            target.hash_slow().0
        );
        assert_eq!(
            verified.target_block().checkpoint_root(),
            anchor.checkpoint_root()
        );
        assert_eq!(
            verified.target_block().consensus_bundle_hash(),
            anchor.consensus_bundle_hash()
        );
        assert!(verified.receipt().succeeded());
        assert_eq!(verified.receipt().block_hash(), target.hash_slow().0);
        assert_eq!(verified.receipt().proof_bundle_hash(), sha256(&bytes));
    }

    #[test]
    fn rejects_reordered_duplicate_skipped_and_same_height_fork_headers() {
        let (anchor, target, headers, receipt) = two_header_fixture();
        for invalid in [
            vec![headers[1].clone(), headers[0].clone()],
            vec![headers[0].clone(), headers[0].clone()],
            vec![headers[1].clone()],
        ] {
            assert!(matches!(
                Verifier::sepolia().verify_finalized_tx_receipt(
                    &encode(&anchor, &target, &invalid, &receipt),
                    &anchor
                ),
                Err(VerifyError::InvalidExecutionAncestry)
            ));
        }
        let mut fork = decode_header(&headers[0]).unwrap();
        fork.parent_hash = [0x99; 32].into();
        let fork = vec![alloy_rlp::encode(&fork), headers[1].clone()];
        assert!(matches!(
            Verifier::sepolia()
                .verify_finalized_tx_receipt(&encode(&anchor, &target, &fork, &receipt), &anchor),
            Err(VerifyError::InvalidExecutionAncestry)
        ));
    }

    #[test]
    fn rejects_wrong_target_root_and_anchor() {
        let (anchor, mut target, headers, receipt) = two_header_fixture();
        target.receipts_root = [0x77; 32].into();
        assert!(matches!(
            Verifier::sepolia().verify_finalized_tx_receipt(
                &encode(&anchor, &target, &headers, &receipt),
                &anchor
            ),
            Err(VerifyError::InvalidExecutionAncestry)
        ));

        let (_, target, headers, receipt) = two_header_fixture();
        let wrong_anchor = verified_anchor(
            anchor.execution_block_number(),
            [0x88; 32],
            anchor.parent_hash(),
        );
        assert!(matches!(
            Verifier::sepolia().verify_finalized_tx_receipt(
                &encode(&anchor, &target, &headers, &receipt),
                &wrong_anchor
            ),
            Err(VerifyError::InvalidExecutionAncestry)
        ));
    }

    #[test]
    fn enforces_header_count_and_per_header_bounds_before_allocation() {
        let (anchor, target, _, receipt) = two_header_fixture();
        let mut excessive = encode(&anchor, &target, &[], &receipt);
        let prelude_len = MAGIC.len() + 1 + 8 + 2 + SEPOLIA_NETWORK.len() + 1;
        let count_offset = prelude_len + 8 + 8 + 32 + 8 + 32;
        excessive[count_offset..count_offset + 2]
            .copy_from_slice(&((MAX_ANCESTRY_HEADERS + 1) as u16).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().parse_finalized_tx_receipt_proof(&excessive),
            Err(VerifyError::TooManyAncestryHeaders)
        ));

        let mut oversized = encode(&anchor, &target, &[vec![0]], &receipt);
        let length_offset = count_offset + 2;
        oversized[length_offset..length_offset + 4]
            .copy_from_slice(&((MAX_ANCESTRY_HEADER_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().parse_finalized_tx_receipt_proof(&oversized),
            Err(VerifyError::OversizedAncestryHeader)
        ));
    }
}
