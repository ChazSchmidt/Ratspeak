use super::{
    AccountProofBundle, BeaconCheckpointRoot, ExecutionHeaderProofBundle,
    FinalizedTxReceiptProofBundle, MAX_BUNDLE_BYTES, MAX_COMPOSITE_EVIDENCE_BYTES, Result,
    SEPOLIA_NETWORK, VerifiedAccount, VerifiedExecutionBlock, VerifiedExecutionHeader,
    VerifiedFinalizedTxReceipt, Verifier, VerifyError, parse_account_proof, sha256, verify_account,
};

const COMPOSITE_MAGIC: &[u8; 6] = b"RSECP1";
const COMPOSITE_VERSION: u8 = 1;
const KIND_ACCOUNT_STATE_EVIDENCE: u8 = 1;
const KIND_FINALIZED_RECEIPT_EVIDENCE: u8 = 2;

/// One bounded, byte-stable account-state package.
///
/// The package deliberately contains no checkpoint root. Its consensus bytes
/// acquire authority only when `verify_account_state_evidence` is called with
/// an independently approved `BeaconCheckpointRoot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStateEvidencePackage {
    created_at_unix: u64,
    consensus_bundle_bytes: Vec<u8>,
    execution_header_bytes: Vec<u8>,
    account_proof_bytes: Vec<u8>,
    consensus: super::ConsensusBootstrapBundle,
    execution_header: ExecutionHeaderProofBundle,
    account_proof: AccountProofBundle,
}

impl AccountStateEvidencePackage {
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn consensus_bundle_bytes(&self) -> &[u8] {
        &self.consensus_bundle_bytes
    }

    pub fn execution_header_bytes(&self) -> &[u8] {
        &self.execution_header_bytes
    }

    pub fn account_proof_bytes(&self) -> &[u8] {
        &self.account_proof_bytes
    }

    pub fn consensus(&self) -> &super::ConsensusBootstrapBundle {
        &self.consensus
    }

    pub fn execution_header(&self) -> &ExecutionHeaderProofBundle {
        &self.execution_header
    }

    pub fn account_proof(&self) -> &AccountProofBundle {
        &self.account_proof
    }
}

/// One bounded, byte-stable finalized-receipt package.
///
/// The receipt is bound to the exact consensus anchor included in this
/// package. A later local head neither replaces nor authenticates that anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedReceiptEvidencePackage {
    created_at_unix: u64,
    consensus_bundle_bytes: Vec<u8>,
    execution_header_bytes: Vec<u8>,
    finalized_receipt_bytes: Vec<u8>,
    consensus: super::ConsensusBootstrapBundle,
    execution_header: ExecutionHeaderProofBundle,
    finalized_receipt: FinalizedTxReceiptProofBundle,
}

impl FinalizedReceiptEvidencePackage {
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn consensus_bundle_bytes(&self) -> &[u8] {
        &self.consensus_bundle_bytes
    }

    pub fn execution_header_bytes(&self) -> &[u8] {
        &self.execution_header_bytes
    }

    pub fn finalized_receipt_bytes(&self) -> &[u8] {
        &self.finalized_receipt_bytes
    }

    pub fn consensus(&self) -> &super::ConsensusBootstrapBundle {
        &self.consensus
    }

    pub fn execution_header(&self) -> &ExecutionHeaderProofBundle {
        &self.execution_header
    }

    pub fn finalized_receipt(&self) -> &FinalizedTxReceiptProofBundle {
        &self.finalized_receipt
    }
}

/// Coherent account state derived from one package and one approved root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccountStateEvidence {
    consensus: VerifiedExecutionHeader,
    execution_block: VerifiedExecutionBlock,
    account: VerifiedAccount,
    package_hash: [u8; 32],
}

impl VerifiedAccountStateEvidence {
    pub fn consensus(&self) -> &VerifiedExecutionHeader {
        &self.consensus
    }

    pub fn execution_block(&self) -> &VerifiedExecutionBlock {
        &self.execution_block
    }

    pub fn account(&self) -> &VerifiedAccount {
        &self.account
    }

    pub fn package_hash(&self) -> [u8; 32] {
        self.package_hash
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifiedExecutionHeader,
        VerifiedExecutionBlock,
        VerifiedAccount,
    ) {
        (self.consensus, self.execution_block, self.account)
    }
}

/// Coherent finalized receipt derived from one package and one approved root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFinalizedReceiptEvidence {
    consensus: VerifiedExecutionHeader,
    anchor: VerifiedExecutionBlock,
    finalized_receipt: VerifiedFinalizedTxReceipt,
    package_hash: [u8; 32],
}

impl VerifiedFinalizedReceiptEvidence {
    pub fn consensus(&self) -> &VerifiedExecutionHeader {
        &self.consensus
    }

    pub fn anchor(&self) -> &VerifiedExecutionBlock {
        &self.anchor
    }

    pub fn finalized_receipt(&self) -> &VerifiedFinalizedTxReceipt {
        &self.finalized_receipt
    }

    pub fn package_hash(&self) -> [u8; 32] {
        self.package_hash
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifiedExecutionHeader,
        VerifiedExecutionBlock,
        VerifiedFinalizedTxReceipt,
    ) {
        (self.consensus, self.anchor, self.finalized_receipt)
    }
}

impl Verifier {
    /// Constructs a canonical account-state envelope after validating every
    /// untrusted inner section. Identical inputs produce identical bytes.
    pub fn build_account_state_evidence(
        &self,
        created_at_unix: u64,
        consensus_bundle_bytes: &[u8],
        execution_header_bytes: &[u8],
        account_proof_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        self.parse_consensus_bootstrap(consensus_bundle_bytes)?;
        self.parse_execution_header_proof(execution_header_bytes)?;
        let canonical = self.canonical_bundle(account_proof_bytes)?;
        parse_account_proof(&canonical, self.chain_id, self.network)?;
        encode_envelope(
            self.chain_id,
            self.network,
            KIND_ACCOUNT_STATE_EVIDENCE,
            created_at_unix,
            consensus_bundle_bytes,
            execution_header_bytes,
            account_proof_bytes,
        )
    }

    /// Constructs a canonical finalized-receipt envelope after validating
    /// every untrusted inner section. Identical inputs produce identical bytes.
    pub fn build_finalized_receipt_evidence(
        &self,
        created_at_unix: u64,
        consensus_bundle_bytes: &[u8],
        execution_header_bytes: &[u8],
        finalized_receipt_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        self.parse_consensus_bootstrap(consensus_bundle_bytes)?;
        self.parse_execution_header_proof(execution_header_bytes)?;
        self.parse_finalized_tx_receipt_proof(finalized_receipt_bytes)?;
        encode_envelope(
            self.chain_id,
            self.network,
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            created_at_unix,
            consensus_bundle_bytes,
            execution_header_bytes,
            finalized_receipt_bytes,
        )
    }

    pub fn parse_account_state_evidence(
        &self,
        bytes: &[u8],
    ) -> Result<AccountStateEvidencePackage> {
        let envelope = parse_envelope(
            bytes,
            self.chain_id,
            self.network,
            KIND_ACCOUNT_STATE_EVIDENCE,
        )?;
        let consensus = self.parse_consensus_bootstrap(&envelope.consensus_bundle_bytes)?;
        let execution_header =
            self.parse_execution_header_proof(&envelope.execution_header_bytes)?;
        let canonical_account = self.canonical_bundle(&envelope.subject_evidence_bytes)?;
        let account_proof = parse_account_proof(&canonical_account, self.chain_id, self.network)?;
        Ok(AccountStateEvidencePackage {
            created_at_unix: envelope.created_at_unix,
            consensus_bundle_bytes: envelope.consensus_bundle_bytes,
            execution_header_bytes: envelope.execution_header_bytes,
            account_proof_bytes: envelope.subject_evidence_bytes,
            consensus,
            execution_header,
            account_proof,
        })
    }

    /// Re-verifies a coherent historical account-state package.
    ///
    /// `checkpoint` must have been approved independently while it was within
    /// the caller's weak-subjectivity policy. This method deliberately does not
    /// infer current chain freshness from the package's creation timestamp.
    pub fn verify_account_state_evidence(
        &self,
        bytes: &[u8],
        checkpoint: &BeaconCheckpointRoot,
        expected_address: [u8; 20],
    ) -> Result<VerifiedAccountStateEvidence> {
        let package = self.parse_account_state_evidence(bytes)?;
        let consensus = self
            .reverify_historical_consensus_bootstrap(&package.consensus_bundle_bytes, checkpoint)?;
        let (execution_block, account) = self.verify_account_sections(
            &package.execution_header_bytes,
            &package.account_proof_bytes,
            &consensus,
            expected_address,
        )?;
        Ok(VerifiedAccountStateEvidence {
            consensus,
            execution_block,
            account,
            package_hash: sha256(bytes),
        })
    }

    pub fn parse_finalized_receipt_evidence(
        &self,
        bytes: &[u8],
    ) -> Result<FinalizedReceiptEvidencePackage> {
        let envelope = parse_envelope(
            bytes,
            self.chain_id,
            self.network,
            KIND_FINALIZED_RECEIPT_EVIDENCE,
        )?;
        let consensus = self.parse_consensus_bootstrap(&envelope.consensus_bundle_bytes)?;
        let execution_header =
            self.parse_execution_header_proof(&envelope.execution_header_bytes)?;
        let finalized_receipt =
            self.parse_finalized_tx_receipt_proof(&envelope.subject_evidence_bytes)?;
        Ok(FinalizedReceiptEvidencePackage {
            created_at_unix: envelope.created_at_unix,
            consensus_bundle_bytes: envelope.consensus_bundle_bytes,
            execution_header_bytes: envelope.execution_header_bytes,
            finalized_receipt_bytes: envelope.subject_evidence_bytes,
            consensus,
            execution_header,
            finalized_receipt,
        })
    }

    /// Re-verifies one exact transaction and receipt against the package's
    /// own finalized consensus anchor, regardless of any newer local head.
    pub fn verify_finalized_receipt_evidence(
        &self,
        bytes: &[u8],
        checkpoint: &BeaconCheckpointRoot,
        expected_tx_hash: [u8; 32],
    ) -> Result<VerifiedFinalizedReceiptEvidence> {
        let package = self.parse_finalized_receipt_evidence(bytes)?;
        let consensus = self
            .reverify_historical_consensus_bootstrap(&package.consensus_bundle_bytes, checkpoint)?;
        let anchor = self.verify_execution_header(&package.execution_header_bytes, &consensus)?;
        let finalized_receipt =
            self.verify_finalized_tx_receipt(&package.finalized_receipt_bytes, &anchor)?;
        if finalized_receipt.receipt().tx_hash() != expected_tx_hash {
            return Err(VerifyError::UnexpectedTransaction);
        }
        Ok(VerifiedFinalizedReceiptEvidence {
            consensus,
            anchor,
            finalized_receipt,
            package_hash: sha256(bytes),
        })
    }

    fn verify_account_sections(
        &self,
        execution_header_bytes: &[u8],
        account_proof_bytes: &[u8],
        consensus: &VerifiedExecutionHeader,
        expected_address: [u8; 20],
    ) -> Result<(VerifiedExecutionBlock, VerifiedAccount)> {
        let execution_block = self.verify_execution_header(execution_header_bytes, consensus)?;
        let canonical = self.canonical_bundle(account_proof_bytes)?;
        let bundle = parse_account_proof(&canonical, self.chain_id, self.network)?;
        if bundle.address != expected_address {
            return Err(VerifyError::UnexpectedAccount);
        }
        let checkpoint = super::PinnedCheckpoint {
            chain_id: execution_block.chain_id(),
            network: SEPOLIA_NETWORK,
            execution_block_number: execution_block.execution_block_number(),
            execution_block_hash: execution_block.execution_block_hash(),
            state_root: execution_block.state_root(),
        };
        let account = verify_account(bundle, &checkpoint, sha256(&canonical))?;
        Ok((execution_block, account))
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_envelope(
    chain_id: u64,
    network: &str,
    kind: u8,
    created_at_unix: u64,
    consensus_bundle_bytes: &[u8],
    execution_header_bytes: &[u8],
    subject_evidence_bytes: &[u8],
) -> Result<Vec<u8>> {
    let sections = [
        consensus_bundle_bytes,
        execution_header_bytes,
        subject_evidence_bytes,
    ];
    if sections
        .iter()
        .any(|section| section.is_empty() || section.len() > MAX_BUNDLE_BYTES)
    {
        return Err(VerifyError::Malformed("invalid composite section length"));
    }
    let capacity = COMPOSITE_MAGIC
        .len()
        .checked_add(1 + 8 + 2 + network.len() + 1 + 8 + 3 * 4)
        .and_then(|length| {
            sections
                .iter()
                .try_fold(length, |sum, section| sum.checked_add(section.len()))
        })
        .ok_or(VerifyError::OversizedCompositeEvidence)?;
    if capacity > MAX_COMPOSITE_EVIDENCE_BYTES {
        return Err(VerifyError::OversizedCompositeEvidence);
    }
    let network_len =
        u16::try_from(network.len()).map_err(|_| VerifyError::Malformed("string exceeds limit"))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(COMPOSITE_MAGIC);
    out.push(COMPOSITE_VERSION);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&network_len.to_le_bytes());
    out.extend_from_slice(network.as_bytes());
    out.push(kind);
    out.extend_from_slice(&created_at_unix.to_le_bytes());
    for section in sections {
        let length = u32::try_from(section.len())
            .map_err(|_| VerifyError::Malformed("composite section exceeds limit"))?;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(section);
    }
    Ok(out)
}

struct CompositeEnvelope {
    created_at_unix: u64,
    consensus_bundle_bytes: Vec<u8>,
    execution_header_bytes: Vec<u8>,
    subject_evidence_bytes: Vec<u8>,
}

fn parse_envelope(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
    expected_kind: u8,
) -> Result<CompositeEnvelope> {
    if bytes.len() > MAX_COMPOSITE_EVIDENCE_BYTES {
        return Err(VerifyError::OversizedCompositeEvidence);
    }
    let mut cursor = CompositeCursor { bytes, pos: 0 };
    if cursor.take(COMPOSITE_MAGIC.len())? != COMPOSITE_MAGIC {
        return Err(VerifyError::WrongMagic);
    }
    let version = cursor.u8()?;
    if version != COMPOSITE_VERSION {
        return Err(VerifyError::UnsupportedVersion(version));
    }
    let chain_id = cursor.u64()?;
    let network = cursor.string(32)?;
    if chain_id != expected_chain_id || network != expected_network {
        return Err(VerifyError::UnsupportedNetwork { chain_id, network });
    }
    let kind = cursor.u8()?;
    if kind != expected_kind {
        return Err(VerifyError::UnsupportedKind(kind));
    }
    let created_at_unix = cursor.u64()?;
    let consensus_bundle_bytes = cursor.section()?;
    let execution_header_bytes = cursor.section()?;
    let subject_evidence_bytes = cursor.section()?;
    cursor.finish()?;
    Ok(CompositeEnvelope {
        created_at_unix,
        consensus_bundle_bytes,
        execution_header_bytes,
        subject_evidence_bytes,
    })
}

struct CompositeCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CompositeCursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(VerifyError::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(VerifyError::Malformed("unexpected end of bundle"));
        }
        let start = self.pos;
        self.pos = end;
        Ok(&self.bytes[start..end])
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn string(&mut self, maximum: usize) -> Result<String> {
        let length = self.u16()? as usize;
        if length > maximum {
            return Err(VerifyError::Malformed("string exceeds limit"));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| VerifyError::Malformed("invalid utf-8"))
    }

    fn section(&mut self) -> Result<Vec<u8>> {
        let length = self.u32()? as usize;
        if length == 0 {
            return Err(VerifyError::Malformed("empty composite section"));
        }
        if length > MAX_BUNDLE_BYTES {
            return Err(VerifyError::Malformed("composite section exceeds limit"));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifyError::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use alloy_primitives::{B256, U256, keccak256};
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount};
    use base64::Engine;

    use super::*;
    use crate::execution::decode_header;
    use crate::{
        ExecutionHeaderProvenance, MAGIC, SEPOLIA_CHAIN_ID, VERSION, sepolia_slot_start_unix,
    };

    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    fn inner_prelude(kind: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        out.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        out.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        out.push(kind);
        out
    }

    fn consensus_fixture() -> Vec<u8> {
        let bootstrap = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-bootstrap-343888.ssz.b64").trim())
            .unwrap();
        let mut out = inner_prelude(super::super::KIND_PINNED_CONSENSUS_BOOTSTRAP);
        out.extend_from_slice(&0_u64.to_le_bytes());
        write_section(&mut out, &bootstrap);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.push(0);
        out
    }

    fn execution_fixture() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../tests/fixtures/sepolia-execution-header-11574048.rseth.b64")
                    .trim(),
            )
            .unwrap()
    }

    fn receipt_fixture() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-receipt-11574048-0.rseth.b64").trim())
            .unwrap()
    }

    fn finalized_receipt_fixture(execution: &[u8], receipt: &[u8]) -> Vec<u8> {
        let parsed = Verifier::sepolia()
            .parse_execution_header_proof(execution)
            .unwrap();
        let header = decode_header(&parsed.rlp_header).unwrap();
        let mut out = inner_prelude(super::super::KIND_FINALIZED_TX_RECEIPT_PROOF);
        out.extend_from_slice(&0_u64.to_le_bytes());
        out.extend_from_slice(&header.number.to_le_bytes());
        out.extend_from_slice(&header.hash_slow().0);
        out.extend_from_slice(&header.number.to_le_bytes());
        out.extend_from_slice(&header.hash_slow().0);
        out.extend_from_slice(&0_u16.to_le_bytes());
        write_section(&mut out, receipt);
        out
    }

    fn envelope(kind: u8, consensus: &[u8], execution: &[u8], subject: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(COMPOSITE_MAGIC);
        out.push(COMPOSITE_VERSION);
        out.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        out.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        out.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        out.push(kind);
        out.extend_from_slice(&1_800_000_000_u64.to_le_bytes());
        write_section(&mut out, consensus);
        write_section(&mut out, execution);
        write_section(&mut out, subject);
        out
    }

    fn write_section(out: &mut Vec<u8>, section: &[u8]) {
        out.extend_from_slice(&(section.len() as u32).to_le_bytes());
        out.extend_from_slice(section);
    }

    #[test]
    fn verifies_delayed_exact_receipt_from_packages_own_consensus_anchor() {
        let verifier = Verifier::sepolia();
        let consensus = consensus_fixture();
        let execution = execution_fixture();
        let receipt = receipt_fixture();
        let finalized = finalized_receipt_fixture(&execution, &receipt);
        let package = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &consensus,
            &execution,
            &finalized,
        );
        let expected_tx = verifier.parse_tx_receipt_proof(&receipt).unwrap().tx_hash;

        let verified = verifier
            .verify_finalized_receipt_evidence(
                &package,
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                expected_tx,
            )
            .unwrap();
        assert_eq!(
            verified.finalized_receipt().receipt().tx_hash(),
            expected_tx
        );
        assert!(verified.finalized_receipt().receipt().succeeded());
        assert_eq!(verified.package_hash(), sha256(&package));

        // A hypothetical newer local head cannot be substituted for the exact
        // historical consensus carried by the package.
        let mut newer = verified.consensus().clone();
        newer.execution_block_number += 1;
        newer.execution_block_hash = [0x99; 32];
        assert!(matches!(
            verifier.verify_execution_header(&execution, &newer),
            Err(VerifyError::ExecutionHeaderMismatch)
        ));
        verifier
            .verify_finalized_receipt_evidence(
                &package,
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                expected_tx,
            )
            .unwrap();
    }

    #[test]
    fn receipt_package_rejects_mixed_head_and_wrong_requested_transaction() {
        let verifier = Verifier::sepolia();
        let consensus = consensus_fixture();
        let execution = execution_fixture();
        let receipt = receipt_fixture();
        let finalized = finalized_receipt_fixture(&execution, &receipt);
        let expected_tx = verifier.parse_tx_receipt_proof(&receipt).unwrap().tx_hash;

        let mut parsed = verifier.parse_execution_header_proof(&execution).unwrap();
        let mut mixed_header = decode_header(&parsed.rlp_header).unwrap();
        mixed_header.number += 1;
        parsed.rlp_header = alloy_rlp::encode(&mixed_header);
        let mut mixed_execution = inner_prelude(super::super::KIND_EXECUTION_HEADER_PROOF);
        mixed_execution.extend_from_slice(&parsed.created_at_unix.to_le_bytes());
        write_section(&mut mixed_execution, &parsed.rlp_header);
        let mixed = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &consensus,
            &mixed_execution,
            &finalized,
        );
        assert!(matches!(
            verifier.verify_finalized_receipt_evidence(
                &mixed,
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                expected_tx,
            ),
            Err(VerifyError::ExecutionHeaderMismatch)
        ));

        let package = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &consensus,
            &execution,
            &finalized,
        );
        assert!(matches!(
            verifier.verify_finalized_receipt_evidence(
                &package,
                &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
                [0x55; 32],
            ),
            Err(VerifyError::UnexpectedTransaction)
        ));
    }

    #[test]
    fn caller_supplied_checkpoint_is_the_only_consensus_authority() {
        let verifier = Verifier::sepolia();
        let execution = execution_fixture();
        let receipt = receipt_fixture();
        let finalized = finalized_receipt_fixture(&execution, &receipt);
        let expected_tx = verifier.parse_tx_receipt_proof(&receipt).unwrap().tx_hash;
        let package = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &consensus_fixture(),
            &execution,
            &finalized,
        );
        assert!(matches!(
            verifier.verify_finalized_receipt_evidence(
                &package,
                &BeaconCheckpointRoot::sepolia([0x55; 32]),
                expected_tx,
            ),
            Err(VerifyError::ConsensusVerification(_))
        ));

        let legacy_self_authenticated = inner_prelude(1);
        let package = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &legacy_self_authenticated,
            &execution,
            &finalized,
        );
        assert!(matches!(
            verifier.parse_finalized_receipt_evidence(&package),
            Err(VerifyError::UntrustedHeader)
        ));
    }

    fn synthetic_account_sections() -> (Vec<u8>, Vec<u8>, VerifiedExecutionHeader, [u8; 20]) {
        let address = [0x11; 20];
        let account = TrieAccount {
            nonce: 7,
            balance: U256::from(123_456_u64),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };
        let key = Nibbles::unpack(keccak256(address));
        let mut trie = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([key]));
        trie.add_leaf(key, &alloy_rlp::encode(account));
        let state_root: [u8; 32] = trie.root().into();
        let proof = trie
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();

        let slot = 1_000;
        let header = Header {
            number: 42,
            state_root: B256::from(state_root),
            receipts_root: B256::repeat_byte(0x22),
            transactions_root: B256::repeat_byte(0x33),
            timestamp: sepolia_slot_start_unix(slot).unwrap(),
            ..Default::default()
        };
        let rlp_header = alloy_rlp::encode(&header);
        let mut execution = inner_prelude(super::super::KIND_EXECUTION_HEADER_PROOF);
        execution.extend_from_slice(&0_u64.to_le_bytes());
        write_section(&mut execution, &rlp_header);

        let mut account_bytes = inner_prelude(super::super::KIND_ACCOUNT_PROOF);
        account_bytes.extend_from_slice(&0_u64.to_le_bytes());
        account_bytes.extend_from_slice(&header.number.to_le_bytes());
        account_bytes.extend_from_slice(&header.hash_slow().0);
        account_bytes.extend_from_slice(&state_root);
        account_bytes.extend_from_slice(&address);
        account_bytes.extend_from_slice(&account.balance.to_be_bytes::<32>());
        account_bytes.extend_from_slice(&account.nonce.to_le_bytes());
        account_bytes.extend_from_slice(account.code_hash.as_slice());
        account_bytes.extend_from_slice(account.storage_root.as_slice());
        account_bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        for node in proof {
            write_section(&mut account_bytes, &node);
        }

        let consensus = VerifiedExecutionHeader {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            finalized_slot: slot,
            execution_block_number: header.number,
            execution_block_hash: header.hash_slow().0,
            state_root,
            receipts_root: header.receipts_root.0,
            beacon_transactions_root: [0x44; 32],
            checkpoint_root: CHECKPOINT_ROOT,
            provenance: ExecutionHeaderProvenance::HeliosFinalityUpdate,
            proof_bundle_hash: [0x55; 32],
        };
        (execution, account_bytes, consensus, address)
    }

    #[test]
    fn account_sections_are_bound_to_their_exact_historical_head_and_subject() {
        let verifier = Verifier::sepolia();
        let (execution, account, historical, address) = synthetic_account_sections();
        let (_, verified) = verifier
            .verify_account_sections(&execution, &account, &historical, address)
            .unwrap();
        assert_eq!(verified.address(), address);
        assert_eq!(verified.block_hash(), historical.execution_block_hash());

        let mut newer = historical.clone();
        newer.execution_block_number += 1;
        newer.execution_block_hash = [0x77; 32];
        assert!(matches!(
            verifier.verify_account_sections(&execution, &account, &newer, address),
            Err(VerifyError::ExecutionHeaderMismatch)
        ));
        assert!(matches!(
            verifier.verify_account_sections(&execution, &account, &historical, [0x12; 20]),
            Err(VerifyError::UnexpectedAccount)
        ));
    }

    #[test]
    fn builders_are_byte_stable_and_preserve_exact_validated_sections() {
        let verifier = Verifier::sepolia();
        let consensus = consensus_fixture();
        let execution = execution_fixture();
        let receipt = receipt_fixture();
        let finalized = finalized_receipt_fixture(&execution, &receipt);
        let first = verifier
            .build_finalized_receipt_evidence(1_800_000_000, &consensus, &execution, &finalized)
            .unwrap();
        let second = verifier
            .build_finalized_receipt_evidence(1_800_000_000, &consensus, &execution, &finalized)
            .unwrap();
        assert_eq!(first, second);
        let parsed = verifier.parse_finalized_receipt_evidence(&first).unwrap();
        assert_eq!(parsed.created_at_unix(), 1_800_000_000);
        assert_eq!(parsed.consensus_bundle_bytes(), consensus);
        assert_eq!(parsed.execution_header_bytes(), execution);
        assert_eq!(parsed.finalized_receipt_bytes(), finalized);

        let (account_execution, account, _, _) = synthetic_account_sections();
        let first = verifier
            .build_account_state_evidence(1_800_000_001, &consensus, &account_execution, &account)
            .unwrap();
        let second = verifier
            .build_account_state_evidence(1_800_000_001, &consensus, &account_execution, &account)
            .unwrap();
        assert_eq!(first, second);
        let parsed = verifier.parse_account_state_evidence(&first).unwrap();
        assert_eq!(parsed.created_at_unix(), 1_800_000_001);
        assert_eq!(parsed.consensus_bundle_bytes(), consensus);
        assert_eq!(parsed.execution_header_bytes(), account_execution);
        assert_eq!(parsed.account_proof_bytes(), account);
    }

    #[test]
    fn parser_rejects_wrong_kind_trailing_bytes_and_inner_decompression_bomb() {
        let verifier = Verifier::sepolia();
        let consensus = consensus_fixture();
        let execution = execution_fixture();
        let receipt = receipt_fixture();
        let finalized = finalized_receipt_fixture(&execution, &receipt);

        let wrong_kind = envelope(
            KIND_ACCOUNT_STATE_EVIDENCE,
            &consensus,
            &execution,
            &finalized,
        );
        assert!(matches!(
            verifier.parse_finalized_receipt_evidence(&wrong_kind),
            Err(VerifyError::UnsupportedKind(KIND_ACCOUNT_STATE_EVIDENCE))
        ));

        let mut trailing = envelope(
            KIND_FINALIZED_RECEIPT_EVIDENCE,
            &consensus,
            &execution,
            &finalized,
        );
        trailing.push(0);
        assert!(matches!(
            verifier.parse_finalized_receipt_evidence(&trailing),
            Err(VerifyError::Malformed("trailing bytes"))
        ));

        let mut bomb = inner_prelude(super::super::KIND_COMPRESSED_BUNDLE);
        bomb.extend_from_slice(&0_u64.to_le_bytes());
        bomb.push(super::super::COMPRESSION_ALGORITHM_GZIP);
        bomb.extend_from_slice(&((MAX_BUNDLE_BYTES + 1) as u64).to_le_bytes());
        bomb.extend_from_slice(&[0; 32]);
        write_section(&mut bomb, &[0]);
        let account_package = envelope(KIND_ACCOUNT_STATE_EVIDENCE, &consensus, &execution, &bomb);
        assert!(matches!(
            verifier.parse_account_state_evidence(&account_package),
            Err(VerifyError::OversizedDecompressedBundle)
        ));
    }

    #[test]
    fn envelope_enforces_aggregate_and_per_section_bounds_before_allocation() {
        assert!(matches!(
            Verifier::sepolia()
                .parse_account_state_evidence(&vec![0; MAX_COMPOSITE_EVIDENCE_BYTES + 1]),
            Err(VerifyError::OversizedCompositeEvidence)
        ));

        let mut oversized_section = Vec::new();
        oversized_section.extend_from_slice(COMPOSITE_MAGIC);
        oversized_section.push(COMPOSITE_VERSION);
        oversized_section.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        oversized_section.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        oversized_section.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        oversized_section.push(KIND_ACCOUNT_STATE_EVIDENCE);
        oversized_section.extend_from_slice(&0_u64.to_le_bytes());
        oversized_section.extend_from_slice(&((MAX_BUNDLE_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            Verifier::sepolia().parse_account_state_evidence(&oversized_section),
            Err(VerifyError::Malformed("composite section exceeds limit"))
        ));
    }
}
