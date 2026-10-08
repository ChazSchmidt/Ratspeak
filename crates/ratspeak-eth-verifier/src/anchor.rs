use super::{PinnedCheckpoint, VerifiedExecutionBlock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorAssurance {
    EthereumFinalized,
    SequencerAuthenticated,
    RollupConfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvmAnchor {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    transactions_root: [u8; 32],
    receipts_root: [u8; 32],
    timestamp: u64,
    assurance: AnchorAssurance,
    evidence_hash: [u8; 32],
}

impl VerifiedEvmAnchor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        chain_id: u64,
        network: impl Into<String>,
        block_number: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        transactions_root: [u8; 32],
        receipts_root: [u8; 32],
        timestamp: u64,
        assurance: AnchorAssurance,
        evidence_hash: [u8; 32],
    ) -> Self {
        Self {
            chain_id,
            network: network.into(),
            block_number,
            block_hash,
            parent_hash,
            state_root,
            transactions_root,
            receipts_root,
            timestamp,
            assurance,
            evidence_hash,
        }
    }

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
    pub fn assurance(&self) -> AnchorAssurance {
        self.assurance
    }
    pub fn evidence_hash(&self) -> [u8; 32] {
        self.evidence_hash
    }

    pub fn pinned_checkpoint(&self) -> PinnedCheckpoint {
        PinnedCheckpoint::for_network(
            self.chain_id,
            &self.network,
            self.block_number,
            self.block_hash,
            self.state_root,
        )
        .expect("verified anchor always uses a supported network")
    }
}

impl From<&VerifiedExecutionBlock> for VerifiedEvmAnchor {
    fn from(block: &VerifiedExecutionBlock) -> Self {
        Self::new(
            block.chain_id(),
            block.network(),
            block.execution_block_number(),
            block.execution_block_hash(),
            block.parent_hash(),
            block.state_root(),
            block.transactions_root(),
            block.receipts_root(),
            0,
            AnchorAssurance::EthereumFinalized,
            block.proof_bundle_hash(),
        )
    }
}
