use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_trie::Nibbles;
use alloy_trie::proof::verify_proof;

use super::{
    Cursor, KIND_STORAGE_PROOF, MAX_PROOF_NODE_BYTES, MAX_PROOF_NODES, Result, VerifiedAccount,
    Verifier, VerifyError, sha256,
};

/// One contract-storage proof bound to an already verified account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProofBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub account_address: [u8; 20],
    pub storage_root: [u8; 32],
    pub key: [u8; 32],
    pub value: U256,
    pub proof: Vec<Vec<u8>>,
}

/// Storage value authenticated against the storage root of a verified account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStorageValue {
    chain_id: u64,
    network: String,
    block_number: u64,
    block_hash: [u8; 32],
    account_address: [u8; 20],
    storage_root: [u8; 32],
    key: [u8; 32],
    value: U256,
    proof_bundle_hash: [u8; 32],
}

impl VerifiedStorageValue {
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

    pub fn account_address(&self) -> [u8; 20] {
        self.account_address
    }

    pub fn storage_root(&self) -> [u8; 32] {
        self.storage_root
    }

    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn value(&self) -> U256 {
        self.value
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

impl Verifier {
    pub fn parse_storage_proof(&self, bytes: &[u8]) -> Result<StorageProofBundle> {
        let canonical = self.canonical_bundle(bytes)?;
        parse_storage_proof(&canonical, self.chain_id, self.network)
    }

    /// Verifies one storage slot against an account whose storage root was
    /// already authenticated against the block state root.
    pub fn verify_storage_proof(
        &self,
        bytes: &[u8],
        account: &VerifiedAccount,
    ) -> Result<VerifiedStorageValue> {
        if account.chain_id() != self.chain_id || account.network() != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: account.chain_id(),
                network: account.network().to_owned(),
            });
        }
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_storage_proof(&canonical, self.chain_id, self.network)?;
        verify_storage(bundle, account, sha256(&canonical))
    }
}

fn parse_storage_proof(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<StorageProofBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_STORAGE_PROOF {
        return Err(VerifyError::UnsupportedKind(prelude.kind));
    }

    let created_at_unix = cursor.u64()?;
    let block_number = cursor.u64()?;
    let block_hash = cursor.array32()?;
    let account_address = cursor.array20()?;
    let storage_root = cursor.array32()?;
    let key = cursor.array32()?;
    let value = U256::from_be_bytes(cursor.array32()?);

    let count = cursor.u32()? as usize;
    if count == 0 {
        return Err(VerifyError::Malformed("storage proof is empty"));
    }
    if count > MAX_PROOF_NODES {
        return Err(VerifyError::TooManyProofNodes);
    }
    let mut proof = Vec::with_capacity(count);
    for _ in 0..count {
        let node = cursor.sized_bytes(MAX_PROOF_NODE_BYTES, "storage proof node exceeds limit")?;
        if node.is_empty() {
            return Err(VerifyError::Malformed("storage proof node is empty"));
        }
        proof.push(node);
    }
    cursor.finish()?;

    Ok(StorageProofBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        block_number,
        block_hash,
        account_address,
        storage_root,
        key,
        value,
        proof,
    })
}

fn verify_storage(
    bundle: StorageProofBundle,
    account: &VerifiedAccount,
    proof_bundle_hash: [u8; 32],
) -> Result<VerifiedStorageValue> {
    if bundle.chain_id != account.chain_id()
        || bundle.network != account.network()
        || bundle.block_number != account.block_number()
        || bundle.block_hash != account.block_hash()
        || bundle.account_address != account.address()
        || bundle.storage_root != account.storage_root()
    {
        return Err(VerifyError::CheckpointMismatch);
    }

    let expected = if bundle.value == U256::ZERO {
        None
    } else {
        Some(alloy_rlp::encode(bundle.value))
    };
    let nodes = bundle
        .proof
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect::<Vec<_>>();

    verify_proof(
        B256::from(bundle.storage_root),
        Nibbles::unpack(keccak256(bundle.key)),
        expected,
        nodes.iter(),
    )
    .map_err(|error| VerifyError::InvalidAccountProof(error.to_string()))?;

    Ok(VerifiedStorageValue {
        chain_id: bundle.chain_id,
        network: bundle.network,
        block_number: bundle.block_number,
        block_hash: bundle.block_hash,
        account_address: bundle.account_address,
        storage_root: bundle.storage_root,
        key: bundle.key,
        value: bundle.value,
        proof_bundle_hash,
    })
}

#[cfg(test)]
mod tests {
    use alloy_trie::proof::ProofRetainer;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, KECCAK_EMPTY, TrieAccount};

    use super::*;
    use crate::{
        BASE_SEPOLIA_CHAIN_ID, BASE_SEPOLIA_NETWORK, MAGIC, MemoryAccountStore, PinnedCheckpoint,
        VERSION,
    };

    fn write_string(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn prelude(kind: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&BASE_SEPOLIA_CHAIN_ID.to_le_bytes());
        write_string(&mut out, BASE_SEPOLIA_NETWORK);
        out.push(kind);
        out
    }

    #[test]
    fn verifies_base_sepolia_storage_value_against_verified_account() {
        let address = [0x44; 20];
        let storage_key = [0x77; 32];
        let storage_value = U256::from(123_456_789u64);

        let storage_path = Nibbles::unpack(keccak256(storage_key));
        let mut storage_builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([storage_path]));
        storage_builder.add_leaf(storage_path, &alloy_rlp::encode(storage_value));
        let storage_root: [u8; 32] = storage_builder.root().into();
        let storage_proof = storage_builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();

        let account = TrieAccount {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: B256::from(storage_root),
            code_hash: KECCAK_EMPTY,
        };
        let account_path = Nibbles::unpack(keccak256(address));
        let mut account_builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([account_path]));
        account_builder.add_leaf(account_path, &alloy_rlp::encode(account));
        let state_root: [u8; 32] = account_builder.root().into();
        let account_proof = account_builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node.to_vec())
            .collect::<Vec<_>>();

        let block_hash = [0x55; 32];

        let mut account_bytes = prelude(crate::KIND_ACCOUNT_PROOF);
        account_bytes.extend_from_slice(&1_780_000_000u64.to_le_bytes());
        account_bytes.extend_from_slice(&77u64.to_le_bytes());
        account_bytes.extend_from_slice(&block_hash);
        account_bytes.extend_from_slice(&state_root);
        account_bytes.extend_from_slice(&address);
        account_bytes.extend_from_slice(&account.balance.to_be_bytes::<32>());
        account_bytes.extend_from_slice(&account.nonce.to_le_bytes());
        account_bytes.extend_from_slice(account.code_hash.as_slice());
        account_bytes.extend_from_slice(account.storage_root.as_slice());
        account_bytes.extend_from_slice(&(account_proof.len() as u32).to_le_bytes());
        for node in account_proof {
            write_bytes(&mut account_bytes, &node);
        }

        let verifier = Verifier::base_sepolia();
        let verified_account = verifier
            .verify_and_import(
                &account_bytes,
                &PinnedCheckpoint::base_sepolia(77, block_hash, state_root),
                &mut MemoryAccountStore::default(),
            )
            .unwrap();

        let mut storage_bytes = prelude(KIND_STORAGE_PROOF);
        storage_bytes.extend_from_slice(&1_780_000_001u64.to_le_bytes());
        storage_bytes.extend_from_slice(&77u64.to_le_bytes());
        storage_bytes.extend_from_slice(&block_hash);
        storage_bytes.extend_from_slice(&address);
        storage_bytes.extend_from_slice(&storage_root);
        storage_bytes.extend_from_slice(&storage_key);
        storage_bytes.extend_from_slice(&storage_value.to_be_bytes::<32>());
        storage_bytes.extend_from_slice(&(storage_proof.len() as u32).to_le_bytes());
        for node in storage_proof {
            write_bytes(&mut storage_bytes, &node);
        }

        let verified = verifier
            .verify_storage_proof(&storage_bytes, &verified_account)
            .unwrap();
        assert_eq!(verified.value(), storage_value);
        assert_eq!(verified.key(), storage_key);
    }
}
