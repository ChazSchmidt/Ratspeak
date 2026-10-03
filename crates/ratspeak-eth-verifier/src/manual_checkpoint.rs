//! Bounded, transport-neutral manual checkpoint cards.
//!
//! A card is an untrusted container for a user-selected weak-subjectivity
//! checkpoint and its canonical Helios bootstrap.  The outer checkpoint root
//! is intentionally separate from the inner consensus bundle: importing a
//! card still requires the node policy and native user approval.

use std::fmt;

use super::{
    Cursor, KIND_PINNED_CONSENSUS_BOOTSTRAP, MAX_BUNDLE_BYTES, Result, SEPOLIA_CHAIN_ID,
    SEPOLIA_NETWORK, Verifier, VerifyError,
};

const MAGIC: &[u8; 8] = b"RSETHCF1";
const VERSION: u8 = 1;
const MAX_NETWORK_BYTES: usize = 32;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 8 + 2 + SEPOLIA_NETWORK.len() + 8 + 32 + 4;
const FILE_FINGERPRINT_DOMAIN: &[u8] = b"ratspeak-eth-manual-checkpoint-file-v1\0";

/// Maximum encoded size of a selected manual checkpoint card.
pub const MAX_MANUAL_CHECKPOINT_FILE_BYTES: usize = MAX_BUNDLE_BYTES;

/// Returns the stable, domain-separated fingerprint used for native manual
/// checkpoint provenance. This identifies exact bytes; it does not
/// authenticate their publisher or establish checkpoint authority.
pub fn manual_checkpoint_file_fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(FILE_FINGERPRINT_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A parsed manual checkpoint card.  This remains untrusted until the node
/// policy verifies its bootstrap from the outer root and a native surface
/// explicitly approves the resulting review.
pub struct ManualCheckpointFile {
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    bootstrap_bundle: Vec<u8>,
}

impl ManualCheckpointFile {
    /// Parses the exact closed card format and validates its structural
    /// consensus-bundle constraints.  This does not establish checkpoint
    /// trust or perform Helios cryptographic verification.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANUAL_CHECKPOINT_FILE_BYTES {
            return Err(VerifyError::OversizedBundle);
        }
        let mut cursor = FileCursor::new(bytes);
        if cursor.take(MAGIC.len())? != MAGIC {
            return Err(VerifyError::WrongMagic);
        }
        let version = cursor.u8()?;
        if version != VERSION {
            return Err(VerifyError::UnsupportedVersion(version));
        }
        let chain_id = cursor.u64()?;
        let network = cursor.string(MAX_NETWORK_BYTES)?;
        if chain_id != SEPOLIA_CHAIN_ID || network != SEPOLIA_NETWORK {
            return Err(VerifyError::UnsupportedNetwork { chain_id, network });
        }
        let checkpoint_epoch = cursor.u64()?;
        if checkpoint_epoch == 0 {
            return Err(VerifyError::Malformed("checkpoint epoch is zero"));
        }
        let checkpoint_root = cursor.array32()?;
        if checkpoint_root == [0; 32] {
            return Err(VerifyError::Malformed("checkpoint root is zero"));
        }
        let bootstrap_len = cursor.u32()? as usize;
        if bootstrap_len == 0 {
            return Err(VerifyError::EmptyConsensusPayload);
        }
        if bootstrap_len > MAX_BUNDLE_BYTES {
            return Err(VerifyError::OversizedConsensusPayload);
        }
        if bootstrap_len > MAX_MANUAL_CHECKPOINT_FILE_BYTES.saturating_sub(cursor.pos) {
            return Err(VerifyError::OversizedConsensusPayload);
        }
        let bootstrap_bundle = cursor.take(bootstrap_len)?.to_vec();
        cursor.finish()?;

        // Cards carry the canonical uncompressed pinned-bootstrap frame.  In
        // particular, a compressed or other application frame cannot hide a
        // second authority-bearing object inside this container.
        let mut bundle_cursor = Cursor::new(&bootstrap_bundle)?;
        let prelude = bundle_cursor.prelude(SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK)?;
        if prelude.kind != KIND_PINNED_CONSENSUS_BOOTSTRAP {
            return Err(VerifyError::UnsupportedKind(prelude.kind));
        }
        let parsed = Verifier::sepolia().parse_consensus_bootstrap(&bootstrap_bundle)?;
        if !parsed.updates_ssz.is_empty() || parsed.finality_update_ssz.is_some() {
            return Err(VerifyError::Malformed(
                "manual checkpoint bootstrap contains updates or finality",
            ));
        }

        Ok(Self {
            checkpoint_epoch,
            checkpoint_root,
            bootstrap_bundle,
        })
    }

    pub fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    /// Returns the exact inner bootstrap bytes.  The bytes are still
    /// untrusted; callers must pass them through node policy verification.
    pub fn bootstrap_bundle(&self) -> &[u8] {
        &self.bootstrap_bundle
    }

    /// Encodes this parsed card byte-for-byte deterministically.
    pub fn encode(&self) -> Vec<u8> {
        encode_inner(
            self.checkpoint_epoch,
            self.checkpoint_root,
            &self.bootstrap_bundle,
        )
    }
}

impl fmt::Debug for ManualCheckpointFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManualCheckpointFile")
            .field("checkpoint_epoch", &self.checkpoint_epoch)
            .field("checkpoint_root", &self.checkpoint_root)
            .field("bootstrap_bytes", &self.bootstrap_bundle.len())
            .finish_non_exhaustive()
    }
}

/// Encodes an untrusted Sepolia checkpoint card.  The inner bundle is parsed
/// by the same strict rules as [`ManualCheckpointFile::parse`].
pub fn encode_manual_checkpoint_file(
    checkpoint_epoch: u64,
    checkpoint_root: [u8; 32],
    bootstrap_bundle: &[u8],
) -> Result<Vec<u8>> {
    if checkpoint_epoch == 0 {
        return Err(VerifyError::Malformed("checkpoint epoch is zero"));
    }
    if checkpoint_root == [0; 32] {
        return Err(VerifyError::Malformed("checkpoint root is zero"));
    }
    if bootstrap_bundle.is_empty() {
        return Err(VerifyError::EmptyConsensusPayload);
    }
    if bootstrap_bundle.len() > u32::MAX as usize
        || bootstrap_bundle.len() > MAX_MANUAL_CHECKPOINT_FILE_BYTES.saturating_sub(HEADER_BYTES)
    {
        return Err(VerifyError::OversizedConsensusPayload);
    }
    let bytes = encode_inner(checkpoint_epoch, checkpoint_root, bootstrap_bundle);
    ManualCheckpointFile::parse(&bytes)?;
    Ok(bytes)
}

fn encode_inner(epoch: u64, root: [u8; 32], bootstrap_bundle: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + bootstrap_bundle.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
    bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
    bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
    bytes.extend_from_slice(&epoch.to_le_bytes());
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&(bootstrap_bundle.len() as u32).to_le_bytes());
    bytes.extend_from_slice(bootstrap_bundle);
    bytes
}

struct FileCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> FileCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(VerifyError::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(VerifyError::Malformed("unexpected end of checkpoint file"));
        }
        let start = self.pos;
        self.pos = end;
        Ok(&self.bytes[start..end])
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let mut value = [0; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(value))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(value))
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        let mut value = [0; 32];
        value.copy_from_slice(self.take(32)?);
        Ok(value)
    }

    fn string(&mut self, max_len: usize) -> Result<String> {
        let mut length = [0; 2];
        length.copy_from_slice(self.take(2)?);
        let length = u16::from_le_bytes(length) as usize;
        if length > max_len {
            return Err(VerifyError::Malformed("network exceeds limit"));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| VerifyError::Malformed("invalid network utf-8"))
    }

    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifyError::Malformed("trailing checkpoint file bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap(updates: u16, finality: u8) -> Vec<u8> {
        // The parser tests only exercise framing and bundle-kind boundaries;
        // a nonempty payload is enough to reach those checks.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RSETH1");
        bytes.push(1);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(KIND_PINNED_CONSENSUS_BOOTSTRAP);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&updates.to_le_bytes());
        bytes.push(finality);
        if updates != 0 {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(0);
        }
        if finality == 1 {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn frame_is_byte_stable_and_debug_redacts_bytes() {
        let bundle = bootstrap(0, 0);
        let encoded = encode_manual_checkpoint_file(7, [1; 32], &bundle).unwrap();
        let parsed = ManualCheckpointFile::parse(&encoded).unwrap();
        assert_eq!(parsed.encode(), encoded);
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("RSETH1"));
        assert!(debug.contains("bootstrap_bytes"));
    }

    #[test]
    fn rejects_wrong_and_truncated_frames() {
        let bundle = bootstrap(0, 0);
        let encoded = encode_manual_checkpoint_file(7, [1; 32], &bundle).unwrap();
        for size in [0, 1, encoded.len() - 1] {
            assert!(ManualCheckpointFile::parse(&encoded[..size]).is_err());
        }
        let mut wrong = encoded.clone();
        wrong[0] ^= 1;
        assert!(matches!(
            ManualCheckpointFile::parse(&wrong),
            Err(VerifyError::WrongMagic)
        ));
        let mut version = encoded;
        version[8] = 2;
        assert!(matches!(
            ManualCheckpointFile::parse(&version),
            Err(VerifyError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_root_epoch_network_trailing_and_updates() {
        let bundle = bootstrap(0, 0);
        for (epoch, root) in [(0, [1; 32]), (7, [0; 32])] {
            assert!(encode_manual_checkpoint_file(epoch, root, &bundle).is_err());
        }
        let mut wrong_network = encode_inner(7, [1; 32], &bundle);
        let network_start = MAGIC.len() + 1 + 8 + 2;
        wrong_network[network_start] ^= 1;
        assert!(ManualCheckpointFile::parse(&wrong_network).is_err());
        let mut trailing = encode_manual_checkpoint_file(7, [1; 32], &bundle).unwrap();
        trailing.push(0);
        assert!(ManualCheckpointFile::parse(&trailing).is_err());
        assert!(encode_manual_checkpoint_file(7, [1; 32], &bootstrap(1, 0)).is_err());
        assert!(encode_manual_checkpoint_file(7, [1; 32], &bootstrap(0, 1)).is_err());
    }

    #[test]
    fn rejects_oversized_length_wrong_inner_kind_network_and_malformed_inner() {
        let bundle = bootstrap(0, 0);
        let encoded = encode_manual_checkpoint_file(7, [1; 32], &bundle).unwrap();
        let length_offset = HEADER_BYTES - 4;
        let mut oversized = encoded.clone();
        oversized[length_offset..length_offset + 4]
            .copy_from_slice(&((MAX_BUNDLE_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            ManualCheckpointFile::parse(&oversized),
            Err(VerifyError::OversizedConsensusPayload)
        ));

        let inner_kind_offset = 6 + 1 + 8 + 2 + SEPOLIA_NETWORK.len();
        let mut wrong_kind_bundle = bundle.clone();
        wrong_kind_bundle[inner_kind_offset] = 1;
        assert!(encode_manual_checkpoint_file(7, [1; 32], &wrong_kind_bundle).is_err());

        let mut wrong_network_bundle = bundle;
        wrong_network_bundle[6 + 1 + 8 + 2] ^= 1;
        assert!(encode_manual_checkpoint_file(7, [1; 32], &wrong_network_bundle).is_err());
        assert!(encode_manual_checkpoint_file(7, [1; 32], &[1, 2, 3]).is_err());
    }
}
