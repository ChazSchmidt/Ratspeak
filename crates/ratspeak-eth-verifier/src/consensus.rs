use std::collections::HashSet;
use std::fmt;
#[cfg(test)]
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{B256, fixed_bytes};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::{
    Bootstrap, ExecutionPayloadHeader, FinalityUpdate, Fork, Forks, LightClientHeader,
    LightClientStore, Update,
};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update, verify_bootstrap, verify_finality_update,
    verify_update,
};
use serde::Deserialize;
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;
use ssz::Decode;

use super::{
    Cursor, KIND_PINNED_CONSENSUS_BOOTSTRAP, MAGIC, MAX_BUNDLE_BYTES, Result, SEPOLIA_CHAIN_ID,
    SEPOLIA_NETWORK, VERSION, Verifier, VerifyError, sha256,
};

pub const SEPOLIA_GENESIS_TIME: u64 = 1_655_733_600;
pub const SEPOLIA_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
    0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
];
pub const SEPOLIA_SECONDS_PER_SLOT: u64 = 12;
pub const SEPOLIA_SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = 32 * 256;
const MAX_CHECKPOINT_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
const MAX_BOOTSTRAP_BYTES: usize = 1024 * 1024;
const MAX_CONSENSUS_UPDATE_BYTES: usize = 512 * 1024;
const MAX_CONSENSUS_UPDATES: usize = 128;
const BEACON_JSON_TAG: &[u8; 8] = b"RSJSON1\0";
const MAX_BEACON_JSON_DEPTH: usize = 32;
const MAX_BEACON_JSON_NODES: usize = 16_384;
const MAX_BEACON_JSON_CONTAINER_ITEMS: usize = 4_096;
const MAX_BEACON_JSON_OBJECT_FIELDS: usize = 128;
const MAX_BEACON_JSON_STRING_BYTES: usize = 16 * 1024;

/// A weak-subjectivity checkpoint root supplied independently of a bundle.
///
/// This is a cryptographic verification input, not evidence that the
/// application approved or cross-checked the root. That trust decision belongs
/// to the field-node layer; bundle parsing has no path that can create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconCheckpointRoot {
    chain_id: u64,
    network: &'static str,
    beacon_block_root: [u8; 32],
}

impl BeaconCheckpointRoot {
    pub fn sepolia(beacon_block_root: [u8; 32]) -> Self {
        Self {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK,
            beacon_block_root,
        }
    }

    pub fn beacon_block_root(&self) -> [u8; 32] {
        self.beacon_block_root
    }
}

/// Transport-neutral consensus material. The checkpoint root is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusBootstrapBundle {
    pub chain_id: u64,
    pub network: String,
    pub created_at_unix: u64,
    /// SSZ bytes, or an explicitly tagged standard Beacon JSON response.
    pub bootstrap_ssz: Vec<u8>,
    /// SSZ bytes, or explicitly tagged standard Beacon JSON response items.
    pub updates_ssz: Vec<Vec<u8>>,
    /// SSZ bytes, or an explicitly tagged standard Beacon JSON response.
    pub finality_update_ssz: Option<Vec<u8>>,
}

/// Frames one bounded Beacon light-client bootstrap for verification against
/// a checkpoint root established elsewhere. The returned bytes carry no trust
/// root and cannot authenticate themselves.
pub fn encode_pinned_consensus_bootstrap(
    created_at_unix: u64,
    bootstrap_payload: &[u8],
) -> Result<Vec<u8>> {
    if created_at_unix == 0 {
        return Err(VerifyError::Malformed("consensus capture time is zero"));
    }
    if bootstrap_payload.is_empty() {
        return Err(VerifyError::EmptyConsensusPayload);
    }
    if bootstrap_payload.len() > MAX_BOOTSTRAP_BYTES {
        return Err(VerifyError::OversizedConsensusPayload);
    }
    let payload_len = u32::try_from(bootstrap_payload.len())
        .map_err(|_| VerifyError::OversizedConsensusPayload)?;
    let mut bytes = Vec::with_capacity(
        MAGIC.len()
            + 1
            + 8
            + 2
            + SEPOLIA_NETWORK.len()
            + 1
            + 8
            + 4
            + bootstrap_payload.len()
            + 2
            + 1,
    );
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
    bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
    bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
    bytes.push(KIND_PINNED_CONSENSUS_BOOTSTRAP);
    bytes.extend_from_slice(&created_at_unix.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(bootstrap_payload);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.push(0);
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::OversizedBundle);
    }
    Ok(bytes)
}

/// How canonicality and finality were established for an execution header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionHeaderProvenance {
    /// Inherited from the supplied weak-subjectivity checkpoint anchor.
    CheckpointAnchor,
    /// Advanced beyond that checkpoint by a Helios-verified consensus update.
    HeliosFinalityUpdate,
}

/// Execution commitments linked to a checkpoint anchor and verified by Helios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExecutionHeader {
    pub(super) chain_id: u64,
    pub(super) network: String,
    pub(super) finalized_slot: u64,
    pub(super) execution_block_number: u64,
    pub(super) execution_block_hash: [u8; 32],
    pub(super) state_root: [u8; 32],
    pub(super) receipts_root: [u8; 32],
    pub(super) beacon_transactions_root: [u8; 32],
    pub(super) checkpoint_root: [u8; 32],
    pub(super) provenance: ExecutionHeaderProvenance,
    pub(super) proof_bundle_hash: [u8; 32],
}

impl VerifiedExecutionHeader {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }

    /// Trustworthy wall-clock time implied by the consensus-verified slot.
    pub fn finalized_at_unix(&self) -> Result<u64> {
        sepolia_slot_start_unix(self.finalized_slot)
    }

    pub fn execution_block_number(&self) -> u64 {
        self.execution_block_number
    }

    pub fn execution_block_hash(&self) -> [u8; 32] {
        self.execution_block_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }

    /// SSZ root of the Beacon execution payload's transaction list.
    ///
    /// This is not the Merkle-Patricia transactions root from the RLP
    /// execution block header and cannot authenticate an execution trie proof.
    pub fn beacon_transactions_root(&self) -> [u8; 32] {
        self.beacon_transactions_root
    }

    pub fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn provenance(&self) -> ExecutionHeaderProvenance {
        self.provenance
    }

    pub fn proof_bundle_hash(&self) -> [u8; 32] {
        self.proof_bundle_hash
    }
}

impl Verifier {
    pub fn parse_consensus_bootstrap(&self, bytes: &[u8]) -> Result<ConsensusBootstrapBundle> {
        let canonical = self.canonical_bundle(bytes)?;
        parse_consensus_bootstrap(&canonical, self.chain_id, self.network)
    }

    /// Verifies consensus material from an independently installed checkpoint.
    pub fn verify_consensus_bootstrap(
        &self,
        bytes: &[u8],
        checkpoint: &BeaconCheckpointRoot,
    ) -> Result<VerifiedExecutionHeader> {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::InvalidLocalClock)?
            .as_secs();
        self.verify_consensus_bootstrap_at_unix(bytes, checkpoint, unix_seconds)
    }

    /// Verifies consensus material using an explicit trusted clock sample.
    ///
    /// Daemons use this form so their policy clock can be injected in tests.
    /// The clock is not a substitute for the separately configured checkpoint.
    pub fn verify_consensus_bootstrap_at_unix(
        &self,
        bytes: &[u8],
        checkpoint: &BeaconCheckpointRoot,
        unix_seconds: u64,
    ) -> Result<VerifiedExecutionHeader> {
        self.validate_consensus_checkpoint(checkpoint)?;
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_consensus_bootstrap(&canonical, self.chain_id, self.network)?;
        verify_consensus_bundle(
            bundle,
            checkpoint,
            sepolia_slot_at_unix(unix_seconds)?,
            sha256(&canonical),
        )
    }

    /// Re-verifies a previously retained canonical consensus proof at the
    /// proof's own terminal signature slot. This establishes only the same
    /// cryptographic chain from `checkpoint`; the caller remains responsible
    /// for proving that the checkpoint was independently trusted and had not
    /// expired or been revoked when this evidence was finalized.
    pub fn reverify_historical_consensus_bootstrap(
        &self,
        bytes: &[u8],
        checkpoint: &BeaconCheckpointRoot,
    ) -> Result<VerifiedExecutionHeader> {
        self.validate_consensus_checkpoint(checkpoint)?;
        let canonical = self.canonical_bundle(bytes)?;
        let bundle = parse_consensus_bootstrap(&canonical, self.chain_id, self.network)?;
        let terminal_slot = consensus_bundle_terminal_slot(&bundle)?;
        verify_consensus_bundle(bundle, checkpoint, terminal_slot, sha256(&canonical))
    }

    fn validate_consensus_checkpoint(&self, checkpoint: &BeaconCheckpointRoot) -> Result<()> {
        if checkpoint.chain_id != self.chain_id || checkpoint.network != self.network {
            return Err(VerifyError::UnsupportedNetwork {
                chain_id: checkpoint.chain_id,
                network: checkpoint.network.to_owned(),
            });
        }
        Ok(())
    }
}

fn consensus_bundle_terminal_slot(bundle: &ConsensusBootstrapBundle) -> Result<u64> {
    let bootstrap = decode_bootstrap(&bundle.bootstrap_ssz)?;
    let mut terminal_slot = bootstrap.header().beacon().slot;
    for encoded in &bundle.updates_ssz {
        let update = decode_update(encoded)?;
        terminal_slot = terminal_slot.max(*update.signature_slot());
    }
    if let Some(encoded) = &bundle.finality_update_ssz {
        let finality = decode_finality_update(encoded)?;
        terminal_slot = terminal_slot.max(*finality.signature_slot());
    }
    Ok(terminal_slot)
}

/// Converts a local Unix clock sample to a Sepolia consensus slot.
pub fn sepolia_slot_at_unix(unix_seconds: u64) -> Result<u64> {
    let since_genesis = unix_seconds
        .checked_sub(SEPOLIA_GENESIS_TIME)
        .ok_or(VerifyError::InvalidLocalClock)?;
    Ok(since_genesis / SEPOLIA_SECONDS_PER_SLOT)
}

/// Returns the protocol-defined Unix start time for a Sepolia slot.
pub fn sepolia_slot_start_unix(slot: u64) -> Result<u64> {
    slot.checked_mul(SEPOLIA_SECONDS_PER_SLOT)
        .and_then(|seconds| SEPOLIA_GENESIS_TIME.checked_add(seconds))
        .ok_or(VerifyError::InvalidLocalClock)
}

/// Decodes only enough untrusted update metadata for bounded REST pagination.
/// Cryptographic authority still requires `verify_consensus_bootstrap`.
pub fn sepolia_consensus_update_slot(encoded: &[u8]) -> Result<u64> {
    let update = decode_update(encoded)?;
    Ok(update.attested_header().beacon().slot)
}

/// Tags one bounded Beacon REST JSON response for independent downstream decoding.
///
/// The tag prevents an SSZ payload from being reinterpreted based on its first
/// byte. The original JSON bytes remain intact so duplicate keys and the exact
/// response schema are checked again by every verifier.
pub fn tag_beacon_json_payload(json: &[u8]) -> Result<Vec<u8>> {
    let _ = bounded_json_value(json)?;
    let mut tagged = Vec::with_capacity(BEACON_JSON_TAG.len() + json.len());
    tagged.extend_from_slice(BEACON_JSON_TAG);
    tagged.extend_from_slice(json);
    Ok(tagged)
}

/// Splits a standard Beacon update array without normalizing its elements.
///
/// Each returned element retains its original JSON representation and is
/// tagged for independent schema and cryptographic verification later.
pub fn split_and_tag_beacon_json_updates(
    json: &[u8],
    maximum_updates: usize,
) -> Result<Vec<Vec<u8>>> {
    if maximum_updates == 0 || maximum_updates > MAX_CONSENSUS_UPDATES {
        return Err(VerifyError::ConsensusJsonLimit);
    }
    let value = bounded_json_value(json)?;
    let item_count = value
        .as_array()
        .ok_or(VerifyError::ConsensusJsonSchema)?
        .len();
    if item_count == 0 || item_count > maximum_updates {
        return Err(VerifyError::ConsensusJsonLimit);
    }
    let raw: Vec<Box<RawValue>> =
        serde_json::from_slice(json).map_err(|_| VerifyError::ConsensusJsonSchema)?;
    if raw.len() != item_count {
        return Err(VerifyError::ConsensusJsonSchema);
    }
    raw.into_iter()
        .map(|item| tag_beacon_json_payload(item.get().as_bytes()))
        .collect()
}

fn parse_consensus_bootstrap(
    bytes: &[u8],
    expected_chain_id: u64,
    expected_network: &str,
) -> Result<ConsensusBootstrapBundle> {
    let mut cursor = Cursor::new(bytes)?;
    let prelude = cursor.prelude(expected_chain_id, expected_network)?;
    if prelude.kind != KIND_PINNED_CONSENSUS_BOOTSTRAP {
        return Err(if matches!(prelude.kind, 1 | 2 | 7) {
            VerifyError::UntrustedHeader
        } else {
            VerifyError::UnsupportedKind(prelude.kind)
        });
    }

    let created_at_unix = cursor.u64()?;
    let bootstrap_ssz = consensus_payload(&mut cursor, MAX_BOOTSTRAP_BYTES)?;
    let update_count = cursor.u16()? as usize;
    if update_count > MAX_CONSENSUS_UPDATES {
        return Err(VerifyError::TooManyConsensusUpdates);
    }
    let mut updates_ssz = Vec::with_capacity(update_count);
    for _ in 0..update_count {
        updates_ssz.push(consensus_payload(&mut cursor, MAX_CONSENSUS_UPDATE_BYTES)?);
    }
    let finality_update_ssz = match cursor.u8()? {
        0 => None,
        1 => Some(consensus_payload(&mut cursor, MAX_CONSENSUS_UPDATE_BYTES)?),
        _ => return Err(VerifyError::Malformed("invalid finality presence flag")),
    };
    cursor.finish()?;

    Ok(ConsensusBootstrapBundle {
        chain_id: prelude.chain_id,
        network: prelude.network,
        created_at_unix,
        bootstrap_ssz,
        updates_ssz,
        finality_update_ssz,
    })
}

fn consensus_payload(cursor: &mut Cursor<'_>, max_len: usize) -> Result<Vec<u8>> {
    let len = cursor.u32()? as usize;
    if len > max_len {
        return Err(VerifyError::OversizedConsensusPayload);
    }
    let payload = cursor.take(len)?.to_vec();
    if payload.is_empty() {
        return Err(VerifyError::EmptyConsensusPayload);
    }
    Ok(payload)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedBeaconResponse<T> {
    version: String,
    data: T,
}

fn decode_bootstrap(encoded: &[u8]) -> Result<Bootstrap<MainnetConsensusSpec>> {
    if let Some(json) = encoded.strip_prefix(BEACON_JSON_TAG) {
        let response: VersionedBeaconResponse<Bootstrap<MainnetConsensusSpec>> =
            decode_versioned_beacon_json(json)?;
        validate_json_fork(&response.version, response.data.header().beacon().slot)?;
        Ok(response.data)
    } else {
        Bootstrap::<MainnetConsensusSpec>::from_ssz_bytes(encoded)
            .map_err(|error| VerifyError::ConsensusDecode(format!("bootstrap: {error:?}")))
    }
}

fn decode_update(encoded: &[u8]) -> Result<Update<MainnetConsensusSpec>> {
    if let Some(json) = encoded.strip_prefix(BEACON_JSON_TAG) {
        let response: VersionedBeaconResponse<Update<MainnetConsensusSpec>> =
            decode_versioned_beacon_json(json)?;
        validate_json_fork(
            &response.version,
            response.data.attested_header().beacon().slot,
        )?;
        Ok(response.data)
    } else {
        Update::<MainnetConsensusSpec>::from_ssz_bytes(encoded)
            .map_err(|error| VerifyError::ConsensusDecode(format!("update: {error:?}")))
    }
}

fn decode_finality_update(encoded: &[u8]) -> Result<FinalityUpdate<MainnetConsensusSpec>> {
    if let Some(json) = encoded.strip_prefix(BEACON_JSON_TAG) {
        let response: VersionedBeaconResponse<FinalityUpdate<MainnetConsensusSpec>> =
            decode_versioned_beacon_json(json)?;
        validate_json_fork(
            &response.version,
            response.data.attested_header().beacon().slot,
        )?;
        Ok(response.data)
    } else {
        FinalityUpdate::<MainnetConsensusSpec>::from_ssz_bytes(encoded)
            .map_err(|error| VerifyError::ConsensusDecode(format!("finality update: {error:?}")))
    }
}

fn decode_versioned_beacon_json<T: DeserializeOwned>(
    json: &[u8],
) -> Result<VersionedBeaconResponse<T>> {
    let value = bounded_json_value(json)?;
    serde_json::from_value(value).map_err(|_| VerifyError::ConsensusJsonSchema)
}

fn validate_json_fork(version: &str, slot: u64) -> Result<()> {
    let expected = if slot / 32 >= 272_640 {
        "fulu"
    } else {
        "electra"
    };
    if version != expected {
        return Err(VerifyError::ConsensusJsonSchema);
    }
    Ok(())
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
}

impl JsonBudget {
    fn consume_node(&mut self) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(VerifyError::ConsensusJsonLimit)?;
        if self.nodes > MAX_BEACON_JSON_NODES {
            return Err(VerifyError::ConsensusJsonLimit);
        }
        Ok(())
    }
}

struct BoundedJsonSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_BEACON_JSON_DEPTH {
            return Err(serde::de::Error::custom("JSON depth limit"));
        }
        self.budget
            .consume_node()
            .map_err(serde::de::Error::custom)?;
        deserializer.deserialize_any(BoundedJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedJsonVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedJsonVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded Beacon JSON")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point Beacon JSON is not accepted"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_BEACON_JSON_STRING_BYTES {
            return Err(E::custom("JSON string limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedJsonSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if values.len() >= MAX_BEACON_JSON_CONTAINER_ITEMS {
                return Err(serde::de::Error::custom("JSON array limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = serde_json::Map::new();
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_BEACON_JSON_STRING_BYTES {
                return Err(serde::de::Error::custom("JSON key limit"));
            }
            if fields.len() >= MAX_BEACON_JSON_OBJECT_FIELDS {
                return Err(serde::de::Error::custom("JSON object limit"));
            }
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value_seed(BoundedJsonSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            fields.insert(key, value);
        }
        Ok(Value::Object(fields))
    }
}

fn bounded_json_value(json: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let mut budget = JsonBudget::default();
    let result = BoundedJsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer);
    let value = match result {
        Ok(value) => value,
        Err(error) if error.to_string().contains("duplicate JSON key") => {
            return Err(VerifyError::ConsensusJsonDuplicateKey);
        }
        Err(error)
            if error.to_string().contains("limit")
                || error.to_string().contains("recursion limit") =>
        {
            return Err(VerifyError::ConsensusJsonLimit);
        }
        Err(_) => return Err(VerifyError::ConsensusJsonSchema),
    };
    deserializer
        .end()
        .map_err(|_| VerifyError::ConsensusJsonSchema)?;
    Ok(value)
}

fn verify_consensus_bundle(
    bundle: ConsensusBootstrapBundle,
    checkpoint: &BeaconCheckpointRoot,
    current_slot: u64,
    proof_bundle_hash: [u8; 32],
) -> Result<VerifiedExecutionHeader> {
    let bootstrap = decode_bootstrap(&bundle.bootstrap_ssz)?;
    validate_checkpoint_age(bootstrap.header().beacon().slot, current_slot)?;
    let bootstrap_slot = bootstrap.header().beacon().slot;
    let forks = sepolia_forks();
    verify_bootstrap::<MainnetConsensusSpec>(
        &bootstrap,
        B256::from(checkpoint.beacon_block_root),
        &forks,
    )
    .map_err(consensus_verification_error)?;

    let mut store = LightClientStore::<MainnetConsensusSpec>::default();
    apply_bootstrap(&mut store, &bootstrap);
    let genesis_root = sepolia_genesis_root()?;
    for encoded in bundle.updates_ssz {
        let update = decode_update(&encoded)?;
        verify_update::<MainnetConsensusSpec>(&update, current_slot, &store, genesis_root, &forks)
            .map_err(consensus_verification_error)?;
        apply_update(&mut store, &update);
    }
    if let Some(encoded) = bundle.finality_update_ssz {
        let finality = decode_finality_update(&encoded)?;
        verify_finality_update::<MainnetConsensusSpec>(
            &finality,
            current_slot,
            &store,
            genesis_root,
            &forks,
        )
        .map_err(consensus_verification_error)?;
        apply_finality_update(&mut store, &finality);
    }

    execution_state(
        bundle.chain_id,
        bundle.network,
        checkpoint.beacon_block_root,
        bootstrap_slot,
        proof_bundle_hash,
        &store,
    )
}

fn validate_checkpoint_age(checkpoint_slot: u64, current_slot: u64) -> Result<()> {
    let slot_age = current_slot
        .checked_sub(checkpoint_slot)
        .ok_or(VerifyError::FutureCheckpoint)?;
    let age_seconds = slot_age
        .checked_mul(SEPOLIA_SECONDS_PER_SLOT)
        .ok_or(VerifyError::StaleCheckpoint)?;
    if age_seconds >= MAX_CHECKPOINT_AGE_SECONDS {
        return Err(VerifyError::StaleCheckpoint);
    }
    Ok(())
}

fn consensus_verification_error(error: impl std::fmt::Display) -> VerifyError {
    VerifyError::ConsensusVerification(error.to_string())
}

fn sepolia_genesis_root() -> Result<B256> {
    Ok(B256::from(SEPOLIA_GENESIS_VALIDATORS_ROOT))
}

fn sepolia_forks() -> Forks {
    Forks {
        genesis: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("90000069"),
        },
        altair: Fork {
            epoch: 50,
            fork_version: fixed_bytes!("90000070"),
        },
        bellatrix: Fork {
            epoch: 100,
            fork_version: fixed_bytes!("90000071"),
        },
        capella: Fork {
            epoch: 56_832,
            fork_version: fixed_bytes!("90000072"),
        },
        deneb: Fork {
            epoch: 132_608,
            fork_version: fixed_bytes!("90000073"),
        },
        electra: Fork {
            epoch: 222_464,
            fork_version: fixed_bytes!("90000074"),
        },
        fulu: Fork {
            epoch: 272_640,
            fork_version: fixed_bytes!("90000075"),
        },
    }
}

fn execution_state(
    chain_id: u64,
    network: String,
    checkpoint_root: [u8; 32],
    bootstrap_slot: u64,
    proof_bundle_hash: [u8; 32],
    store: &LightClientStore<MainnetConsensusSpec>,
) -> Result<VerifiedExecutionHeader> {
    let finalized = &store.finalized_header;
    let execution = execution_header(finalized)?;
    let provenance = if finalized.beacon().slot > bootstrap_slot {
        ExecutionHeaderProvenance::HeliosFinalityUpdate
    } else {
        ExecutionHeaderProvenance::CheckpointAnchor
    };
    Ok(VerifiedExecutionHeader {
        chain_id,
        network,
        finalized_slot: finalized.beacon().slot,
        execution_block_number: *execution.block_number(),
        execution_block_hash: execution.block_hash().0,
        state_root: execution.state_root().0,
        receipts_root: execution.receipts_root().0,
        beacon_transactions_root: execution.transactions_root().0,
        checkpoint_root,
        provenance,
        proof_bundle_hash,
    })
}

fn execution_header(header: &LightClientHeader) -> Result<&ExecutionPayloadHeader> {
    match header {
        LightClientHeader::Bellatrix(_) => Err(VerifyError::MissingExecutionHeader),
        LightClientHeader::Capella(inner) => Ok(&inner.execution),
        LightClientHeader::Deneb(inner) => Ok(&inner.execution),
        LightClientHeader::Electra(inner) => Ok(&inner.execution),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::{MAGIC, VERSION};

    fn prelude(kind: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.extend_from_slice(&(SEPOLIA_NETWORK.len() as u16).to_le_bytes());
        bytes.extend_from_slice(SEPOLIA_NETWORK.as_bytes());
        bytes.push(kind);
        bytes
    }

    fn framed_bundle(bootstrap: &[u8]) -> Vec<u8> {
        let mut bytes = prelude(KIND_PINNED_CONSENSUS_BOOTSTRAP);
        bytes.extend_from_slice(&123_u64.to_le_bytes());
        bytes.extend_from_slice(&(bootstrap.len() as u32).to_le_bytes());
        bytes.extend_from_slice(bootstrap);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.push(0);
        bytes
    }

    #[test]
    fn public_bootstrap_encoder_builds_only_the_pinned_frame() {
        assert_eq!(
            encode_pinned_consensus_bootstrap(123, &[1, 2, 3]).unwrap(),
            framed_bundle(&[1, 2, 3])
        );
        assert!(matches!(
            encode_pinned_consensus_bootstrap(0, &[1]),
            Err(VerifyError::Malformed(_))
        ));
        assert!(matches!(
            encode_pinned_consensus_bootstrap(123, &[]),
            Err(VerifyError::EmptyConsensusPayload)
        ));
        assert!(matches!(
            encode_pinned_consensus_bootstrap(123, &vec![0; MAX_BOOTSTRAP_BYTES + 1]),
            Err(VerifyError::OversizedConsensusPayload)
        ));
    }

    fn framed_bundle_with_tail(
        bootstrap_len: u32,
        update_count: u16,
        finality_flag: u8,
    ) -> Vec<u8> {
        let mut bytes = prelude(KIND_PINNED_CONSENSUS_BOOTSTRAP);
        bytes.extend_from_slice(&123_u64.to_le_bytes());
        bytes.extend_from_slice(&bootstrap_len.to_le_bytes());
        if bootstrap_len <= MAX_BOOTSTRAP_BYTES as u32 {
            bytes.resize(bytes.len() + bootstrap_len as usize, 1);
        }
        bytes.extend_from_slice(&update_count.to_le_bytes());
        bytes.push(finality_flag);
        bytes
    }

    fn json_bootstrap(bootstrap: &Bootstrap<MainnetConsensusSpec>) -> Vec<u8> {
        let data = match bootstrap {
            Bootstrap::Base(inner) => serde_json::json!({
                "header": &inner.header,
                "current_sync_committee": &inner.current_sync_committee,
                "current_sync_committee_branch": &inner.current_sync_committee_branch,
            }),
            Bootstrap::Electra(inner) => serde_json::json!({
                "header": &inner.header,
                "current_sync_committee": &inner.current_sync_committee,
                "current_sync_committee_branch": &inner.current_sync_committee_branch,
            }),
        };
        serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": data,
        }))
        .unwrap()
    }

    fn framed_update_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut cursor = bytes;
        let mut updates = Vec::new();
        while !cursor.is_empty() {
            let length = u64::from_le_bytes(cursor[..8].try_into().unwrap()) as usize;
            let chunk = &cursor[8..8 + length];
            updates.push(chunk[4..].to_vec());
            cursor = &cursor[8 + length..];
        }
        updates
    }

    fn decode_b64(value: &str) -> Vec<u8> {
        let compact: String = value
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .unwrap()
    }

    fn json_update(update: &Update<MainnetConsensusSpec>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": update,
        }))
        .unwrap()
    }

    fn json_finality(update: &FinalityUpdate<MainnetConsensusSpec>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": update,
        }))
        .unwrap()
    }

    #[test]
    fn wire_bundle_has_no_checkpoint_field() {
        let bytes = framed_bundle(&[1, 2, 3]);
        let parsed = Verifier::sepolia()
            .parse_consensus_bootstrap(&bytes)
            .unwrap();
        assert_eq!(parsed.bootstrap_ssz, [1, 2, 3]);
        assert!(parsed.updates_ssz.is_empty());
        assert!(parsed.finality_update_ssz.is_none());
    }

    #[test]
    fn rejects_legacy_self_authenticated_bootstrap() {
        for kind in [1, 2, 7] {
            assert!(matches!(
                Verifier::sepolia().parse_consensus_bootstrap(&prelude(kind)),
                Err(VerifyError::UntrustedHeader)
            ));
        }
    }

    #[test]
    fn rejects_empty_bootstrap_before_ssz_decode() {
        assert!(matches!(
            Verifier::sepolia().parse_consensus_bootstrap(&framed_bundle(&[])),
            Err(VerifyError::EmptyConsensusPayload)
        ));
    }

    #[test]
    fn rejects_consensus_wire_limit_and_framing_violations() {
        let oversized = framed_bundle_with_tail(MAX_BOOTSTRAP_BYTES as u32 + 1, 0, 0);
        assert!(matches!(
            Verifier::sepolia().parse_consensus_bootstrap(&oversized),
            Err(VerifyError::OversizedConsensusPayload)
        ));

        let too_many = framed_bundle_with_tail(1, MAX_CONSENSUS_UPDATES as u16 + 1, 0);
        assert!(matches!(
            Verifier::sepolia().parse_consensus_bootstrap(&too_many),
            Err(VerifyError::TooManyConsensusUpdates)
        ));

        let invalid_flag = framed_bundle_with_tail(1, 0, 2);
        assert!(matches!(
            Verifier::sepolia().parse_consensus_bootstrap(&invalid_flag),
            Err(VerifyError::Malformed("invalid finality presence flag"))
        ));

        let mut trailing = framed_bundle(&[1]);
        trailing.push(0);
        assert!(matches!(
            Verifier::sepolia().parse_consensus_bootstrap(&trailing),
            Err(VerifyError::Malformed("trailing bytes"))
        ));
    }

    #[test]
    fn wrong_checkpoint_cannot_verify_malformed_consensus_material() {
        let error = Verifier::sepolia()
            .verify_consensus_bootstrap(
                &framed_bundle(&[1, 2, 3]),
                &BeaconCheckpointRoot::sepolia([9; 32]),
            )
            .unwrap_err();
        assert!(matches!(error, VerifyError::ConsensusDecode(_)));
    }

    #[test]
    fn beacon_json_limits_duplicate_keys_and_exact_envelope_fail_closed() {
        assert!(matches!(
            tag_beacon_json_payload(br#"{"version":"fulu","version":"electra","data":{}}"#),
            Err(VerifyError::ConsensusJsonDuplicateKey)
        ));

        let mut nested = String::new();
        for _ in 0..=MAX_BEACON_JSON_DEPTH {
            nested.push('[');
        }
        nested.push('0');
        for _ in 0..=MAX_BEACON_JSON_DEPTH {
            nested.push(']');
        }
        assert!(matches!(
            tag_beacon_json_payload(nested.as_bytes()),
            Err(VerifyError::ConsensusJsonLimit)
        ));

        let too_long = format!(
            r#"{{"value":"{}"}}"#,
            "x".repeat(MAX_BEACON_JSON_STRING_BYTES + 1)
        );
        assert!(matches!(
            tag_beacon_json_payload(too_long.as_bytes()),
            Err(VerifyError::ConsensusJsonLimit)
        ));

        assert!(matches!(
            split_and_tag_beacon_json_updates(br#"{"version":"fulu","data":{}}"#, 1),
            Err(VerifyError::ConsensusJsonSchema)
        ));
        assert!(matches!(
            split_and_tag_beacon_json_updates(
                br#"[{"version":"fulu","data":{}},{"version":"fulu","data":{}}]"#,
                1,
            ),
            Err(VerifyError::ConsensusJsonLimit)
        ));
    }

    #[test]
    fn real_json_bootstrap_is_verified_from_only_the_pinned_root() {
        let fixture = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-bootstrap-343888.ssz.b64").trim())
            .unwrap();
        let bootstrap = Bootstrap::<MainnetConsensusSpec>::from_ssz_bytes(&fixture).unwrap();
        let json = json_bootstrap(&bootstrap);
        let tagged = tag_beacon_json_payload(&json).unwrap();
        let checkpoint = BeaconCheckpointRoot::sepolia([
            0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92,
            0xb7, 0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a,
            0x94, 0xaa, 0x4d, 0x51,
        ]);

        let verified = Verifier::sepolia()
            .reverify_historical_consensus_bootstrap(&framed_bundle(&tagged), &checkpoint)
            .unwrap();
        assert_eq!(verified.finalized_slot(), bootstrap.header().beacon().slot);

        assert!(matches!(
            Verifier::sepolia().reverify_historical_consensus_bootstrap(
                &framed_bundle(&tagged),
                &BeaconCheckpointRoot::sepolia([0x55; 32]),
            ),
            Err(VerifyError::ConsensusVerification(_))
        ));

        let mut value: Value = serde_json::from_slice(&json).unwrap();
        value.as_object_mut().unwrap().insert(
            "checkpoint_root".to_owned(),
            Value::String("0x00".to_owned()),
        );
        let self_authenticating =
            tag_beacon_json_payload(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            Verifier::sepolia().reverify_historical_consensus_bootstrap(
                &framed_bundle(&self_authenticating),
                &checkpoint,
            ),
            Err(VerifyError::ConsensusJsonSchema)
        ));
    }

    #[test]
    fn standard_json_updates_and_finality_advance_the_verified_chain() {
        let bootstrap_ssz = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-bootstrap-343888.ssz.b64").trim())
            .unwrap();
        let bootstrap = Bootstrap::<MainnetConsensusSpec>::from_ssz_bytes(&bootstrap_ssz).unwrap();
        let mut update_payloads = framed_update_payloads(include_bytes!(
            "../../ratspeak-eth-gateway/tests/fixtures/sepolia-updates-1343-1344.ssz"
        ));
        update_payloads.extend(framed_update_payloads(include_bytes!(
            "../../ratspeak-eth-gateway/tests/fixtures/sepolia-update-1345.ssz"
        )));
        let updates = update_payloads
            .iter()
            .map(|encoded| Update::<MainnetConsensusSpec>::from_ssz_bytes(encoded).unwrap())
            .map(|update| tag_beacon_json_payload(&json_update(&update)).unwrap())
            .collect();
        let finality_ssz = decode_b64(include_str!(
            "../../ratspeak-eth-gateway/tests/fixtures/sepolia-finality-2026-08-29.ssz.b64"
        ));
        let finality =
            FinalityUpdate::<MainnetConsensusSpec>::from_ssz_bytes(&finality_ssz).unwrap();
        let bundle = ConsensusBootstrapBundle {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            created_at_unix: 1_788_034_160,
            bootstrap_ssz: tag_beacon_json_payload(&json_bootstrap(&bootstrap)).unwrap(),
            updates_ssz: updates,
            finality_update_ssz: Some(tag_beacon_json_payload(&json_finality(&finality)).unwrap()),
        };
        let checkpoint = BeaconCheckpointRoot::sepolia([
            0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92,
            0xb7, 0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a,
            0x94, 0xaa, 0x4d, 0x51,
        ]);
        let verified = verify_consensus_bundle(
            bundle,
            &checkpoint,
            sepolia_slot_at_unix(1_788_034_160).unwrap(),
            [0x77; 32],
        )
        .unwrap();
        assert_eq!(verified.finalized_slot(), 11_024_959);
        assert_eq!(
            verified.provenance(),
            ExecutionHeaderProvenance::HeliosFinalityUpdate
        );
    }

    #[test]
    fn checkpoint_age_policy_rejects_future_and_stale_slots() {
        assert!(matches!(
            validate_checkpoint_age(101, 100),
            Err(VerifyError::FutureCheckpoint)
        ));
        let fourteen_days_in_slots = MAX_CHECKPOINT_AGE_SECONDS / SEPOLIA_SECONDS_PER_SLOT;
        assert!(matches!(
            validate_checkpoint_age(100, 100 + fourteen_days_in_slots),
            Err(VerifyError::StaleCheckpoint)
        ));
        validate_checkpoint_age(100, 100 + fourteen_days_in_slots - 1).unwrap();
    }

    #[test]
    fn current_slot_rejects_clock_before_sepolia_genesis() {
        assert!(matches!(
            sepolia_slot_at_unix(SEPOLIA_GENESIS_TIME - 1),
            Err(VerifyError::InvalidLocalClock)
        ));
    }

    #[test]
    fn verifies_real_sepolia_bootstrap_against_independent_checkpoint() {
        // Captured at Sepolia slot 11,004,416: the bootstrap came from a
        // Lodestar Beacon endpoint, the pinned root from the ethPandaOps
        // checkpoint service, and block/receipt data from a separate execution
        // RPC. The exact commitments below make the frozen evidence auditable.
        let fixture = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-bootstrap-343888.ssz.b64").trim())
            .unwrap();
        let bootstrap = Bootstrap::<MainnetConsensusSpec>::from_ssz_bytes(&fixture).unwrap();
        let checkpoint = BeaconCheckpointRoot::sepolia([
            0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92,
            0xb7, 0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a,
            0x94, 0xaa, 0x4d, 0x51,
        ]);
        let bundle = ConsensusBootstrapBundle {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            created_at_unix: 0,
            bootstrap_ssz: fixture.clone(),
            updates_ssz: Vec::new(),
            finality_update_ssz: None,
        };
        let verified = verify_consensus_bundle(
            bundle,
            &checkpoint,
            bootstrap.header().beacon().slot,
            [0x55; 32],
        )
        .unwrap();

        assert_eq!(verified.finalized_slot(), bootstrap.header().beacon().slot);
        assert_eq!(
            verified.provenance(),
            ExecutionHeaderProvenance::CheckpointAnchor
        );
        assert_eq!(verified.checkpoint_root(), checkpoint.beacon_block_root());
        assert_ne!(verified.execution_block_number(), 0);
        assert_ne!(verified.execution_block_hash(), [0; 32]);
        assert_ne!(verified.beacon_transactions_root(), [0; 32]);
        assert_ne!(verified.receipts_root(), [0; 32]);

        // Historical re-verification derives its verification clock from the
        // retained proof rather than treating today's clock as chain freshness.
        let historical = Verifier::sepolia()
            .reverify_historical_consensus_bootstrap(&framed_bundle(&fixture), &checkpoint)
            .unwrap();
        assert_eq!(historical.finalized_slot(), verified.finalized_slot());
        assert_eq!(
            historical.proof_bundle_hash(),
            sha256(&framed_bundle(&fixture))
        );

        let execution_header = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../tests/fixtures/sepolia-execution-header-11574048.rseth.b64")
                    .trim(),
            )
            .unwrap();
        let execution = Verifier::sepolia()
            .verify_execution_header(&execution_header, &verified)
            .unwrap();
        assert_eq!(execution.execution_block_number(), 11_574_048);
        assert_eq!(
            execution.execution_block_hash(),
            B256::from_str("0x60992ba4994f722f262037f1442d7b15b9f6641ed88c3cf837d9f990403631d1")
                .unwrap()
                .0
        );
        assert_eq!(
            execution.transactions_root(),
            B256::from_str("0x7e0af45c36a8536747a6b8dbf364e8adb27bcf32b5d74c954d78734e944ab388")
                .unwrap()
                .0
        );
        assert_eq!(
            execution.receipts_root(),
            B256::from_str("0x09298bffd8a37f9e5b9392eb115e6ec44073fe021b9e632077639e20fa174d29")
                .unwrap()
                .0
        );
        assert_ne!(
            execution.transactions_root(),
            verified.beacon_transactions_root(),
            "the Beacon SSZ transaction-list root is not the execution MPT root"
        );

        let receipt_proof = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/sepolia-receipt-11574048-0.rseth.b64").trim())
            .unwrap();
        let receipt = Verifier::sepolia()
            .verify_tx_receipt(&receipt_proof, &execution)
            .unwrap();
        assert_eq!(receipt.block_number(), 11_574_048);
        assert_eq!(receipt.tx_index(), 0);
        assert_eq!(
            receipt.provenance(),
            ExecutionHeaderProvenance::CheckpointAnchor
        );
        assert_eq!(receipt.checkpoint_root(), checkpoint.beacon_block_root());
        assert_eq!(receipt.consensus_bundle_hash(), [0x55; 32]);
        assert_eq!(
            receipt.execution_header_proof_hash(),
            execution.proof_bundle_hash()
        );
        assert_eq!(
            receipt.tx_hash(),
            B256::from_str("0xcae3e57f08a105535abe148c391a924fb463e16eef2092b5bc28767bf96046c0")
                .unwrap()
                .0
        );
        assert!(receipt.succeeded());
    }
}
