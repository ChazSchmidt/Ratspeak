//! Native-only online Sepolia checkpoint acquisition.
//!
//! Two independently operated checkpoint services establish the candidate
//! root. A separate public Beacon API supplies non-authoritative bootstrap
//! bytes, which Helios must verify against that agreed root before install.

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::keccak256;
use ratspeak_eth_node::{CheckpointProviderObservation, ConfiguredCheckpointProvider};
use serde::Deserialize;

const MAX_STATUS_BYTES: usize = 256 * 1024;
const MAX_GENESIS_BYTES: usize = 16 * 1024;
const MAX_BOOTSTRAP_JSON_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const AGREEMENT_ATTEMPTS: usize = 3;

const ETHPANDAOPS_NAME: &str = "ethPandaOps";
const ETHPANDAOPS_STATUS: &str =
    "https://checkpoint-sync.sepolia.ethpandaops.io/checkpointz/v1/status";
const ETHPANDAOPS_GENESIS: &str =
    "https://checkpoint-sync.sepolia.ethpandaops.io/eth/v1/beacon/genesis";
const CHAINSAFE_NAME: &str = "Lodestar / ChainSafe";
const CHAINSAFE_STATUS: &str = "https://beaconstate-sepolia.chainsafe.io/checkpointz/v1/status";
const CHAINSAFE_GENESIS: &str = "https://beaconstate-sepolia.chainsafe.io/eth/v1/beacon/genesis";
const BOOTSTRAP_BASE: &str =
    "https://ethereum-sepolia-beacon-api.publicnode.com/eth/v1/beacon/light_client/bootstrap/";
const BOOTSTRAP_GENESIS: &str =
    "https://ethereum-sepolia-beacon-api.publicnode.com/eth/v1/beacon/genesis";

#[derive(Clone, Debug)]
pub(crate) struct OnlineCheckpointAgreement {
    pub(crate) providers: Vec<ConfiguredCheckpointProvider>,
    pub(crate) observations: Vec<CheckpointProviderObservation>,
    pub(crate) bootstrap_bundle: Vec<u8>,
    pub(crate) source_names: [&'static str; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalizedObservation {
    epoch: u64,
    root: [u8; 32],
    observed_at_unix: u64,
}

#[derive(Deserialize)]
struct StatusEnvelope {
    data: StatusData,
}

#[derive(Deserialize)]
struct StatusData {
    upstreams: HashMap<String, UpstreamStatus>,
    finality: FinalityData,
}

#[derive(Deserialize)]
struct UpstreamStatus {
    healthy: bool,
    #[serde(default)]
    network_name: Option<String>,
}

#[derive(Deserialize)]
struct FinalityData {
    finalized: CheckpointData,
}

#[derive(Deserialize)]
struct CheckpointData {
    epoch: String,
    root: String,
}

#[derive(Deserialize)]
struct GenesisEnvelope {
    data: GenesisData,
}

#[derive(Deserialize)]
struct GenesisData {
    genesis_time: String,
    genesis_validators_root: String,
}

pub(crate) fn acquire() -> Result<OnlineCheckpointAgreement, &'static str> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent("Ratspeak-Ethereum/1 experimental-sepolia")
        .build()
        .map_err(|_| "ethereum_checkpoint_network_unavailable")?;

    let mut agreement = None;
    let mut last_error = "ethereum_checkpoint_source_unavailable";
    for _ in 0..AGREEMENT_ATTEMPTS {
        let first_client = client.clone();
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(move || {
                fetch_checked_observation(&first_client, ETHPANDAOPS_GENESIS, ETHPANDAOPS_STATUS)
            });
            let second = fetch_checked_observation(&client, CHAINSAFE_GENESIS, CHAINSAFE_STATUS);
            (
                first
                    .join()
                    .unwrap_or(Err("ethereum_checkpoint_source_unavailable")),
                second,
            )
        });
        match (first, second) {
            (Ok(first), Ok(second)) if first.epoch == second.epoch && first.root == second.root => {
                agreement = Some((first, second));
                break;
            }
            (Ok(_), Ok(_)) => last_error = "ethereum_checkpoint_sources_disagree",
            (Err(error), _) | (_, Err(error)) => last_error = error,
        }
    }
    let (first, second) = agreement.ok_or(last_error)?;

    verify_sepolia_genesis(&client, BOOTSTRAP_GENESIS)?;
    let root_hex = format!("0x{}", encode_hex(&first.root));
    let url = format!("{BOOTSTRAP_BASE}{root_hex}");
    let bootstrap_json = get_bounded(&client, &url, MAX_BOOTSTRAP_JSON_BYTES)?;
    let tagged = ratspeak_eth_verifier::tag_beacon_json_payload(&bootstrap_json)
        .map_err(|_| "ethereum_checkpoint_bootstrap_invalid")?;
    let captured_at_unix = trusted_now_unix()?;
    let bootstrap_bundle =
        ratspeak_eth_verifier::encode_pinned_consensus_bootstrap(captured_at_unix, &tagged)
            .map_err(|_| "ethereum_checkpoint_bootstrap_invalid")?;

    let first_provider = provider(ETHPANDAOPS_NAME, ETHPANDAOPS_STATUS)?;
    let second_provider = provider(CHAINSAFE_NAME, CHAINSAFE_STATUS)?;
    Ok(OnlineCheckpointAgreement {
        providers: vec![first_provider, second_provider],
        observations: vec![
            CheckpointProviderObservation::new(
                first_provider,
                first.epoch,
                first.root,
                first.observed_at_unix,
            ),
            CheckpointProviderObservation::new(
                second_provider,
                second.epoch,
                second.root,
                second.observed_at_unix,
            ),
        ],
        bootstrap_bundle,
        source_names: [ETHPANDAOPS_NAME, CHAINSAFE_NAME],
    })
}

fn fetch_checked_observation(
    client: &reqwest::blocking::Client,
    genesis_url: &str,
    status_url: &str,
) -> Result<FinalizedObservation, &'static str> {
    verify_sepolia_genesis(client, genesis_url)?;
    fetch_observation(client, status_url)
}

fn verify_sepolia_genesis(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<(), &'static str> {
    let bytes = get_bounded(client, url, MAX_GENESIS_BYTES)?;
    validate_sepolia_genesis(&bytes)
}

fn validate_sepolia_genesis(bytes: &[u8]) -> Result<(), &'static str> {
    let genesis: GenesisEnvelope =
        serde_json::from_slice(bytes).map_err(|_| "ethereum_checkpoint_source_invalid")?;
    let genesis_time = genesis
        .data
        .genesis_time
        .parse::<u64>()
        .map_err(|_| "ethereum_checkpoint_source_invalid")?;
    let genesis_root = decode_root(&genesis.data.genesis_validators_root)
        .ok_or("ethereum_checkpoint_source_invalid")?;
    if genesis_time != ratspeak_eth_verifier::SEPOLIA_GENESIS_TIME
        || genesis_root != ratspeak_eth_verifier::SEPOLIA_GENESIS_VALIDATORS_ROOT
    {
        return Err("ethereum_checkpoint_source_wrong_network");
    }
    Ok(())
}

fn fetch_observation(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<FinalizedObservation, &'static str> {
    let bytes = get_bounded(client, url, MAX_STATUS_BYTES)?;
    let status: StatusEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| "ethereum_checkpoint_source_invalid")?;
    if !status
        .data
        .upstreams
        .values()
        .any(|upstream| upstream.healthy && upstream.network_name.as_deref() == Some("sepolia"))
    {
        return Err("ethereum_checkpoint_source_wrong_network");
    }
    let epoch = status
        .data
        .finality
        .finalized
        .epoch
        .parse::<u64>()
        .map_err(|_| "ethereum_checkpoint_source_invalid")?;
    let root = decode_root(&status.data.finality.finalized.root)
        .ok_or("ethereum_checkpoint_source_invalid")?;
    Ok(FinalizedObservation {
        epoch,
        root,
        observed_at_unix: trusted_now_unix()?,
    })
}

fn get_bounded(
    client: &reqwest::blocking::Client,
    url: &str,
    maximum: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|_| "ethereum_checkpoint_source_unavailable")?;
    if !response.status().is_success() {
        return Err("ethereum_checkpoint_source_unavailable");
    }
    if response
        .content_length()
        .is_some_and(|length| length == 0 || length > maximum as u64)
    {
        return Err("ethereum_checkpoint_source_invalid");
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "ethereum_checkpoint_source_unavailable")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("ethereum_checkpoint_source_invalid");
    }
    Ok(bytes)
}

fn provider(
    operator_name: &str,
    source_url: &str,
) -> Result<ConfiguredCheckpointProvider, &'static str> {
    let operator = keccak256(
        [
            b"ratspeak-ethereum-checkpoint-operator-v1\0".as_slice(),
            operator_name.as_bytes(),
        ]
        .concat(),
    )
    .0;
    let source = keccak256(
        [
            b"ratspeak-ethereum-checkpoint-source-v1\0".as_slice(),
            source_url.as_bytes(),
        ]
        .concat(),
    )
    .0;
    ConfiguredCheckpointProvider::new(operator, source)
        .map_err(|_| "ethereum_checkpoint_policy_unavailable")
}

/// Maps only the fingerprints produced by this binary's fixed provider list.
/// Stored fingerprints from custom/manual sources remain deliberately generic.
pub(crate) fn known_provider_metadata(
    operator_fingerprint: [u8; 32],
    source_fingerprint: [u8; 32],
) -> Option<(&'static str, &'static str)> {
    [
        (ETHPANDAOPS_NAME, ETHPANDAOPS_STATUS),
        (CHAINSAFE_NAME, CHAINSAFE_STATUS),
    ]
    .into_iter()
    .find_map(|(name, status_url)| {
        let configured = provider(name, status_url).ok()?;
        (configured.operator_fingerprint() == operator_fingerprint
            && configured.source_fingerprint() == source_fingerprint)
            .then_some((name, status_url))
    })
}

fn decode_root(value: &str) -> Option<[u8; 32]> {
    let value = value.strip_prefix("0x")?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut root = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        root[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    (root != [0; 32]).then_some(root)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn trusted_now_unix() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .ok()
        .filter(|value| *value != 0)
        .ok_or("ethereum_clock_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_strict_and_nonzero() {
        assert_eq!(
            decode_root(&format!("0x{}", "11".repeat(32))),
            Some([0x11; 32])
        );
        assert_eq!(decode_root(&format!("0x{}", "00".repeat(32))), None);
        assert_eq!(decode_root(&"11".repeat(32)), None);
        assert_eq!(decode_root("0x11"), None);
    }

    #[test]
    fn configured_operators_are_independent() {
        let first = provider(ETHPANDAOPS_NAME, ETHPANDAOPS_STATUS).unwrap();
        let second = provider(CHAINSAFE_NAME, CHAINSAFE_STATUS).unwrap();
        assert_ne!(first.operator_fingerprint(), second.operator_fingerprint());
        assert_ne!(first.source_fingerprint(), second.source_fingerprint());
    }

    #[test]
    fn known_provider_metadata_requires_exact_fingerprints() {
        let first = provider(ETHPANDAOPS_NAME, ETHPANDAOPS_STATUS).unwrap();
        assert_eq!(
            known_provider_metadata(first.operator_fingerprint(), first.source_fingerprint()),
            Some((ETHPANDAOPS_NAME, ETHPANDAOPS_STATUS))
        );
        assert_eq!(known_provider_metadata([0x42; 32], [0x24; 32]), None);
    }

    #[test]
    fn genesis_identity_is_exactly_bound_to_sepolia() {
        let valid = br#"{"data":{"genesis_time":"1655733600","genesis_validators_root":"0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"}}"#;
        assert_eq!(validate_sepolia_genesis(valid), Ok(()));

        let wrong_time = br#"{"data":{"genesis_time":"1655733601","genesis_validators_root":"0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"}}"#;
        assert_eq!(
            validate_sepolia_genesis(wrong_time),
            Err("ethereum_checkpoint_source_wrong_network")
        );

        let wrong_root = format!(
            "{{\"data\":{{\"genesis_time\":\"1655733600\",\"genesis_validators_root\":\"0x{}\"}}}}",
            "11".repeat(32)
        );
        assert_eq!(
            validate_sepolia_genesis(wrong_root.as_bytes()),
            Err("ethereum_checkpoint_source_wrong_network")
        );
        assert_eq!(
            validate_sepolia_genesis(br#"{"data":{}}"#),
            Err("ethereum_checkpoint_source_invalid")
        );
    }

    #[test]
    #[ignore = "live public Sepolia checkpoint sources"]
    fn live_sources_agree_and_helios_verifies_before_install() {
        let agreement = acquire().unwrap();
        let profile = tempfile::tempdir().unwrap();
        let mut store =
            ratspeak_eth_node::EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let policy =
            ratspeak_eth_node::CheckpointBootstrapPolicy::new(agreement.providers).unwrap();
        let _anchor = policy
            .install_provider_observation_agreement(
                &mut store,
                &agreement.observations,
                agreement.bootstrap_bundle,
            )
            .unwrap();
    }
}
