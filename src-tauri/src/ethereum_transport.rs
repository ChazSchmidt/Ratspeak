//! Feature-gated handoff from the field node's durable outbox to generic LXMF.
//!
//! Local LXMF queue acceptance is the end of this module's authority. Delivery,
//! gateway acknowledgements, RPC responses, and transaction confirmation remain
//! separate states owned by the transport and Ethereum verifier respectively.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratspeak_eth_node::{EthereumNodeStore, OutboundMessageBinding, OutboundMessageLease};
use ratspeak_tauri::lxmf::{AttachmentMessageRequest, DeliveryPreference};
use tauri::Manager;

use crate::ethereum::{EthereumApplicationState, EthereumTransportBinding};

const OUTBOUND_LEASE_SECONDS: u64 = 60;
const OUTBOUND_IDLE_SECONDS: u64 = 60;
const GATEWAY_ROUTE_DISCOVERY_SECONDS: u64 = 15;
const MAX_DRAIN_PER_WAKE: usize = 8;
const ATTACHMENT_FILE_NAME: &str = "ratspeak-ethereum.rseth";
const ATTACHMENT_CONTENT: &str = "";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunOutcome {
    NoWork,
    Queued,
    RetryLater,
}

pub(crate) fn install(
    app_handle: tauri::AppHandle,
    runtime: Arc<ratspeak_tauri::state::AppState>,
) -> Result<(), &'static str> {
    let state = app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or("ethereum_state_unavailable")?;
    if !state.claim_outbound_coordinator() {
        return Ok(());
    }
    let notify = state.outbound_notify();
    tauri::async_runtime::spawn(async move {
        loop {
            for _ in 0..MAX_DRAIN_PER_WAKE {
                match run_once(&app_handle, &runtime).await {
                    Ok(RunOutcome::Queued) => continue,
                    Ok(RunOutcome::NoWork | RunOutcome::RetryLater) => break,
                    Err(error) => {
                        // Closed internal reason tokens are safe for explicitly
                        // enabled diagnostics; the generic `error` field is
                        // intentionally filtered by the process log policy.
                        tracing::warn!(reason = error, "Ethereum outbound handoff deferred");
                        break;
                    }
                }
            }
            tokio::select! {
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(OUTBOUND_IDLE_SECONDS)) => {},
            }
        }
    });
    Ok(())
}

async fn run_once(
    app_handle: &tauri::AppHandle,
    runtime: &Arc<ratspeak_tauri::state::AppState>,
) -> Result<RunOutcome, &'static str> {
    let binding = {
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        let Some(binding) = state.transport_binding()? else {
            return Ok(RunOutcome::NoWork);
        };
        binding
    };

    let destination = encode_hex(&binding.gateway_destination_hash);
    if !ratspeak_tauri::commands::shared::hydrate_contact_identity_for_send(runtime, &destination)
        .await
    {
        return Err("ethereum_gateway_contact_unavailable");
    }

    // A valid Contact authenticates the service identity, but it does not
    // establish a usable Reticulum route. Do not consume an outbox attempt or
    // hand bytes to LXMF until bounded path discovery succeeds. The command
    // performs the same check before creating new work; this coordinator check
    // also protects durable requests resumed after a restart.
    let rns_handle = runtime
        .rns
        .read()
        .ok()
        .and_then(|manager| manager.as_ref().map(|manager| manager.handle.clone()))
        .ok_or("ethereum_reticulum_unavailable")?;
    if rns_handle
        .await_path(
            binding.gateway_destination_hash,
            Duration::from_secs(GATEWAY_ROUTE_DISCOVERY_SECONDS),
        )
        .await
        .is_err()
    {
        tracing::debug!(
            destination = %encode_hex(&binding.gateway_destination_hash),
            "Ethereum outbound handoff waiting for a Reticulum route"
        );
        return Ok(RunOutcome::RetryLater);
    }

    let local_source_hash = live_source_snapshot(app_handle, runtime, &binding).await?;
    let outbound_binding = OutboundMessageBinding::new(
        binding.gateway_destination_hash,
        local_source_hash,
        binding.identity_session_generation,
    )
    .map_err(|_| "ethereum_outbound_binding_invalid")?;

    // Store open, integrity checks, and SQLite waits run only on a blocking
    // worker. The scoped binding read fence excludes gateway replacement while
    // a lease can be created without holding the identity lifecycle lock.
    let now_unix = trusted_now_unix()?;
    let worker_app = app_handle.clone();
    let worker_binding = binding.clone();
    let lease = tokio::task::spawn_blocking(move || -> Result<_, &'static str> {
        use tauri::Manager;
        let state = worker_app
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        state
            .with_current_transport_binding(&worker_binding, |profile_dir| {
                let mut store = EthereumNodeStore::open_in_profile(profile_dir)
                    .map_err(|_| "ethereum_outbound_store_unavailable")?;
                store
                    .lease_next_outbound_message(outbound_binding, now_unix, OUTBOUND_LEASE_SECONDS)
                    .map_err(|_| "ethereum_outbound_lease_failed")
            })
            .map_err(|_| "ethereum_outbound_lease_failed")
    })
    .await
    .map_err(|_| "ethereum_outbound_lease_task_failed")?
    .map_err(|_| "ethereum_outbound_lease_failed")?;
    let Some(lease) = lease else {
        return Ok(RunOutcome::NoWork);
    };

    let queued = match submit_lease(app_handle, runtime, &binding, &lease).await {
        Ok(queued) => queued,
        Err(error) => {
            tracing::debug!(reason = error, "Ethereum outbound lease was not queued");
            false
        }
    };
    if queued {
        runtime.lxmf_notify.notify_one();
    }

    let transition_profile = binding.profile_dir.clone();
    let transition_lease = lease.clone();
    let transition_time = trusted_now_unix()?;
    tokio::task::spawn_blocking(move || {
        let mut store = EthereumNodeStore::open_in_profile(&transition_profile)?;
        if queued {
            // This settlement means only that the generic Ratspeak database
            // and router accepted the exact attachment. It grants no chain
            // authority.
            store.settle_outbound_message_queued(
                outbound_binding,
                &transition_lease,
                transition_time,
            )
        } else {
            store.release_outbound_message(outbound_binding, &transition_lease, transition_time)
        }
    })
    .await
    .map_err(|_| "ethereum_outbound_transition_task_failed")?
    .map_err(|_| "ethereum_outbound_transition_failed")?;

    Ok(if queued {
        RunOutcome::Queued
    } else {
        RunOutcome::RetryLater
    })
}

async fn live_source_snapshot(
    app_handle: &tauri::AppHandle,
    runtime: &Arc<ratspeak_tauri::state::AppState>,
    binding: &EthereumTransportBinding,
) -> Result<[u8; 16], &'static str> {
    let app_handle = app_handle.clone();
    let runtime = Arc::clone(runtime);
    let binding = binding.clone();
    tokio::task::spawn_blocking(move || {
        // The blocking worker, rather than an executor thread, owns this short
        // validation fence. No node-store or SQLite operation occurs inside it.
        let _identity_lifecycle = runtime.identity_switch_lock.blocking_lock();
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        let (_, local_source_hash) = validate_live_binding(&state, &runtime, &binding)?;
        let manager = runtime
            .lxmf
            .lock()
            .map_err(|_| "ethereum_lxmf_unavailable")?;
        let Some(manager) = manager.as_ref() else {
            return Err("ethereum_lxmf_unavailable");
        };
        if manager.lxmf_dest_hash != local_source_hash {
            return Err("ethereum_lxmf_identity_changed");
        }
        Ok(local_source_hash)
    })
    .await
    .map_err(|_| "ethereum_identity_snapshot_task_failed")?
}

async fn submit_lease(
    app_handle: &tauri::AppHandle,
    runtime: &Arc<ratspeak_tauri::state::AppState>,
    binding: &EthereumTransportBinding,
    lease: &OutboundMessageLease,
) -> Result<bool, &'static str> {
    let app_handle = app_handle.clone();
    let runtime = Arc::clone(runtime);
    let binding = binding.clone();
    let lease = lease.clone();
    tokio::task::spawn_blocking(move || {
        // The signed queue handoff is the only blocking operation protected by
        // the identity fence. Slow node-store work stays outside this section.
        let _identity_lifecycle = runtime.identity_switch_lock.blocking_lock();
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        let (identity_id, local_source_hash) = validate_live_binding(&state, &runtime, &binding)?;
        if local_source_hash != lease.source_hash()
            || binding.gateway_destination_hash != lease.destination_hash()
        {
            return Err("ethereum_outbound_binding_changed");
        }
        let destination = encode_hex(&lease.destination_hash());
        let mut manager = runtime
            .lxmf
            .lock()
            .map_err(|_| "ethereum_lxmf_unavailable")?;
        let Some(manager) = manager.as_mut() else {
            return Ok(false);
        };
        if manager.lxmf_dest_hash != lease.source_hash() {
            return Err("ethereum_lxmf_identity_changed");
        }
        Ok(manager
            .submit_strict_authenticated_attachment(AttachmentMessageRequest {
                dest_hash_hex: &destination,
                content: ATTACHMENT_CONTENT,
                title: "",
                file_name: ATTACHMENT_FILE_NAME,
                file_bytes: lease.attachment(),
                staged_path: None,
                is_image: false,
                image_mime: "",
                db_pool: &runtime.db,
                identity_id: &identity_id,
                // Auto starts live and uses Ratspeak's configured
                // propagation fallback only after a terminal live failure.
                preference: DeliveryPreference::Auto,
            })
            .is_ok())
    })
    .await
    .map_err(|_| "ethereum_outbound_submission_task_failed")?
}

fn validate_live_binding(
    state: &EthereumApplicationState,
    runtime: &ratspeak_tauri::state::AppState,
    binding: &EthereumTransportBinding,
) -> Result<(String, [u8; 16]), &'static str> {
    if !state.transport_binding_is_current(binding)?
        || runtime.current_identity_session_generation() != binding.identity_session_generation
    {
        return Err("ethereum_profile_changed");
    }
    let identity_id = ratspeak_tauri::helpers::active_identity_id(runtime);
    if decode_hash(&identity_id) != Some(binding.ratspeak_identity_hash) {
        return Err("ethereum_ratspeak_identity_changed");
    }
    let local_source_hash = decode_hash(&ratspeak_tauri::helpers::active_lxmf_hash(runtime))
        .ok_or("ethereum_lxmf_identity_unavailable")?;
    if local_source_hash == [0; 16] || local_source_hash == binding.gateway_destination_hash {
        return Err("ethereum_lxmf_identity_invalid");
    }
    Ok((identity_id, local_source_hash))
}

fn trusted_now_unix() -> Result<u64, &'static str> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "ethereum_clock_unavailable")?
        .as_secs();
    (now != 0)
        .then_some(now)
        .ok_or("ethereum_clock_unavailable")
}

fn decode_hash(encoded: &str) -> Option<[u8; 16]> {
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    if encoded.len() != 32 || !encoded.is_ascii() {
        return None;
    }
    let mut decoded = [0u8; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
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
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_exact_and_canonicalized_for_lxmf() {
        let expected = [0xab; 16];
        assert_eq!(decode_hash(&encode_hex(&expected)), Some(expected));
        assert_eq!(
            decode_hash(&format!("0x{}", encode_hex(&expected))),
            Some(expected)
        );
        assert_eq!(decode_hash("abab"), None);
        assert_eq!(decode_hash("gggggggggggggggggggggggggggggggg"), None);
        assert_eq!(encode_hex(&expected), "abababababababababababababababab");
    }

    #[test]
    fn protocol_attachment_metadata_does_not_claim_delivery_or_authority() {
        assert_eq!(ATTACHMENT_FILE_NAME, "ratspeak-ethereum.rseth");
        assert!(!ATTACHMENT_CONTENT
            .to_ascii_lowercase()
            .contains("confirmed"));
        assert!(!ATTACHMENT_CONTENT
            .to_ascii_lowercase()
            .contains("delivered"));
        assert!(!ATTACHMENT_CONTENT.to_ascii_lowercase().contains("verified"));
    }

    #[test]
    fn outbound_lease_is_created_inside_the_transport_binding_fence() {
        let source = include_str!("ethereum_transport.rs");
        let fence = source
            .find(".with_current_transport_binding(&worker_binding")
            .expect("transport binding fence");
        let open = source[fence..]
            .find("EthereumNodeStore::open_in_profile(profile_dir)")
            .map(|offset| fence + offset)
            .expect("node store open");
        let lease = source[open..]
            .find(".lease_next_outbound_message(")
            .map(|offset| open + offset)
            .expect("outbound lease");
        let fence_end = source[lease..]
            .find(".map_err(|_| \"ethereum_outbound_lease_failed\")\n            })")
            .map(|offset| lease + offset)
            .expect("transport binding fence end");

        assert!(fence < open && open < lease && lease < fence_end);
    }

    #[test]
    fn route_discovery_precedes_every_durable_outbound_lease() {
        let source = include_str!("ethereum_transport.rs");
        let route = source.find(".await_path(").expect("route discovery");
        let retry = source[route..]
            .find("return Ok(RunOutcome::RetryLater)")
            .map(|offset| route + offset)
            .expect("route failure deferral");
        let lease = source
            .find(".lease_next_outbound_message(")
            .expect("outbound lease");

        assert!(route < retry && retry < lease);
    }
}
