//! Explicit, single-relay LXMF pickup. This module never discovers or selects
//! a relay and performs no work until the configured polling interval elapses.

use std::collections::HashMap;
use std::time::Instant;

use lxmf_core::propagation_client::{PropagationClient, PropagationClientState};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_identity::identity::Identity;
use rns_transport::messages::TransportMessage;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::{DaemonError, ValidatedPropagationConfig};

pub const MAX_PROPAGATED_PLAINTEXT_BYTES: usize = 8 * 1024;
// Covers the Link response envelope, Resource token/padding, array header,
// and conservative implementation slack beyond the per-item binary headers.
const RESPONSE_FIXED_PROTOCOL_OVERHEAD_BYTES: usize = 512;
const RESPONSE_ITEM_MSGPACK_OVERHEAD_BYTES: usize = 5;
const RESPONSE_RESOURCE_SEGMENTS_PER_ITEM: usize = 4;
const MAX_RESPONSE_RESOURCES: usize = 64;
const MAX_LIST_RESPONSE_BYTES: usize = 256 * 1024;
const ENCODED_TRANSIENT_ID_BYTES: usize = 34;
const MAX_LIST_RESPONSE_ITEMS: usize =
    (MAX_LIST_RESPONSE_BYTES - RESPONSE_ITEM_MSGPACK_OVERHEAD_BYTES) / ENCODED_TRANSIENT_ID_BYTES;

fn response_size_limit(maximum_ciphertext_bytes: usize, maximum_messages: usize) -> Option<usize> {
    maximum_ciphertext_bytes
        .checked_mul(maximum_messages)
        .and_then(|size| {
            RESPONSE_ITEM_MSGPACK_OVERHEAD_BYTES
                .checked_mul(maximum_messages)
                .and_then(|overhead| size.checked_add(overhead))
        })
        .and_then(|size| size.checked_add(RESPONSE_FIXED_PROTOCOL_OVERHEAD_BYTES))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadBatchResolution {
    /// Every item was durably admitted or was invalid and safe to discard.
    Resolved,
    /// At least one item encountered ambiguous durable-state failure.
    Retry,
}

pub struct ConfiguredPropagationClient {
    client: PropagationClient,
    identity: Identity,
    service_destination_hash: [u8; 16],
    known_identities: HashMap<String, [u8; 64]>,
    maximum_ciphertext_bytes: usize,
    maximum_messages_per_poll: usize,
    poll_interval: std::time::Duration,
    next_poll: Instant,
    awaiting_disposition: bool,
    awaiting_purge: bool,
}

impl std::fmt::Debug for ConfiguredPropagationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfiguredPropagationClient")
            .field("state", &self.client.state())
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl ConfiguredPropagationClient {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        service_destination_hash: [u8; 16],
        config: &ValidatedPropagationConfig,
        now: Instant,
    ) -> Result<Self, DaemonError> {
        let private = identity
            .get_private_key()
            .ok_or(DaemonError::IdentityUnavailable)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&private[32..]);
        let mut client = PropagationClient::new(
            transport_tx,
            Some(identity.get_public_key()),
            Some(Ed25519PrivateKey::from_bytes(&seed)),
        );
        client.set_propagation_node(config.node_destination_hash);
        client.set_delivery_limit(f64::from(config.delivery_limit_kb));
        let maximum_ciphertext_bytes = config.delivery_limit_kb as usize * 1024;
        let maximum_response_bytes =
            response_size_limit(maximum_ciphertext_bytes, config.maximum_messages_per_poll)
                .ok_or(DaemonError::InvalidConfiguration)?;
        if !client.set_response_size_limit(Some(maximum_response_bytes)) {
            return Err(DaemonError::InvalidConfiguration);
        }
        if !client.set_response_phase_size_limits(MAX_LIST_RESPONSE_BYTES, maximum_response_bytes) {
            return Err(DaemonError::InvalidConfiguration);
        }
        let maximum_response_resources = config
            .maximum_messages_per_poll
            .checked_mul(RESPONSE_RESOURCE_SEGMENTS_PER_ITEM)
            .map(|limit| limit.clamp(2, MAX_RESPONSE_RESOURCES))
            .ok_or(DaemonError::InvalidConfiguration)?;
        if !client.set_response_complexity_limits(
            maximum_response_resources,
            MAX_LIST_RESPONSE_ITEMS,
            config.maximum_messages_per_poll,
        ) {
            return Err(DaemonError::InvalidConfiguration);
        }
        // The propagation relay is non-authoritative. Never let it purge a
        // download before the authenticated gateway store has admitted it.
        // Repeated pickup is safe because durable admission is idempotent.
        client.set_retain_synced_on_node(true);
        if !client.set_purge_downloads_from_node(false) {
            return Err(DaemonError::InvalidConfiguration);
        }
        let mut known_identities = HashMap::new();
        known_identities.insert(
            hex::encode(config.node_destination_hash),
            config.node_rns_public_key,
        );
        Ok(Self {
            client,
            identity,
            service_destination_hash,
            known_identities,
            maximum_ciphertext_bytes,
            maximum_messages_per_poll: config.maximum_messages_per_poll,
            poll_interval: config.poll_interval,
            next_poll: now + config.poll_interval,
            awaiting_disposition: false,
            awaiting_purge: false,
        })
    }

    /// Advance an existing transfer and start at most one explicitly timed
    /// pickup. A newly constructed client is silent for one full interval.
    pub fn tick(&mut self, now: Instant) -> Option<Vec<Vec<u8>>> {
        self.client.drain_events(&self.known_identities);
        self.client.tick();

        if self.client.state() == PropagationClientState::Failed {
            self.client.acknowledge_transfer();
            self.awaiting_disposition = false;
            self.awaiting_purge = false;
            self.next_poll = now + self.poll_interval;
        }

        if self.awaiting_purge {
            if self.client.state() == PropagationClientState::Complete {
                self.client.acknowledge_transfer();
                self.awaiting_purge = false;
                self.next_poll = now + self.poll_interval;
            }
            return None;
        }

        if self.awaiting_disposition {
            return None;
        }

        if self.client.state() == PropagationClientState::Complete {
            let downloaded = self.client.take_received_messages();
            // The request limit is only a hint to an untrusted relay. Reject
            // the complete over-count response before decryption, while still
            // allowing the application to safely discard and purge the batch.
            let received = decode_download_batch(
                &self.identity,
                self.service_destination_hash,
                self.maximum_ciphertext_bytes,
                self.maximum_messages_per_poll,
                downloaded,
            );
            self.awaiting_disposition = true;
            return Some(received);
        }

        if self.client.state() == PropagationClientState::Idle
            && now >= self.next_poll
            && self
                .client
                .start_download_with_limit(Some(self.maximum_messages_per_poll))
        {
            self.next_poll = now + self.poll_interval;
        }
        None
    }

    /// Resolve the batch returned by `tick`. Relay deletion is requested only
    /// after a fully resolved batch. Retryable failures close the local Link
    /// without purging, so the relay can redeliver after the polling interval.
    pub fn resolve_batch(&mut self, resolution: DownloadBatchResolution, now: Instant) -> bool {
        if !self.awaiting_disposition || self.client.state() != PropagationClientState::Complete {
            return false;
        }
        self.awaiting_disposition = false;

        if resolution == DownloadBatchResolution::Retry {
            let acknowledged = self.client.acknowledge_transfer();
            self.next_poll = now + self.poll_interval;
            return acknowledged;
        }

        if !self.client.finalize_deferred_download() {
            if matches!(
                self.client.state(),
                PropagationClientState::Complete | PropagationClientState::Failed
            ) {
                self.client.acknowledge_transfer();
            }
            self.next_poll = now + self.poll_interval;
            return false;
        }
        if self.client.state() == PropagationClientState::PurgeRequested {
            self.awaiting_purge = true;
        } else {
            self.client.acknowledge_transfer();
            self.next_poll = now + self.poll_interval;
        }
        true
    }

    pub fn cancel(&mut self) {
        self.client.cancel_download();
    }
}

fn decode_download(
    identity: &Identity,
    expected_destination: [u8; 16],
    maximum_ciphertext_bytes: usize,
    data: &[u8],
) -> Option<Vec<u8>> {
    if data.len() <= 16
        || data.len() > maximum_ciphertext_bytes
        || data[..16] != expected_destination
    {
        return None;
    }
    let plaintext = identity.decrypt(&data[16..], None, false).ok()?;
    if plaintext.len() + 16 > MAX_PROPAGATED_PLAINTEXT_BYTES {
        return None;
    }
    let mut packed = Vec::with_capacity(16 + plaintext.len());
    packed.extend_from_slice(&expected_destination);
    packed.extend_from_slice(&plaintext);
    Some(packed)
}

pub(crate) fn decode_download_batch(
    identity: &Identity,
    expected_destination: [u8; 16],
    maximum_ciphertext_bytes: usize,
    maximum_messages: usize,
    downloaded: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    if downloaded.len() > maximum_messages {
        return Vec::new();
    }
    downloaded
        .into_iter()
        .filter_map(|data| {
            decode_download(
                identity,
                expected_destination,
                maximum_ciphertext_bytes,
                &data,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_decoder_rejects_wrong_destination_oversize_and_bad_ciphertext() {
        let identity = Identity::new();
        let destination = [0x41; 16];
        assert!(decode_download(&identity, destination, 64, &[0; 17]).is_none());
        let mut oversized = destination.to_vec();
        oversized.extend_from_slice(&[0; 65]);
        assert!(decode_download(&identity, destination, 64, &oversized).is_none());
        let mut malformed = destination.to_vec();
        malformed.extend_from_slice(&[0; 32]);
        assert!(decode_download(&identity, destination, 64, &malformed).is_none());
    }

    #[test]
    fn bounded_decoder_accepts_only_exact_service_ciphertext() {
        let identity = Identity::new();
        let destination = [0x42; 16];
        let plaintext = b"signed-lxmf-tail";
        let encrypted = Identity::from_public_key(&identity.get_public_key())
            .unwrap()
            .encrypt(plaintext, None)
            .unwrap();
        let mut downloaded = destination.to_vec();
        downloaded.extend_from_slice(&encrypted);
        let decoded = decode_download(&identity, destination, 4096, &downloaded).unwrap();
        assert_eq!(&decoded[..16], &destination);
        assert_eq!(&decoded[16..], plaintext);
    }

    #[test]
    fn new_client_is_idle_and_silent_until_first_interval() {
        let (tx, mut rx) = mpsc::channel(8);
        let identity = Identity::new();
        let node = Identity::new();
        let config = ValidatedPropagationConfig {
            node_destination_hash: [0x51; 16],
            node_rns_public_key: node.get_public_key(),
            poll_interval: std::time::Duration::from_secs(60),
            delivery_limit_kb: 8,
            maximum_messages_per_poll: 2,
            outbound_fallback: false,
            node_transfer_limit_kb: 64,
            node_stamp_cost: 0,
        };
        let now = Instant::now();
        let mut client =
            ConfiguredPropagationClient::new(tx, identity, [0x52; 16], &config, now).unwrap();
        assert!(
            client
                .tick(now + std::time::Duration::from_secs(59))
                .is_none()
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn hostile_over_count_is_rejected_before_any_item_is_accepted() {
        let identity = Identity::new();
        let destination = [0x53; 16];
        let remote = Identity::from_public_key(&identity.get_public_key()).unwrap();
        let item = |tail: &[u8]| {
            let mut data = destination.to_vec();
            data.extend_from_slice(&remote.encrypt(tail, None).unwrap());
            data
        };
        assert!(
            decode_download_batch(
                &identity,
                destination,
                4096,
                1,
                vec![item(b"one"), item(b"two")],
            )
            .is_empty()
        );
    }

    #[test]
    fn response_limit_is_tight_per_item_bounded_and_overflow_safe() {
        assert_eq!(
            response_size_limit(8 * 1024, 2),
            Some(2 * 8 * 1024 + 2 * RESPONSE_ITEM_MSGPACK_OVERHEAD_BYTES + 512)
        );
        assert_eq!(response_size_limit(usize::MAX, 2), None);
    }
}
