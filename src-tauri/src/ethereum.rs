//! Experimental, public-only Sepolia WebView boundary.
//!
//! Wallet secrets and signing stay behind native adapters. This module exposes
//! only assurance-qualified public state and immutable transfer-review fields.

use std::collections::HashMap;
#[cfg(any(target_os = "android", target_os = "linux", test))]
use std::collections::HashSet;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(any(target_os = "android", target_os = "linux", test))]
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io::Read;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "android", target_os = "linux", test))]
use alloy_primitives::{Address, Bytes, U256, keccak256};
#[cfg(any(target_os = "android", test))]
use base64::Engine;
use ratspeak_eth_clearsign::DefinitionRegistry;
#[cfg(any(target_os = "android", target_os = "linux", test))]
use ratspeak_eth_node::FieldTransferRequest;
use ratspeak_eth_node::{
    AccountAssurance, BulkEvidenceReviewDecision, BulkEvidenceReviewResolution, EthereumNodeStore,
    EvidenceSyncTrigger, FinalizedReceiptRequestProgress, FinalizedStatusReceiptRequest,
    MessagingEvidenceKind, NodeMessageOutcome, NonAuthoritativeTransactionObservation,
    OutboundMessageBinding, OutboundTransactionStatusRequest, PreparedFieldTransfer,
    StoredSignedTransaction, TransactionAssurance, TransactionStatus, TransactionStatusContinuity,
    TransactionStatusHistoryView,
};
#[cfg(any(target_os = "android", target_os = "linux", test))]
use ratspeak_eth_wallet::{ClearSignedIntent, OperationId, PreparedClearSignedOperation};
use ratspeak_eth_wallet::{WalletAccount, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK};
#[cfg(any(target_os = "android", test))]
use rns_identity::{destination::Destination, identity::Identity};
use serde::{Deserialize, Serialize};

const UNKNOWN_DISPLAY: &str = "...";
// Sepolia finality is ordinarily already several epochs behind wall time.
// Leave enough room to construct and transport a proof without mislabeling a
// freshly verified finalized head as unknown; the gateway enforces the same
// 30-minute maximum before constructing evidence.
pub(crate) const MAX_CURRENT_EVIDENCE_AGE_SECONDS: u64 = 30 * 60;
const MAX_AUTOMATIC_ACCOUNT_EVIDENCE_BYTES: u32 = 128 * 1024;
// A locally signed transaction already expresses the user's intent to obtain
// its exact result. Receipt manifests remain correlated to that transaction,
// configured service, approved checkpoint, and this fixed response ceiling;
// downloading them does not grant signing authority or establish assurance.
const MAX_AUTOMATIC_RECEIPT_EVIDENCE_BYTES: u32 = 2 * 1024 * 1024;
const MAX_PENDING_REVIEW_SURFACES: usize = 32;
const GATEWAY_DESTINATION_FILE: &str = "gateway-destination";
#[cfg(any(target_os = "android", test))]
pub(crate) const MAX_GATEWAY_CARD_BYTES: usize = 256;
#[cfg(any(target_os = "android", test))]
const GATEWAY_CARD_PREFIX: &str = "RSEG1";
const EVIDENCE_SYNC_EXPIRY_SECONDS: u64 = 2 * 60 * 60;
const TRANSACTION_STATUS_REQUEST_EXPIRY_SECONDS: u64 = 30 * 60;
const EVIDENCE_SYNC_COMMAND_COOLDOWN_SECONDS: u64 = 5;
const MAX_MULTICHAIN_RELAYS_PER_SYNC: usize = 16;
const GATEWAY_ROUTE_DISCOVERY_SECONDS: u64 = 15;
// The node and verifier reject anything larger than this per-response bound.
const MAX_EVIDENCE_SYNC_RESPONSE_BYTES: u32 = 2 * 1024 * 1024;
// Matches the verifier's production bundle bound plus the messaging envelope.
const MAX_PERSISTED_GATEWAY_MESSAGE_BYTES: usize = 2 * 1024 * 1024 + 128;

#[cfg(test)]
pub(crate) const WEBVIEW_COMMAND_ALLOWLIST: [&str; 17] = [
    "ethereum_feature_status",
    "ethereum_setup_status",
    "ethereum_install_builtin_asset",
    "ethereum_launch_native_wallet",
    "ethereum_review_pending_bulk_evidence",
    "ethereum_review_pending_checkpoint",
    "ethereum_import_checkpoint_file",
    "ethereum_connect_sepolia",
    "ethereum_import_gateway_card",
    "ethereum_add_public_service_contact",
    "ethereum_review_pending_gateway_card",
    "ethereum_public_account",
    "ethereum_synchronize",
    "ethereum_update_transaction_status",
    "ethereum_transfer_review",
    "ethereum_transaction_assurance",
    "ethereum_latest_transaction",
];

pub(crate) struct EthereumApplicationState {
    scoped: RwLock<EthereumScopedState>,
    outbound_notify: Arc<tokio::sync::Notify>,
    outbound_coordinator_started: AtomicBool,
    sync_command_active: Arc<AtomicBool>,
    checkpoint_connect_active: Arc<AtomicBool>,
    sync_not_before_unix: AtomicU64,
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    operation_ids: RandomState,
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    operation_nonce: AtomicU64,
}

#[derive(Clone)]
struct EthereumProfileBinding {
    generation: EthereumProfileGeneration,
    profile_dir: PathBuf,
    public_account: Option<WalletAccount>,
    ratspeak_identity_hash: [u8; 16],
    identity_session_generation: u64,
    configured_gateway_source_hash: Option<[u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EthereumGatewayCard {
    destination_hash: [u8; 16],
    public_key: [u8; 64],
    public_key_fingerprint: [u8; 32],
}

/// Build a gateway routing card from the exact Contact row bound to the
/// active Ratspeak identity. The Contact database is the authority for this
/// picker; callers must not provide a destination or key from the WebView.
pub(crate) fn gateway_card_from_active_contact(
    runtime: &ratspeak_tauri::state::AppState,
    destination_hash: [u8; 16],
) -> Option<EthereumGatewayCard> {
    if destination_hash == [0; 16] {
        return None;
    }
    let identity_id = ratspeak_tauri::helpers::active_identity_id(runtime);
    let destination = encode_hex(&destination_hash);
    let public_key = ratspeak_tauri::commands::shared::validated_contact_public_key(
        runtime,
        &identity_id,
        &destination,
    )?;
    Some(EthereumGatewayCard::from_public_key(
        destination_hash,
        public_key,
    ))
}

impl EthereumGatewayCard {
    fn from_public_key(destination_hash: [u8; 16], public_key: [u8; 64]) -> Self {
        let mut fingerprint_input = Vec::with_capacity(49 + public_key.len());
        fingerprint_input.extend_from_slice(b"ratspeak-ethereum-gateway-public-key-v1\0");
        fingerprint_input.extend_from_slice(&public_key);
        Self {
            destination_hash,
            public_key,
            public_key_fingerprint: alloy_primitives::keccak256(fingerprint_input).0,
        }
    }
}

impl EthereumGatewayCard {
    pub(crate) fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }

    pub(crate) fn public_key_fingerprint(&self) -> [u8; 32] {
        self.public_key_fingerprint
    }

    pub(crate) fn public_key(&self) -> [u8; 64] {
        self.public_key
    }
}

pub(crate) fn gateway_card_matches_active_contact(
    runtime: &ratspeak_tauri::state::AppState,
    card: &EthereumGatewayCard,
) -> bool {
    gateway_card_from_active_contact(runtime, card.destination_hash())
        .is_some_and(|current| current.public_key() == card.public_key())
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn parse_gateway_card(bytes: &[u8]) -> Result<EthereumGatewayCard, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_GATEWAY_CARD_BYTES {
        return Err("ethereum_gateway_card_invalid");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "ethereum_gateway_card_invalid")?;
    let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
    let mut fields = text.split(':');
    if fields.next() != Some(GATEWAY_CARD_PREFIX) || fields.next() != Some(SEPOLIA_NETWORK) {
        return Err("ethereum_gateway_card_invalid");
    }
    let destination = fields.next().ok_or("ethereum_gateway_card_invalid")?;
    let encoded_key = fields.next().ok_or("ethereum_gateway_card_invalid")?;
    if fields.next().is_some()
        || destination.len() != 32
        || !destination.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("ethereum_gateway_card_invalid");
    }
    let destination_hash = decode_fixed_hex::<16>(destination)
        .filter(|hash| *hash != [0; 16])
        .ok_or("ethereum_gateway_card_invalid")?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| "ethereum_gateway_card_invalid")?;
    let public_key: [u8; 64] = decoded
        .try_into()
        .map_err(|_| "ethereum_gateway_card_invalid")?;
    let identity =
        Identity::from_public_key(&public_key).map_err(|_| "ethereum_gateway_card_invalid")?;
    if Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash))
        != destination_hash
    {
        return Err("ethereum_gateway_card_invalid");
    }
    Ok(EthereumGatewayCard::from_public_key(
        destination_hash,
        public_key,
    ))
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Clone)]
pub(crate) struct EthereumNativeProfileBinding {
    pub(crate) public_account: WalletAccount,
    pub(crate) ratspeak_identity_hash: [u8; 16],
    pub(crate) identity_session_generation: u64,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EthereumNativeTransportProfileBinding {
    pub(crate) generation: EthereumProfileGeneration,
    pub(crate) profile_dir: PathBuf,
    pub(crate) ratspeak_identity_hash: [u8; 16],
    pub(crate) identity_session_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EthereumProfileGeneration(u64);

#[derive(Clone)]
pub(crate) struct EthereumTransportBinding {
    pub(crate) generation: EthereumProfileGeneration,
    pub(crate) profile_dir: PathBuf,
    pub(crate) ratspeak_identity_hash: [u8; 16],
    pub(crate) identity_session_generation: u64,
    pub(crate) gateway_destination_hash: [u8; 16],
}

struct EthereumScopedState {
    generation: u64,
    profile_binding: Option<EthereumProfileBinding>,
    pending_reviews: HashMap<[u8; 16], EthereumTransferReviewView>,
    pending_native_transfers: HashMap<[u8; 16], PreparedFieldTransfer>,
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pending_clear_signed_operations: HashMap<[u8; 16], PreparedClearSignedOperation>,
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pending_native_cancellations: HashSet<PendingNativeCancellation>,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PendingNativeCancellation {
    profile_dir: PathBuf,
    ratspeak_identity_hash: [u8; 16],
    identity_session_generation: u64,
    operation_id: [u8; 16],
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
impl EthereumApplicationState {
    pub(crate) fn new() -> Self {
        Self {
            scoped: RwLock::new(EthereumScopedState {
                generation: 0,
                profile_binding: None,
                pending_reviews: HashMap::new(),
                pending_native_transfers: HashMap::new(),
                #[cfg(any(target_os = "android", target_os = "linux", test))]
                pending_clear_signed_operations: HashMap::new(),
                #[cfg(any(target_os = "android", target_os = "linux", test))]
                pending_native_cancellations: HashSet::new(),
            }),
            outbound_notify: Arc::new(tokio::sync::Notify::new()),
            outbound_coordinator_started: AtomicBool::new(false),
            sync_command_active: Arc::new(AtomicBool::new(false)),
            checkpoint_connect_active: Arc::new(AtomicBool::new(false)),
            sync_not_before_unix: AtomicU64::new(0),
            #[cfg(any(target_os = "android", target_os = "linux", test))]
            operation_ids: RandomState::new(),
            #[cfg(any(target_os = "android", target_os = "linux", test))]
            operation_nonce: AtomicU64::new(1),
        }
    }

    /// Native profile/custody integration installs the active profile and its
    /// derived public account as one binding. Switching clears prior-profile
    /// review projections under the same lock. This is not a Tauri command.
    #[allow(dead_code)]
    pub(crate) fn install_profile_binding(
        &self,
        profile_dir: PathBuf,
        account: WalletAccount,
    ) -> Result<EthereumProfileGeneration, &'static str> {
        self.install_profile_binding_for_identity(profile_dir, account, [0xff; 16], 0)
    }

    /// Binds wallet state and pending native operations to one exact active
    /// Ratspeak identity. Reinstalling the same tuple is idempotent; an actual
    /// profile or account switch advances the generation and clears pending work.
    pub(crate) fn install_profile_binding_for_identity(
        &self,
        profile_dir: PathBuf,
        account: WalletAccount,
        ratspeak_identity_hash: [u8; 16],
        identity_session_generation: u64,
    ) -> Result<EthereumProfileGeneration, &'static str> {
        if ratspeak_identity_hash == [0; 16] {
            return Err("ethereum_identity_unavailable");
        }
        let profile_dir = profile_dir
            .canonicalize()
            .map_err(|_| "ethereum_profile_unavailable")?;
        let configured_gateway_source_hash = load_gateway_destination(&profile_dir).ok();
        let generation = {
            let mut scoped = self
                .scoped
                .write()
                .map_err(|_| "ethereum_state_unavailable")?;
            if let Some(binding) = scoped.profile_binding.as_ref() {
                if binding.profile_dir == profile_dir
                    && binding.public_account == Some(account)
                    && binding.ratspeak_identity_hash == ratspeak_identity_hash
                    && binding.identity_session_generation == identity_session_generation
                    && binding.configured_gateway_source_hash == configured_gateway_source_hash
                {
                    self.outbound_notify.notify_one();
                    return Ok(binding.generation);
                }
            }
            scoped.generation = scoped
                .generation
                .checked_add(1)
                .ok_or("ethereum_profile_generation_exhausted")?;
            let generation = EthereumProfileGeneration(scoped.generation);
            scoped.pending_reviews.clear();
            scoped.pending_native_transfers.clear();
            #[cfg(any(target_os = "android", target_os = "linux", test))]
            scoped.pending_clear_signed_operations.clear();
            scoped.profile_binding = Some(EthereumProfileBinding {
                generation,
                profile_dir: profile_dir.clone(),
                public_account: Some(account),
                ratspeak_identity_hash,
                identity_session_generation,
                configured_gateway_source_hash,
            });
            generation
        };
        self.sync_not_before_unix.store(0, Ordering::Release);
        retry_pending_evidence(&profile_dir);
        #[cfg(any(target_os = "android", target_os = "linux", test))]
        self.retry_native_cancellations();
        self.outbound_notify.notify_one();
        Ok(generation)
    }

    /// Installs the active profile/identity/gateway transport fence without
    /// requiring wallet custody. Native evidence and checkpoint review must
    /// remain usable before a wallet account exists.
    pub(crate) fn install_transport_profile_for_identity(
        &self,
        profile_dir: PathBuf,
        ratspeak_identity_hash: [u8; 16],
        identity_session_generation: u64,
    ) -> Result<EthereumProfileGeneration, &'static str> {
        if ratspeak_identity_hash == [0; 16] {
            return Err("ethereum_identity_unavailable");
        }
        let profile_dir = profile_dir
            .canonicalize()
            .map_err(|_| "ethereum_profile_unavailable")?;
        let configured_gateway_source_hash = load_gateway_destination(&profile_dir).ok();
        let generation = {
            let mut scoped = self
                .scoped
                .write()
                .map_err(|_| "ethereum_state_unavailable")?;
            if let Some(binding) = scoped.profile_binding.as_ref() {
                if binding.profile_dir == profile_dir
                    && binding.ratspeak_identity_hash == ratspeak_identity_hash
                    && binding.identity_session_generation == identity_session_generation
                    && binding.configured_gateway_source_hash == configured_gateway_source_hash
                {
                    self.outbound_notify.notify_one();
                    return Ok(binding.generation);
                }
            }
            scoped.generation = scoped
                .generation
                .checked_add(1)
                .ok_or("ethereum_profile_generation_exhausted")?;
            let generation = EthereumProfileGeneration(scoped.generation);
            scoped.pending_reviews.clear();
            scoped.pending_native_transfers.clear();
            #[cfg(any(target_os = "android", target_os = "linux", test))]
            scoped.pending_clear_signed_operations.clear();
            scoped.profile_binding = Some(EthereumProfileBinding {
                generation,
                profile_dir: profile_dir.clone(),
                public_account: None,
                ratspeak_identity_hash,
                identity_session_generation,
                configured_gateway_source_hash,
            });
            generation
        };
        self.sync_not_before_unix.store(0, Ordering::Release);
        retry_pending_evidence(&profile_dir);
        #[cfg(any(target_os = "android", target_os = "linux", test))]
        self.retry_native_cancellations();
        self.outbound_notify.notify_one();
        Ok(generation)
    }

    /// Native profile configuration binds one exact LXMF delivery destination
    /// to the active Ethereum gateway. This is intentionally not a WebView
    /// command and zero is never a valid configured identity.
    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn configure_gateway_source_hash(
        &self,
        generation: EthereumProfileGeneration,
        source_hash: [u8; 16],
    ) -> Result<(), &'static str> {
        if source_hash == [0; 16] {
            return Err("invalid_gateway_source_hash");
        }
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_mut()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.generation != generation {
            return Err("ethereum_profile_changed");
        }
        let profile_dir = binding.profile_dir.clone();
        binding.configured_gateway_source_hash = Some(source_hash);
        drop(scoped);
        self.sync_not_before_unix.store(0, Ordering::Release);
        retry_pending_evidence(&profile_dir);
        self.outbound_notify.notify_one();
        Ok(())
    }

    /// Persists one natively approved transport destination for the exact
    /// profile generation. Gateway selection is routing metadata only and
    /// never establishes checkpoint, RPC, or Ethereum authority.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub(crate) fn persist_gateway_source_hash(
        &self,
        generation: EthereumProfileGeneration,
        source_hash: [u8; 16],
        now_unix: u64,
        approval_current: impl FnOnce() -> bool,
    ) -> Result<(), &'static str> {
        self.persist_gateway_source_hash_with(
            generation,
            source_hash,
            now_unix,
            approval_current,
            persist_gateway_destination,
        )
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn persist_gateway_source_hash_with(
        &self,
        generation: EthereumProfileGeneration,
        source_hash: [u8; 16],
        now_unix: u64,
        approval_current: impl FnOnce() -> bool,
        publisher: impl FnOnce(&Path, [u8; 16]) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        if source_hash == [0; 16] || now_unix == 0 {
            return Err("invalid_gateway_source_hash");
        }
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.generation != generation {
            return Err("ethereum_profile_changed");
        }
        if !approval_current() {
            return Err("ethereum_gateway_review_expired");
        }
        let profile_dir = binding.profile_dir.clone();
        let gateway_path = profile_dir
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join(GATEWAY_DESTINATION_FILE);
        let disk_gateway = match load_gateway_destination(&profile_dir) {
            Ok(gateway) => Some(gateway),
            Err(()) if !gateway_path.exists() => None,
            Err(()) => return Err("ethereum_gateway_storage_changed"),
        };
        if disk_gateway != binding.configured_gateway_source_hash {
            return Err("ethereum_gateway_storage_changed");
        }
        if disk_gateway == Some(source_hash) {
            scoped
                .profile_binding
                .as_mut()
                .ok_or("ethereum_profile_unavailable")?
                .configured_gateway_source_hash = Some(source_hash);
            return Ok(());
        }
        if !scoped.pending_reviews.is_empty()
            || !scoped.pending_native_transfers.is_empty()
            || {
                #[cfg(any(target_os = "android", target_os = "linux", test))]
                {
                    !scoped.pending_clear_signed_operations.is_empty()
                }
                #[cfg(not(any(target_os = "android", target_os = "linux", test)))]
                {
                    false
                }
            }
        {
            return Err("ethereum_gateway_change_blocked");
        }
        let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
            .map_err(|_| "ethereum_state_unavailable")?;
        store
            .ensure_gateway_replacement_allowed(source_hash, now_unix)
            .map_err(|_| "ethereum_gateway_change_blocked")?;
        if let Err(error) = publisher(&profile_dir, source_hash) {
            if error == "ethereum_gateway_storage_reconciliation_required" {
                let durable = load_gateway_destination(&profile_dir).ok();
                let reconciled = if durable == Some(source_hash) || durable == disk_gateway {
                    durable
                } else {
                    None
                };
                scoped
                    .profile_binding
                    .as_mut()
                    .ok_or("ethereum_profile_unavailable")?
                    .configured_gateway_source_hash = reconciled;
                if durable == Some(source_hash) {
                    self.sync_not_before_unix.store(0, Ordering::Release);
                    self.outbound_notify.notify_one();
                    return Ok(());
                }
            }
            return Err(error);
        }
        scoped
            .profile_binding
            .as_mut()
            .ok_or("ethereum_profile_unavailable")?
            .configured_gateway_source_hash = Some(source_hash);
        drop(scoped);
        self.sync_not_before_unix.store(0, Ordering::Release);
        self.outbound_notify.notify_one();
        Ok(())
    }

    pub(crate) fn transport_binding(
        &self,
    ) -> Result<Option<EthereumTransportBinding>, &'static str> {
        self.profile_binding().map(|binding| {
            binding.and_then(|binding| {
                binding
                    .configured_gateway_source_hash
                    .map(|gateway_destination_hash| EthereumTransportBinding {
                        generation: binding.generation,
                        profile_dir: binding.profile_dir,
                        ratspeak_identity_hash: binding.ratspeak_identity_hash,
                        identity_session_generation: binding.identity_session_generation,
                        gateway_destination_hash,
                    })
            })
        })
    }

    pub(crate) fn transport_binding_is_current(
        &self,
        expected: &EthereumTransportBinding,
    ) -> Result<bool, &'static str> {
        Ok(self.transport_binding()?.is_some_and(|current| {
            current.generation == expected.generation
                && current.profile_dir == expected.profile_dir
                && current.ratspeak_identity_hash == expected.ratspeak_identity_hash
                && current.identity_session_generation == expected.identity_session_generation
                && current.gateway_destination_hash == expected.gateway_destination_hash
        }))
    }

    pub(crate) fn wake_outbound(&self) {
        self.outbound_notify.notify_one();
    }

    /// Best-effort transport planning after an exact native ClearSign result
    /// has already been durably persisted. Absence of a configured gateway is
    /// not a signing failure; a later explicit sync can queue the same relay.
    #[cfg(any(target_os = "android", test))]
    pub(crate) fn plan_signed_relay_if_configured(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        signed: &StoredSignedTransaction,
        now_unix: u64,
    ) -> Result<bool, &'static str> {
        if now_unix == 0 {
            return Err("clock_unavailable");
        }
        let scoped = self
            .scoped
            .read()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
        {
            return Err("ethereum_profile_changed");
        }
        let Some(gateway) = binding.configured_gateway_source_hash else {
            return Ok(false);
        };
        let request_id = secure_trigger_id()?;
        let expires_at_unix = now_unix
            .checked_add(EVIDENCE_SYNC_EXPIRY_SECONDS)
            .ok_or("ethereum_sync_unavailable")?;
        let mut store = open_profile_store(&binding.profile_dir)?;
        let outcome = store
            .plan_signed_transaction_relay(
                request_id,
                gateway,
                signed,
                now_unix,
                expires_at_unix,
            )
            .map_err(|_| "ethereum_relay_unavailable")?;
        Ok(outcome == ratspeak_eth_node::RecordOutcome::Inserted)
    }

    pub(crate) fn outbound_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.outbound_notify)
    }

    pub(crate) fn claim_outbound_coordinator(&self) -> bool {
        self.outbound_coordinator_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn claim_sync_command(&self) -> Option<EthereumSyncCommandAdmission> {
        self.sync_command_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| EthereumSyncCommandAdmission {
                active: Arc::clone(&self.sync_command_active),
            })
    }

    fn claim_checkpoint_connect(&self) -> Option<EthereumSyncCommandAdmission> {
        self.checkpoint_connect_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| EthereumSyncCommandAdmission {
                active: Arc::clone(&self.checkpoint_connect_active),
            })
    }

    fn sync_command_is_rate_limited(&self, now_unix: u64) -> bool {
        now_unix < self.sync_not_before_unix.load(Ordering::Acquire)
    }

    fn record_sync_command_success(&self, now_unix: u64) -> Result<(), &'static str> {
        let not_before = now_unix
            .checked_add(EVIDENCE_SYNC_COMMAND_COOLDOWN_SECONDS)
            .ok_or("ethereum_sync_unavailable")?;
        self.sync_not_before_unix
            .store(not_before, Ordering::Release);
        Ok(())
    }

    /// Retains a public projection of a field-node-owned pending transfer.
    /// The non-serializable prepared transfer remains outside the WebView.
    #[allow(dead_code)]
    pub(crate) fn register_prepared_transfer(
        &self,
        generation: EthereumProfileGeneration,
        pending: PreparedFieldTransfer,
    ) -> Result<(), &'static str> {
        let operation_id = *pending.operation_id().as_bytes();
        let review = EthereumTransferReviewView::from_review(pending.review());
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        let account = binding
            .public_account
            .ok_or("ethereum_wallet_unavailable")?;
        if binding.generation != generation || review.from != format!("{:#x}", account.address()) {
            return Err("ethereum_profile_changed");
        }
        if scoped.pending_native_transfers.len() >= MAX_PENDING_REVIEW_SURFACES
            && !scoped.pending_native_transfers.contains_key(&operation_id)
        {
            return Err("ethereum_review_capacity_reached");
        }
        scoped.pending_reviews.insert(operation_id, review);
        scoped
            .pending_native_transfers
            .insert(operation_id, pending);
        Ok(())
    }

    #[cfg(test)]
    fn register_review_surface(
        &self,
        generation: EthereumProfileGeneration,
        operation_id: [u8; 16],
        review: EthereumTransferReviewView,
    ) -> Result<(), &'static str> {
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        let account = binding
            .public_account
            .ok_or("ethereum_wallet_unavailable")?;
        if binding.generation != generation || review.from != format!("{:#x}", account.address()) {
            return Err("ethereum_profile_changed");
        }
        if scoped.pending_reviews.len() >= MAX_PENDING_REVIEW_SURFACES
            && !scoped.pending_reviews.contains_key(&operation_id)
        {
            return Err("ethereum_review_capacity_reached");
        }
        scoped.pending_reviews.insert(operation_id, review);
        Ok(())
    }

    fn profile_binding(&self) -> Result<Option<EthereumProfileBinding>, &'static str> {
        self.scoped
            .read()
            .map(|scoped| scoped.profile_binding.clone())
            .map_err(|_| "ethereum_state_unavailable")
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn native_profile_binding(
        &self,
    ) -> Result<Option<EthereumNativeProfileBinding>, &'static str> {
        self.profile_binding().map(|binding| {
            binding.and_then(|binding| {
                binding
                    .public_account
                    .map(|public_account| EthereumNativeProfileBinding {
                        public_account,
                        ratspeak_identity_hash: binding.ratspeak_identity_hash,
                        identity_session_generation: binding.identity_session_generation,
                    })
            })
        })
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn native_transport_profile_binding(
        &self,
    ) -> Result<Option<EthereumNativeTransportProfileBinding>, &'static str> {
        self.profile_binding().map(|binding| {
            binding.map(|binding| EthereumNativeTransportProfileBinding {
                generation: binding.generation,
                profile_dir: binding.profile_dir,
                ratspeak_identity_hash: binding.ratspeak_identity_hash,
                identity_session_generation: binding.identity_session_generation,
            })
        })
    }

    /// Returns the exact active transport binding, installing a new identity
    /// session only when the native runtime has actually changed profiles.
    ///
    /// Native file pickers use this narrow transition instead of reinstalling
    /// the current profile on every launch. That keeps a same-session picker
    /// from observing an out-of-band gateway-file change and clearing an
    /// unrelated prepared transfer or review, while still invalidating the
    /// old session promptly after a real Ratspeak identity switch.
    #[cfg(any(target_os = "android", test))]
    pub(crate) fn ensure_native_transport_profile_binding(
        &self,
        profile_dir: PathBuf,
        public_account: Option<WalletAccount>,
        ratspeak_identity_hash: [u8; 16],
        identity_session_generation: u64,
    ) -> Result<EthereumNativeTransportProfileBinding, &'static str> {
        let profile_dir = profile_dir
            .canonicalize()
            .map_err(|_| "ethereum_profile_unavailable")?;
        if let Some(binding) = self.native_transport_profile_binding()?.filter(|binding| {
            binding.profile_dir == profile_dir
                && binding.ratspeak_identity_hash == ratspeak_identity_hash
                && binding.identity_session_generation == identity_session_generation
        }) {
            return Ok(binding);
        }

        let generation = if let Some(account) = public_account {
            self.install_profile_binding_for_identity(
                profile_dir.clone(),
                account,
                ratspeak_identity_hash,
                identity_session_generation,
            )?
        } else {
            self.install_transport_profile_for_identity(
                profile_dir.clone(),
                ratspeak_identity_hash,
                identity_session_generation,
            )?
        };
        Ok(EthereumNativeTransportProfileBinding {
            generation,
            profile_dir,
            ratspeak_identity_hash,
            identity_session_generation,
        })
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn ensure_native_identity(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
    ) -> Result<(), &'static str> {
        let scoped = self
            .scoped
            .read()
            .map_err(|_| "ethereum_state_unavailable")?;
        if scoped.profile_binding.as_ref().is_some_and(|binding| {
            binding.ratspeak_identity_hash == identity_hash
                && binding.identity_session_generation == identity_session_generation
        }) {
            Ok(())
        } else {
            Err("ethereum_profile_changed")
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn cancel_native_transfer(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        operation_id: [u8; 16],
    ) -> Result<(), &'static str> {
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
        {
            return Err("ethereum_profile_changed");
        }
        let cancellation = PendingNativeCancellation {
            profile_dir: binding.profile_dir.clone(),
            ratspeak_identity_hash: identity_hash,
            identity_session_generation,
            operation_id,
        };
        scoped.pending_reviews.remove(&operation_id);
        scoped.pending_native_transfers.remove(&operation_id);
        drop(scoped);
        match cancel_persisted_native_transfer(&cancellation) {
            Ok(()) => {
                if let Ok(mut scoped) = self.scoped.write() {
                    scoped.pending_native_cancellations.remove(&cancellation);
                }
                Ok(())
            }
            Err(error) => {
                self.scoped
                    .write()
                    .map_err(|_| "ethereum_state_unavailable")?
                    .pending_native_cancellations
                    .insert(cancellation);
                Err(error)
            }
        }
    }

    /// Retries durable-store cancellation after native/JNI callers have lost
    /// their copy of the one-shot operation identifier. Tombstones are scoped
    /// to the exact profile and Ratspeak identity session, and never restore a
    /// removed signing capability.
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn retry_native_cancellations(&self) {
        let cancellations = self
            .scoped
            .read()
            .map(|scoped| {
                scoped
                    .pending_native_cancellations
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for cancellation in cancellations {
            if cancel_persisted_native_transfer(&cancellation).is_ok() {
                if let Ok(mut scoped) = self.scoped.write() {
                    scoped.pending_native_cancellations.remove(&cancellation);
                }
            }
        }
    }

    #[cfg(test)]
    fn pending_native_cancellation_count(&self) -> usize {
        self.scoped
            .read()
            .map(|scoped| scoped.pending_native_cancellations.len())
            .unwrap_or(usize::MAX)
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn next_operation_id(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        intent: &EthereumNativeTransferIntent,
        now_unix: u64,
    ) -> Result<OperationId, &'static str> {
        let nonce = self.operation_nonce.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; 16];
        for (index, domain) in [0x52534554484f5031_u64, 0x52534554484f5032]
            .into_iter()
            .enumerate()
        {
            let mut hasher = self.operation_ids.build_hasher();
            hasher.write_u64(domain);
            hasher.write(&identity_hash);
            hasher.write_u64(identity_session_generation);
            hasher.write_u64(nonce);
            hasher.write_u64(now_unix);
            hasher.write(intent.recipient.as_bytes());
            hasher.write(intent.value_wei.as_bytes());
            hasher.write(intent.max_fee_per_gas_wei.as_bytes());
            hasher.write(intent.max_priority_fee_per_gas_wei.as_bytes());
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        }
        OperationId::new(bytes).map_err(|_| "ethereum_operation_id_unavailable")
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn prepare_clear_signed_operation_for_native(
        &self,
        generation: EthereumProfileGeneration,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        request: &EthereumClearSignedOperationRequest,
        prepared_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<NativeClearSignedCandidate, &'static str> {
        let (profile_dir, account) = {
            let scoped = self
                .scoped
                .read()
                .map_err(|_| "ethereum_state_unavailable")?;
            let binding = scoped
                .profile_binding
                .as_ref()
                .ok_or("ethereum_profile_unavailable")?;
            if binding.generation != generation
                || binding.ratspeak_identity_hash != identity_hash
                || binding.identity_session_generation != identity_session_generation
            {
                return Err("ethereum_profile_changed");
            }
            (
                binding.profile_dir.clone(),
                binding.public_account.ok_or("ethereum_wallet_unavailable")?,
            )
        };

        let definitions_path = profile_dir
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join("definitions");
        let mut definitions = DefinitionRegistry::load_dir(&definitions_path)
            .map_err(|_| "ethereum_definition_store_unavailable")?;
        definitions
            .install_poc_native_definitions()
            .map_err(|_| "ethereum_definition_store_unavailable")?;

        let intent = request.intent(account)?;
        let operation_id = self.next_clear_signed_operation_id(
            identity_hash,
            identity_session_generation,
            request,
            prepared_at_unix,
        )?;
        let prepared = account
            .prepare_clear_signed_operation(
                intent,
                &definitions,
                operation_id,
                prepared_at_unix,
                expires_at_unix,
            )
            .map_err(|_| "ethereum_clear_sign_rejected")?;
        let review = prepared.review();
        let candidate = NativeClearSignedCandidate {
            operation_id: *review.operation_id.as_bytes(),
            chain_id: review.chain_id,
            sender: format!("{:#x}", review.from),
            network: review.clear_sign.network.clone(),
            definition_hash: review.clear_sign.definition_hash.0,
            operation_hash: review.clear_sign.operation_hash.0,
            asset_symbol: review.clear_sign.asset_symbol.clone(),
            asset_decimals: review.clear_sign.asset_decimals,
            recipient: format!("{:#x}", review.clear_sign.recipient),
            amount: review.clear_sign.amount.to_string(),
            nonce: review.nonce,
            gas_limit: review.gas_limit,
            max_fee_per_gas_wei: review.max_fee_per_gas,
            max_priority_fee_per_gas_wei: review.max_priority_fee_per_gas,
            expires_at_unix: review.expires_at_unix,
            canonical_signing_payload: prepared.canonical_signing_bytes().to_vec(),
        };
        self.register_prepared_clear_signed_operation(generation, prepared)?;
        Ok(candidate)
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    fn next_clear_signed_operation_id(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        request: &EthereumClearSignedOperationRequest,
        now_unix: u64,
    ) -> Result<OperationId, &'static str> {
        let nonce = self.operation_nonce.fetch_add(1, Ordering::Relaxed);
        let mut material = Vec::with_capacity(256 + request.calldata_hex.len());
        material.extend_from_slice(b"ratspeak.ethereum.clear-sign-operation-id.v1\0");
        material.extend_from_slice(&identity_hash);
        material.extend_from_slice(&identity_session_generation.to_be_bytes());
        material.extend_from_slice(&nonce.to_be_bytes());
        material.extend_from_slice(&now_unix.to_be_bytes());
        material.extend_from_slice(&request.chain_id.to_be_bytes());
        material.extend_from_slice(request.target.as_bytes());
        material.extend_from_slice(request.value_wei.as_bytes());
        material.extend_from_slice(request.calldata_hex.as_bytes());
        material.extend_from_slice(&request.nonce.to_be_bytes());
        material.extend_from_slice(&request.gas_limit.to_be_bytes());
        material.extend_from_slice(request.max_fee_per_gas_wei.as_bytes());
        material.extend_from_slice(request.max_priority_fee_per_gas_wei.as_bytes());
        let digest = keccak256(material);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest.as_slice()[..16]);
        if bytes == [0; 16] {
            bytes[15] = 1;
        }
        OperationId::new(bytes).map_err(|_| "ethereum_operation_id_unavailable")
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn register_prepared_clear_signed_operation(
        &self,
        generation: EthereumProfileGeneration,
        pending: PreparedClearSignedOperation,
    ) -> Result<(), &'static str> {
        let operation_id = *pending.review().operation_id.as_bytes();
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        let account = binding
            .public_account
            .ok_or("ethereum_wallet_unavailable")?;
        if binding.generation != generation
            || pending.review().from != account.address()
        {
            return Err("ethereum_profile_changed");
        }
        if scoped.pending_clear_signed_operations.len() >= MAX_PENDING_REVIEW_SURFACES
            && !scoped
                .pending_clear_signed_operations
                .contains_key(&operation_id)
        {
            return Err("ethereum_review_capacity_reached");
        }
        scoped
            .pending_clear_signed_operations
            .insert(operation_id, pending);
        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn cancel_native_clear_signed_operation(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        operation_id: [u8; 16],
    ) -> Result<(), &'static str> {
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
        {
            return Err("ethereum_profile_changed");
        }
        scoped.pending_clear_signed_operations.remove(&operation_id);
        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn with_native_clear_signed_operation<T>(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        account: WalletAccount,
        candidate: &NativeClearSignedCandidate,
        operation: impl FnOnce(&Path, PreparedClearSignedOperation) -> T,
    ) -> Result<T, &'static str> {
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
            || binding.public_account != Some(account)
            || candidate.sender != format!("{:#x}", account.address())
        {
            return Err("ethereum_profile_changed");
        }
        let profile_dir = binding.profile_dir.clone();
        let operation_id = candidate.operation_id;
        let matches = scoped
            .pending_clear_signed_operations
            .get(&operation_id)
            .is_some_and(|pending| candidate.matches(pending));
        if !matches {
            return Err("ethereum_review_mismatch");
        }
        let pending = scoped
            .pending_clear_signed_operations
            .remove(&operation_id)
            .ok_or("ethereum_review_mismatch")?;
        Ok(operation(&profile_dir, pending))
    }

    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn with_native_transfer<T>(
        &self,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        account: WalletAccount,
        candidate: &NativeExactTransferCandidate,
        operation: impl FnOnce(&Path, PreparedFieldTransfer) -> T,
    ) -> Result<T, &'static str> {
        let mut scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
            || binding.public_account != Some(account)
            || candidate.sender != format!("{:#x}", account.address())
        {
            return Err("ethereum_profile_changed");
        }
        let profile_dir = binding.profile_dir.clone();

        let operation_id = candidate.operation_id;
        let matches = scoped
            .pending_native_transfers
            .get(&operation_id)
            .is_some_and(|pending| candidate.matches(pending));
        if !matches {
            return Err("ethereum_review_mismatch");
        }
        let pending = scoped
            .pending_native_transfers
            .remove(&operation_id)
            .ok_or("ethereum_review_mismatch")?;
        scoped.pending_reviews.remove(&operation_id);
        // Keep the profile write lock through exact signing and persistence so
        // a concurrent profile switch cannot redirect or outlive this native
        // authorization. Android has already completed its user-presence prompt.
        Ok(operation(&profile_dir, pending))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_linux_profile<T>(
        &self,
        generation: EthereumProfileGeneration,
        identity_hash: [u8; 16],
        identity_session_generation: u64,
        account: WalletAccount,
        operation: impl FnOnce(&Path) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let scoped = self
            .scoped
            .write()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.generation != generation
            || binding.ratspeak_identity_hash != identity_hash
            || binding.identity_session_generation != identity_session_generation
            || binding.public_account != Some(account)
        {
            return Err("ethereum_profile_changed");
        }
        operation(&binding.profile_dir)
    }

    /// Linux native bulk-evidence review uses the same profile, identity, and
    /// configured-gateway fence as outbound transport. The caller holds the
    /// runtime identity lifecycle lock while invoking this short operation.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_linux_transport_binding<T>(
        &self,
        expected: &EthereumTransportBinding,
        operation: impl FnOnce(&Path) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.with_current_transport_binding(expected, operation)
    }

    fn ensure_current_generation(
        &self,
        generation: EthereumProfileGeneration,
    ) -> Result<(), &'static str> {
        let scoped = self
            .scoped
            .read()
            .map_err(|_| "ethereum_state_unavailable")?;
        if scoped
            .profile_binding
            .as_ref()
            .is_some_and(|binding| binding.generation == generation)
        {
            Ok(())
        } else {
            Err("ethereum_profile_changed")
        }
    }

    /// Runs one short profile-local operation while the exact profile,
    /// identity session, and configured gateway remain fixed. The runtime
    /// identity lifecycle fence is acquired by the caller before this lock.
    pub(crate) fn with_current_transport_binding<T>(
        &self,
        expected: &EthereumTransportBinding,
        operation: impl FnOnce(&Path) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let scoped = self
            .scoped
            .read()
            .map_err(|_| "ethereum_state_unavailable")?;
        let binding = scoped
            .profile_binding
            .as_ref()
            .ok_or("ethereum_profile_unavailable")?;
        if binding.generation != expected.generation
            || binding.profile_dir != expected.profile_dir
            || binding.ratspeak_identity_hash != expected.ratspeak_identity_hash
            || binding.identity_session_generation != expected.identity_session_generation
            || binding.configured_gateway_source_hash != Some(expected.gateway_destination_hash)
        {
            return Err("ethereum_profile_changed");
        }
        let canonical = binding
            .profile_dir
            .canonicalize()
            .map_err(|_| "ethereum_profile_unavailable")?;
        if canonical != binding.profile_dir {
            return Err("ethereum_profile_changed");
        }
        operation(&binding.profile_dir)
    }

    fn review(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<EthereumTransferReviewView>, &'static str> {
        self.scoped
            .read()
            .map(|scoped| scoped.pending_reviews.get(&operation_id).cloned())
            .map_err(|_| "ethereum_state_unavailable")
    }
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct NativeClearSignedCandidate {
    pub(crate) operation_id: [u8; 16],
    pub(crate) chain_id: u64,
    pub(crate) sender: String,
    pub(crate) network: String,
    pub(crate) definition_hash: [u8; 32],
    pub(crate) operation_hash: [u8; 32],
    pub(crate) asset_symbol: String,
    pub(crate) asset_decimals: u8,
    pub(crate) recipient: String,
    pub(crate) amount: String,
    pub(crate) nonce: u64,
    pub(crate) gas_limit: u64,
    pub(crate) max_fee_per_gas_wei: u128,
    pub(crate) max_priority_fee_per_gas_wei: u128,
    pub(crate) expires_at_unix: u64,
    pub(crate) canonical_signing_payload: Vec<u8>,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
impl NativeClearSignedCandidate {
    fn matches(&self, pending: &PreparedClearSignedOperation) -> bool {
        let review = pending.review();
        review.operation_id.as_bytes() == &self.operation_id
            && review.chain_id == self.chain_id
            && format!("{:#x}", review.from) == self.sender
            && review.clear_sign.network == self.network
            && review.clear_sign.definition_hash.0 == self.definition_hash
            && review.clear_sign.operation_hash.0 == self.operation_hash
            && review.clear_sign.asset_symbol == self.asset_symbol
            && review.clear_sign.asset_decimals == self.asset_decimals
            && format!("{:#x}", review.clear_sign.recipient) == self.recipient
            && review.clear_sign.amount.to_string() == self.amount
            && review.nonce == self.nonce
            && review.gas_limit == self.gas_limit
            && review.max_fee_per_gas == self.max_fee_per_gas_wei
            && review.max_priority_fee_per_gas == self.max_priority_fee_per_gas_wei
            && review.expires_at_unix == self.expires_at_unix
            && pending.canonical_signing_bytes() == self.canonical_signing_payload
    }
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct NativeExactTransferCandidate {
    pub(crate) operation_id: [u8; 16],
    pub(crate) chain_id: u64,
    pub(crate) sender: String,
    pub(crate) recipient: String,
    pub(crate) value_wei: String,
    pub(crate) nonce: u64,
    pub(crate) gas_limit: u64,
    pub(crate) max_fee_per_gas_wei: u128,
    pub(crate) max_priority_fee_per_gas_wei: u128,
    pub(crate) expires_at_unix: u64,
    pub(crate) canonical_signing_payload: Vec<u8>,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
impl NativeExactTransferCandidate {
    fn matches(&self, pending: &PreparedFieldTransfer) -> bool {
        self.matches_review(
            pending.operation_id(),
            pending.review(),
            pending.canonical_signing_bytes(),
        )
    }

    fn matches_review(
        &self,
        operation_id: OperationId,
        review: &ratspeak_eth_wallet::TransferReview,
        signing_bytes: &[u8],
    ) -> bool {
        operation_id.as_bytes() == &self.operation_id
            && review.chain_id() == self.chain_id
            && review.network() == SEPOLIA_NETWORK
            && format!("{:#x}", review.from()) == self.sender
            && format!("{:#x}", review.to()) == self.recipient
            && review.value().to_string() == self.value_wei
            && review.nonce() == self.nonce
            && review.gas_limit() == self.gas_limit
            && review.max_fee_per_gas() == self.max_fee_per_gas_wei
            && review.max_priority_fee_per_gas() == self.max_priority_fee_per_gas_wei
            && review.expires_at_unix() == self.expires_at_unix
            && signing_bytes == self.canonical_signing_payload
    }
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EthereumClearSignedOperationRequest {
    pub(crate) chain_id: u64,
    pub(crate) target: String,
    pub(crate) value_wei: String,
    pub(crate) calldata_hex: String,
    pub(crate) nonce: u64,
    pub(crate) gas_limit: u64,
    pub(crate) max_fee_per_gas_wei: String,
    pub(crate) max_priority_fee_per_gas_wei: String,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
impl EthereumClearSignedOperationRequest {
    fn intent(&self, account: WalletAccount) -> Result<ClearSignedIntent, &'static str> {
        if ratspeak_eth_verifier::chain_definition(self.chain_id).is_none() {
            return Err("unsupported_ethereum_chain");
        }
        let target = self
            .target
            .parse::<Address>()
            .map_err(|_| "invalid_ethereum_target")?;
        let value = parse_canonical_u256(&self.value_wei).ok_or("invalid_ethereum_value")?;
        let max_fee_per_gas =
            parse_canonical_u128(&self.max_fee_per_gas_wei).ok_or("invalid_ethereum_max_fee")?;
        let max_priority_fee_per_gas = parse_canonical_u128(
            &self.max_priority_fee_per_gas_wei,
        )
        .ok_or("invalid_ethereum_priority_fee")?;
        if self.gas_limit == 0 || max_priority_fee_per_gas > max_fee_per_gas {
            return Err("invalid_ethereum_fee_policy");
        }
        let digits = self
            .calldata_hex
            .strip_prefix("0x")
            .ok_or("invalid_ethereum_calldata")?;
        if digits.len() % 2 != 0
            || digits.len() > 128 * 1024
            || digits
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err("invalid_ethereum_calldata");
        }
        let input = alloy_primitives::hex::decode(digits)
            .map_err(|_| "invalid_ethereum_calldata")?;
        Ok(ClearSignedIntent {
            chain_id: self.chain_id,
            from: account.address(),
            to: target,
            value,
            input: Bytes::from(input),
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }
}

/// The only mutating WebView request admitted by the experimental Ethereum
/// surface. It selects a native ceremony or supplies public operation facts.
/// Rust still loads trusted definitions, constructs and retains the exact
/// canonical signing bytes, revalidates the native review, signs, and persists.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EthereumNativeWalletLaunchRequest {
    ManageWallet,
    Transfer(EthereumNativeTransferIntent),
    #[cfg(any(target_os = "android", test))]
    ClearSigned(EthereumClearSignedOperationRequest),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EthereumNativeTransferIntent {
    pub(crate) recipient: String,
    pub(crate) value_wei: String,
    pub(crate) max_fee_per_gas_wei: String,
    pub(crate) max_priority_fee_per_gas_wei: String,
}

impl EthereumNativeTransferIntent {
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn field_request(&self) -> Result<FieldTransferRequest, &'static str> {
        let recipient = self
            .recipient
            .parse::<Address>()
            .map_err(|_| "invalid_ethereum_recipient")?;
        let value = parse_canonical_u256(&self.value_wei).ok_or("invalid_ethereum_value")?;
        let max_fee_per_gas =
            parse_canonical_u128(&self.max_fee_per_gas_wei).ok_or("invalid_ethereum_max_fee")?;
        let max_priority_fee_per_gas = parse_canonical_u128(&self.max_priority_fee_per_gas_wei)
            .ok_or("invalid_ethereum_priority_fee")?;
        Ok(FieldTransferRequest::new(
            recipient,
            value,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumNativeWalletLaunchView {
    operation_id: Option<String>,
    tx_hash: Option<String>,
}

/// Deliberately coarse result from a native-only bulk evidence ceremony. No
/// request identifier, gateway, evidence subject, manifest, or decision is
/// returned to the WebView.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumBulkEvidenceReviewView {
    reviewed: usize,
    approved: usize,
    denied: usize,
    launched: bool,
}

/// Deliberately coarse result from a native-only manual checkpoint ceremony.
/// Checkpoint values, provenance, bundle bytes, and approval authority do not
/// cross the WebView boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumCheckpointReviewView {
    reviewed: usize,
    approved: usize,
    denied: usize,
    launched: bool,
}

/// Coarse result from native manual-checkpoint file selection and staging.
/// Paths, URIs, file bytes, roots, provenance, and pending-review snapshots
/// stay native/Rust-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumCheckpointFileImportView {
    staged: bool,
    cancelled: bool,
    launched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumGatewayCardImportView {
    staged: bool,
    cancelled: bool,
    launched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumGatewayCardReviewView {
    reviewed: bool,
    approved: bool,
    denied: bool,
    launched: bool,
}

impl EthereumCheckpointFileImportView {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_linux(
        outcome: crate::ethereum_linux::LinuxCheckpointFileImportOutcome,
    ) -> Self {
        use crate::ethereum_linux::LinuxCheckpointFileImportOutcome;

        match outcome {
            LinuxCheckpointFileImportOutcome::Staged => Self {
                staged: true,
                cancelled: false,
                launched: false,
            },
            LinuxCheckpointFileImportOutcome::Cancelled => Self {
                staged: false,
                cancelled: true,
                launched: false,
            },
        }
    }

    #[cfg(target_os = "android")]
    pub(crate) fn launched() -> Self {
        Self {
            staged: false,
            cancelled: false,
            launched: true,
        }
    }
}

#[cfg(target_os = "linux")]
impl From<crate::ethereum_linux::LinuxGatewayCardImportOutcome> for EthereumGatewayCardImportView {
    fn from(outcome: crate::ethereum_linux::LinuxGatewayCardImportOutcome) -> Self {
        match outcome {
            crate::ethereum_linux::LinuxGatewayCardImportOutcome::Staged => Self {
                staged: true,
                cancelled: false,
                launched: false,
            },
            crate::ethereum_linux::LinuxGatewayCardImportOutcome::Cancelled => Self {
                staged: false,
                cancelled: true,
                launched: false,
            },
        }
    }
}

#[cfg(target_os = "linux")]
impl From<crate::ethereum_linux::LinuxGatewayCardReviewOutcome> for EthereumGatewayCardReviewView {
    fn from(outcome: crate::ethereum_linux::LinuxGatewayCardReviewOutcome) -> Self {
        use crate::ethereum_linux::LinuxGatewayCardReviewOutcome;
        match outcome {
            LinuxGatewayCardReviewOutcome::Approved => Self {
                reviewed: true,
                approved: true,
                denied: false,
                launched: false,
            },
            LinuxGatewayCardReviewOutcome::Denied => Self {
                reviewed: true,
                approved: false,
                denied: true,
                launched: false,
            },
            LinuxGatewayCardReviewOutcome::NoDecision => Self {
                reviewed: false,
                approved: false,
                denied: false,
                launched: false,
            },
        }
    }
}

impl EthereumGatewayCardImportView {
    #[cfg(target_os = "android")]
    pub(crate) fn launched() -> Self {
        Self {
            staged: false,
            cancelled: false,
            launched: true,
        }
    }
}

impl EthereumGatewayCardReviewView {
    #[cfg(target_os = "android")]
    pub(crate) fn launched() -> Self {
        Self {
            reviewed: false,
            approved: false,
            denied: false,
            launched: true,
        }
    }
}

impl EthereumCheckpointReviewView {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_linux(outcome: crate::ethereum_linux::LinuxCheckpointReviewOutcome) -> Self {
        use crate::ethereum_linux::LinuxCheckpointReviewOutcome;

        match outcome {
            LinuxCheckpointReviewOutcome::ResolvedApproved => Self {
                reviewed: 1,
                approved: 1,
                denied: 0,
                launched: false,
            },
            LinuxCheckpointReviewOutcome::ResolvedDenied => Self {
                reviewed: 1,
                approved: 0,
                denied: 1,
                launched: false,
            },
            LinuxCheckpointReviewOutcome::NoDecision => Self {
                reviewed: 0,
                approved: 0,
                denied: 0,
                launched: false,
            },
        }
    }

    #[cfg(target_os = "android")]
    pub(crate) fn launched() -> Self {
        Self {
            reviewed: 0,
            approved: 0,
            denied: 0,
            launched: true,
        }
    }
}

impl EthereumBulkEvidenceReviewView {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(reviewed: usize, approved: usize, denied: usize) -> Self {
        Self {
            reviewed,
            approved,
            denied,
            launched: false,
        }
    }

    #[cfg(target_os = "android")]
    pub(crate) fn launched() -> Self {
        Self {
            reviewed: 0,
            approved: 0,
            denied: 0,
            launched: true,
        }
    }
}

impl EthereumNativeWalletLaunchView {
    #[cfg(any(target_os = "android", target_os = "linux", test))]
    pub(crate) fn wallet() -> Self {
        Self {
            operation_id: None,
            tx_hash: None,
        }
    }

    #[cfg(any(target_os = "android", test))]
    pub(crate) fn transfer_launched(operation_id: OperationId) -> Self {
        Self {
            operation_id: Some(encode_hex(operation_id.as_bytes())),
            tx_hash: None,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn transfer_signed(operation_id: OperationId, tx_hash: [u8; 32]) -> Self {
        Self {
            operation_id: Some(encode_hex(operation_id.as_bytes())),
            tx_hash: Some(encode_hex(&tx_hash)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EthereumInboundDisposition {
    IgnoredUnauthenticated,
    RejectedAttachment,
    RejectedMessage,
    AcceptedNonAuthoritative,
    BulkApprovalRequired,
    PendingVerification,
    ImportedVerified,
    ServiceFailed,
    Duplicate,
}

struct EthereumInboundLxmfObserver {
    app_handle: tauri::AppHandle,
}

impl ratspeak_tauri::state::InboundLxmfPostPersistenceObserver for EthereumInboundLxmfObserver {
    fn observe(
        &self,
        attachment: ratspeak_tauri::state::PersistedInboundLxmfAttachment,
    ) -> ratspeak_tauri::state::InboundLxmfPostPersistenceDisposition {
        use tauri::Manager;

        let Some(state) = self.app_handle.try_state::<EthereumApplicationState>() else {
            return ratspeak_tauri::state::InboundLxmfPostPersistenceDisposition::OrdinaryMessage;
        };
        let disposition = handle_persisted_gateway_attachment(&state, &attachment);
        let wake_outbound = matches!(
            disposition,
            EthereumInboundDisposition::AcceptedNonAuthoritative
                | EthereumInboundDisposition::PendingVerification
                | EthereumInboundDisposition::ImportedVerified
                | EthereumInboundDisposition::ServiceFailed
        );
        match disposition {
            EthereumInboundDisposition::IgnoredUnauthenticated => {}
            EthereumInboundDisposition::RejectedAttachment => tracing::warn!(
                reason = "persisted_attachment_rejected",
                "ignored persisted Ethereum gateway attachment"
            ),
            EthereumInboundDisposition::RejectedMessage => tracing::warn!(
                reason = "gateway_message_rejected",
                "ignored authenticated Ethereum gateway message"
            ),
            EthereumInboundDisposition::AcceptedNonAuthoritative => tracing::debug!(
                "accepted correlated Ethereum gateway data; verification remains required"
            ),
            EthereumInboundDisposition::BulkApprovalRequired => {
                tracing::debug!(
                    "authenticated Ethereum evidence manifest awaits bounded native approval"
                );
                use tauri::Emitter;
                let _ = self
                    .app_handle
                    .emit("ethereum_bulk_evidence_review_ready", ());
            }
            EthereumInboundDisposition::PendingVerification => tracing::debug!(
                "retained authenticated Ethereum evidence pending local verification"
            ),
            EthereumInboundDisposition::ImportedVerified => {
                tracing::debug!("imported locally verified Ethereum evidence")
            }
            EthereumInboundDisposition::ServiceFailed => tracing::warn!(
                reason = "authenticated_gateway_request_failed",
                "Ethereum service could not complete a correlated request; retry is available"
            ),
            EthereumInboundDisposition::Duplicate => {
                tracing::debug!("ignored duplicate Ethereum gateway message")
            }
        }
        if wake_outbound {
            state.wake_outbound();
        }
        let claimed_application = matches!(
            disposition,
            EthereumInboundDisposition::AcceptedNonAuthoritative
                | EthereumInboundDisposition::BulkApprovalRequired
                | EthereumInboundDisposition::PendingVerification
                | EthereumInboundDisposition::ImportedVerified
                | EthereumInboundDisposition::ServiceFailed
                | EthereumInboundDisposition::Duplicate
        );
        if claimed_application && disposition != EthereumInboundDisposition::BulkApprovalRequired {
            // This is a coarse, secret-free invalidation hint.  The WebView
            // re-reads setup/account state; the protocol bytes never cross
            // into the generic Messages surface or WebView event payload.
            use tauri::Emitter;
            let _ = self.app_handle.emit("ethereum_state_updated", ());
            ratspeak_tauri::state::InboundLxmfPostPersistenceDisposition::ClaimedApplication {
                application_id: "ratspeak.ethereum",
            }
        } else {
            ratspeak_tauri::state::InboundLxmfPostPersistenceDisposition::OrdinaryMessage
        }
    }
}

/// Install the default-off feature adapter on the generic runtime hook. The
/// hook receives only accepted messages after generic DB persistence.
pub(crate) fn install_runtime_adapter(
    app_handle: tauri::AppHandle,
    runtime: &Arc<ratspeak_tauri::state::AppState>,
) -> Result<(), &'static str> {
    runtime.install_inbound_lxmf_post_persistence_observer(Arc::new(
        EthereumInboundLxmfObserver {
            app_handle: app_handle.clone(),
        },
    ))?;
    crate::ethereum_transport::install(app_handle, Arc::clone(runtime))
}

fn handle_persisted_gateway_attachment(
    state: &EthereumApplicationState,
    event: &ratspeak_tauri::state::PersistedInboundLxmfAttachment,
) -> EthereumInboundDisposition {
    // Authentication and exact configured identity are checked before any
    // peer-controlled path is opened or message bytes are decoded.
    if !event.signature_valid {
        return EthereumInboundDisposition::IgnoredUnauthenticated;
    }
    let Ok(scoped) = state.scoped.read() else {
        return EthereumInboundDisposition::RejectedMessage;
    };
    let Some(binding) = scoped.profile_binding.as_ref() else {
        return EthereumInboundDisposition::IgnoredUnauthenticated;
    };
    let Some(receiving_identity) = decode_fixed_hex::<16>(&event.identity_id) else {
        return EthereumInboundDisposition::RejectedMessage;
    };
    if receiving_identity != binding.ratspeak_identity_hash
        || event.identity_session_generation != binding.identity_session_generation
    {
        return EthereumInboundDisposition::RejectedMessage;
    }
    let Some(configured_gateway) = binding.configured_gateway_source_hash else {
        return EthereumInboundDisposition::IgnoredUnauthenticated;
    };
    if event.source_hash != configured_gateway {
        return EthereumInboundDisposition::IgnoredUnauthenticated;
    }

    // Hold the profile read lock through the operation so a native profile
    // switch cannot redirect an old-profile attachment into a new store.
    let Ok(bytes) = read_bounded_persisted_attachment(&event.attachment) else {
        return EthereumInboundDisposition::RejectedAttachment;
    };
    if !event.attachment.matches_authenticated_bytes(&bytes) {
        return EthereumInboundDisposition::RejectedAttachment;
    }
    let Ok(mut store) = EthereumNodeStore::open_in_profile(&binding.profile_dir) else {
        return EthereumInboundDisposition::RejectedMessage;
    };
    let Ok(now_unix) = trusted_now_unix() else {
        return EthereumInboundDisposition::RejectedMessage;
    };
    match store.handle_attachment_from_trusted_lxmf_adapter(
        configured_gateway,
        event.source_hash,
        &bytes,
        now_unix,
    ) {
        Ok(NodeMessageOutcome::IgnoredUnauthenticated) => {
            EthereumInboundDisposition::IgnoredUnauthenticated
        }
        Ok(NodeMessageOutcome::Duplicate) => EthereumInboundDisposition::Duplicate,
        Ok(NodeMessageOutcome::EvidencePending(pending)) => {
            match store.process_pending_message_evidence(pending.request_id()) {
                Ok(_) => EthereumInboundDisposition::ImportedVerified,
                Err(_) => EthereumInboundDisposition::PendingVerification,
            }
        }
        // Manifests and relay observations remain non-authoritative. This
        // adapter has no checkpoint/bootstrap route.
        Ok(NodeMessageOutcome::BulkApprovalRequired(manifest))
            if automatically_approve_expected_evidence(
                manifest.kind(),
                manifest.encoded_size(),
            ) =>
        {
            let review = store
                .pending_bulk_evidence_reviews(configured_gateway, now_unix)
                .ok()
                .and_then(|reviews| {
                    reviews
                        .into_iter()
                        .find(|review| review.request_id() == manifest.request_id())
                });
            match review.and_then(|review| {
                store
                    .resolve_bulk_evidence_review(
                        &review,
                        BulkEvidenceReviewDecision::Approve,
                        now_unix,
                    )
                    .ok()
            }) {
                Some(BulkEvidenceReviewResolution::Approved) => {
                    EthereumInboundDisposition::AcceptedNonAuthoritative
                }
                Some(BulkEvidenceReviewResolution::Denied) | None => {
                    EthereumInboundDisposition::RejectedMessage
                }
            }
        }
        Ok(NodeMessageOutcome::BulkApprovalRequired(_)) => {
            EthereumInboundDisposition::BulkApprovalRequired
        }
        Ok(NodeMessageOutcome::ManifestAccepted(_) | NodeMessageOutcome::RelayObserved { .. }) => {
            EthereumInboundDisposition::AcceptedNonAuthoritative
        }
        Ok(NodeMessageOutcome::TransactionStatusObserved {
            request_id,
            tx_hash,
            status,
        }) => {
            // A service's status can only trigger a locally checkpoint-bound
            // proof request. It never supplies the block, root, proof bytes,
            // or transaction outcome used by local verification.
            if status == TransactionStatus::Included {
                let eligible = store
                    .transaction_status_history_view(tx_hash)
                    .ok()
                    .flatten()
                    .and_then(|history| {
                        let latest = history.latest();
                        latest.included_block_number().map(|included| {
                            included <= latest.finalized_head_number()
                                && latest.source_hash() == configured_gateway
                        })
                    })
                    .unwrap_or(false);
                if eligible {
                    let schedule = secure_trigger_id().and_then(|receipt_request_id| {
                        let expires_at_unix = now_unix
                            .checked_add(EVIDENCE_SYNC_EXPIRY_SECONDS)
                            .ok_or("ethereum_sync_unavailable")?;
                        store
                            .plan_finalized_receipt_after_status(
                                FinalizedStatusReceiptRequest::new(
                                    receipt_request_id,
                                    request_id,
                                    configured_gateway,
                                    MAX_EVIDENCE_SYNC_RESPONSE_BYTES,
                                    now_unix,
                                    expires_at_unix,
                                ),
                            )
                            .map_err(|_| "ethereum_receipt_request_unavailable")
                    });
                    if let Err(error) = schedule {
                        tracing::warn!(
                            reason = error,
                            "Ethereum receipt proof request was not scheduled"
                        );
                    }
                }
            }
            EthereumInboundDisposition::AcceptedNonAuthoritative
        }
        Ok(NodeMessageOutcome::ServiceFailed) => EthereumInboundDisposition::ServiceFailed,
        Err(_) => EthereumInboundDisposition::RejectedMessage,
    }
}

fn automatically_approve_expected_evidence(kind: MessagingEvidenceKind, encoded_size: u32) -> bool {
    if encoded_size == 0 {
        return false;
    }
    match kind {
        MessagingEvidenceKind::AccountStatePackage => {
            encoded_size <= MAX_AUTOMATIC_ACCOUNT_EVIDENCE_BYTES
        }
        MessagingEvidenceKind::FinalizedReceiptPackage => {
            encoded_size <= MAX_AUTOMATIC_RECEIPT_EVIDENCE_BYTES
        }
        _ => false,
    }
}

fn retry_pending_evidence(profile_dir: &Path) {
    let Ok(mut store) = EthereumNodeStore::open_in_profile(profile_dir) else {
        return;
    };
    if store.process_all_pending_message_evidence().is_err() {
        tracing::debug!("Ethereum evidence remains pending local verification");
    }
}

/// Loads a native-administered public gateway destination. The file is not a
/// secret, but accepting aliases or permissive profile files would let another
/// local process silently redirect Ethereum request metadata and relay bytes.
fn load_gateway_destination(profile_dir: &Path) -> Result<[u8; 16], ()> {
    load_gateway_destination_with(profile_dir, |_| {})
}

fn load_gateway_destination_with(
    profile_dir: &Path,
    before_open: impl FnOnce(&Path),
) -> Result<[u8; 16], ()> {
    let root = profile_dir.canonicalize().map_err(|_| ())?;
    let ethereum_dir = root.join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
    let canonical_dir = ethereum_dir.canonicalize().map_err(|_| ())?;
    if canonical_dir.parent() != Some(root.as_path()) {
        return Err(());
    }
    let path = canonical_dir.join(GATEWAY_DESTINATION_FILE);
    let before = std::fs::symlink_metadata(&path).map_err(|_| ())?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() > 33 {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root_metadata = std::fs::metadata(&root).map_err(|_| ())?;
        let directory = std::fs::metadata(&canonical_dir).map_err(|_| ())?;
        if directory.uid() != root_metadata.uid()
            || directory.permissions().mode() & 0o077 != 0
            || before.nlink() != 1
            || before.uid() != directory.uid()
            || before.permissions().mode() & 0o077 != 0
        {
            return Err(());
        }
    }
    before_open(&path);
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ())?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(&path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    let canonical = path.canonicalize().map_err(|_| ())?;
    let after = std::fs::metadata(&path).map_err(|_| ())?;
    if canonical.parent() != Some(canonical_dir.as_path())
        || opened.len() != before.len()
        || after.len() != before.len()
    {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = std::fs::metadata(&canonical_dir).map_err(|_| ())?;
        if !opened.file_type().is_file()
            || opened.nlink() != 1
            || opened.uid() != directory.uid()
            || opened.permissions().mode() & 0o077 != 0
            || opened.len() > 33
            || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
            || (after.dev(), after.ino()) != (before.dev(), before.ino())
        {
            return Err(());
        }
    }
    let mut encoded = Vec::with_capacity(33);
    std::io::Read::by_ref(&mut file)
        .take(34)
        .read_to_end(&mut encoded)
        .map_err(|_| ())?;
    if encoded.last() == Some(&b'\n') {
        encoded.pop();
    }
    decode_gateway_hash(&encoded).ok_or(())
}

fn decode_gateway_hash(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 32 || !encoded.is_ascii() {
        return None;
    }
    let mut hash = [0; 16];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        hash[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    (hash != [0; 16]).then_some(hash)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn persist_gateway_destination(
    profile_dir: &Path,
    source_hash: [u8; 16],
) -> Result<(), &'static str> {
    persist_gateway_destination_with(profile_dir, source_hash, || Ok(()))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn persist_gateway_destination_with(
    profile_dir: &Path,
    source_hash: [u8; 16],
    after_publish: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    persist_gateway_destination_with_hooks(
        profile_dir,
        source_hash,
        || Ok(()),
        || Ok(()),
        || Ok(()),
        after_publish,
    )
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn persist_gateway_destination_with_hooks(
    profile_dir: &Path,
    source_hash: [u8; 16],
    before_publish: impl FnOnce() -> Result<(), &'static str>,
    after_exchange: impl FnOnce() -> Result<(), &'static str>,
    before_rollback: impl Fn() -> Result<(), &'static str>,
    after_publish: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = profile_dir
        .canonicalize()
        .map_err(|_| "ethereum_profile_unavailable")?;
    let directory = root.join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
    let directory = directory
        .canonicalize()
        .map_err(|_| "ethereum_state_unavailable")?;
    let root_metadata = std::fs::metadata(&root).map_err(|_| "ethereum_profile_unavailable")?;
    let directory_metadata =
        std::fs::metadata(&directory).map_err(|_| "ethereum_state_unavailable")?;
    if directory.parent() != Some(root.as_path())
        || !directory_metadata.is_dir()
        || directory_metadata.uid() != root_metadata.uid()
        || directory_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("ethereum_gateway_storage_insecure");
    }
    let mut nonce = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut nonce))
        .map_err(|_| "ethereum_gateway_storage_unavailable")?;
    let temporary = directory.join(format!(".gateway-destination-{}.tmp", encode_hex(&nonce)));
    let target = directory.join(GATEWAY_DESTINATION_FILE);
    let existing = match std::fs::symlink_metadata(&target) {
        Ok(metadata) => {
            load_gateway_destination(&root).map_err(|_| "ethereum_gateway_storage_insecure")?;
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("ethereum_gateway_storage_insecure"),
    };
    let existing_guard = if let Some(expected) = existing.as_ref() {
        let descriptor = rustix::fs::open(
            &target,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "ethereum_gateway_storage_changed")?;
        let file = File::from(descriptor);
        let guarded = file
            .metadata()
            .map_err(|_| "ethereum_gateway_storage_changed")?;
        if !guarded.is_file()
            || guarded.nlink() != 1
            || guarded.uid() != directory_metadata.uid()
            || guarded.permissions().mode() & 0o7177 != 0
            || guarded.len() != 32
            || (guarded.dev(), guarded.ino()) != (expected.dev(), expected.ino())
        {
            return Err("ethereum_gateway_storage_changed");
        }
        Some(file)
    } else {
        None
    };
    let directory_descriptor = rustix::fs::open(
        &directory,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "ethereum_gateway_storage_unavailable")?;
    let mut created_temporary = None;
    let result = (|| {
        let descriptor = rustix::fs::open(
            &temporary,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| "ethereum_gateway_storage_unavailable")?;
        let mut file = File::from(descriptor);
        let encoded = encode_hex(&source_hash);
        file.write_all(encoded.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| "ethereum_gateway_storage_unavailable")?;
        let opened = file
            .metadata()
            .map_err(|_| "ethereum_gateway_storage_unavailable")?;
        let path_metadata = std::fs::symlink_metadata(&temporary)
            .map_err(|_| "ethereum_gateway_storage_unavailable")?;
        created_temporary = Some((opened.dev(), opened.ino(), opened.uid()));
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.uid() != directory_metadata.uid()
            || opened.permissions().mode() & 0o7177 != 0
            || opened.len() != 32
            || (opened.dev(), opened.ino()) != (path_metadata.dev(), path_metadata.ino())
        {
            return Err("ethereum_gateway_storage_insecure");
        }
        let temporary_name = temporary
            .file_name()
            .ok_or("ethereum_gateway_storage_unavailable")?;
        before_publish()?;
        let exchanged = match existing.as_ref() {
            None => {
                rustix::fs::renameat_with(
                    &directory_descriptor,
                    temporary_name,
                    &directory_descriptor,
                    GATEWAY_DESTINATION_FILE,
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(|_| "ethereum_gateway_storage_unavailable")?;
                false
            }
            Some(_) => {
                rustix::fs::renameat_with(
                    &directory_descriptor,
                    temporary_name,
                    &directory_descriptor,
                    GATEWAY_DESTINATION_FILE,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .map_err(|_| "ethereum_gateway_storage_unavailable")?;
                true
            }
        };
        if exchanged {
            let expected = existing_guard
                .as_ref()
                .ok_or("ethereum_gateway_storage_reconciliation_required")?
                .metadata()
                .map_err(|_| "ethereum_gateway_storage_reconciliation_required")?;
            let exchange_hook = after_exchange();
            let displaced_valid = std::fs::symlink_metadata(&temporary).is_ok_and(|displaced| {
                (displaced.dev(), displaced.ino()) == (expected.dev(), expected.ino())
            });
            if !displaced_valid {
                return Err("ethereum_gateway_storage_reconciliation_required");
            }
            if let Err(error) = exchange_hook {
                before_rollback()?;
                let restored = rustix::fs::renameat_with(
                    &directory_descriptor,
                    temporary_name,
                    &directory_descriptor,
                    GATEWAY_DESTINATION_FILE,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .is_ok();
                if !restored || rustix::fs::fsync(&directory_descriptor).is_err() {
                    return Err("ethereum_gateway_storage_reconciliation_required");
                }
                let restored_target = std::fs::symlink_metadata(&target).ok();
                let restored_candidate = std::fs::symlink_metadata(&temporary).ok();
                if !restored_target.as_ref().is_some_and(|metadata| {
                    (metadata.dev(), metadata.ino()) == (expected.dev(), expected.ino())
                }) || !restored_candidate.as_ref().is_some_and(|metadata| {
                    (metadata.dev(), metadata.ino()) == (opened.dev(), opened.ino())
                }) {
                    return Err("ethereum_gateway_storage_reconciliation_required");
                }
                return Err(error);
            }
        }
        let published = after_publish()
            .and_then(|_| {
                rustix::fs::fsync(&directory_descriptor)
                    .map_err(|_| "ethereum_gateway_storage_unavailable")
            })
            .and_then(|_| {
                (load_gateway_destination(&root).ok() == Some(source_hash))
                    .then_some(())
                    .ok_or("ethereum_gateway_storage_insecure")
            });
        if let Err(error) = published {
            let rolled_back = if exchanged {
                let expected = existing_guard
                    .as_ref()
                    .ok_or("ethereum_gateway_storage_reconciliation_required")?
                    .metadata()
                    .map_err(|_| "ethereum_gateway_storage_reconciliation_required")?;
                let displaced_valid =
                    std::fs::symlink_metadata(&temporary).is_ok_and(|displaced| {
                        (displaced.dev(), displaced.ino()) == (expected.dev(), expected.ino())
                    });
                if !displaced_valid {
                    return Err("ethereum_gateway_storage_reconciliation_required");
                }
                before_rollback()?;
                let restored = rustix::fs::renameat_with(
                    &directory_descriptor,
                    temporary_name,
                    &directory_descriptor,
                    GATEWAY_DESTINATION_FILE,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .is_ok();
                let restored_target = std::fs::symlink_metadata(&target).ok();
                let restored_candidate = std::fs::symlink_metadata(&temporary).ok();
                restored
                    && restored_target.as_ref().is_some_and(|metadata| {
                        (metadata.dev(), metadata.ino()) == (expected.dev(), expected.ino())
                    })
                    && restored_candidate.as_ref().is_some_and(|metadata| {
                        (metadata.dev(), metadata.ino()) == (opened.dev(), opened.ino())
                    })
            } else {
                let target_metadata = std::fs::symlink_metadata(&target).ok();
                target_metadata.as_ref().is_some_and(|metadata| {
                    (metadata.dev(), metadata.ino()) == (opened.dev(), opened.ino())
                }) && std::fs::remove_file(&target).is_ok()
            };
            if !rolled_back || rustix::fs::fsync(&directory_descriptor).is_err() {
                return Err("ethereum_gateway_storage_reconciliation_required");
            }
            return Err(error);
        }
        if exchanged {
            // The displaced public routing value remains available for atomic
            // rollback until the new target is synced and securely re-read.
            let expected = existing_guard
                .as_ref()
                .ok_or("ethereum_gateway_storage_reconciliation_required")?
                .metadata()
                .map_err(|_| "ethereum_gateway_storage_reconciliation_required")?;
            if std::fs::symlink_metadata(&temporary).is_ok_and(|displaced| {
                (displaced.dev(), displaced.ino()) == (expected.dev(), expected.ino())
            }) {
                let _ = std::fs::remove_file(&temporary);
            }
            let _ = rustix::fs::fsync(&directory_descriptor);
        }
        Ok(())
    })();
    if result.is_err() {
        // Remove only the exact newly created inode if it is still parked at
        // the random temporary name. After a failed exchange rollback that
        // name may instead hold the displaced prior value and must survive.
        if let (Some(expected), Ok(metadata)) =
            (created_temporary, std::fs::symlink_metadata(&temporary))
        {
            if metadata.is_file()
                && metadata.nlink() == 1
                && (metadata.dev(), metadata.ino(), metadata.uid()) == expected
            {
                let _ = std::fs::remove_file(&temporary);
            }
        }
    }
    result
}

fn read_bounded_persisted_attachment(
    attachment: &ratspeak_tauri::state::PersistedInboundAttachment,
) -> Result<Vec<u8>, ()> {
    let Some(sanitized) = ratspeak_tauri::lxmf::sanitize_stored_file_name(&attachment.stored_name)
    else {
        return Err(());
    };
    if sanitized != attachment.stored_name {
        return Err(());
    }
    let root = attachment.files_dir.canonicalize().map_err(|_| ())?;
    let candidate = root.join(&sanitized);
    let before = std::fs::symlink_metadata(&candidate).map_err(|_| ())?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        return Err(());
    }
    let file = File::open(&candidate).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    let canonical = candidate.canonicalize().map_err(|_| ())?;
    if !canonical.starts_with(&root)
        || opened.len() == 0
        || opened.len() > MAX_PERSISTED_GATEWAY_MESSAGE_BYTES as u64
    {
        return Err(());
    }
    let after = std::fs::metadata(&candidate).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != after.dev() || opened.ino() != after.ino() {
            return Err(());
        }
    }
    #[cfg(not(unix))]
    if opened.len() != after.len() {
        return Err(());
    }

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((MAX_PERSISTED_GATEWAY_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > MAX_PERSISTED_GATEWAY_MESSAGE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumPlatform {
    #[cfg(target_os = "android")]
    Android,
    #[cfg(target_os = "linux")]
    Linux,
    #[cfg(target_os = "ios")]
    Ios,
    #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "ios")))]
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeAuthorizationState {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Available,
    #[cfg(target_os = "linux")]
    Checking,
    Unavailable,
}

/// Availability of the native-only bulk-evidence review ceremony. This is
/// intentionally independent of wallet custody: it permits a configured
/// profile to review gateway evidence even when no wallet exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeBulkEvidenceReviewState {
    Available,
    Unavailable,
}

/// Availability of native review for already-staged manual checkpoint
/// candidates. Candidate acquisition is a separate native-only capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeCheckpointReviewState {
    Available,
    Unavailable,
}

/// Availability of native manual checkpoint file selection and staging.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeCheckpointFileImportState {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeGatewayPairingState {
    #[cfg(any(target_os = "linux", test))]
    Contacts,
    #[cfg(any(target_os = "android", test))]
    File,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumFeatureStatus {
    chain_id: u64,
    network: &'static str,
    mainnet_available: bool,
    platform: EthereumPlatform,
    native_authorization: NativeAuthorizationState,
    native_bulk_evidence_review: NativeBulkEvidenceReviewState,
    native_checkpoint_review: NativeCheckpointReviewState,
    native_checkpoint_file_import: NativeCheckpointFileImportState,
    native_gateway_pairing: NativeGatewayPairingState,
    unavailable_reason: Option<&'static str>,
}

impl EthereumFeatureStatus {
    fn current() -> Self {
        #[cfg(target_os = "android")]
        if crate::ethereum_android::native_wallet_available() {
            return Self {
                chain_id: SEPOLIA_CHAIN_ID,
                network: SEPOLIA_NETWORK,
                mainnet_available: false,
                platform: EthereumPlatform::Android,
                native_authorization: NativeAuthorizationState::Available,
                native_bulk_evidence_review: native_bulk_evidence_review_state(),
                native_checkpoint_review: native_checkpoint_review_state(),
                native_checkpoint_file_import: native_checkpoint_file_import_state(),
                native_gateway_pairing: native_gateway_pairing_state(),
                unavailable_reason: None,
            };
        }
        #[cfg(target_os = "linux")]
        match crate::ethereum_linux::native_wallet_status() {
            crate::ethereum_linux::LinuxWalletStatus::Available => {
                return Self {
                    chain_id: SEPOLIA_CHAIN_ID,
                    network: SEPOLIA_NETWORK,
                    mainnet_available: false,
                    platform: EthereumPlatform::Linux,
                    native_authorization: NativeAuthorizationState::Available,
                    native_bulk_evidence_review: native_bulk_evidence_review_state(),
                    native_checkpoint_review: native_checkpoint_review_state(),
                    native_checkpoint_file_import: native_checkpoint_file_import_state(),
                    native_gateway_pairing: native_gateway_pairing_state(),
                    unavailable_reason: None,
                };
            }
            crate::ethereum_linux::LinuxWalletStatus::Checking => {
                return Self {
                    chain_id: SEPOLIA_CHAIN_ID,
                    network: SEPOLIA_NETWORK,
                    mainnet_available: false,
                    platform: EthereumPlatform::Linux,
                    native_authorization: NativeAuthorizationState::Checking,
                    native_bulk_evidence_review: native_bulk_evidence_review_state(),
                    native_checkpoint_review: native_checkpoint_review_state(),
                    native_checkpoint_file_import: native_checkpoint_file_import_state(),
                    native_gateway_pairing: native_gateway_pairing_state(),
                    unavailable_reason: Some("linux_secret_service_not_checked"),
                };
            }
            crate::ethereum_linux::LinuxWalletStatus::Unavailable => {}
        }
        let (platform, unavailable_reason) = native_unavailable_reason();
        Self {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK,
            mainnet_available: false,
            platform,
            native_authorization: NativeAuthorizationState::Unavailable,
            native_bulk_evidence_review: native_bulk_evidence_review_state(),
            native_checkpoint_review: native_checkpoint_review_state(),
            native_checkpoint_file_import: native_checkpoint_file_import_state(),
            native_gateway_pairing: native_gateway_pairing_state(),
            unavailable_reason: Some(unavailable_reason),
        }
    }
}

fn native_bulk_evidence_review_state() -> NativeBulkEvidenceReviewState {
    #[cfg(target_os = "android")]
    {
        native_bulk_evidence_review_state_from_available(
            crate::ethereum_android::native_bulk_evidence_review_available(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        native_bulk_evidence_review_state_from_available(
            crate::ethereum_linux::native_bulk_evidence_review_available(),
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        native_bulk_evidence_review_state_from_available(false)
    }
}

fn native_bulk_evidence_review_state_from_available(
    available: bool,
) -> NativeBulkEvidenceReviewState {
    if available {
        NativeBulkEvidenceReviewState::Available
    } else {
        NativeBulkEvidenceReviewState::Unavailable
    }
}

fn native_checkpoint_review_state() -> NativeCheckpointReviewState {
    #[cfg(target_os = "android")]
    {
        native_checkpoint_review_state_from_available(
            crate::ethereum_android::native_checkpoint_review_available(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        native_checkpoint_review_state_from_available(
            crate::ethereum_linux::native_checkpoint_review_available(),
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        native_checkpoint_review_state_from_available(false)
    }
}

fn native_checkpoint_review_state_from_available(available: bool) -> NativeCheckpointReviewState {
    if available {
        NativeCheckpointReviewState::Available
    } else {
        NativeCheckpointReviewState::Unavailable
    }
}

fn native_checkpoint_file_import_state() -> NativeCheckpointFileImportState {
    #[cfg(target_os = "android")]
    {
        native_checkpoint_file_import_state_from_available(
            crate::ethereum_android::native_checkpoint_file_import_available(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        native_checkpoint_file_import_state_from_available(
            crate::ethereum_linux::native_checkpoint_review_available(),
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        native_checkpoint_file_import_state_from_available(false)
    }
}

fn native_checkpoint_file_import_state_from_available(
    available: bool,
) -> NativeCheckpointFileImportState {
    if available {
        NativeCheckpointFileImportState::Available
    } else {
        NativeCheckpointFileImportState::Unavailable
    }
}

fn native_gateway_pairing_state() -> NativeGatewayPairingState {
    #[cfg(target_os = "android")]
    {
        if crate::ethereum_android::native_gateway_pairing_available() {
            NativeGatewayPairingState::File
        } else {
            NativeGatewayPairingState::Unavailable
        }
    }
    #[cfg(target_os = "linux")]
    {
        if crate::ethereum_linux::native_gateway_pairing_available() {
            NativeGatewayPairingState::Contacts
        } else {
            NativeGatewayPairingState::Unavailable
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        NativeGatewayPairingState::Unavailable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountAssuranceState {
    Unknown,
    Stale,
    CurrentVerified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumAccountView {
    address: Option<String>,
    assurance: AccountAssuranceState,
    balance_display: String,
    nonce_display: String,
    evidence_age_seconds: Option<u64>,
}

impl EthereumAccountView {
    fn unknown(address: Option<String>) -> Self {
        Self {
            address,
            assurance: AccountAssuranceState::Unknown,
            balance_display: UNKNOWN_DISPLAY.to_owned(),
            nonce_display: UNKNOWN_DISPLAY.to_owned(),
            evidence_age_seconds: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumTransferReviewView {
    operation_id: String,
    review_digest: String,
    chain_id: u64,
    network: &'static str,
    from: String,
    to: String,
    value_wei: String,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas_wei: u128,
    max_priority_fee_per_gas_wei: u128,
    maximum_total_cost_wei: String,
    prepared_at_unix: u64,
    expires_at_unix: u64,
}

impl EthereumTransferReviewView {
    fn from_review(review: &ratspeak_eth_wallet::TransferReview) -> Self {
        Self {
            operation_id: encode_hex(review.operation_id().as_bytes()),
            review_digest: encode_hex(review.review_digest().as_slice()),
            chain_id: review.chain_id(),
            network: review.network(),
            from: format!("{:#x}", review.from()),
            to: format!("{:#x}", review.to()),
            value_wei: review.value().to_string(),
            nonce: review.nonce(),
            gas_limit: review.gas_limit(),
            max_fee_per_gas_wei: review.max_fee_per_gas(),
            max_priority_fee_per_gas_wei: review.max_priority_fee_per_gas(),
            maximum_total_cost_wei: review.maximum_total_cost().to_string(),
            prepared_at_unix: review.prepared_at_unix(),
            expires_at_unix: review.expires_at_unix(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionAssuranceState {
    Unknown,
    SignedUnconfirmed,
    ReceiptNeedsReverification,
    VerifiedSuccess,
    VerifiedFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionProgressState {
    Unknown,
    SignedLocally,
    TransportDelivered,
    GatewayAcknowledged,
    RpcAccepted,
    ReceiptVerifying,
    Finalized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionStatusState {
    NotSeen,
    Pending,
    Included,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionStatusContinuityState {
    Observed,
    AwaitingReinclusion,
    Inconsistent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumBlockObservationView {
    number: u64,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumPreviousInclusionView {
    number: u64,
    hash: String,
    observed_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumTransactionHeadsView {
    latest: EthereumBlockObservationView,
    safe: EthereumBlockObservationView,
    finalized: EthereumBlockObservationView,
}

/// A source-bound Ethereum RPC status observation. This projection intentionally
/// carries no confirmation or assurance field; only the separately verified
/// receipt state below can establish a transaction outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumTransactionStatusObservationView {
    authority: &'static str,
    status: TransactionStatusState,
    observed_at_unix: u64,
    source_hash: String,
    included_block: Option<EthereumBlockObservationView>,
    heads: EthereumTransactionHeadsView,
    continuity: TransactionStatusContinuityState,
    previous_inclusion: Option<EthereumPreviousInclusionView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumReceiptRequestState {
    Requested,
    AwaitingDownload,
    Downloading,
    Verifying,
    Complete,
    Unavailable,
}

/// Secret-free transport/verification progress only. `Complete` is not a
/// transaction outcome; the separately projected assurance remains the sole
/// source of verified success or failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumReceiptRequestView {
    state: EthereumReceiptRequestState,
    created_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumTransactionView {
    tx_hash: String,
    assurance: TransactionAssuranceState,
    progress: TransactionProgressState,
    status_observation: Option<EthereumTransactionStatusObservationView>,
    receipt_request: Option<EthereumReceiptRequestView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumSyncStartState {
    Queued,
    Active,
}

/// Coarse scheduling result only. Request identifiers, checkpoint authority,
/// gateway identity, proof digests, and response limits stay native.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumSyncStartView {
    state: EthereumSyncStartState,
    evidence_requests: usize,
    transaction_relays: usize,
    transaction_status_requests: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumTransactionStatusStartView {
    state: EthereumTransactionStatusStartState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumTransactionStatusStartState {
    Queued,
    Active,
    Recent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumCheckpointSourceView {
    name: String,
    status_url: Option<String>,
    source_fingerprint: String,
    operator_fingerprint: String,
    observation_hash: String,
    observed_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumCheckpointDetailsView {
    epoch: u64,
    root: String,
    approval_basis: String,
    approved_at_unix: u64,
    valid_until_unix: u64,
    sources: Vec<EthereumCheckpointSourceView>,
    local_bootstrap_verified: bool,
    known_online_provider_agreement: bool,
}

/// Profile-scoped Ethereum onboarding and public account state captured under
/// one identity-lifecycle fence. Checkpoint details are public, read-only
/// evidence; gateway keys, bytes, paths, secrets, and review contents remain
/// native-only.
///
/// Native adapters expose only whether a current review exists, never its
/// destination, key, bytes, or approval capability.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumBuiltinAsset {
    BaseSepoliaUsdc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumOfflineReadinessView {
    Ready,
    MissingChainSupport,
    MissingEthereumBootstrap,
    MissingAssetDefinitions,
}

impl From<ratspeak_eth_node::OfflineReadiness> for EthereumOfflineReadinessView {
    fn from(value: ratspeak_eth_node::OfflineReadiness) -> Self {
        match value {
            ratspeak_eth_node::OfflineReadiness::Ready => Self::Ready,
            ratspeak_eth_node::OfflineReadiness::MissingChainSupport => Self::MissingChainSupport,
            ratspeak_eth_node::OfflineReadiness::MissingEthereumBootstrap => {
                Self::MissingEthereumBootstrap
            }
            ratspeak_eth_node::OfflineReadiness::MissingAssetDefinitions => {
                Self::MissingAssetDefinitions
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumAssetInstallView {
    chain_id: u64,
    network: String,
    symbol: String,
    decimals: u8,
    readiness: EthereumOfflineReadinessView,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumSetupStatus {
    identity_ready: bool,
    wallet_configured: bool,
    account: EthereumAccountView,
    account_check: Option<EthereumAccountCheckView>,
    checkpoint_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<EthereumCheckpointDetailsView>,
    gateway_selected: bool,
    gateway_contact_ready: bool,
    gateway_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_service: Option<EthereumServiceView>,
    public_service_available: bool,
    public_service_contact_added: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_checkpoint_review: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_gateway_review: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_evidence_review: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumServiceView {
    display_name: String,
    /// The canonical LXMF destination used by the existing Contact identicon
    /// renderer. This is public Contact metadata, not key or card material.
    avatar_seed: String,
    destination_fingerprint: String,
}

impl EthereumSetupStatus {
    fn unavailable() -> Self {
        Self {
            identity_ready: false,
            wallet_configured: false,
            account: EthereumAccountView::unknown(None),
            account_check: None,
            checkpoint_installed: false,
            checkpoint: None,
            gateway_selected: false,
            gateway_contact_ready: false,
            gateway_configured: false,
            selected_service: None,
            public_service_available: configured_public_service_card().is_some(),
            public_service_contact_added: false,
            pending_checkpoint_review: None,
            pending_gateway_review: None,
            pending_evidence_review: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumAccountCheckStage {
    Queued,
    ServiceContactRequired,
    Sending,
    WaitingForGateway,
    AwaitingDownloadApproval,
    Verifying,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumAccountCheckView {
    stage: EthereumAccountCheckStage,
    created_at_unix: u64,
    expires_at_unix: u64,
}

impl From<ratspeak_eth_node::AccountSyncProgress> for EthereumAccountCheckView {
    fn from(progress: ratspeak_eth_node::AccountSyncProgress) -> Self {
        let stage = match progress.stage() {
            ratspeak_eth_node::AccountSyncStage::Queued => EthereumAccountCheckStage::Queued,
            ratspeak_eth_node::AccountSyncStage::Sending => EthereumAccountCheckStage::Sending,
            ratspeak_eth_node::AccountSyncStage::WaitingForGateway => {
                EthereumAccountCheckStage::WaitingForGateway
            }
            ratspeak_eth_node::AccountSyncStage::AwaitingDownloadApproval => {
                EthereumAccountCheckStage::AwaitingDownloadApproval
            }
            ratspeak_eth_node::AccountSyncStage::Verifying => EthereumAccountCheckStage::Verifying,
            ratspeak_eth_node::AccountSyncStage::Completed => EthereumAccountCheckStage::Completed,
            ratspeak_eth_node::AccountSyncStage::Failed => EthereumAccountCheckStage::Failed,
        };
        Self {
            stage,
            created_at_unix: progress.created_at_unix(),
            expires_at_unix: progress.expires_at_unix(),
        }
    }
}

fn checkpoint_details_view(
    approval: ratspeak_eth_node::StoredCheckpointApproval,
) -> EthereumCheckpointDetailsView {
    let is_provider_agreement =
        approval.approval_basis() == ratspeak_eth_node::CheckpointApprovalBasis::ProviderAgreement;
    let sources: Vec<EthereumCheckpointSourceView> = approval
        .attestations()
        .iter()
        .map(|attestation| {
            let metadata = if attestation.source_kind()
                == ratspeak_eth_node::CheckpointSourceKind::BeaconApi
            {
                crate::ethereum_online::known_provider_metadata(
                    attestation.operator_fingerprint(),
                    attestation.source_fingerprint(),
                )
            } else {
                None
            };
            let fallback_name = match attestation.source_kind() {
                ratspeak_eth_node::CheckpointSourceKind::ManualFile => {
                    "Explicitly approved checkpoint file"
                }
                ratspeak_eth_node::CheckpointSourceKind::ManualQr => {
                    "Explicitly approved checkpoint QR"
                }
                ratspeak_eth_node::CheckpointSourceKind::ManualUrl => {
                    "Explicitly approved checkpoint URL"
                }
                _ => "Configured checkpoint source",
            };
            EthereumCheckpointSourceView {
                name: metadata
                    .map(|(name, _)| name.to_owned())
                    .unwrap_or_else(|| fallback_name.to_owned()),
                status_url: metadata.map(|(_, url)| url.to_owned()),
                source_fingerprint: encode_hex(&attestation.source_fingerprint()),
                operator_fingerprint: encode_hex(&attestation.operator_fingerprint()),
                observation_hash: encode_hex(&attestation.observation_hash()),
                observed_at_unix: attestation.observed_at_unix(),
            }
        })
        .collect();
    let known_online_provider_agreement = is_provider_agreement
        && sources.len() == 2
        && sources.iter().all(|source| {
            source.status_url.as_deref().is_some_and(|url| {
                matches!(
                    url,
                    "https://checkpoint-sync.sepolia.ethpandaops.io/checkpointz/v1/status"
                        | "https://beaconstate-sepolia.chainsafe.io/checkpointz/v1/status"
                )
            })
        })
        && sources
            .iter()
            .map(|source| source.status_url.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 2;
    EthereumCheckpointDetailsView {
        epoch: approval.checkpoint_epoch(),
        root: format!("0x{}", encode_hex(&approval.checkpoint_root())),
        approval_basis: match approval.approval_basis() {
            ratspeak_eth_node::CheckpointApprovalBasis::ProviderAgreement => "provider_agreement",
            ratspeak_eth_node::CheckpointApprovalBasis::ExplicitUserApproval => {
                "explicit_user_approval"
            }
        }
        .to_owned(),
        approved_at_unix: approval.approved_at_unix(),
        valid_until_unix: approval.valid_until_unix(),
        sources,
        // An approval can only be persisted after the policy's bootstrap
        // validator succeeds, including for manual/native review paths.
        local_bootstrap_verified: true,
        known_online_provider_agreement,
    }
}

fn account_check_with_contact_status(
    mut account_check: Option<EthereumAccountCheckView>,
    gateway_contact_ready: bool,
) -> Option<EthereumAccountCheckView> {
    if !gateway_contact_ready
        && account_check.is_some_and(|check| check.stage == EthereumAccountCheckStage::Queued)
    {
        if let Some(check) = account_check.as_mut() {
            check.stage = EthereumAccountCheckStage::ServiceContactRequired;
        }
    }
    account_check
}

fn ethereum_service_view_for_contact(
    runtime: &ratspeak_tauri::state::AppState,
    identity_id: &str,
    destination: [u8; 16],
) -> Option<EthereumServiceView> {
    let destination = encode_hex(&destination);
    if !ratspeak_tauri::commands::shared::has_valid_contact_identity(
        runtime,
        identity_id,
        &destination,
    ) {
        return None;
    }
    let contact = ratspeak_tauri::db::get_contact(&runtime.db, &destination, identity_id)?;
    let display_name = contact
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .map(|name| ratspeak_tauri::helpers::sanitize_text(name, 64))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Unnamed Contact".to_owned());
    Some(EthereumServiceView {
        display_name,
        avatar_seed: destination.clone(),
        destination_fingerprint: format!("{}…{}", &destination[..4], &destination[28..]),
    })
}

#[tauri::command]
pub(crate) fn ethereum_feature_status() -> EthereumFeatureStatus {
    EthereumFeatureStatus::current()
}

/// Returns only coarse setup state for the currently active Ratspeak
/// identity.  The identity lifecycle lock keeps the profile/session fence
/// stable while the profile-local store is inspected.
#[tauri::command]
pub(crate) async fn ethereum_setup_status(
    state: tauri::State<'_, EthereumApplicationState>,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
) -> Result<EthereumSetupStatus, &'static str> {
    let runtime = runtime.inner();
    let _identity_lifecycle = runtime.identity_switch_lock.lock().await;
    let identity = decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_identity_id(runtime));
    let Some(identity) = identity else {
        return Ok(EthereumSetupStatus::unavailable());
    };
    let identity_id = ratspeak_tauri::helpers::active_identity_id(runtime);
    let public_service_contact_added =
        configured_public_service_destination().is_some_and(|destination| {
            ratspeak_tauri::commands::shared::has_valid_contact_identity(
                runtime,
                &identity_id,
                &encode_hex(&destination),
            )
        });
    let selected_service = std::cell::RefCell::new(None);
    let mut status = setup_status_for_identity(
        &state,
        identity,
        runtime.current_identity_session_generation(),
        public_service_contact_added,
        |destination| {
            let service = ethereum_service_view_for_contact(runtime, &identity_id, destination);
            let ready = service.is_some();
            selected_service.replace(service);
            ready
        },
    )?;
    status.selected_service = selected_service.into_inner();
    if status.gateway_configured
        && status
            .account_check
            .is_some_and(|check| check.stage == EthereumAccountCheckStage::Queued)
    {
        // A contact-card import can make an already durable request sendable.
        // Rechecking setup is enough to resume it without manufacturing a new
        // plan or waiting for the coordinator's idle fallback.
        state.wake_outbound();
    }
    Ok(status)
}

/// Installs one built-in PoC asset as an atomic pair of trusted local
/// definitions. The WebView selects only a compiled-in asset identifier; it
/// cannot supply descriptor bytes, storage layout, contract address, chain
/// configuration, or publisher metadata.
#[tauri::command]
pub(crate) async fn ethereum_install_builtin_asset(
    state: tauri::State<'_, EthereumApplicationState>,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
    asset: EthereumBuiltinAsset,
) -> Result<EthereumAssetInstallView, &'static str> {
    let runtime = runtime.inner();
    let _identity_lifecycle = runtime.identity_switch_lock.lock().await;
    let identity = decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_identity_id(runtime))
        .ok_or("ethereum_identity_unavailable")?;
    let binding = state
        .profile_binding()?
        .ok_or("ethereum_profile_unavailable")?;
    if binding.ratspeak_identity_hash != identity
        || binding.identity_session_generation != runtime.current_identity_session_generation()
    {
        return Err("ethereum_profile_changed");
    }

    let definitions_path = binding
        .profile_dir
        .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
        .join("definitions");
    let installed = match asset {
        EthereumBuiltinAsset::BaseSepoliaUsdc => {
            DefinitionRegistry::install_base_sepolia_usdc_bundle_files(&definitions_path)
                .map_err(|_| "ethereum_asset_install_failed")?
        }
    };

    let definitions = DefinitionRegistry::load_dir(&definitions_path)
        .map_err(|_| "ethereum_definition_store_unavailable")?;
    let store = open_profile_store(&binding.profile_dir)?;
    let report = store
        .offline_readiness(
            installed.chain_id,
            trusted_now_unix()?,
            &definitions,
            Some(&installed.clear_sign_definition_id),
            Some(&installed.balance_definition_id),
        )
        .map_err(|_| "ethereum_state_unavailable")?;
    state.ensure_current_generation(binding.generation)?;

    Ok(EthereumAssetInstallView {
        chain_id: installed.chain_id,
        network: installed.network,
        symbol: installed.symbol,
        decimals: installed.decimals,
        readiness: report.readiness.into(),
    })
}

fn setup_status_for_identity(
    state: &EthereumApplicationState,
    identity: [u8; 16],
    identity_session_generation: u64,
    public_service_contact_added: bool,
    gateway_contact_ready: impl FnOnce([u8; 16]) -> bool,
) -> Result<EthereumSetupStatus, &'static str> {
    let Some(binding) = state.profile_binding()? else {
        return Ok(EthereumSetupStatus::unavailable());
    };
    if binding.ratspeak_identity_hash != identity
        || binding.identity_session_generation != identity_session_generation
    {
        // A stale native binding is never reported as belonging to the
        // current profile.  Returning a redacted unavailable state avoids
        // leaking old-profile setup information across an identity switch.
        return Ok(EthereumSetupStatus::unavailable());
    }

    let mut store = open_profile_status_store(&binding.profile_dir)?;
    let stored_account = store
        .wallet_account()
        .map_err(|error| setup_status_store_error("wallet_account", error))?;
    if binding.public_account != stored_account {
        return Err("ethereum_profile_changed");
    }
    let now_unix = trusted_now_unix()?;
    let account = match stored_account {
        Some(account) => {
            let assurance = store
                .account_assurance(account, now_unix, MAX_CURRENT_EVIDENCE_AGE_SECONDS)
                .map_err(|error| setup_status_store_error("account_assurance", error))?;
            account_view_from_assurance(format!("{:#x}", account.address()), &assurance)
        }
        None => EthereumAccountView::unknown(None),
    };
    let policy = ratspeak_eth_node::CheckpointBootstrapPolicy::new(Vec::new())
        .map_err(|_| "ethereum_state_unavailable")?;
    let checkpoint = match policy.active_checkpoint_details(&store) {
        Ok(approval) => Some(checkpoint_details_view(approval)),
        Err(
            ratspeak_eth_node::CheckpointPolicyError::NoApprovedCheckpoint
            | ratspeak_eth_node::CheckpointPolicyError::StaleCheckpoint
            | ratspeak_eth_node::CheckpointPolicyError::RevokedCheckpoint,
        ) => None,
        Err(error) => return Err(setup_status_store_error("active_checkpoint", error)),
    };
    let checkpoint_installed = checkpoint.is_some();
    let pending_checkpoint_review = policy
        .has_pending_manual_checkpoint_review(&mut store)
        .map_err(|error| setup_status_store_error("checkpoint_reviews", error))?;

    // Re-read the protected gateway marker instead of trusting the cached
    // binding: an out-of-band deletion must not remain reported as configured.
    let gateway_source_hash = match load_gateway_destination(&binding.profile_dir) {
        Ok(hash) => Some(hash),
        Err(()) if gateway_destination_is_absent(&binding.profile_dir) => None,
        Err(()) => return Err("ethereum_state_unavailable"),
    };
    if gateway_source_hash != binding.configured_gateway_source_hash {
        return Err("ethereum_profile_changed");
    }
    let mut account_check = store
        .latest_account_sync_progress(now_unix)
        .map_err(|error| setup_status_store_error("account_sync_progress", error))?
        .filter(|progress| {
            gateway_source_hash.is_some_and(|gateway| progress.belongs_to_gateway(gateway))
        })
        .map(Into::into);
    let gateway_selected = gateway_source_hash.is_some();
    let gateway_contact_ready = gateway_source_hash.is_some_and(gateway_contact_ready);
    account_check = account_check_with_contact_status(account_check, gateway_contact_ready);
    let pending_evidence_review = match gateway_source_hash {
        Some(gateway_source_hash) => Some(
            store
                .has_pending_bulk_evidence_review(gateway_source_hash, now_unix)
                .map_err(|error| setup_status_store_error("bulk_evidence_reviews", error))?,
        ),
        // Without a configured gateway there is no safe expected-source key
        // with which to query the durable evidence review queue.
        None => None,
    };

    Ok(EthereumSetupStatus {
        identity_ready: true,
        wallet_configured: stored_account.is_some(),
        account,
        account_check,
        checkpoint_installed,
        checkpoint,
        gateway_selected,
        gateway_contact_ready,
        gateway_configured: gateway_selected && gateway_contact_ready,
        selected_service: None,
        public_service_available: configured_public_service_card().is_some(),
        public_service_contact_added,
        pending_checkpoint_review: Some(pending_checkpoint_review),
        pending_gateway_review: Some(pending_native_gateway_review(
            identity,
            identity_session_generation,
        )?),
        pending_evidence_review,
    })
}

fn gateway_destination_is_absent(profile_dir: &Path) -> bool {
    std::fs::symlink_metadata(
        profile_dir
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join(GATEWAY_DESTINATION_FILE),
    )
    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn pending_native_gateway_review(
    identity_hash: [u8; 16],
    identity_session_generation: u64,
) -> Result<bool, &'static str> {
    #[cfg(target_os = "linux")]
    return crate::ethereum_linux::pending_gateway_card_review(
        identity_hash,
        identity_session_generation,
    );
    #[cfg(target_os = "android")]
    return crate::ethereum_android::pending_gateway_card_review(
        identity_hash,
        identity_session_generation,
    );
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (identity_hash, identity_session_generation);
        Ok(false)
    }
}

#[tauri::command]
pub(crate) fn ethereum_launch_native_wallet(
    state: tauri::State<'_, EthereumApplicationState>,
    request: EthereumNativeWalletLaunchRequest,
) -> Result<EthereumNativeWalletLaunchView, &'static str> {
    match request {
        #[cfg(any(target_os = "android", test))]
        EthereumNativeWalletLaunchRequest::ClearSigned(request) => {
            #[cfg(target_os = "android")]
            {
                return crate::ethereum_android::launch_native_clear_signed_operation(&state, request)
                    .map(EthereumNativeWalletLaunchView::transfer_launched);
            }
            #[cfg(not(target_os = "android"))]
            {
                let _ = request;
                return Err("native_ethereum_wallet_unavailable");
            }
        }
        request => {
            #[cfg(target_os = "android")]
            {
                crate::ethereum_android::launch_native_wallet(&state, request)
            }
            #[cfg(target_os = "linux")]
            {
                crate::ethereum_linux::launch_native_wallet(&state, request)
            }
            #[cfg(not(any(target_os = "android", target_os = "linux")))]
            {
                let _ = (state, request);
                Err("native_ethereum_wallet_unavailable")
            }
        }
    }
}

/// Opens a platform-native review of durable, gateway-bound bulk evidence
/// manifests. It intentionally accepts no WebView arguments: exact review
/// snapshots and authorization authority never cross the WebView boundary.
#[tauri::command]
pub(crate) fn ethereum_review_pending_bulk_evidence(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumBulkEvidenceReviewView, &'static str> {
    #[cfg(target_os = "linux")]
    {
        crate::ethereum_linux::review_pending_bulk_evidence(&state)
    }
    #[cfg(target_os = "android")]
    {
        crate::ethereum_android::launch_native_bulk_evidence_review(&state)?;
        Ok(EthereumBulkEvidenceReviewView::launched())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = state;
        Err("native_ethereum_bulk_review_unavailable")
    }
}

/// Opens native review of one already-staged, locally validated manual
/// checkpoint candidate. It accepts no WebView arguments: exact checkpoint,
/// provenance, bootstrap bytes, and approval authority remain native/Rust-only.
#[tauri::command]
pub(crate) fn ethereum_review_pending_checkpoint(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumCheckpointReviewView, &'static str> {
    #[cfg(target_os = "linux")]
    {
        crate::ethereum_linux::review_pending_checkpoint(&state)
            .map(EthereumCheckpointReviewView::from_linux)
    }
    #[cfg(target_os = "android")]
    {
        crate::ethereum_android::launch_native_checkpoint_review(&state)?;
        Ok(EthereumCheckpointReviewView::launched())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = state;
        Err("native_ethereum_checkpoint_review_unavailable")
    }
}

/// Opens a native document picker and stages one locally selected checkpoint
/// card after strict parsing and Helios verification. It accepts no WebView
/// arguments; file location, bytes, root, provenance, and review authority
/// remain native/Rust-only.
#[tauri::command]
pub(crate) fn ethereum_import_checkpoint_file(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumCheckpointFileImportView, &'static str> {
    #[cfg(target_os = "linux")]
    {
        crate::ethereum_linux::import_manual_checkpoint_file(&state)
            .map(EthereumCheckpointFileImportView::from_linux)
    }
    #[cfg(target_os = "android")]
    {
        crate::ethereum_android::launch_native_checkpoint_file_import(&state)?;
        Ok(EthereumCheckpointFileImportView::launched())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = state;
        Err("native_ethereum_checkpoint_file_unavailable")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumOnlineCheckpointView {
    state: &'static str,
    sources: [&'static str; 2],
}

/// Cross-checks a current Sepolia checkpoint through two fixed independent
/// operators, obtains non-authoritative bootstrap bytes separately, verifies
/// them locally with Helios, and persists the resulting approved anchor.
/// The WebView supplies no URL, root, epoch, or proof bytes.
#[tauri::command]
pub(crate) async fn ethereum_connect_sepolia(
    state: tauri::State<'_, EthereumApplicationState>,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
) -> Result<EthereumOnlineCheckpointView, &'static str> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _admission = state
            .claim_checkpoint_connect()
            .ok_or("ethereum_checkpoint_connect_active")?;
        let runtime = runtime.inner();
        let (identity, binding) = {
            let _identity_lifecycle = runtime.identity_switch_lock.lock().await;
            let identity =
                decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_identity_id(runtime))
                    .filter(|identity| *identity != [0; 16])
                    .ok_or("ethereum_identity_unavailable")?;
            let session = runtime.current_identity_session_generation();
            let binding = state
                .native_transport_profile_binding()?
                .filter(|binding| {
                    binding.ratspeak_identity_hash == identity
                        && binding.identity_session_generation == session
                })
                .ok_or("ethereum_profile_unavailable")?;
            (identity, binding)
        };

        let agreement = tokio::task::spawn_blocking(crate::ethereum_online::acquire)
            .await
            .map_err(|_| "ethereum_checkpoint_network_unavailable")??;

        let _identity_lifecycle = runtime.identity_switch_lock.lock().await;
        if decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_identity_id(runtime))
            != Some(identity)
            || runtime.current_identity_session_generation() != binding.identity_session_generation
            || state.native_transport_profile_binding()?.as_ref() != Some(&binding)
        {
            return Err("ethereum_profile_changed");
        }
        let crate::ethereum_online::OnlineCheckpointAgreement {
            providers,
            observations,
            bootstrap_bundle,
            source_names,
        } = agreement;
        let mut store = open_profile_store(&binding.profile_dir)?;
        let policy = ratspeak_eth_node::CheckpointBootstrapPolicy::new(providers)
            .map_err(|_| "ethereum_checkpoint_policy_unavailable")?;
        policy
            .install_provider_observation_agreement(&mut store, &observations, bootstrap_bundle)
            .map_err(|error| match error {
                ratspeak_eth_node::CheckpointPolicyError::ProviderMismatch => {
                    "ethereum_checkpoint_sources_disagree"
                }
                ratspeak_eth_node::CheckpointPolicyError::InsufficientOperatorAgreement
                | ratspeak_eth_node::CheckpointPolicyError::DuplicateProviderObservation
                | ratspeak_eth_node::CheckpointPolicyError::UnconfiguredProvider => {
                    "ethereum_checkpoint_source_invalid"
                }
                ratspeak_eth_node::CheckpointPolicyError::StaleCheckpoint
                | ratspeak_eth_node::CheckpointPolicyError::StaleObservation => {
                    "ethereum_checkpoint_stale"
                }
                ratspeak_eth_node::CheckpointPolicyError::CheckpointRollback
                | ratspeak_eth_node::CheckpointPolicyError::EpochRootConflict
                | ratspeak_eth_node::CheckpointPolicyError::RootEpochConflict => {
                    "ethereum_checkpoint_conflict"
                }
                _ => "ethereum_checkpoint_verification_failed",
            })?;
        Ok(EthereumOnlineCheckpointView {
            state: "installed",
            sources: source_names,
        })
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (state, runtime);
        Err("ethereum_checkpoint_online_unavailable")
    }
}

/// Opens native file acquisition for an unauthenticated public gateway card.
/// No path, bytes, destination, key, or decision crosses WebView IPC.
#[tauri::command]
pub(crate) fn ethereum_import_gateway_card(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumGatewayCardImportView, &'static str> {
    #[cfg(target_os = "linux")]
    {
        crate::ethereum_linux::import_gateway_card(&state).map(Into::into)
    }
    #[cfg(target_os = "android")]
    {
        crate::ethereum_android::launch_native_gateway_card_import(&state)?;
        Ok(EthereumGatewayCardImportView::launched())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = state;
        Err("native_ethereum_gateway_card_unavailable")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EthereumPublicServiceContactState {
    Added,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EthereumPublicServiceContactView {
    state: EthereumPublicServiceContactState,
}

fn configured_public_service_card() -> Option<String> {
    let card = option_env!("RATSPEAK_ETH_PUBLIC_SERVICE_CARD")
        .map(str::to_owned)
        .or_else(|| std::env::var("RATSPEAK_ETH_PUBLIC_SERVICE_CARD").ok())?;
    let card = card.trim();
    if card.is_empty() || card.len() > 512 {
        return None;
    }
    ratspeak_tauri::commands::contact_card::parse_contact_card_payload(card).ok()?;
    Some(card.to_owned())
}

fn configured_public_service_destination() -> Option<[u8; 16]> {
    let card = configured_public_service_card()?;
    let parsed = ratspeak_tauri::commands::contact_card::parse_contact_card_payload(&card).ok()?;
    decode_fixed_hex::<16>(&parsed.lxmf_hash)
}

/// Adds the build/operator-configured public Sepolia service as an ordinary
/// profile-scoped Ratspeak Contact. The WebView supplies no card or identity.
#[tauri::command]
pub(crate) async fn ethereum_add_public_service_contact(
    state: tauri::State<'_, EthereumApplicationState>,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
) -> Result<EthereumPublicServiceContactView, &'static str> {
    let card = configured_public_service_card().ok_or("ethereum_public_service_unavailable")?;
    let runtime = runtime.inner();
    ratspeak_tauri::commands::contact_card::import_contact_card_payload(runtime, &card)
        .await
        .map_err(|_| "ethereum_public_service_import_failed")?;
    state.wake_outbound();
    Ok(EthereumPublicServiceContactView {
        state: EthereumPublicServiceContactState::Added,
    })
}

/// Opens native review of the exact staged gateway card. Approval remains
/// profile/session fenced and no review authority crosses WebView IPC.
#[tauri::command]
pub(crate) fn ethereum_review_pending_gateway_card(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumGatewayCardReviewView, &'static str> {
    #[cfg(target_os = "linux")]
    {
        crate::ethereum_linux::review_pending_gateway_card(&state).map(Into::into)
    }
    #[cfg(target_os = "android")]
    {
        crate::ethereum_android::launch_native_gateway_card_review(&state)?;
        Ok(EthereumGatewayCardReviewView::launched())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = state;
        Err("native_ethereum_gateway_review_unavailable")
    }
}

#[tauri::command]
pub(crate) fn ethereum_public_account(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<EthereumAccountView, &'static str> {
    public_account_view(&state)
}

/// Takes a short identity-fenced service/contact snapshot, then performs only
/// bounded Reticulum path discovery without holding the lifecycle lock. A
/// valid Contact authenticates the selected service identity; the discovered
/// path is reachability only and does not authenticate Ethereum state.
async fn reachable_transport_binding(
    app_handle: &tauri::AppHandle,
    runtime: &Arc<ratspeak_tauri::state::AppState>,
) -> Result<EthereumTransportBinding, &'static str> {
    use tauri::Manager;

    let route_binding = {
        let _identity_lifecycle = runtime.identity_switch_lock.lock().await;
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        let binding = state
            .transport_binding()?
            .ok_or("ethereum_gateway_unavailable")?;
        validate_sync_runtime_binding(runtime, &binding)?;
        let identity_id = ratspeak_tauri::helpers::active_identity_id(runtime);
        if !ratspeak_tauri::commands::shared::has_valid_contact_identity(
            runtime,
            &identity_id,
            &encode_hex(&binding.gateway_destination_hash),
        ) {
            return Err("ethereum_gateway_contact_unavailable");
        }
        binding
    };
    let rns_handle = runtime
        .rns
        .read()
        .ok()
        .and_then(|manager| manager.as_ref().map(|manager| manager.handle.clone()))
        .ok_or("ethereum_reticulum_unavailable")?;
    rns_handle
        .await_path(
            route_binding.gateway_destination_hash,
            Duration::from_secs(GATEWAY_ROUTE_DISCOVERY_SECONDS),
        )
        .await
        .map_err(|_| "ethereum_gateway_route_unavailable")?;
    Ok(route_binding)
}

/// Explicitly schedules one finite synchronization. This command accepts no
/// WebView arguments: checkpoint authority, gateway selection, byte budgets,
/// request identifiers, and expiry are all selected from trusted native state.
#[tauri::command]
pub(crate) async fn ethereum_synchronize(
    app_handle: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
) -> Result<EthereumSyncStartView, &'static str> {
    use tauri::Manager;

    let command_admission = app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or("ethereum_state_unavailable")?
        .claim_sync_command()
        .ok_or("ethereum_sync_in_progress")?;
    let route_binding = reachable_transport_binding(&app_handle, runtime.inner()).await?;
    let worker_app = app_handle.clone();
    let worker_runtime = Arc::clone(runtime.inner());
    let worker_route_binding = route_binding;
    let task = tokio::task::spawn_blocking(move || {
        // The owned atomic token remains live even if the invoking async task
        // is cancelled. Dropping or unwinding the worker always releases it.
        let _command_admission = command_admission;
        // This may wait, so it belongs on the blocking pool. The short node
        // transaction is serialized with identity/profile replacement and
        // never runs on an async executor thread.
        let _identity_lifecycle = worker_runtime.identity_switch_lock.blocking_lock();
        let worker_state = worker_app
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        if !worker_state.transport_binding_is_current(&worker_route_binding)? {
            return Err("ethereum_profile_changed");
        }
        let binding = worker_state
            .transport_binding()?
            .ok_or("ethereum_gateway_unavailable")?;
        validate_sync_runtime_binding(&worker_runtime, &binding)?;
        let identity_id = ratspeak_tauri::helpers::active_identity_id(&worker_runtime);
        if !ratspeak_tauri::commands::shared::has_valid_contact_identity(
            &worker_runtime,
            &identity_id,
            &encode_hex(&binding.gateway_destination_hash),
        ) {
            return Err("ethereum_gateway_contact_unavailable");
        }
        let local_source_hash =
            decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_lxmf_hash(&worker_runtime))
                .ok_or("ethereum_lxmf_identity_unavailable")?;
        let outbound_binding = OutboundMessageBinding::new(
            binding.gateway_destination_hash,
            local_source_hash,
            binding.identity_session_generation,
        )
        .map_err(|_| "ethereum_profile_changed")?;
        let now_unix = trusted_now_unix()?;
        if worker_state.sync_command_is_rate_limited(now_unix) {
            return Err("ethereum_sync_recently_requested");
        }
        let expires_at_unix = now_unix
            .checked_add(EVIDENCE_SYNC_EXPIRY_SECONDS)
            .ok_or("ethereum_sync_unavailable")?;
        let trigger_id = secure_trigger_id()?;
        let result = worker_state.with_current_transport_binding(&binding, |profile_dir| {
            let mut store = open_profile_store(profile_dir)?;
            let generation = store
                .next_evidence_sync_generation()
                .map_err(|_| "ethereum_sync_unavailable")?;
            let (outcome, mut plan) = store
                .plan_or_resume_evidence_sync(EvidenceSyncTrigger::new(
                    trigger_id,
                    generation,
                    binding.gateway_destination_hash,
                    MAX_EVIDENCE_SYNC_RESPONSE_BYTES,
                    now_unix,
                    expires_at_unix,
                ))
                .map_err(|_| "ethereum_sync_unavailable")?;
            let start_state = match outcome {
                ratspeak_eth_node::RecordOutcome::Inserted => EthereumSyncStartState::Queued,
                ratspeak_eth_node::RecordOutcome::Replay => {
                    let retrying_wait = store
                        .latest_account_sync_progress(now_unix)
                        .map_err(|_| "ethereum_sync_unavailable")?
                        .is_some_and(|progress| {
                            progress.stage()
                                == ratspeak_eth_node::AccountSyncStage::WaitingForGateway
                                && progress.belongs_to_gateway(binding.gateway_destination_hash)
                        });
                    if retrying_wait {
                        // A user retry creates a fresh correlation rather than
                        // replaying an ambiguous request the service may have
                        // completed. Late replies to the cancelled request
                        // cannot update account state.
                        if !store
                            .cancel_settled_account_sync_for_retry(outbound_binding, now_unix)
                            .map_err(|_| "ethereum_sync_retry_unavailable")?
                        {
                            return Err("ethereum_sync_retry_unavailable");
                        }
                        let (replacement_outcome, replacement) = store
                            .plan_or_resume_evidence_sync(EvidenceSyncTrigger::new(
                                trigger_id,
                                generation,
                                binding.gateway_destination_hash,
                                MAX_EVIDENCE_SYNC_RESPONSE_BYTES,
                                now_unix,
                                expires_at_unix,
                            ))
                            .map_err(|_| "ethereum_sync_retry_unavailable")?;
                        if replacement_outcome != ratspeak_eth_node::RecordOutcome::Inserted {
                            return Err("ethereum_sync_retry_unavailable");
                        }
                        plan = replacement;
                        EthereumSyncStartState::Queued
                    } else {
                        EthereumSyncStartState::Active
                    }
                }
            };
            // The legacy evidence plan is intentionally Sepolia-specific.
            // Relay transport is not: pick up signed transactions from every
            // other supported PoC chain without assigning Sepolia checkpoint
            // semantics to their state or receipt verification.
            let mut transaction_relays = plan.relay_requests().len();
            let mut multichain_candidates = 0usize;
            'chains: for chain in ratspeak_eth_verifier::SUPPORTED_CHAINS {
                if chain.chain_id == SEPOLIA_CHAIN_ID {
                    continue;
                }
                let pending = store
                    .unconfirmed_signed_transactions(chain.chain_id)
                    .map_err(|_| "ethereum_sync_unavailable")?;
                for signed in pending {
                    if multichain_candidates >= MAX_MULTICHAIN_RELAYS_PER_SYNC {
                        break 'chains;
                    }
                    multichain_candidates = multichain_candidates.saturating_add(1);
                    let request_id = secure_trigger_id()?;
                    match store
                        .plan_signed_transaction_relay(
                            request_id,
                            binding.gateway_destination_hash,
                            &signed,
                            now_unix,
                            expires_at_unix,
                        )
                        .map_err(|_| "ethereum_sync_unavailable")?
                    {
                        ratspeak_eth_node::RecordOutcome::Inserted => {
                            transaction_relays = transaction_relays.saturating_add(1);
                        }
                        ratspeak_eth_node::RecordOutcome::Replay => {}
                    }
                }
            }

            // Transaction-location reports remain Sepolia-only until OP/Nitro
            // status and receipt scheduling can be anchored to their actual L2
            // verification families. Do not reuse L1 finalized-head semantics.
            let mut transaction_status_requests = 0usize;
            for receipt_request in plan.receipt_requests() {
                let Ok(request_id) = secure_trigger_id() else {
                    tracing::warn!(
                        "Ethereum transaction status request identifier was unavailable"
                    );
                    continue;
                };
                match store.plan_transaction_status_poll(OutboundTransactionStatusRequest::new(
                    request_id,
                    binding.gateway_destination_hash,
                    receipt_request.subject(),
                    now_unix,
                    expires_at_unix,
                )) {
                    Ok(ratspeak_eth_node::RecordOutcome::Inserted) => {
                        transaction_status_requests = transaction_status_requests.saturating_add(1);
                    }
                    Ok(ratspeak_eth_node::RecordOutcome::Replay) => {}
                    Err(_) => tracing::warn!(
                        "Supplementary Ethereum transaction status request was not scheduled"
                    ),
                }
            }
            worker_state.record_sync_command_success(now_unix)?;
            Ok(EthereumSyncStartView {
                state: start_state,
                evidence_requests: 1usize.saturating_add(plan.receipt_requests().len()),
                transaction_relays,
                transaction_status_requests,
            })
        })?;
        Ok(result)
    });
    let result = task.await.map_err(|_| "ethereum_sync_task_failed");
    let state = app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or("ethereum_state_unavailable")?;
    let result = result??;
    state.wake_outbound();
    Ok(result)
}

/// Queues one small, non-authoritative status query for the latest locally
/// signed transaction. The WebView supplies neither a transaction hash nor a
/// service identity. Repeated calls are durably coalesced by the node store.
#[tauri::command]
pub(crate) async fn ethereum_update_transaction_status(
    app_handle: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<ratspeak_tauri::state::AppState>>,
) -> Result<EthereumTransactionStatusStartView, &'static str> {
    use tauri::Manager;

    let route_binding = reachable_transport_binding(&app_handle, runtime.inner()).await?;
    let worker_app = app_handle.clone();
    let worker_runtime = Arc::clone(runtime.inner());
    let task = tokio::task::spawn_blocking(move || {
        let _identity_lifecycle = worker_runtime.identity_switch_lock.blocking_lock();
        let worker_state = worker_app
            .try_state::<EthereumApplicationState>()
            .ok_or("ethereum_state_unavailable")?;
        if !worker_state.transport_binding_is_current(&route_binding)? {
            return Err("ethereum_profile_changed");
        }
        let binding = worker_state
            .transport_binding()?
            .ok_or("ethereum_gateway_unavailable")?;
        validate_sync_runtime_binding(&worker_runtime, &binding)?;
        let identity_id = ratspeak_tauri::helpers::active_identity_id(&worker_runtime);
        if !ratspeak_tauri::commands::shared::has_valid_contact_identity(
            &worker_runtime,
            &identity_id,
            &encode_hex(&binding.gateway_destination_hash),
        ) {
            return Err("ethereum_gateway_contact_unavailable");
        }
        let now_unix = trusted_now_unix()?;
        let expires_at_unix = now_unix
            .checked_add(TRANSACTION_STATUS_REQUEST_EXPIRY_SECONDS)
            .ok_or("ethereum_transaction_status_unavailable")?;
        worker_state.with_current_transport_binding(&binding, |profile_dir| {
            let mut store = open_profile_store(profile_dir)?;
            let transaction = store
                .latest_signed_transaction(SEPOLIA_CHAIN_ID)
                .map_err(|_| "ethereum_state_unavailable")?
                .ok_or("ethereum_transaction_unavailable")?;
            match store
                .transaction_assurance_reverified(transaction.tx_hash())
                .map_err(|_| "ethereum_state_unavailable")?
            {
                Some(TransactionAssurance::Signed { .. }) => {}
                Some(TransactionAssurance::NeedsReverification(_)) => {
                    return Err("ethereum_receipt_reverification_required");
                }
                Some(
                    TransactionAssurance::FinalizedSuccess(_)
                    | TransactionAssurance::FinalizedFailure(_),
                ) => return Err("ethereum_transaction_already_finalized"),
                None => return Err("ethereum_transaction_unavailable"),
            }
            let already_active = store
                .has_active_transaction_status_request(
                    transaction.tx_hash(),
                    binding.gateway_destination_hash,
                    now_unix,
                )
                .map_err(|_| "ethereum_transaction_status_unavailable")?;
            let request_id = secure_trigger_id()?;
            let outcome = store
                .plan_transaction_status_poll(OutboundTransactionStatusRequest::new(
                    request_id,
                    binding.gateway_destination_hash,
                    transaction.tx_hash(),
                    now_unix,
                    expires_at_unix,
                ))
                .map_err(|_| "ethereum_transaction_status_unavailable")?;
            let state = match outcome {
                ratspeak_eth_node::RecordOutcome::Inserted => {
                    EthereumTransactionStatusStartState::Queued
                }
                ratspeak_eth_node::RecordOutcome::Replay if already_active => {
                    EthereumTransactionStatusStartState::Active
                }
                ratspeak_eth_node::RecordOutcome::Replay => {
                    EthereumTransactionStatusStartState::Recent
                }
            };
            Ok(EthereumTransactionStatusStartView { state })
        })
    });
    let result = task
        .await
        .map_err(|_| "ethereum_transaction_status_task_failed")??;
    let state = app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or("ethereum_state_unavailable")?;
    state.wake_outbound();
    Ok(result)
}

struct EthereumSyncCommandAdmission {
    active: Arc<AtomicBool>,
}

impl Drop for EthereumSyncCommandAdmission {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

fn validate_sync_runtime_binding(
    runtime: &ratspeak_tauri::state::AppState,
    binding: &EthereumTransportBinding,
) -> Result<(), &'static str> {
    if runtime.current_identity_session_generation() != binding.identity_session_generation {
        return Err("ethereum_profile_changed");
    }
    let identity = decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_identity_id(runtime))
        .ok_or("ethereum_identity_unavailable")?;
    let lxmf_source = decode_fixed_hex::<16>(&ratspeak_tauri::helpers::active_lxmf_hash(runtime))
        .ok_or("ethereum_lxmf_identity_unavailable")?;
    validate_sync_runtime_snapshot(
        binding,
        runtime.current_identity_session_generation(),
        identity,
        lxmf_source,
    )
}

fn validate_sync_runtime_snapshot(
    binding: &EthereumTransportBinding,
    identity_session_generation: u64,
    identity: [u8; 16],
    lxmf_source: [u8; 16],
) -> Result<(), &'static str> {
    if identity_session_generation != binding.identity_session_generation
        || identity != binding.ratspeak_identity_hash
        || lxmf_source == [0; 16]
        || lxmf_source == binding.gateway_destination_hash
    {
        return Err("ethereum_profile_changed");
    }
    Ok(())
}

fn secure_trigger_id() -> Result<[u8; 16], &'static str> {
    #[cfg(unix)]
    {
        for _ in 0..4 {
            let mut bytes = [0u8; 16];
            File::open("/dev/urandom")
                .and_then(|mut random| random.read_exact(&mut bytes))
                .map_err(|_| "ethereum_sync_random_unavailable")?;
            if bytes != [0; 16] {
                return Ok(bytes);
            }
        }
        Err("ethereum_sync_random_unavailable")
    }
    #[cfg(not(unix))]
    {
        Err("ethereum_sync_random_unavailable")
    }
}

fn public_account_view(
    state: &EthereumApplicationState,
) -> Result<EthereumAccountView, &'static str> {
    public_account_view_with(state, open_profile_store)
}

fn public_account_view_with(
    state: &EthereumApplicationState,
    open_store: impl FnOnce(&Path) -> Result<EthereumNodeStore, &'static str>,
) -> Result<EthereumAccountView, &'static str> {
    let Some(binding) = state.profile_binding()? else {
        return Ok(EthereumAccountView::unknown(None));
    };
    let Some(public_account) = binding.public_account else {
        return Ok(EthereumAccountView::unknown(None));
    };
    let address = format!("{:#x}", public_account.address());
    let now_unix = trusted_now_unix()?;
    let store = open_store(&binding.profile_dir)?;
    let assurance = store
        .account_assurance(public_account, now_unix, MAX_CURRENT_EVIDENCE_AGE_SECONDS)
        .map_err(|_| "ethereum_state_unavailable")?;
    state.ensure_current_generation(binding.generation)?;
    Ok(account_view_from_assurance(address, &assurance))
}

#[tauri::command]
pub(crate) fn ethereum_transfer_review(
    state: tauri::State<'_, EthereumApplicationState>,
    operation_id: String,
) -> Result<EthereumTransferReviewView, &'static str> {
    let operation_id = decode_fixed_hex::<16>(&operation_id).ok_or("invalid_operation_id")?;
    state.review(operation_id)?.ok_or("unknown_operation")
}

#[tauri::command]
pub(crate) fn ethereum_transaction_assurance(
    state: tauri::State<'_, EthereumApplicationState>,
    tx_hash: String,
) -> Result<EthereumTransactionView, &'static str> {
    let tx_hash = decode_fixed_hex::<32>(&tx_hash).ok_or("invalid_transaction_hash")?;
    transaction_assurance_view(&state, tx_hash)
}

#[tauri::command]
pub(crate) fn ethereum_latest_transaction(
    state: tauri::State<'_, EthereumApplicationState>,
) -> Result<Option<EthereumTransactionView>, &'static str> {
    latest_transaction_view(&state)
}

fn latest_transaction_view(
    state: &EthereumApplicationState,
) -> Result<Option<EthereumTransactionView>, &'static str> {
    latest_transaction_view_with(state, open_profile_store)
}

fn latest_transaction_view_with(
    state: &EthereumApplicationState,
    open_store: impl FnOnce(&Path) -> Result<EthereumNodeStore, &'static str>,
) -> Result<Option<EthereumTransactionView>, &'static str> {
    let Some(binding) = state.profile_binding()? else {
        return Ok(None);
    };
    let store = open_store(&binding.profile_dir)?;
    let view = if let Some(transaction) = store
        .latest_signed_transaction_any_chain()
        .map_err(|_| "ethereum_state_unavailable")?
    {
        let assurance = store
            .transaction_assurance_reverified(transaction.tx_hash())
            .map_err(|_| "ethereum_state_unavailable")?;
        let status = store
            .transaction_status_history_view(transaction.tx_hash())
            .map_err(|_| "ethereum_state_unavailable")?;
        let receipt_request = binding
            .configured_gateway_source_hash
            .map(|gateway| {
                store.latest_finalized_receipt_request_progress(transaction.tx_hash(), gateway)
            })
            .transpose()
            .map_err(|_| "ethereum_state_unavailable")?
            .flatten();
        Some(transaction_view_with_status(
            transaction.tx_hash(),
            assurance.as_ref(),
            status.as_ref(),
            receipt_request.as_ref(),
        ))
    } else {
        None
    };
    state.ensure_current_generation(binding.generation)?;
    Ok(view)
}

fn transaction_assurance_view(
    state: &EthereumApplicationState,
    tx_hash: [u8; 32],
) -> Result<EthereumTransactionView, &'static str> {
    transaction_assurance_view_with(state, tx_hash, open_profile_store)
}

fn transaction_assurance_view_with(
    state: &EthereumApplicationState,
    tx_hash: [u8; 32],
    open_store: impl FnOnce(&Path) -> Result<EthereumNodeStore, &'static str>,
) -> Result<EthereumTransactionView, &'static str> {
    let Some(binding) = state.profile_binding()? else {
        return Ok(transaction_view(tx_hash, None));
    };
    let store = open_store(&binding.profile_dir)?;
    let assurance = store
        .transaction_assurance_reverified(tx_hash)
        .map_err(|_| "ethereum_state_unavailable")?;
    let status = store
        .transaction_status_history_view(tx_hash)
        .map_err(|_| "ethereum_state_unavailable")?;
    let receipt_request = binding
        .configured_gateway_source_hash
        .map(|gateway| store.latest_finalized_receipt_request_progress(tx_hash, gateway))
        .transpose()
        .map_err(|_| "ethereum_state_unavailable")?
        .flatten();
    state.ensure_current_generation(binding.generation)?;
    Ok(transaction_view_with_status(
        tx_hash,
        assurance.as_ref(),
        status.as_ref(),
        receipt_request.as_ref(),
    ))
}

fn open_profile_store(profile_dir: &Path) -> Result<EthereumNodeStore, &'static str> {
    EthereumNodeStore::open_in_profile(profile_dir).map_err(|_| "ethereum_state_unavailable")
}

fn open_profile_status_store(profile_dir: &Path) -> Result<EthereumNodeStore, &'static str> {
    EthereumNodeStore::open_existing_read_only_in_profile(profile_dir)
        .map_err(|error| setup_status_store_error("open_read_only", error))
}

fn setup_status_store_error(stage: &'static str, _error: impl std::fmt::Display) -> &'static str {
    tracing::warn!(stage, "Ethereum setup status read failed");
    "ethereum_state_unavailable"
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn cancel_persisted_native_transfer(
    cancellation: &PendingNativeCancellation,
) -> Result<(), &'static str> {
    let operation_id =
        OperationId::new(cancellation.operation_id).map_err(|_| "invalid_operation_id")?;
    let mut store = open_profile_store(&cancellation.profile_dir)?;
    store
        .cancel_operation_if_present(operation_id)
        .map(|_| ())
        .map_err(|_| "ethereum_operation_cancellation_failed")
}

fn account_view_from_assurance(
    address: String,
    assurance: &AccountAssurance,
) -> EthereumAccountView {
    match assurance {
        AccountAssurance::Unknown => EthereumAccountView::unknown(Some(address)),
        AccountAssurance::Stale(evidence) => render_account_evidence(
            address,
            AccountAssuranceState::Stale,
            evidence.balance().to_string(),
            evidence.nonce(),
            evidence.age_seconds(),
        ),
        AccountAssurance::CurrentVerified(evidence) => render_account_evidence(
            address,
            AccountAssuranceState::CurrentVerified,
            evidence.balance().to_string(),
            evidence.nonce(),
            evidence.age_seconds(),
        ),
    }
}

fn render_account_evidence(
    address: String,
    assurance: AccountAssuranceState,
    balance_wei: String,
    nonce: u64,
    evidence_age_seconds: u64,
) -> EthereumAccountView {
    let (balance_display, nonce_display) = match assurance {
        AccountAssuranceState::Unknown => {
            return EthereumAccountView::unknown(Some(address));
        }
        AccountAssuranceState::Stale if balance_wei == "0" => {
            (UNKNOWN_DISPLAY.to_owned(), format!("{nonce} (stale)"))
        }
        AccountAssuranceState::Stale => {
            (format!("{balance_wei} (stale)"), format!("{nonce} (stale)"))
        }
        AccountAssuranceState::CurrentVerified => (balance_wei, nonce.to_string()),
    };
    EthereumAccountView {
        address: Some(address),
        assurance,
        balance_display,
        nonce_display,
        evidence_age_seconds: Some(evidence_age_seconds),
    }
}

fn transaction_view(
    tx_hash: [u8; 32],
    assurance: Option<&TransactionAssurance>,
) -> EthereumTransactionView {
    transaction_view_with_status(tx_hash, assurance, None, None)
}

fn transaction_view_with_status(
    tx_hash: [u8; 32],
    assurance: Option<&TransactionAssurance>,
    status: Option<&TransactionStatusHistoryView>,
    receipt_request: Option<&FinalizedReceiptRequestProgress>,
) -> EthereumTransactionView {
    let (assurance, progress) = match assurance {
        None => (
            TransactionAssuranceState::Unknown,
            TransactionProgressState::Unknown,
        ),
        Some(TransactionAssurance::Signed {
            non_authoritative_observations,
        }) => {
            let progress = if non_authoritative_observations
                .contains(&NonAuthoritativeTransactionObservation::RpcAccepted)
            {
                TransactionProgressState::RpcAccepted
            } else if non_authoritative_observations
                .contains(&NonAuthoritativeTransactionObservation::GatewayAcknowledged)
            {
                TransactionProgressState::GatewayAcknowledged
            } else if non_authoritative_observations
                .contains(&NonAuthoritativeTransactionObservation::TransportDelivered)
            {
                TransactionProgressState::TransportDelivered
            } else {
                TransactionProgressState::SignedLocally
            };
            (TransactionAssuranceState::SignedUnconfirmed, progress)
        }
        Some(TransactionAssurance::NeedsReverification(_)) => (
            TransactionAssuranceState::ReceiptNeedsReverification,
            TransactionProgressState::ReceiptVerifying,
        ),
        Some(TransactionAssurance::FinalizedSuccess(_)) => (
            TransactionAssuranceState::VerifiedSuccess,
            TransactionProgressState::Finalized,
        ),
        Some(TransactionAssurance::FinalizedFailure(_)) => (
            TransactionAssuranceState::VerifiedFailure,
            TransactionProgressState::Finalized,
        ),
    };
    EthereumTransactionView {
        tx_hash: encode_hex(&tx_hash),
        assurance,
        progress,
        status_observation: status.map(transaction_status_observation_view),
        receipt_request: receipt_request.map(receipt_request_view),
    }
}

fn receipt_request_view(progress: &FinalizedReceiptRequestProgress) -> EthereumReceiptRequestView {
    let state = match progress.status() {
        ratspeak_eth_node::MessageRequestStatus::Pending => EthereumReceiptRequestState::Requested,
        ratspeak_eth_node::MessageRequestStatus::AwaitingBulkApproval => {
            EthereumReceiptRequestState::AwaitingDownload
        }
        ratspeak_eth_node::MessageRequestStatus::Ready => EthereumReceiptRequestState::Downloading,
        ratspeak_eth_node::MessageRequestStatus::PendingVerification => {
            EthereumReceiptRequestState::Verifying
        }
        ratspeak_eth_node::MessageRequestStatus::Completed => EthereumReceiptRequestState::Complete,
        ratspeak_eth_node::MessageRequestStatus::Cancelled
        | ratspeak_eth_node::MessageRequestStatus::Expired => {
            EthereumReceiptRequestState::Unavailable
        }
    };
    EthereumReceiptRequestView {
        state,
        created_at_unix: progress.created_at_unix(),
        expires_at_unix: progress.expires_at_unix(),
    }
}

fn transaction_status_observation_view(
    history: &TransactionStatusHistoryView,
) -> EthereumTransactionStatusObservationView {
    let observation = history.latest();
    let status = match observation.status() {
        TransactionStatus::NotSeen => TransactionStatusState::NotSeen,
        TransactionStatus::Pending => TransactionStatusState::Pending,
        TransactionStatus::Included => TransactionStatusState::Included,
    };
    let continuity = match history.continuity() {
        TransactionStatusContinuity::AwaitingReinclusion => {
            TransactionStatusContinuityState::AwaitingReinclusion
        }
        TransactionStatusContinuity::Inconsistent => TransactionStatusContinuityState::Inconsistent,
        TransactionStatusContinuity::FirstObservation
        | TransactionStatusContinuity::StillIncluded
        | TransactionStatusContinuity::IncludedMoved
        | TransactionStatusContinuity::Reincluded
        | TransactionStatusContinuity::StatusChanged => TransactionStatusContinuityState::Observed,
    };
    let included_block = observation
        .included_block_number()
        .zip(observation.included_block_hash())
        .map(|(number, hash)| block_observation_view(number, hash));
    let previous_inclusion = history.previous_inclusion().and_then(|previous| {
        previous
            .included_block_number()
            .zip(previous.included_block_hash())
            .map(|(number, hash)| EthereumPreviousInclusionView {
                number,
                hash: prefixed_hex(&hash),
                observed_at_unix: previous.observed_at_unix(),
            })
    });
    EthereumTransactionStatusObservationView {
        authority: "rpc_status",
        status,
        observed_at_unix: observation.observed_at_unix(),
        source_hash: encode_hex(&observation.source_hash()),
        included_block,
        heads: EthereumTransactionHeadsView {
            latest: block_observation_view(
                observation.latest_head_number(),
                observation.latest_head_hash(),
            ),
            safe: block_observation_view(
                observation.safe_head_number(),
                observation.safe_head_hash(),
            ),
            finalized: block_observation_view(
                observation.finalized_head_number(),
                observation.finalized_head_hash(),
            ),
        },
        continuity,
        previous_inclusion,
    }
}

fn block_observation_view(number: u64, hash: [u8; 32]) -> EthereumBlockObservationView {
    EthereumBlockObservationView {
        number,
        hash: prefixed_hex(&hash),
    }
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", encode_hex(bytes))
}

fn trusted_now_unix() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "clock_unavailable")
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn parse_canonical_u128(value: &str) -> Option<u128> {
    if !canonical_unsigned_decimal(value) {
        return None;
    }
    value.parse().ok()
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn parse_canonical_u256(value: &str) -> Option<U256> {
    if !canonical_unsigned_decimal(value) {
        return None;
    }
    U256::from_str_radix(value, 10).ok()
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn canonical_unsigned_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn native_unavailable_reason() -> (EthereumPlatform, &'static str) {
    #[cfg(target_os = "android")]
    return (
        EthereumPlatform::Android,
        "android_native_wallet_unavailable",
    );
    #[cfg(target_os = "linux")]
    return (
        EthereumPlatform::Linux,
        "linux_native_transfer_review_unavailable",
    );
    #[cfg(target_os = "ios")]
    return (EthereumPlatform::Ios, "ios_custody_adapter_not_implemented");
    #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "ios")))]
    return (
        EthereumPlatform::Unsupported,
        "platform_custody_adapter_not_implemented",
    );
}

pub(crate) fn decode_fixed_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    if encoded.len() != N * 2 || !encoded.is_ascii() {
        return None;
    }
    let mut decoded = [0u8; N];
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
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use ratspeak_eth_node::{
        MessageRequestStatus, MessagingEvidenceKind, OutboundEvidenceRequest,
        OutboundMessageBinding,
    };
    use ratspeak_eth_wallet::{OperationId, ReviewContext, TransferIntent};
    use serde_json::Value;

    use super::*;

    fn test_account() -> WalletAccount {
        WalletAccount::sepolia(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
        )
    }

    fn test_gateway_card(identity: &Identity) -> String {
        let destination =
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash));
        format!(
            "RSEG1:sepolia:{}:{}",
            encode_hex(&destination),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identity.get_public_key())
        )
    }

    #[test]
    fn gateway_card_parser_binds_network_destination_and_exact_public_key() {
        let identity = Identity::new();
        let card = test_gateway_card(&identity);
        let parsed = parse_gateway_card(format!("{card}\n").as_bytes()).unwrap();
        assert_eq!(
            parsed.destination_hash(),
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash))
        );
        assert_ne!(parsed.public_key_fingerprint(), [0; 32]);

        for invalid in [
            card.replacen("sepolia", "mainnet", 1),
            card.replacen(card.split(':').nth(2).unwrap(), &"0".repeat(32), 1),
            format!("{card}:extra"),
            format!("{card}\nnot-whitespace"),
        ] {
            assert!(parse_gateway_card(invalid.as_bytes()).is_err());
        }
        let other = Identity::new();
        let wrong_key = format!(
            "RSEG1:sepolia:{}:{}",
            card.split(':').nth(2).unwrap(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other.get_public_key())
        );
        assert!(parse_gateway_card(wrong_key.as_bytes()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_destination_persistence_is_private_atomic_and_rejects_alias_target() {
        let profile = tempfile::tempdir().unwrap();
        let directory = profile
            .path()
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        persist_gateway_destination(profile.path(), [0x61; 16]).unwrap();
        assert_eq!(load_gateway_destination(profile.path()), Ok([0x61; 16]));
        assert_eq!(
            std::fs::metadata(directory.join(GATEWAY_DESTINATION_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        persist_gateway_destination(profile.path(), [0x62; 16]).unwrap();
        assert_eq!(load_gateway_destination(profile.path()), Ok([0x62; 16]));

        std::fs::remove_file(directory.join(GATEWAY_DESTINATION_FILE)).unwrap();
        let outside = profile.path().join("outside");
        std::fs::write(&outside, encode_hex(&[0x63; 16])).unwrap();
        std::os::unix::fs::symlink(&outside, directory.join(GATEWAY_DESTINATION_FILE)).unwrap();
        assert_eq!(
            persist_gateway_destination(profile.path(), [0x64; 16]),
            Err("ethereum_gateway_storage_insecure")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_destination_post_publish_failure_restores_exact_prior_state() {
        let first = tempfile::tempdir().unwrap();
        let directory = first
            .path()
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            persist_gateway_destination_with(first.path(), [0x71; 16], || {
                Err("injected_post_publish_failure")
            }),
            Err("injected_post_publish_failure")
        );
        assert!(!directory.join(GATEWAY_DESTINATION_FILE).exists());

        persist_gateway_destination(first.path(), [0x72; 16]).unwrap();
        assert_eq!(
            persist_gateway_destination_with_hooks(
                first.path(),
                [0x73; 16],
                || Err("injected_pre_publish_failure"),
                || Ok(()),
                || Ok(()),
                || Ok(()),
            ),
            Err("injected_pre_publish_failure")
        );
        assert_eq!(load_gateway_destination(first.path()), Ok([0x72; 16]));
        assert_eq!(
            std::fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".gateway-destination-")
                })
                .count(),
            0
        );
        assert_eq!(
            persist_gateway_destination_with(first.path(), [0x73; 16], || {
                Err("injected_post_publish_failure")
            }),
            Err("injected_post_publish_failure")
        );
        assert_eq!(load_gateway_destination(first.path()), Ok([0x72; 16]));

        // Restart/profile installation always securely reloads the durable
        // destination; memory is never treated as authority over the file.
        let state = EthereumApplicationState::new();
        state
            .install_transport_profile_for_identity(first.path().to_owned(), [0x74; 16], 9)
            .unwrap();
        assert_eq!(
            state
                .transport_binding()
                .unwrap()
                .unwrap()
                .gateway_destination_hash,
            [0x72; 16]
        );

        let rollback_failure = tempfile::tempdir().unwrap();
        let rollback_directory = rollback_failure
            .path()
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
        std::fs::create_dir(&rollback_directory).unwrap();
        std::fs::set_permissions(&rollback_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        persist_gateway_destination(rollback_failure.path(), [0x75; 16]).unwrap();
        let result = persist_gateway_destination_with(rollback_failure.path(), [0x76; 16], || {
            std::fs::set_permissions(&rollback_directory, std::fs::Permissions::from_mode(0o500))
                .unwrap();
            Err("injected_post_publish_failure")
        });
        std::fs::set_permissions(&rollback_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(
            result,
            Err("ethereum_gateway_storage_reconciliation_required")
        );
        assert_eq!(
            load_gateway_destination(rollback_failure.path()),
            Ok([0x76; 16])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_replacement_rejects_valid_disk_mutation_after_profile_binding() {
        let profile = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        create_gateway_destination_file(profile.path(), b"61616161616161616161616161616161");
        let state = EthereumApplicationState::new();
        let generation = state
            .install_transport_profile_for_identity(profile.path().to_owned(), [0x44; 16], 7)
            .unwrap();
        std::fs::write(
            profile
                .path()
                .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
                .join(GATEWAY_DESTINATION_FILE),
            b"62626262626262626262626262626262",
        )
        .unwrap();
        assert_eq!(
            state.persist_gateway_source_hash(generation, [0x63; 16], 100, || true),
            Err("ethereum_gateway_storage_changed")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_persistence_rechecks_native_approval_inside_state_write_fence() {
        let profile = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        create_gateway_destination_file(profile.path(), b"81818181818181818181818181818181");
        let state = EthereumApplicationState::new();
        let generation = state
            .install_transport_profile_for_identity(profile.path().to_owned(), [0x82; 16], 10)
            .unwrap();
        assert_eq!(
            state.persist_gateway_source_hash(generation, [0x83; 16], 100, || false),
            Err("ethereum_gateway_review_expired")
        );
        assert_eq!(load_gateway_destination(profile.path()), Ok([0x81; 16]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_reconciliation_never_adopts_an_unapproved_third_value() {
        fn configured_state(
            initial: [u8; 16],
        ) -> (
            tempfile::TempDir,
            EthereumApplicationState,
            EthereumProfileGeneration,
        ) {
            let profile = tempfile::tempdir().unwrap();
            EthereumNodeStore::open_in_profile(profile.path()).unwrap();
            create_gateway_destination_file(profile.path(), encode_hex(&initial).as_bytes());
            let state = EthereumApplicationState::new();
            let generation = state
                .install_transport_profile_for_identity(profile.path().to_owned(), [0x91; 16], 11)
                .unwrap();
            (profile, state, generation)
        }

        fn replace_displaced(directory: &Path, replacement: [u8; 16]) {
            let displaced = std::fs::read_dir(directory)
                .unwrap()
                .filter_map(Result::ok)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".gateway-destination-")
                })
                .unwrap();
            std::fs::remove_file(displaced.path()).unwrap();
            std::fs::write(displaced.path(), encode_hex(&replacement)).unwrap();
            std::fs::set_permissions(displaced.path(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        let old = [0x92; 16];
        let approved = [0x93; 16];
        let third = [0x94; 16];

        let (profile, state, generation) = configured_state(old);
        assert_eq!(
            state.persist_gateway_source_hash_with(
                generation,
                approved,
                100,
                || true,
                |profile_dir, _| {
                    persist_gateway_destination(profile_dir, third)?;
                    Err("ethereum_gateway_storage_reconciliation_required")
                },
            ),
            Err("ethereum_gateway_storage_reconciliation_required")
        );
        assert!(state.transport_binding().unwrap().is_none());
        assert_eq!(load_gateway_destination(profile.path()), Ok(third));

        let (_profile, state, generation) = configured_state(old);
        assert_eq!(
            state.persist_gateway_source_hash_with(
                generation,
                approved,
                100,
                || true,
                |profile_dir, candidate| {
                    persist_gateway_destination(profile_dir, candidate)?;
                    Err("ethereum_gateway_storage_reconciliation_required")
                },
            ),
            Ok(())
        );
        assert_eq!(
            state
                .transport_binding()
                .unwrap()
                .unwrap()
                .gateway_destination_hash,
            approved
        );

        let (_profile, state, generation) = configured_state(old);
        assert_eq!(
            state.persist_gateway_source_hash_with(
                generation,
                approved,
                100,
                || true,
                |_, _| Err("ethereum_gateway_storage_reconciliation_required"),
            ),
            Err("ethereum_gateway_storage_reconciliation_required")
        );
        assert_eq!(
            state
                .transport_binding()
                .unwrap()
                .unwrap()
                .gateway_destination_hash,
            old
        );

        let (profile, state, generation) = configured_state(old);
        assert_eq!(
            state.persist_gateway_source_hash_with(
                generation,
                approved,
                100,
                || true,
                |profile_dir, candidate| {
                    let directory = profile_dir.join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
                    persist_gateway_destination_with_hooks(
                        profile_dir,
                        candidate,
                        || Ok(()),
                        || {
                            let displaced = std::fs::read_dir(&directory)
                                .unwrap()
                                .filter_map(Result::ok)
                                .find(|entry| {
                                    entry
                                        .file_name()
                                        .to_string_lossy()
                                        .starts_with(".gateway-destination-")
                                })
                                .unwrap();
                            std::fs::remove_file(displaced.path()).unwrap();
                            Ok(())
                        },
                        || Ok(()),
                        || Ok(()),
                    )
                },
            ),
            Ok(())
        );
        assert_eq!(load_gateway_destination(profile.path()), Ok(approved));
        assert_eq!(
            state
                .transport_binding()
                .unwrap()
                .unwrap()
                .gateway_destination_hash,
            approved
        );

        for replace_before_metadata in [true, false] {
            let (profile, state, generation) = configured_state(old);
            let result = state.persist_gateway_source_hash_with(
                generation,
                approved,
                100,
                || true,
                |profile_dir, candidate| {
                    let directory = profile_dir.join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
                    persist_gateway_destination_with_hooks(
                        profile_dir,
                        candidate,
                        || Ok(()),
                        || {
                            if replace_before_metadata {
                                replace_displaced(&directory, third);
                            }
                            Ok(())
                        },
                        || Ok(()),
                        || {
                            if !replace_before_metadata {
                                replace_displaced(&directory, third);
                            }
                            Err("injected_post_publish_failure")
                        },
                    )
                },
            );
            assert_eq!(result, Ok(()));
            assert_eq!(load_gateway_destination(profile.path()), Ok(approved));
            assert_eq!(
                state
                    .transport_binding()
                    .unwrap()
                    .unwrap()
                    .gateway_destination_hash,
                approved
            );
        }

        let (profile, state, generation) = configured_state(old);
        let result = state.persist_gateway_source_hash_with(
            generation,
            approved,
            100,
            || true,
            |profile_dir, candidate| {
                let directory = profile_dir.join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY);
                persist_gateway_destination_with_hooks(
                    profile_dir,
                    candidate,
                    || Ok(()),
                    || Ok(()),
                    || {
                        replace_displaced(&directory, third);
                        Ok(())
                    },
                    || Err("injected_post_publish_failure"),
                )
            },
        );
        assert_eq!(
            result,
            Err("ethereum_gateway_storage_reconciliation_required")
        );
        assert_eq!(load_gateway_destination(profile.path()), Ok(third));
        assert!(state.transport_binding().unwrap().is_none());
    }

    fn create_gateway_destination_file(profile: &Path, encoded: &[u8]) -> PathBuf {
        EthereumNodeStore::open_in_profile(profile).unwrap();
        let path = profile
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join(GATEWAY_DESTINATION_FILE);
        std::fs::write(&path, encoded).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn transport_binding_is_available_before_wallet_custody() {
        let profile = tempfile::tempdir().unwrap();
        let gateway = [0x2a; 16];
        let identity = [0x31; 16];
        create_gateway_destination_file(profile.path(), encode_hex(&gateway).as_bytes());

        let state = EthereumApplicationState::new();
        let transport_generation = state
            .install_transport_profile_for_identity(profile.path().to_owned(), identity, 17)
            .unwrap();
        let transport = state.transport_binding().unwrap().unwrap();
        assert_eq!(transport.generation, transport_generation);
        assert_eq!(transport.gateway_destination_hash, gateway);
        assert!(state.native_profile_binding().unwrap().is_none());

        let wallet_generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                17,
            )
            .unwrap();
        assert_ne!(wallet_generation, transport_generation);
        assert!(!state.transport_binding_is_current(&transport).unwrap());
        assert!(state.native_profile_binding().unwrap().is_some());
    }

    #[test]
    fn native_picker_binding_preserves_same_session_and_rebinds_identity_switch() {
        let profile = tempfile::tempdir().unwrap();
        let original_gateway = [0x2a; 16];
        let changed_gateway = [0x2b; 16];
        let first_identity = [0x31; 16];
        let second_identity = [0x32; 16];
        let account = test_account();
        let gateway_path = create_gateway_destination_file(
            profile.path(),
            encode_hex(&original_gateway).as_bytes(),
        );
        let state = EthereumApplicationState::new();
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                account,
                first_identity,
                17,
            )
            .unwrap();
        state
            .register_review_surface(generation, [0x41; 16], test_review_projection())
            .unwrap();

        // A file picker must not turn an out-of-band routing-file mutation into
        // an implicit profile reinstall that discards the active review.
        std::fs::write(&gateway_path, encode_hex(&changed_gateway)).unwrap();
        let same = state
            .ensure_native_transport_profile_binding(
                profile.path().to_owned(),
                Some(account),
                first_identity,
                17,
            )
            .unwrap();
        assert_eq!(same.generation, generation);
        assert_eq!(state.scoped.read().unwrap().pending_reviews.len(), 1);

        // A real identity-session transition cannot inherit that capability.
        let switched = state
            .ensure_native_transport_profile_binding(
                profile.path().to_owned(),
                Some(account),
                second_identity,
                18,
            )
            .unwrap();
        assert_ne!(switched.generation, generation);
        assert_eq!(switched.ratspeak_identity_hash, second_identity);
        assert!(state.scoped.read().unwrap().pending_reviews.is_empty());
        assert_eq!(
            state
                .transport_binding()
                .unwrap()
                .unwrap()
                .gateway_destination_hash,
            changed_gateway
        );
        assert_eq!(
            state
                .native_profile_binding()
                .unwrap()
                .unwrap()
                .public_account,
            account
        );
    }

    #[test]
    fn gateway_destination_file_binds_the_exact_profile_and_identity_session() {
        let profile = tempfile::tempdir().unwrap();
        let expected = [0x2a; 16];
        create_gateway_destination_file(profile.path(), encode_hex(&expected).as_bytes());

        assert_eq!(load_gateway_destination(profile.path()), Ok(expected));

        let state = EthereumApplicationState::new();
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                [0x31; 16],
                17,
            )
            .unwrap();
        let binding = state.transport_binding().unwrap().unwrap();
        assert_eq!(binding.generation, generation);
        assert_eq!(binding.profile_dir, profile.path());
        assert_eq!(binding.ratspeak_identity_hash, [0x31; 16]);
        assert_eq!(binding.identity_session_generation, 17);
        assert_eq!(binding.gateway_destination_hash, expected);
        assert!(state.transport_binding_is_current(&binding).unwrap());

        state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                [0x31; 16],
                18,
            )
            .unwrap();
        assert!(!state.transport_binding_is_current(&binding).unwrap());
    }

    #[test]
    fn finite_sync_profile_fence_rejects_session_gateway_and_profile_races() {
        fn installed(
            identity: [u8; 16],
            session: u64,
            gateway: [u8; 16],
        ) -> (
            tempfile::TempDir,
            EthereumApplicationState,
            EthereumProfileGeneration,
            EthereumTransportBinding,
        ) {
            let profile = tempfile::tempdir().unwrap();
            create_gateway_destination_file(profile.path(), encode_hex(&gateway).as_bytes());
            let state = EthereumApplicationState::new();
            let generation = state
                .install_profile_binding_for_identity(
                    profile.path().to_owned(),
                    test_account(),
                    identity,
                    session,
                )
                .unwrap();
            let binding = state.transport_binding().unwrap().unwrap();
            (profile, state, generation, binding)
        }

        let (session_profile, session_state, _, session_binding) =
            installed([0x41; 16], 7, [0x51; 16]);
        session_state
            .install_profile_binding_for_identity(
                session_profile.path().to_owned(),
                test_account(),
                [0x41; 16],
                8,
            )
            .unwrap();
        let called = Cell::new(false);
        assert_eq!(
            session_state
                .with_current_transport_binding(&session_binding, |_| {
                    called.set(true);
                    Ok(())
                })
                .unwrap_err(),
            "ethereum_profile_changed"
        );
        assert!(!called.get());

        let (_gateway_profile, gateway_state, gateway_generation, gateway_binding) =
            installed([0x42; 16], 9, [0x52; 16]);
        gateway_state
            .configure_gateway_source_hash(gateway_generation, [0x53; 16])
            .unwrap();
        assert_eq!(
            gateway_state
                .with_current_transport_binding(&gateway_binding, |_| Ok(()))
                .unwrap_err(),
            "ethereum_profile_changed"
        );

        let (_first_profile, profile_state, _, profile_binding) =
            installed([0x43; 16], 10, [0x54; 16]);
        let replacement = tempfile::tempdir().unwrap();
        create_gateway_destination_file(replacement.path(), encode_hex(&[0x54; 16]).as_bytes());
        profile_state
            .install_profile_binding_for_identity(
                replacement.path().to_owned(),
                test_account(),
                [0x43; 16],
                10,
            )
            .unwrap();
        assert_eq!(
            profile_state
                .with_current_transport_binding(&profile_binding, |_| Ok(()))
                .unwrap_err(),
            "ethereum_profile_changed"
        );

        let local_lxmf_source = [0x61; 16];
        assert!(validate_sync_runtime_snapshot(
            &profile_binding,
            profile_binding.identity_session_generation,
            profile_binding.ratspeak_identity_hash,
            local_lxmf_source,
        )
        .is_ok());
        assert!(validate_sync_runtime_snapshot(
            &profile_binding,
            profile_binding.identity_session_generation + 1,
            profile_binding.ratspeak_identity_hash,
            local_lxmf_source,
        )
        .is_err());
        assert!(validate_sync_runtime_snapshot(
            &profile_binding,
            profile_binding.identity_session_generation,
            [0x62; 16],
            local_lxmf_source,
        )
        .is_err());
        assert!(validate_sync_runtime_snapshot(
            &profile_binding,
            profile_binding.identity_session_generation,
            profile_binding.ratspeak_identity_hash,
            profile_binding.gateway_destination_hash,
        )
        .is_err());
    }

    #[test]
    fn finite_sync_trigger_ids_come_from_the_os_and_never_return_zero() {
        let first = secure_trigger_id().unwrap();
        let second = secure_trigger_id().unwrap();
        assert_ne!(first, [0; 16]);
        assert_ne!(second, [0; 16]);
        assert_ne!(first, second);
        assert_eq!(EVIDENCE_SYNC_EXPIRY_SECONDS, 2 * 60 * 60);
        assert_eq!(MAX_EVIDENCE_SYNC_RESPONSE_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn finite_sync_admission_is_single_flight_and_unwind_safe() {
        let state = EthereumApplicationState::new();
        let admission = state.claim_sync_command().unwrap();
        assert!(state.claim_sync_command().is_none());
        drop(admission);

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _admission = state.claim_sync_command().unwrap();
            panic!("cancelled sync worker");
        }));
        assert!(unwind.is_err());
        assert!(state.claim_sync_command().is_some());
    }

    #[test]
    fn finite_sync_command_cooldown_is_short_and_bounded() {
        let state = EthereumApplicationState::new();
        assert!(!state.sync_command_is_rate_limited(1_000));
        state.record_sync_command_success(1_000).unwrap();
        assert!(state.sync_command_is_rate_limited(1_000));
        assert!(state.sync_command_is_rate_limited(1_004));
        assert!(!state.sync_command_is_rate_limited(1_005));
        assert_eq!(
            state.record_sync_command_success(u64::MAX).unwrap_err(),
            "ethereum_sync_unavailable"
        );
    }

    #[test]
    fn missing_or_malformed_gateway_destination_is_not_configured() {
        let missing = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(missing.path()).unwrap();
        assert_eq!(load_gateway_destination(missing.path()), Err(()));
        let state = EthereumApplicationState::new();
        state
            .install_profile_binding_for_identity(
                missing.path().to_owned(),
                test_account(),
                [0x41; 16],
                1,
            )
            .unwrap();
        assert!(state.transport_binding().unwrap().is_none());

        for invalid in [
            b"00000000000000000000000000000000".as_slice(),
            b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2".as_slice(),
            b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \n".as_slice(),
            b"gggggggggggggggggggggggggggggggg".as_slice(),
        ] {
            let profile = tempfile::tempdir().unwrap();
            create_gateway_destination_file(profile.path(), invalid);
            assert_eq!(load_gateway_destination(profile.path()), Err(()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn gateway_destination_aliases_and_permissive_files_are_rejected() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let permissive = tempfile::tempdir().unwrap();
        let path =
            create_gateway_destination_file(permissive.path(), b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_gateway_destination(permissive.path()), Err(()));

        let permissive_directory = tempfile::tempdir().unwrap();
        create_gateway_destination_file(
            permissive_directory.path(),
            b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
        );
        std::fs::set_permissions(
            permissive_directory
                .path()
                .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(
            load_gateway_destination(permissive_directory.path()),
            Err(())
        );

        let linked = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(linked.path()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap();
        symlink(
            outside.path(),
            linked
                .path()
                .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
                .join(GATEWAY_DESTINATION_FILE),
        )
        .unwrap();
        assert_eq!(load_gateway_destination(linked.path()), Err(()));

        let hard_linked = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(hard_linked.path()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap();
        let hard_link_result = std::fs::hard_link(
            source.path(),
            hard_linked
                .path()
                .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
                .join(GATEWAY_DESTINATION_FILE),
        );
        match hard_link_result {
            Ok(()) => assert_eq!(load_gateway_destination(hard_linked.path()), Err(())),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Sandboxed runners may prohibit hard links even for files
                // owned by the test process. The production loader still
                // rejects nlink != 1; CI on a normal filesystem exercises it.
            }
            Err(error) => panic!("hard-link fixture setup failed: {error}"),
        }

        let special = tempfile::tempdir().unwrap();
        EthereumNodeStore::open_in_profile(special.path()).unwrap();
        let special_path = special
            .path()
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join(GATEWAY_DESTINATION_FILE);
        let _listener = match UnixListener::bind(&special_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Some sandboxed runners prohibit Unix-domain sockets. The
                // loader checks this class of alias on normal CI hosts.
                return;
            }
            Err(error) => panic!("Unix socket fixture setup failed: {error}"),
        };
        assert_eq!(load_gateway_destination(special.path()), Err(()));

        let swapped = tempfile::tempdir().unwrap();
        let swapped_path =
            create_gateway_destination_file(swapped.path(), b"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
        let original_path = swapped_path.with_extension("checked");
        let held_listener = RefCell::new(None);
        assert_eq!(
            load_gateway_destination_with(swapped.path(), |path| {
                std::fs::rename(path, &original_path).unwrap();
                *held_listener.borrow_mut() = Some(UnixListener::bind(path).unwrap());
            }),
            Err(())
        );
        drop(held_listener.into_inner());
    }

    #[cfg(unix)]
    #[test]
    fn profile_symlink_retarget_cannot_redirect_the_bound_outbox() {
        use std::os::unix::fs::symlink;

        let link_parent = tempfile::tempdir().unwrap();
        let original = tempfile::tempdir().unwrap();
        let replacement = tempfile::tempdir().unwrap();
        let gateway = [0x6b; 16];
        create_gateway_destination_file(original.path(), encode_hex(&gateway).as_bytes());
        create_gateway_destination_file(replacement.path(), encode_hex(&gateway).as_bytes());

        let now = trusted_now_unix().unwrap();
        EthereumNodeStore::open_in_profile(replacement.path())
            .unwrap()
            .create_evidence_request(OutboundEvidenceRequest::new(
                [0x6c; 16],
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0x6d; 32],
                1024,
                now,
                now + 60,
            ))
            .unwrap();

        let profile_link = link_parent.path().join("active-profile");
        symlink(original.path(), &profile_link).unwrap();
        let state = EthereumApplicationState::new();
        state
            .install_profile_binding_for_identity(
                profile_link.clone(),
                test_account(),
                [0x6e; 16],
                7,
            )
            .unwrap();
        let binding = state.transport_binding().unwrap().unwrap();
        assert_eq!(binding.profile_dir, original.path().canonicalize().unwrap());

        std::fs::remove_file(&profile_link).unwrap();
        symlink(replacement.path(), &profile_link).unwrap();
        assert_eq!(profile_link.canonicalize().unwrap(), replacement.path());
        assert_eq!(binding.profile_dir, original.path().canonicalize().unwrap());

        let outbound = OutboundMessageBinding::new(gateway, [0x6f; 16], 7).unwrap();
        assert!(EthereumNodeStore::open_in_profile(&binding.profile_dir)
            .unwrap()
            .lease_next_outbound_message(outbound, now + 1, 10)
            .unwrap()
            .is_none());
    }

    fn gateway_manifest(
        request_id: [u8; 16],
        kind: MessagingEvidenceKind,
        digest: [u8; 32],
        size: u32,
    ) -> Vec<u8> {
        let mut bytes = b"RSETHM1".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.push(2);
        bytes.extend_from_slice(&request_id);
        bytes.push(match kind {
            MessagingEvidenceKind::ExecutionHeader => 1,
            MessagingEvidenceKind::AccountProof => 2,
            MessagingEvidenceKind::ReceiptProof => 3,
            MessagingEvidenceKind::Consensus => 4,
            MessagingEvidenceKind::AccountStatePackage => 5,
            MessagingEvidenceKind::FinalizedReceiptPackage => 6,
        });
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes
    }

    fn persisted_attachment_event(
        files_dir: &Path,
        stored_name: &str,
        source_hash: [u8; 16],
        signature_valid: bool,
        authenticated_bytes: &[u8],
    ) -> ratspeak_tauri::state::PersistedInboundLxmfAttachment {
        ratspeak_tauri::state::PersistedInboundLxmfAttachment {
            message_id: "11".repeat(32),
            identity_id: encode_hex(&[0xff; 16]),
            identity_session_generation: 0,
            source_hash,
            signature_valid,
            attachment: ratspeak_tauri::state::PersistedInboundAttachment::from_authenticated_bytes(
                files_dir.to_owned(),
                stored_name.to_owned(),
                authenticated_bytes,
            ),
        }
    }

    #[test]
    fn persisted_gateway_manifest_is_correlated_and_duplicate_safe() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x22; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        let request_id = [0x33; 16];
        let now = trusted_now_unix().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0x44; 32],
                1_024,
                now.saturating_sub(1),
                now + 60,
            ))
            .unwrap();
        let stored_name = "100-test_gateway.rseth";
        let manifest = gateway_manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            [0x55; 32],
            100,
        );
        std::fs::write(files.path().join(stored_name), &manifest).unwrap();
        let event = persisted_attachment_event(files.path(), stored_name, gateway, true, &manifest);

        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::AcceptedNonAuthoritative
        );
        assert_eq!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap()
                .message_request_status(request_id)
                .unwrap(),
            Some(MessageRequestStatus::Ready)
        );
        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::Duplicate
        );
    }

    #[test]
    fn persisted_gateway_attachment_cannot_cross_identity_session() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x23; 16];
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                [0x24; 16],
                7,
            )
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        let bytes = b"old profile frame";
        let stored_name = "stale-profile.rseth";
        std::fs::write(files.path().join(stored_name), bytes).unwrap();
        let mut event = persisted_attachment_event(files.path(), stored_name, gateway, true, bytes);

        event.identity_id = encode_hex(&[0x25; 16]);
        event.identity_session_generation = 7;
        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::RejectedMessage
        );

        event.identity_id = encode_hex(&[0x24; 16]);
        event.identity_session_generation = 8;
        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::RejectedMessage
        );
    }

    #[test]
    fn authenticated_bulk_manifest_requests_native_download_review() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x27; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        let request_id = [0x38; 16];
        let now = trusted_now_unix().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0x49; 32],
                8_192,
                now.saturating_sub(1),
                now + 60,
            ))
            .unwrap();
        let stored_name = "101-test_bulk_gateway.rseth";
        let manifest = gateway_manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            [0x5a; 32],
            5_000,
        );
        std::fs::write(files.path().join(stored_name), &manifest).unwrap();
        let event = persisted_attachment_event(files.path(), stored_name, gateway, true, &manifest);

        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::BulkApprovalRequired
        );
        assert_eq!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap()
                .message_request_status(request_id)
                .unwrap(),
            Some(MessageRequestStatus::AwaitingBulkApproval)
        );
    }

    #[test]
    fn expected_bounded_wallet_evidence_skips_a_second_download_prompt() {
        assert!(automatically_approve_expected_evidence(
            MessagingEvidenceKind::AccountStatePackage,
            MAX_AUTOMATIC_ACCOUNT_EVIDENCE_BYTES,
        ));
        assert!(!automatically_approve_expected_evidence(
            MessagingEvidenceKind::AccountStatePackage,
            0,
        ));
        assert!(!automatically_approve_expected_evidence(
            MessagingEvidenceKind::AccountStatePackage,
            MAX_AUTOMATIC_ACCOUNT_EVIDENCE_BYTES + 1,
        ));
        assert!(automatically_approve_expected_evidence(
            MessagingEvidenceKind::FinalizedReceiptPackage,
            MAX_AUTOMATIC_RECEIPT_EVIDENCE_BYTES,
        ));
        assert!(!automatically_approve_expected_evidence(
            MessagingEvidenceKind::FinalizedReceiptPackage,
            MAX_AUTOMATIC_RECEIPT_EVIDENCE_BYTES + 1,
        ));
        assert!(!automatically_approve_expected_evidence(
            MessagingEvidenceKind::Consensus,
            1024,
        ));
    }

    #[test]
    fn substituted_persisted_bytes_cannot_reuse_the_lxmf_signature() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x42; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        let request_id = [0x43; 16];
        let now = trusted_now_unix().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0x44; 32],
                1_024,
                now.saturating_sub(1),
                now + 60,
            ))
            .unwrap();
        let stored_name = "substituted.rseth";
        let authenticated = gateway_manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            [0x45; 32],
            100,
        );
        let substituted = gateway_manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            [0x46; 32],
            100,
        );
        assert_eq!(authenticated.len(), substituted.len());
        std::fs::write(files.path().join(stored_name), substituted).unwrap();
        let event =
            persisted_attachment_event(files.path(), stored_name, gateway, true, &authenticated);

        assert_eq!(
            handle_persisted_gateway_attachment(&state, &event),
            EthereumInboundDisposition::RejectedAttachment
        );
        assert_eq!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap()
                .message_request_status(request_id)
                .unwrap(),
            Some(MessageRequestStatus::Pending)
        );
    }

    #[test]
    fn authentication_precedes_attachment_io_and_gateway_decoding() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x62; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        let nonexistent = profile.path().join("does-not-exist");

        for event in [
            persisted_attachment_event(&nonexistent, "missing", gateway, false, b"signed"),
            persisted_attachment_event(&nonexistent, "missing", [0x63; 16], true, b"signed"),
        ] {
            assert_eq!(
                handle_persisted_gateway_attachment(&state, &event),
                EthereumInboundDisposition::IgnoredUnauthenticated
            );
        }
    }

    #[test]
    fn configured_source_cannot_answer_a_request_pinned_to_another_gateway() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let configured_gateway = [0x66; 16];
        let request_gateway = [0x67; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, configured_gateway)
            .unwrap();
        let request_id = [0x68; 16];
        let now = trusted_now_unix().unwrap();
        let mut store = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        store
            .create_evidence_request(OutboundEvidenceRequest::new(
                request_id,
                request_gateway,
                MessagingEvidenceKind::ReceiptProof,
                [0x69; 32],
                1_024,
                now.saturating_sub(1),
                now + 60,
            ))
            .unwrap();
        let stored_name = "request-specific.rseth";
        let manifest = gateway_manifest(
            request_id,
            MessagingEvidenceKind::ReceiptProof,
            [0x6A; 32],
            100,
        );
        std::fs::write(files.path().join(stored_name), &manifest).unwrap();

        assert_eq!(
            handle_persisted_gateway_attachment(
                &state,
                &persisted_attachment_event(
                    files.path(),
                    stored_name,
                    configured_gateway,
                    true,
                    &manifest,
                ),
            ),
            EthereumInboundDisposition::IgnoredUnauthenticated
        );
        assert_eq!(
            EthereumNodeStore::open_in_profile(profile.path())
                .unwrap()
                .message_request_status(request_id)
                .unwrap(),
            Some(MessageRequestStatus::Pending)
        );
    }

    #[test]
    fn malformed_oversized_and_traversal_attachments_are_rejected() {
        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x72; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();

        let malformed = b"not a gateway message";
        std::fs::write(files.path().join("malformed.rseth"), malformed).unwrap();
        assert_eq!(
            handle_persisted_gateway_attachment(
                &state,
                &persisted_attachment_event(
                    files.path(),
                    "malformed.rseth",
                    gateway,
                    true,
                    malformed,
                ),
            ),
            EthereumInboundDisposition::RejectedMessage
        );
        let oversized = vec![0; MAX_PERSISTED_GATEWAY_MESSAGE_BYTES + 1];
        std::fs::write(files.path().join("oversized.rseth"), &oversized).unwrap();
        assert_eq!(
            handle_persisted_gateway_attachment(
                &state,
                &persisted_attachment_event(
                    files.path(),
                    "oversized.rseth",
                    gateway,
                    true,
                    &oversized,
                ),
            ),
            EthereumInboundDisposition::RejectedAttachment
        );
        assert_eq!(
            handle_persisted_gateway_attachment(
                &state,
                &persisted_attachment_event(
                    files.path(),
                    "../malformed.rseth",
                    gateway,
                    true,
                    malformed,
                ),
            ),
            EthereumInboundDisposition::RejectedAttachment
        );
    }

    #[cfg(unix)]
    #[test]
    fn persisted_attachment_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let profile = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let state = EthereumApplicationState::new();
        let gateway = [0x82; 16];
        let generation = state
            .install_profile_binding(profile.path().to_owned(), test_account())
            .unwrap();
        state
            .configure_gateway_source_hash(generation, gateway)
            .unwrap();
        symlink(outside.path(), files.path().join("linked.rseth")).unwrap();

        assert_eq!(
            handle_persisted_gateway_attachment(
                &state,
                &persisted_attachment_event(files.path(), "linked.rseth", gateway, true, b""),
            ),
            EthereumInboundDisposition::RejectedAttachment
        );
    }

    #[test]
    fn unknown_and_stale_zero_never_render_as_zero() {
        let unknown = EthereumAccountView::unknown(Some("0x11".to_owned()));
        assert_eq!(unknown.balance_display, "...");
        assert_eq!(unknown.nonce_display, "...");

        let stale_zero = render_account_evidence(
            "0x11".to_owned(),
            AccountAssuranceState::Stale,
            "0".to_owned(),
            0,
            901,
        );
        assert_eq!(stale_zero.balance_display, "...");
        assert_eq!(stale_zero.nonce_display, "0 (stale)");
        assert_eq!(stale_zero.assurance, AccountAssuranceState::Stale);

        let stale_nonzero = render_account_evidence(
            "0x11".to_owned(),
            AccountAssuranceState::Stale,
            "42".to_owned(),
            7,
            901,
        );
        assert_eq!(stale_nonzero.balance_display, "42 (stale)");

        let current_zero = render_account_evidence(
            "0x11".to_owned(),
            AccountAssuranceState::CurrentVerified,
            "0".to_owned(),
            0,
            2,
        );
        assert_eq!(current_zero.balance_display, "0");
        assert_eq!(
            current_zero.assurance,
            AccountAssuranceState::CurrentVerified
        );
    }

    #[test]
    fn missing_profile_account_binding_stays_unknown_without_creating_a_database() {
        let state = EthereumApplicationState::new();
        assert!(state.profile_binding().unwrap().is_none());
        let open_calls = Cell::new(0);
        let account = public_account_view_with(&state, |_| {
            open_calls.set(open_calls.get() + 1);
            Err("unexpected_database_open")
        })
        .unwrap();
        let transaction = transaction_assurance_view_with(&state, [9; 32], |_| {
            open_calls.set(open_calls.get() + 1);
            Err("unexpected_database_open")
        })
        .unwrap();
        assert_eq!(account.assurance, AccountAssuranceState::Unknown);
        assert_eq!(account.balance_display, "...");
        assert_eq!(transaction.assurance, TransactionAssuranceState::Unknown);
        assert!(latest_transaction_view_with(&state, |_| {
            open_calls.set(open_calls.get() + 1);
            Err("unexpected_database_open")
        })
        .unwrap()
        .is_none());
        assert_eq!(open_calls.get(), 0);
    }

    #[test]
    fn transaction_progress_reports_observations_without_promoting_confirmation() {
        let signed = TransactionAssurance::Signed {
            non_authoritative_observations: vec![
                NonAuthoritativeTransactionObservation::TransportDelivered,
                NonAuthoritativeTransactionObservation::GatewayAcknowledged,
                NonAuthoritativeTransactionObservation::RpcAccepted,
            ],
        };
        let view = transaction_view([0x91; 32], Some(&signed));
        assert_eq!(view.assurance, TransactionAssuranceState::SignedUnconfirmed);
        assert_eq!(view.progress, TransactionProgressState::RpcAccepted);

        let local_only = transaction_view(
            [0x92; 32],
            Some(&TransactionAssurance::Signed {
                non_authoritative_observations: Vec::new(),
            }),
        );
        assert_eq!(
            local_only.assurance,
            TransactionAssuranceState::SignedUnconfirmed
        );
        assert_eq!(local_only.progress, TransactionProgressState::SignedLocally);
        assert!(local_only.status_observation.is_none());
    }

    #[test]
    fn transaction_status_projection_labels_service_authority_without_confirmation() {
        let view = EthereumTransactionView {
            tx_hash: encode_hex(&[0x91; 32]),
            assurance: TransactionAssuranceState::SignedUnconfirmed,
            progress: TransactionProgressState::RpcAccepted,
            status_observation: Some(EthereumTransactionStatusObservationView {
                authority: "rpc_status",
                status: TransactionStatusState::Included,
                observed_at_unix: 1_788_270_000,
                source_hash: encode_hex(&[0x21; 16]),
                included_block: Some(block_observation_view(9_100_000, [0x31; 32])),
                heads: EthereumTransactionHeadsView {
                    latest: block_observation_view(9_100_004, [0x41; 32]),
                    safe: block_observation_view(9_100_002, [0x42; 32]),
                    finalized: block_observation_view(9_099_990, [0x43; 32]),
                },
                continuity: TransactionStatusContinuityState::Observed,
                previous_inclusion: None,
            }),
            receipt_request: None,
        };
        let value = serde_json::to_value(view).unwrap();
        let observation = value.get("status_observation").unwrap();
        assert_eq!(observation.get("authority").unwrap(), "rpc_status");
        assert_eq!(observation.get("status").unwrap(), "included");
        assert_eq!(
            observation
                .pointer("/included_block/number")
                .unwrap()
                .as_u64(),
            Some(9_100_000)
        );
        assert_eq!(
            observation
                .pointer("/heads/finalized/number")
                .unwrap()
                .as_u64(),
            Some(9_099_990)
        );
        assert_eq!(value.get("assurance").unwrap(), "signed_unconfirmed");
        assert!(!value.to_string().contains("verified_success"));
    }

    #[test]
    fn switching_profile_binding_clears_prior_profile_review_projection() {
        let state = EthereumApplicationState::new();
        let first_profile = tempfile::tempdir().unwrap();
        let second_profile = tempfile::tempdir().unwrap();
        let first_account = WalletAccount::sepolia(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
        );
        let second_account = WalletAccount::sepolia(
            "0x2222222222222222222222222222222222222222"
                .parse()
                .unwrap(),
        );
        let first_generation = state
            .install_profile_binding(first_profile.path().to_owned(), first_account)
            .unwrap();
        let review = test_review_projection();
        state
            .register_review_surface(first_generation, [7; 16], review.clone())
            .unwrap();
        assert!(state.review([7; 16]).unwrap().is_some());

        state
            .install_profile_binding(second_profile.path().to_owned(), second_account)
            .unwrap();
        assert!(state.review([7; 16]).unwrap().is_none());
        assert_eq!(
            state
                .register_review_surface(first_generation, [8; 16], review)
                .unwrap_err(),
            "ethereum_profile_changed"
        );
        assert!(state.review([8; 16]).unwrap().is_none());
    }

    #[test]
    fn switch_during_database_read_rejects_old_profile_response() {
        let state = EthereumApplicationState::new();
        let first_account = WalletAccount::sepolia(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
        );
        let second_account = WalletAccount::sepolia(
            "0x2222222222222222222222222222222222222222"
                .parse()
                .unwrap(),
        );
        let first_profile = tempfile::tempdir().unwrap();
        let second_profile = tempfile::tempdir().unwrap();
        state
            .install_profile_binding(first_profile.path().to_owned(), first_account)
            .unwrap();

        let error = public_account_view_with(&state, |_| {
            state
                .install_profile_binding(second_profile.path().to_owned(), second_account)
                .unwrap();
            open_profile_store(first_profile.path())
        })
        .unwrap_err();
        assert_eq!(error, "ethereum_profile_changed");

        state
            .install_profile_binding(first_profile.path().to_owned(), first_account)
            .unwrap();
        let error = transaction_assurance_view_with(&state, [9; 32], |_| {
            state
                .install_profile_binding(second_profile.path().to_owned(), second_account)
                .unwrap();
            open_profile_store(first_profile.path())
        })
        .unwrap_err();
        assert_eq!(error, "ethereum_profile_changed");

        state
            .install_profile_binding(first_profile.path().to_owned(), first_account)
            .unwrap();
        let error = latest_transaction_view_with(&state, |_| {
            state
                .install_profile_binding(second_profile.path().to_owned(), second_account)
                .unwrap();
            open_profile_store(first_profile.path())
        })
        .unwrap_err();
        assert_eq!(error, "ethereum_profile_changed");
    }

    #[test]
    fn latest_transaction_is_empty_across_restart_until_a_local_signature_exists() {
        let state = EthereumApplicationState::new();
        let account = WalletAccount::sepolia(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
        );
        let profile = tempfile::tempdir().unwrap();
        state
            .install_profile_binding(profile.path().to_owned(), account)
            .unwrap();
        assert!(latest_transaction_view(&state).unwrap().is_none());
        drop(EthereumNodeStore::open_in_profile(profile.path()).unwrap());
        assert!(latest_transaction_view(&state).unwrap().is_none());
    }

    #[test]
    fn immutable_review_projection_contains_only_public_review_fields() {
        let view = test_review_projection();
        let value = serde_json::to_value(view).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "chain_id",
                "expires_at_unix",
                "from",
                "gas_limit",
                "max_fee_per_gas_wei",
                "max_priority_fee_per_gas_wei",
                "maximum_total_cost_wei",
                "network",
                "nonce",
                "operation_id",
                "prepared_at_unix",
                "review_digest",
                "to",
                "value_wei",
            ])
        );
        let serialized = value.to_string();
        for forbidden in [
            "mnemonic",
            "recovery",
            "private_key",
            "seed",
            "passphrase",
            "raw_transaction",
            "signing_bytes",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    fn test_prepared_transfer() -> ratspeak_eth_wallet::PreparedTransfer {
        let from = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let to = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let account = WalletAccount::sepolia(from);
        account
            .prepare_transfer(
                TransferIntent::new(SEPOLIA_CHAIN_ID, from, to, "10".parse().unwrap(), 3, 20, 2),
                OperationId::new([7; 16]).unwrap(),
                ReviewContext::from_canonical_bytes(b"public-proof-context").unwrap(),
                1_000,
                1_100,
            )
            .unwrap()
    }

    fn test_review_projection() -> EthereumTransferReviewView {
        let prepared = test_prepared_transfer();
        EthereumTransferReviewView::from_review(prepared.review())
    }

    #[test]
    fn native_candidate_rejects_changed_review_fields_or_signing_bytes() {
        let prepared = test_prepared_transfer();
        let review = prepared.review();
        let candidate = NativeExactTransferCandidate {
            operation_id: *review.operation_id().as_bytes(),
            chain_id: review.chain_id(),
            sender: format!("{:#x}", review.from()),
            recipient: format!("{:#x}", review.to()),
            value_wei: review.value().to_string(),
            nonce: review.nonce(),
            gas_limit: review.gas_limit(),
            max_fee_per_gas_wei: review.max_fee_per_gas(),
            max_priority_fee_per_gas_wei: review.max_priority_fee_per_gas(),
            expires_at_unix: review.expires_at_unix(),
            canonical_signing_payload: prepared.canonical_signing_bytes().to_vec(),
        };
        assert!(candidate.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));

        let mut changed_operation = candidate.clone();
        changed_operation.operation_id = [8; 16];
        assert!(!changed_operation.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));

        let mut changed_nonce = candidate.clone();
        changed_nonce.nonce += 1;
        assert!(!changed_nonce.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));

        let mut changed_sender = candidate.clone();
        changed_sender.sender = "0x3333333333333333333333333333333333333333".to_owned();
        assert!(!changed_sender.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));

        let mut changed_expiry = candidate.clone();
        changed_expiry.expires_at_unix += 1;
        assert!(!changed_expiry.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));

        let mut changed_payload = candidate.canonical_signing_payload.clone();
        changed_payload[0] ^= 1;
        let changed = NativeExactTransferCandidate {
            canonical_signing_payload: changed_payload,
            ..candidate
        };
        assert!(!changed.matches_review(
            review.operation_id(),
            review,
            prepared.canonical_signing_bytes()
        ));
    }

    #[test]
    fn base_sepolia_native_operation_reaches_retained_clearsign_preparation() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x71; 16];
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                17,
            )
            .unwrap();
        let request = EthereumClearSignedOperationRequest {
            chain_id: ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
            target: "0x2222222222222222222222222222222222222222".to_owned(),
            value_wei: "1000000000000000".to_owned(),
            calldata_hex: "0x".to_owned(),
            nonce: 7,
            gas_limit: 21_000,
            max_fee_per_gas_wei: "2000000000".to_owned(),
            max_priority_fee_per_gas_wei: "1000000000".to_owned(),
        };

        let candidate = state
            .prepare_clear_signed_operation_for_native(
                generation,
                identity,
                17,
                &request,
                1_000,
                1_300,
            )
            .unwrap();
        assert_eq!(candidate.chain_id, ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID);
        assert_eq!(candidate.network, "Base Sepolia");
        assert_eq!(candidate.asset_symbol, "ETH");
        assert_eq!(candidate.asset_decimals, 18);
        assert_eq!(candidate.amount, "1000000000000000");
        assert_eq!(
            state
                .scoped
                .read()
                .unwrap()
                .pending_clear_signed_operations
                .len(),
            1
        );
    }

    #[test]
    fn base_sepolia_usdc_requires_atomic_asset_install_before_preparation() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x72; 16];
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                18,
            )
            .unwrap();
        let recipient = "2222222222222222222222222222222222222222";
        let amount = 5_000_000u64;
        let calldata = format!(
            "0xa9059cbb{}{}",
            format!("{:0>64}", recipient),
            format!("{amount:064x}")
        );
        let request = EthereumClearSignedOperationRequest {
            chain_id: ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
            target: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_owned(),
            value_wei: "0".to_owned(),
            calldata_hex: calldata,
            nonce: 8,
            gas_limit: 65_000,
            max_fee_per_gas_wei: "2000000000".to_owned(),
            max_priority_fee_per_gas_wei: "1000000000".to_owned(),
        };

        assert_eq!(
            state
                .prepare_clear_signed_operation_for_native(
                    generation,
                    identity,
                    18,
                    &request,
                    1_000,
                    1_300,
                )
                .unwrap_err(),
            "ethereum_clear_sign_rejected"
        );

        let definitions_path = profile
            .path()
            .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
            .join("definitions");
        let installed =
            DefinitionRegistry::install_base_sepolia_usdc_bundle_files(&definitions_path).unwrap();
        assert_eq!(installed.symbol, "USDC");

        let candidate = state
            .prepare_clear_signed_operation_for_native(
                generation,
                identity,
                18,
                &request,
                1_001,
                1_301,
            )
            .unwrap();
        assert_eq!(candidate.network, "Base Sepolia");
        assert_eq!(candidate.asset_symbol, "USDC");
        assert_eq!(candidate.asset_decimals, 6);
        assert_eq!(candidate.amount, amount.to_string());
        assert_eq!(candidate.recipient, format!("0x{recipient}"));
    }

    #[test]
    fn builtin_asset_selector_cannot_supply_definition_material() {
        let asset: EthereumBuiltinAsset =
            serde_json::from_str("\"base_sepolia_usdc\"").unwrap();
        assert_eq!(asset, EthereumBuiltinAsset::BaseSepoliaUsdc);
        assert!(
            serde_json::from_value::<EthereumBuiltinAsset>(serde_json::json!({
                "asset": "base_sepolia_usdc",
                "contract": "0x1111111111111111111111111111111111111111"
            }))
            .is_err()
        );

        let source = include_str!("ethereum.rs");
        let start = source
            .find("pub(crate) async fn ethereum_install_builtin_asset(")
            .unwrap();
        let end = source[start..]
            .find("fn setup_status_for_identity(")
            .map(|offset| start + offset)
            .unwrap();
        let command = &source[start..end];
        assert!(command.contains("install_base_sepolia_usdc_bundle_files"));
        for forbidden in ["clear_sign_bytes", "balance_bytes", "mappingSlot", "rpc_hint"] {
            assert!(!command.contains(forbidden));
        }
    }

    #[test]
    fn tauri_command_surface_matches_the_allowlist() {
        let source = include_str!("ethereum.rs");
        let mut commands = Vec::new();
        let mut expects_function = false;
        for line in source.lines() {
            if line.trim() == "#[tauri::command]" {
                expects_function = true;
            } else if expects_function {
                let declaration = line
                    .trim_start()
                    .strip_prefix("pub(crate) fn ")
                    .or_else(|| line.trim_start().strip_prefix("pub(crate) async fn "));
                if let Some(declaration) = declaration {
                    commands.push(declaration.split(['(', '<']).next().unwrap());
                    expects_function = false;
                }
            }
        }
        assert_eq!(commands, WEBVIEW_COMMAND_ALLOWLIST);
    }

    #[test]
    fn synchronize_command_accepts_no_webview_control_or_authority_fields() {
        let source = include_str!("ethereum.rs");
        let start = source
            .find("pub(crate) async fn ethereum_synchronize(")
            .unwrap();
        let signature = &source[start..start + source[start..].find('{').unwrap()];
        assert!(signature.contains("tauri::AppHandle"));
        assert!(signature.contains("tauri::State"));
        for forbidden in [
            "String",
            "Vec<",
            "request",
            "checkpoint",
            "gateway",
            "digest",
            "bytes",
            "expiry",
            "secret",
        ] {
            assert!(
                !signature.contains(forbidden),
                "forbidden command input: {forbidden}"
            );
        }
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        assert_eq!(
            production.matches(".plan_or_resume_evidence_sync(").count(),
            2
        );
        assert_eq!(production.matches(".plan_evidence_sync(").count(), 0);
        let command = &source[start
            ..source[start..]
                .find("struct EthereumSyncCommandAdmission")
                .map(|end| start + end)
                .unwrap()];
        let route_preflight = command.find("reachable_transport_binding(").unwrap();
        let durable_plans = command
            .match_indices(".plan_or_resume_evidence_sync(")
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(durable_plans.len(), 2);
        assert!(durable_plans
            .into_iter()
            .all(|durable_plan| route_preflight < durable_plan));
        let helper_start = production
            .find("async fn reachable_transport_binding(")
            .unwrap();
        let helper = &production[helper_start..start];
        assert!(helper.contains(".await_path("));
        assert!(helper.contains("ethereum_gateway_route_unavailable"));
        assert!(command.contains("transport_binding_is_current(&worker_route_binding)"));
    }

    #[test]
    fn bulk_evidence_review_command_accepts_no_webview_snapshot_or_decision() {
        let source = include_str!("ethereum.rs");
        let start = source
            .find("pub(crate) fn ethereum_review_pending_bulk_evidence(")
            .unwrap();
        let signature = &source[start..start + source[start..].find('{').unwrap()];
        let arguments = &signature[signature.rfind('(').unwrap()..];
        assert!(arguments.contains("tauri::State"));
        for forbidden in [
            "String", "Vec<", "review", "decision", "request", "gateway", "digest", "bytes",
            "expiry", "secret",
        ] {
            assert!(
                !arguments.contains(forbidden),
                "forbidden command input: {forbidden}"
            );
        }
    }

    #[test]
    fn checkpoint_review_command_accepts_no_webview_candidate_or_decision() {
        let source = include_str!("ethereum.rs");
        let start = source
            .find("pub(crate) fn ethereum_review_pending_checkpoint(")
            .unwrap();
        let signature = &source[start..start + source[start..].find('{').unwrap()];
        let arguments = &signature[signature.rfind('(').unwrap()..];
        assert!(arguments.contains("tauri::State"));
        for forbidden in [
            "String",
            "Vec<",
            "candidate",
            "root",
            "bootstrap",
            "source",
            "decision",
            "gateway",
            "bytes",
            "expiry",
            "secret",
        ] {
            assert!(
                !arguments.contains(forbidden),
                "forbidden command input: {forbidden}"
            );
        }
    }

    #[test]
    fn checkpoint_file_import_command_accepts_no_webview_file_or_authority() {
        let source = include_str!("ethereum.rs");
        let start = source
            .find("pub(crate) fn ethereum_import_checkpoint_file(")
            .unwrap();
        let signature = &source[start..start + source[start..].find('{').unwrap()];
        let arguments = &signature[signature.rfind('(').unwrap()..];
        assert!(arguments.contains("tauri::State"));
        for forbidden in [
            "String",
            "Vec<",
            "path: ",
            "uri: ",
            "file: ",
            "candidate: ",
            "root: ",
            "bootstrap: ",
            "source: ",
            "fingerprint: ",
            "decision: ",
            "gateway: ",
            "bytes: ",
            "expiry: ",
            "secret: ",
        ] {
            assert!(
                !arguments.contains(forbidden),
                "forbidden command input: {forbidden}"
            );
        }
    }

    #[test]
    fn native_launch_request_accepts_only_bounded_public_operation_facts() {
        let request: EthereumNativeWalletLaunchRequest =
            serde_json::from_value(serde_json::json!({
                "kind": "transfer",
                "recipient": "0x2222222222222222222222222222222222222222",
                "value_wei": "1000000000000000",
                "max_fee_per_gas_wei": "2000000000",
                "max_priority_fee_per_gas_wei": "1000000000"
            }))
            .unwrap();
        let EthereumNativeWalletLaunchRequest::Transfer(intent) = request else {
            panic!("transfer request expected");
        };
        assert!(intent.field_request().is_ok());
        let noncanonical = EthereumNativeTransferIntent {
            value_wei: "01".to_owned(),
            ..intent.clone()
        };
        assert!(noncanonical.field_request().is_err());

        let request: EthereumNativeWalletLaunchRequest =
            serde_json::from_value(serde_json::json!({
                "kind": "clear_signed",
                "chain_id": 84532,
                "target": "0x2222222222222222222222222222222222222222",
                "value_wei": "1000000000000000",
                "calldata_hex": "0x",
                "nonce": 7,
                "gas_limit": 21000,
                "max_fee_per_gas_wei": "2000000000",
                "max_priority_fee_per_gas_wei": "1000000000"
            }))
            .unwrap();
        let EthereumNativeWalletLaunchRequest::ClearSigned(request) = request else {
            panic!("clear-signed request expected");
        };
        assert_eq!(request.chain_id, ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID);
        assert!(request.intent(test_account()).is_ok());

        assert!(
            serde_json::from_value::<EthereumNativeWalletLaunchRequest>(serde_json::json!({
                "kind": "clear_signed",
                "chain_id": 84532,
                "target": "0x2222222222222222222222222222222222222222",
                "value_wei": "1",
                "calldata_hex": "0x",
                "nonce": 7,
                "gas_limit": 21000,
                "max_fee_per_gas_wei": "2",
                "max_priority_fee_per_gas_wei": "1",
                "signing_hash": "11"
            }))
            .is_err()
        );
    }

    #[test]
    fn operation_ids_and_native_cancellation_are_profile_bound() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x71; 16];
        let other_identity = [0x72; 16];
        let identity_generation = 9;
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                identity_generation,
            )
            .unwrap();
        let intent = EthereumNativeTransferIntent {
            recipient: "0x2222222222222222222222222222222222222222".to_owned(),
            value_wei: "1".to_owned(),
            max_fee_per_gas_wei: "2".to_owned(),
            max_priority_fee_per_gas_wei: "1".to_owned(),
        };
        let first = state
            .next_operation_id(identity, identity_generation, &intent, 100)
            .unwrap();
        let second = state
            .next_operation_id(identity, identity_generation, &intent, 100)
            .unwrap();
        assert_ne!(first, second);
        state
            .register_review_surface(generation, *first.as_bytes(), test_review_projection())
            .unwrap();
        assert_eq!(
            state
                .cancel_native_transfer(other_identity, identity_generation, *first.as_bytes(),)
                .unwrap_err(),
            "ethereum_profile_changed"
        );
        assert!(state.review(*first.as_bytes()).unwrap().is_some());
        state
            .cancel_native_transfer(identity, identity_generation, *first.as_bytes())
            .unwrap();
        assert!(state.review(*first.as_bytes()).unwrap().is_none());
        assert_eq!(state.pending_native_cancellation_count(), 0);
        assert!(state
            .ensure_native_identity(identity, identity_generation)
            .is_ok());
        assert!(state
            .ensure_native_identity(identity, identity_generation + 1)
            .is_err());
        assert!(state
            .ensure_native_identity(other_identity, identity_generation)
            .is_err());

        let wallet = EthereumNativeWalletLaunchView::wallet();
        let transfer = EthereumNativeWalletLaunchView::transfer_launched(second);
        assert_eq!(
            serde_json::to_value(wallet).unwrap()["operation_id"],
            Value::Null
        );
        assert_eq!(
            serde_json::to_value(&transfer).unwrap()["operation_id"],
            encode_hex(second.as_bytes())
        );
        assert_eq!(
            serde_json::to_value(&transfer).unwrap()["tx_hash"],
            Value::Null
        );
        let signed = EthereumNativeWalletLaunchView::transfer_signed(second, [0x8a; 32]);
        assert_eq!(
            serde_json::to_value(&signed).unwrap()["operation_id"],
            encode_hex(second.as_bytes())
        );
        assert_eq!(
            serde_json::to_value(&signed).unwrap()["tx_hash"],
            encode_hex(&[0x8a; 32])
        );
    }

    #[test]
    fn failed_native_cancellation_is_retried_after_jni_loses_the_operation_id() {
        let parent = tempfile::tempdir().unwrap();
        let blocked_profile = parent.path().join("blocked-profile");
        std::fs::write(&blocked_profile, b"not a profile directory").unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x75; 16];
        let identity_generation = 11;
        let operation_id = [0x76; 16];
        let generation = state
            .install_profile_binding_for_identity(
                blocked_profile.clone(),
                test_account(),
                identity,
                identity_generation,
            )
            .unwrap();
        state
            .register_review_surface(generation, operation_id, test_review_projection())
            .unwrap();

        assert_eq!(
            state
                .cancel_native_transfer(identity, identity_generation, operation_id)
                .unwrap_err(),
            "ethereum_state_unavailable"
        );
        assert!(state.review(operation_id).unwrap().is_none());
        assert_eq!(state.pending_native_cancellation_count(), 1);

        std::fs::remove_file(&blocked_profile).unwrap();
        state.retry_native_cancellations();
        assert_eq!(state.pending_native_cancellation_count(), 0);
        assert!(EthereumNodeStore::open_in_profile(&blocked_profile).is_ok());
    }

    #[test]
    fn returning_to_the_same_identity_cannot_revive_an_old_session() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x73; 16];
        let old_session = 10;
        let old_generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                old_session,
            )
            .unwrap();
        state
            .register_review_surface(old_generation, [0x74; 16], test_review_projection())
            .unwrap();

        let returned_session = old_session + 2;
        let returned_generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                test_account(),
                identity,
                returned_session,
            )
            .unwrap();
        assert_ne!(returned_generation, old_generation);
        assert!(state.review([0x74; 16]).unwrap().is_none());
        assert!(state.ensure_native_identity(identity, old_session).is_err());
        assert!(state
            .ensure_native_identity(identity, returned_session)
            .is_ok());
    }

    #[test]
    fn public_response_shapes_do_not_gain_secret_or_raw_byte_fields() {
        let account = EthereumAccountView::unknown(None);
        let transaction = transaction_view([3; 32], None);
        let feature = EthereumFeatureStatus::current();
        let setup = EthereumSetupStatus {
            identity_ready: true,
            wallet_configured: false,
            account: EthereumAccountView::unknown(None),
            account_check: None,
            checkpoint_installed: false,
            checkpoint: None,
            gateway_selected: false,
            gateway_contact_ready: false,
            gateway_configured: false,
            selected_service: Some(EthereumServiceView {
                display_name: "Public Sepolia Gateway".to_owned(),
                avatar_seed: "60c654d3320c1083a08a15e931a7791a".to_owned(),
                destination_fingerprint: "60c6…791a".to_owned(),
            }),
            public_service_available: false,
            public_service_contact_added: false,
            pending_checkpoint_review: Some(false),
            pending_gateway_review: None,
            pending_evidence_review: Some(false),
        };
        let synchronization = EthereumSyncStartView {
            state: EthereumSyncStartState::Queued,
            evidence_requests: 2,
            transaction_relays: 1,
            transaction_status_requests: 1,
        };
        let checkpoint_file_import = EthereumCheckpointFileImportView {
            staged: false,
            cancelled: true,
            launched: false,
        };
        let gateway_import = EthereumGatewayCardImportView {
            staged: false,
            cancelled: false,
            launched: true,
        };
        let gateway_review = EthereumGatewayCardReviewView {
            reviewed: false,
            approved: false,
            denied: false,
            launched: true,
        };
        assert_eq!(
            serde_json::to_value(&synchronization)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "evidence_requests",
                "state",
                "transaction_relays",
                "transaction_status_requests",
            ])
        );
        assert_eq!(
            serde_json::to_value(EthereumSyncStartState::Active).unwrap(),
            Value::String("active".to_owned())
        );
        let setup_value = serde_json::to_value(&setup).unwrap();
        let service = setup_value
            .get("selected_service")
            .and_then(Value::as_object)
            .unwrap();
        assert_eq!(
            service.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["avatar_seed", "destination_fingerprint", "display_name"])
        );
        assert_eq!(
            service.get("display_name").unwrap(),
            "Public Sepolia Gateway"
        );
        assert_eq!(service.get("destination_fingerprint").unwrap(), "60c6…791a");
        assert_eq!(
            service.get("avatar_seed").unwrap(),
            "60c654d3320c1083a08a15e931a7791a"
        );
        for forbidden in ["identity_pubkey", "public_key", "card", "destination_hash"] {
            assert!(!setup_value.to_string().contains(forbidden));
        }
        assert_eq!(
            serde_json::to_value(&checkpoint_file_import)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["cancelled", "launched", "staged"])
        );
        assert_eq!(
            serde_json::to_value(&gateway_import)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["cancelled", "launched", "staged"])
        );
        assert_eq!(
            serde_json::to_value(&gateway_review)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["approved", "denied", "launched", "reviewed"])
        );
        for value in [
            serde_json::to_value(account).unwrap(),
            serde_json::to_value(transaction).unwrap(),
            serde_json::to_value(feature).unwrap(),
            serde_json::to_value(setup).unwrap(),
            serde_json::to_value(synchronization).unwrap(),
            serde_json::to_value(checkpoint_file_import).unwrap(),
            serde_json::to_value(gateway_import).unwrap(),
            serde_json::to_value(gateway_review).unwrap(),
        ] {
            assert_public_keys(&value);
        }
    }

    #[test]
    fn setup_status_is_profile_scoped_and_reports_only_coarse_review_presence() {
        let profile = tempfile::tempdir().unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x31; 16];
        let generation = state
            .install_transport_profile_for_identity(profile.path().to_owned(), identity, 4)
            .unwrap();

        let status = setup_status_for_identity(&state, identity, 4, false, |_| false).unwrap();
        assert!(status.identity_ready);
        assert!(!status.wallet_configured);
        assert_eq!(status.account, EthereumAccountView::unknown(None));
        assert!(!status.checkpoint_installed);
        assert!(!status.gateway_selected);
        assert!(!status.gateway_contact_ready);
        assert!(!status.gateway_configured);
        assert_eq!(status.pending_checkpoint_review, Some(false));
        assert_eq!(status.pending_evidence_review, None);
        assert_eq!(status.pending_gateway_review, Some(false));
        let value = serde_json::to_value(status).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.get("pending_gateway_review").unwrap(), false);

        persist_gateway_destination(profile.path(), [0x42; 16]).unwrap();
        assert_eq!(
            setup_status_for_identity(&state, identity, 4, false, |_| false),
            Err("ethereum_profile_changed")
        );

        // A stale session cannot observe this profile's setup state.
        let stale = setup_status_for_identity(&state, identity, 5, false, |_| false).unwrap();
        assert_eq!(stale, EthereumSetupStatus::unavailable());
        assert_eq!(generation.0, 1);
    }

    #[test]
    fn selected_gateway_is_not_ready_without_a_matching_contact() {
        let profile = tempfile::tempdir().unwrap();
        let destination = [0x52; 16];
        drop(EthereumNodeStore::open_in_profile(profile.path()).unwrap());
        persist_gateway_destination(profile.path(), destination).unwrap();
        let state = EthereumApplicationState::new();
        let identity = [0x53; 16];
        state
            .install_transport_profile_for_identity(profile.path().to_owned(), identity, 8)
            .unwrap();

        let missing = setup_status_for_identity(&state, identity, 8, false, |_| false).unwrap();
        assert!(missing.gateway_selected);
        assert!(!missing.gateway_contact_ready);
        assert!(!missing.gateway_configured);

        let matching = setup_status_for_identity(&state, identity, 8, true, |candidate| {
            candidate == destination
        })
        .unwrap();
        assert!(matching.gateway_selected);
        assert!(matching.gateway_contact_ready);
        assert!(matching.gateway_configured);
        assert!(matching.public_service_contact_added);
    }

    #[test]
    fn queued_account_check_reports_missing_service_contact_as_paused() {
        let queued = EthereumAccountCheckView {
            stage: EthereumAccountCheckStage::Queued,
            created_at_unix: 100,
            expires_at_unix: 200,
        };
        assert_eq!(
            account_check_with_contact_status(Some(queued), false)
                .unwrap()
                .stage,
            EthereumAccountCheckStage::ServiceContactRequired
        );
        assert_eq!(
            account_check_with_contact_status(Some(queued), true)
                .unwrap()
                .stage,
            EthereumAccountCheckStage::Queued
        );
    }

    #[test]
    fn bulk_evidence_review_capability_is_independent_of_wallet_custody() {
        assert_eq!(
            native_bulk_evidence_review_state_from_available(true),
            NativeBulkEvidenceReviewState::Available
        );
        assert_eq!(
            native_bulk_evidence_review_state_from_available(false),
            NativeBulkEvidenceReviewState::Unavailable
        );
    }

    #[test]
    fn gateway_pairing_capability_distinguishes_contacts_from_file_import() {
        assert_ne!(
            NativeGatewayPairingState::Contacts,
            NativeGatewayPairingState::File
        );
        assert_ne!(
            NativeGatewayPairingState::Contacts,
            NativeGatewayPairingState::Unavailable
        );
    }

    #[test]
    fn checkpoint_review_capability_is_independent_of_wallet_custody() {
        assert_eq!(
            native_checkpoint_review_state_from_available(true),
            NativeCheckpointReviewState::Available
        );
        assert_eq!(
            native_checkpoint_review_state_from_available(false),
            NativeCheckpointReviewState::Unavailable
        );
    }

    #[test]
    fn checkpoint_file_import_capability_is_independent_of_wallet_custody() {
        assert_eq!(
            native_checkpoint_file_import_state_from_available(true),
            NativeCheckpointFileImportState::Available
        );
        assert_eq!(
            native_checkpoint_file_import_state_from_available(false),
            NativeCheckpointFileImportState::Unavailable
        );
    }

    fn assert_public_keys(value: &Value) {
        const FORBIDDEN: &[&str] = &[
            "mnemonic",
            "recovery_words",
            "private_key",
            "seed",
            "dek",
            "passphrase",
            "export",
            "unlock",
            "raw_bytes",
            "raw_transaction",
            "signing_bytes",
        ];
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    assert!(!FORBIDDEN.contains(&key.as_str()), "forbidden key: {key}");
                    assert_public_keys(child);
                }
            }
            Value::Array(values) => values.iter().for_each(assert_public_keys),
            _ => {}
        }
    }

    #[test]
    fn fixed_hex_parser_is_bounded_and_canonicalized() {
        assert_eq!(decode_fixed_hex::<2>("0x00Ff"), Some([0, 255]));
        assert_eq!(encode_hex(&[0, 255]), "00ff");
        assert!(decode_fixed_hex::<2>("000").is_none());
        assert!(decode_fixed_hex::<2>("zzzz").is_none());
    }
}
