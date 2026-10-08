//! Linux-native composition for the experimental Sepolia wallet.

use std::{
    cell::Cell,
    fmt::Write,
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use alloy_primitives::keccak256;
use gtk::prelude::*;
use ratspeak_eth_node::{
    BulkEvidenceReviewDecision, CheckpointBootstrapPolicy, EthereumNodeStore, FieldNodeClock,
    ManualCheckpointReview, ManualCheckpointReviewResolution, ManualCheckpointSource,
    NativeCheckpointApproval, PendingBulkEvidenceReview, PendingManualCheckpointReview,
    PlatformTransferCustody, PreparedFieldTransfer,
};
use ratspeak_eth_wallet::{PreparedTransfer, SignedTransfer, WalletAccount};
use ratspeak_eth_wallet_linux::{
    GtkAdapterError, GtkDialogError, GtkNativeDialogBackend, GtkNativeRecoveryReveal,
    GtkNativeTransferAuthorizer, GtkNativeWalletSetup, GtkWalletManagementChoice,
    LinuxWalletController, LinuxWalletVault, NativeControllerSignError, NativeCustodyDialogs,
    NativeProfileSessionGuard, SecretServiceGenerationStore, SecretServiceProfileKey,
    SecretServiceStoreError, SystemClock, SystemClockError, TrustedClock, TrustedGenerationCounter,
    TrustedGenerationState, VaultError, DEFAULT_KDF_PARAMETERS,
};

use crate::ethereum::{
    gateway_card_from_active_contact, gateway_card_matches_active_contact,
    EthereumApplicationState, EthereumBulkEvidenceReviewView, EthereumGatewayCard,
    EthereumNativeWalletLaunchRequest, EthereumNativeWalletLaunchView, EthereumProfileGeneration,
    MAX_CURRENT_EVIDENCE_AGE_SECONDS,
};

const WALLET_DIRECTORY: &str = "ethereum-wallet";
const VAULT_FILE: &str = "wallet.vault";
const CEREMONY_SECONDS: u64 = 5 * 60;
// One explicit WebView action opens at most one synchronous GTK dialog. The
// node still chooses the deterministic first item from its bounded page; a
// later explicit action is required for every subsequent review.
const MAX_BULK_EVIDENCE_REVIEW_DIALOGS_PER_INVOCATION: usize = 1;
const STATUS_CHECKING: u8 = 0;
const STATUS_AVAILABLE: u8 = 1;
const STATUS_UNAVAILABLE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxWalletStatus {
    Checking,
    Available,
    Unavailable,
}

/// Coarse result for the synchronous native checkpoint-review ceremony.
/// Checkpoint values and the decision authority remain inside the node and
/// native adapter; common glue only needs the terminal result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum LinuxCheckpointReviewOutcome {
    ResolvedApproved,
    ResolvedDenied,
    NoDecision,
}

/// Coarse result of a native checkpoint-card import.  The selected path,
/// card bytes, checkpoint values, and source fingerprint remain in the
/// native/node boundary; none of them are returned to the WebView.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum LinuxCheckpointFileImportOutcome {
    Staged,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxGatewayCardImportOutcome {
    Staged,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxGatewayCardReviewOutcome {
    Approved,
    Denied,
    NoDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdentityBinding {
    hash: [u8; 16],
    session_generation: u64,
}

struct InstalledLinuxWalletEngine {
    profile_dir: PathBuf,
    runtime: Arc<ratspeak_tauri::state::AppState>,
    ceremony: Mutex<()>,
    pending_gateway_card: Mutex<Option<PendingGatewayCard>>,
    status: AtomicU8,
}

#[derive(Clone, PartialEq, Eq)]
struct PendingGatewayCard {
    identity: IdentityBinding,
    profile_generation: EthereumProfileGeneration,
    card: EthereumGatewayCard,
    expires_at_unix: u64,
    expires_at_monotonic: Instant,
}

#[derive(Clone)]
struct GatewayContactChoice {
    destination_hash: [u8; 16],
    card: EthereumGatewayCard,
    display_name: String,
}

static INSTALLED: OnceLock<InstalledLinuxWalletEngine> = OnceLock::new();

pub(crate) fn install(
    app_handle: tauri::AppHandle,
    profile_dir: PathBuf,
    runtime: Arc<ratspeak_tauri::state::AppState>,
) -> Result<(), &'static str> {
    let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
        .map_err(|_| "linux_ethereum_store_unavailable")?;
    store
        .reconcile_interrupted_operations()
        .map_err(|_| "linux_ethereum_store_reconciliation_failed")?;
    let restored_account = store
        .wallet_account()
        .map_err(|_| "linux_ethereum_wallet_profile_invalid")?;
    if let Ok(identity) = active_identity(&runtime) {
        use tauri::Manager;
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("linux_ethereum_state_unavailable")?;
        state.install_transport_profile_for_identity(
            profile_dir.clone(),
            identity.hash,
            identity.session_generation,
        )?;
        if let Some(account) = restored_account {
            state.install_profile_binding_for_identity(
                profile_dir.clone(),
                account,
                identity.hash,
                identity.session_generation,
            )?;
        }
    }
    INSTALLED
        .set(InstalledLinuxWalletEngine {
            profile_dir,
            runtime,
            ceremony: Mutex::new(()),
            pending_gateway_card: Mutex::new(None),
            status: AtomicU8::new(STATUS_CHECKING),
        })
        .map_err(|_| "linux_ethereum_engine_already_installed")
}

pub(crate) fn native_wallet_status() -> LinuxWalletStatus {
    let Some(installed) = INSTALLED.get() else {
        return LinuxWalletStatus::Unavailable;
    };
    match installed.status.load(Ordering::Acquire) {
        STATUS_AVAILABLE => LinuxWalletStatus::Available,
        STATUS_UNAVAILABLE => LinuxWalletStatus::Unavailable,
        _ => LinuxWalletStatus::Checking,
    }
}

/// Bulk evidence review needs a native GTK adapter and profile runtime, but
/// does not depend on Secret Service, a wallet, or wallet custody status.
pub(crate) fn native_bulk_evidence_review_available() -> bool {
    INSTALLED.get().is_some()
}

/// Manual checkpoint review only needs the native GTK/runtime installation;
/// wallet custody and protected-generation state are intentionally irrelevant.
#[allow(dead_code)]
pub(crate) fn native_checkpoint_review_available() -> bool {
    INSTALLED.get().is_some()
}

pub(crate) fn native_gateway_pairing_available() -> bool {
    INSTALLED.get().is_some()
}

/// Coarse presence only; card identity, key material, and review contents stay
/// inside the native adapter.
pub(crate) fn pending_gateway_card_review(
    identity_hash: [u8; 16],
    identity_session_generation: u64,
) -> Result<bool, &'static str> {
    let Some(installed) = INSTALLED.get() else {
        return Ok(false);
    };
    let pending = installed
        .pending_gateway_card
        .lock()
        .map_err(|_| "ethereum_gateway_review_unavailable")?;
    let Some(pending) = pending.as_ref() else {
        return Ok(false);
    };
    Ok(pending.identity.hash == identity_hash
        && pending.identity.session_generation == identity_session_generation
        && now_unix()? < pending.expires_at_unix
        && Instant::now() < pending.expires_at_monotonic)
}

/// Select and stage one manual checkpoint card through a native file picker.
///
/// This operation intentionally does not require a wallet or gateway.  The
/// selected file is treated as hostile input: it is opened without following
/// a final symlink, bounded before and during reading, checked for replacement
/// races, and only then passed to the node policy for parsing and Helios
/// validation.  Cancellation has no storage side effect.
#[allow(dead_code)]
pub(crate) fn import_manual_checkpoint_file(
    state: &EthereumApplicationState,
) -> Result<LinuxCheckpointFileImportOutcome, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_checkpoint_file_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_checkpoint_file_busy")?;
    // Snapshot the identity before opening a picker that may remain open
    // indefinitely.  Do not block profile switching while the user browses
    // files; the exact identity/session is checked again before any state is
    // opened or mutated.
    let identity = active_identity(&installed.runtime)?;
    let Some(path) = pick_manual_checkpoint_file()? else {
        return Ok(LinuxCheckpointFileImportOutcome::Cancelled);
    };
    let bytes = read_manual_checkpoint_file(&path)?;

    // The file read is also outside the lifecycle lock.  A profile switch
    // during either user-controlled operation is rejected here, before the
    // transport binding or Ethereum store can be selected.
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if active_identity(&installed.runtime)? != identity {
        return Err("ethereum_profile_changed");
    }
    state.install_transport_profile_for_identity(
        installed.profile_dir.clone(),
        identity.hash,
        identity.session_generation,
    )?;
    state.ensure_native_identity(identity.hash, identity.session_generation)?;
    let profile_dir = installed
        .profile_dir
        .canonicalize()
        .map_err(|_| "ethereum_profile_unavailable")?;

    // The parser/validator and durable review staging are the only authority
    // for card contents.  Do not construct a candidate in this platform
    // adapter, and do not expose path or bytes to the WebView.
    let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let policy = CheckpointBootstrapPolicy::new(Vec::new())
        .map_err(|_| "ethereum_checkpoint_policy_unavailable")?;
    policy
        .stage_manual_checkpoint_file(&mut store, &bytes)
        .map_err(|_| "ethereum_checkpoint_file_rejected")?;
    Ok(LinuxCheckpointFileImportOutcome::Staged)
}

fn pick_manual_checkpoint_file() -> Result<Option<PathBuf>, &'static str> {
    // rfd delegates to the platform-native GTK picker on Linux.  No path is
    // supplied by the WebView or accepted from an LXMF/RPC message.
    Ok(rfd::FileDialog::new()
        .set_title("Import Sepolia checkpoint card")
        .add_filter("Ratspeak Ethereum checkpoint", &["rsethcf", "bin"])
        .pick_file())
}

/// Choose an existing, profile-scoped Ratspeak Contact as the Ethereum
/// service. The WebView receives only the coarse staged/cancelled outcome;
/// destination and public-key material remain inside this native boundary.
pub(crate) fn import_gateway_card(
    state: &EthereumApplicationState,
) -> Result<LinuxGatewayCardImportOutcome, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_gateway_card_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_gateway_card_busy")?;
    let identity = active_identity(&installed.runtime)?;
    let binding = state
        .native_transport_profile_binding()?
        .filter(|binding| {
            binding.profile_dir == installed.profile_dir
                && binding.ratspeak_identity_hash == identity.hash
                && binding.identity_session_generation == identity.session_generation
        })
        .ok_or("ethereum_profile_changed")?;
    // Snapshot Contacts under the lifecycle fence, then release it before
    // entering the blocking GTK modal so profile switching remains possible.
    let choices = {
        let _identity_lifecycle =
            tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
        if active_identity(&installed.runtime)? != identity
            || state.native_transport_profile_binding()?.as_ref() != Some(&binding)
        {
            return Err("ethereum_profile_changed");
        }
        gateway_contact_choices(&installed.runtime, identity)
    };
    if choices.is_empty() {
        return Err("ethereum_gateway_contact_required");
    }
    let Some(selected_destination) =
        pick_gateway_contact(&choices, Arc::clone(&installed.runtime), identity)?
    else {
        return Ok(LinuxGatewayCardImportOutcome::Cancelled);
    };
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if active_identity(&installed.runtime)? != identity
        || state.native_transport_profile_binding()?.as_ref() != Some(&binding)
    {
        return Err("ethereum_profile_changed");
    }
    // Re-read the Contact after the modal closes. A concurrent Contact update
    // must not turn the pre-dialog snapshot into a stale routing approval.
    let card = gateway_card_from_active_contact(&installed.runtime, selected_destination)
        .ok_or("ethereum_gateway_contact_required")?;
    let original = choices
        .iter()
        .find(|choice| choice.destination_hash == selected_destination)
        .ok_or("ethereum_gateway_contact_changed")?;
    if card != original.card {
        return Err("ethereum_gateway_contact_changed");
    }
    state.ensure_native_identity(identity.hash, identity.session_generation)?;
    let expires_at_unix = now_unix()?
        .checked_add(CEREMONY_SECONDS)
        .ok_or("ethereum_gateway_card_unavailable")?;
    *installed
        .pending_gateway_card
        .lock()
        .map_err(|_| "ethereum_gateway_card_unavailable")? = Some(PendingGatewayCard {
        identity,
        profile_generation: binding.generation,
        card,
        expires_at_unix,
        expires_at_monotonic: Instant::now() + Duration::from_secs(CEREMONY_SECONDS),
    });
    Ok(LinuxGatewayCardImportOutcome::Staged)
}

/// Read and validate the active profile's Contacts before opening the GTK
/// dialog. Invalid rows are intentionally omitted; a visible candidate has a
/// verified public-key→LXMF-destination binding, not merely a matching hash.
fn gateway_contact_choices(
    runtime: &ratspeak_tauri::state::AppState,
    identity: IdentityBinding,
) -> Vec<GatewayContactChoice> {
    let identity_id = encode_hex(&identity.hash);
    ratspeak_tauri::db::get_all_contacts(&runtime.db, &identity_id)
        .into_iter()
        .filter_map(|contact| {
            let destination = contact.get("dest_hash")?.as_str()?;
            let destination_hash = decode_hex16(destination)?;
            let card = gateway_card_from_active_contact(runtime, destination_hash)?;
            let display_name = contact
                .get("display_name")
                .and_then(serde_json::Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .map(|name| ratspeak_tauri::helpers::sanitize_text(name, 80))
                .unwrap_or_else(|| "Unnamed Contact".to_string());
            Some(GatewayContactChoice {
                destination_hash,
                card,
                display_name,
            })
        })
        .collect()
}

/// GTK-native chooser for the already validated Contact snapshot. Selection
/// returns only an opaque destination to the caller; the key is re-derived
/// from the Contact database after the modal closes.
fn pick_gateway_contact(
    choices: &[GatewayContactChoice],
    runtime: Arc<ratspeak_tauri::state::AppState>,
    expected_identity: IdentityBinding,
) -> Result<Option<[u8; 16]>, &'static str> {
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let dialog = gtk::Dialog::with_buttons(
        Some("Choose an Ethereum service"),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Choose service", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_default_response(gtk::ResponseType::None);
    dialog.set_default_size(520, 440);
    dialog.set_resizable(true);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.set_border_width(16);
    let explanation = gtk::Label::new(Some(
        "Choose a Ratspeak Contact (a verified contact card) that operates the Sepolia Ethereum service. The service cannot sign for you; Ratspeak verifies its evidence locally.",
    ));
    explanation.set_line_wrap(true);
    explanation.set_xalign(0.0);
    content.add(&explanation);

    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    let scroll = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    scroll.set_vexpand(true);
    for choice in choices {
        let row = gtk::ListBoxRow::new();
        let row_content = gtk::Box::new(gtk::Orientation::Vertical, 3);
        row_content.set_border_width(10);
        let name = gtk::Label::new(Some(&choice.display_name));
        name.set_xalign(0.0);
        name.set_line_wrap(true);
        let destination = gtk::Label::new(Some(&format!(
            "LXMF destination: {}",
            encode_hex(&choice.destination_hash)
        )));
        destination.set_xalign(0.0);
        destination.set_selectable(true);
        destination.style_context().add_class("dim-label");
        row_content.add(&name);
        row_content.add(&destination);
        row.add(&row_content);
        list.add(&row);
    }
    scroll.add(&list);
    content.add(&scroll);
    dialog.content_area().add(&content);

    let choose_button = dialog
        .widget_for_response(gtk::ResponseType::Accept)
        .and_then(|widget| widget.downcast::<gtk::Button>().ok())
        .ok_or("ethereum_gateway_chooser_unavailable")?;
    choose_button.set_sensitive(false);
    list.connect_row_selected(move |_, row| choose_button.set_sensitive(row.is_some()));

    dialog.show_all();
    let guarded_dialog = dialog.clone();
    let identity_watch = gtk::glib::timeout_add_local(Duration::from_millis(200), move || {
        if active_identity(&runtime).ok() != Some(expected_identity) {
            guarded_dialog.response(gtk::ResponseType::Cancel);
            gtk::glib::ControlFlow::Break
        } else {
            gtk::glib::ControlFlow::Continue
        }
    });
    let response = dialog.run();
    identity_watch.remove();
    let selected = if response == gtk::ResponseType::Accept {
        list.selected_row()
            .and_then(|row| usize::try_from(row.index()).ok())
            .and_then(|index| choices.get(index).map(|choice| choice.destination_hash))
    } else {
        None
    };
    dialog.close();
    Ok(selected)
}

fn decode_hex16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    crate::ethereum::decode_fixed_hex::<16>(value)
}

#[cfg(test)]
fn read_gateway_card_file(path: &Path) -> Result<Vec<u8>, &'static str> {
    read_gateway_card_file_with(path, || {}, || {})
}

#[cfg(test)]
fn read_gateway_card_file_with(
    path: &Path,
    before_open: impl FnOnce(),
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, &'static str> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_gateway_card_unavailable")?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.nlink() != 1 {
        return Err("ethereum_gateway_card_insecure");
    }
    if before.len() == 0 || before.len() > crate::ethereum::MAX_GATEWAY_CARD_BYTES as u64 {
        return Err("ethereum_gateway_card_invalid");
    }
    before_open();
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "ethereum_gateway_card_unavailable")?;
    let mut file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| "ethereum_gateway_card_unavailable")?;
    if !opened.is_file()
        || opened.nlink() != 1
        || opened.len() != before.len()
        || !same_unix_identity(&before, &opened)
    {
        return Err("ethereum_gateway_card_changed");
    }
    after_open();
    let after_open_path =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_gateway_card_changed")?;
    if after_open_path.len() != before.len() || !same_unix_identity(&before, &after_open_path) {
        return Err("ethereum_gateway_card_changed");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take((crate::ethereum::MAX_GATEWAY_CARD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "ethereum_gateway_card_unavailable")?;
    let descriptor_after = file
        .metadata()
        .map_err(|_| "ethereum_gateway_card_changed")?;
    let path_after =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_gateway_card_changed")?;
    if bytes.len() as u64 != before.len()
        || descriptor_after.len() != before.len()
        || path_after.len() != before.len()
        || !same_unix_identity(&before, &descriptor_after)
        || !same_unix_identity(&before, &path_after)
    {
        return Err("ethereum_gateway_card_changed");
    }
    Ok(bytes)
}

pub(crate) fn review_pending_gateway_card(
    state: &EthereumApplicationState,
) -> Result<LinuxGatewayCardReviewOutcome, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_gateway_review_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_gateway_review_busy")?;
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity = active_identity(&installed.runtime)?;
    let pending = installed
        .pending_gateway_card
        .lock()
        .map_err(|_| "ethereum_gateway_review_unavailable")?
        .clone();
    let Some(pending) = pending else {
        return Ok(LinuxGatewayCardReviewOutcome::NoDecision);
    };
    if pending.identity != identity
        || now_unix()? >= pending.expires_at_unix
        || Instant::now() >= pending.expires_at_monotonic
    {
        *installed
            .pending_gateway_card
            .lock()
            .map_err(|_| "ethereum_gateway_review_unavailable")? = None;
        return Ok(LinuxGatewayCardReviewOutcome::NoDecision);
    }
    state.ensure_native_identity(identity.hash, identity.session_generation)?;
    if !gateway_card_matches_active_contact(&installed.runtime, &pending.card) {
        return Err("ethereum_gateway_contact_required");
    }
    let Some(approved) = review_gateway_card_with_gtk(&pending)? else {
        return Ok(LinuxGatewayCardReviewOutcome::NoDecision);
    };
    let mut slot = installed
        .pending_gateway_card
        .lock()
        .map_err(|_| "ethereum_gateway_review_unavailable")?;
    if slot.as_ref() != Some(&pending) {
        return Err("ethereum_gateway_review_changed");
    }
    if gateway_review_remaining(
        pending.expires_at_unix,
        pending.expires_at_monotonic,
        now_unix()?,
        Instant::now(),
    )
    .is_none()
    {
        *slot = None;
        return Ok(LinuxGatewayCardReviewOutcome::NoDecision);
    }
    if !approved {
        *slot = None;
        return Ok(LinuxGatewayCardReviewOutcome::Denied);
    }
    if active_identity(&installed.runtime)? != identity {
        return Err("ethereum_profile_changed");
    }
    if !gateway_card_matches_active_contact(&installed.runtime, &pending.card) {
        return Err("ethereum_gateway_contact_required");
    }
    let expires_at_unix = pending.expires_at_unix;
    let expires_at_monotonic = pending.expires_at_monotonic;
    state.persist_gateway_source_hash(
        pending.profile_generation,
        pending.card.destination_hash(),
        now_unix()?,
        || {
            gateway_review_remaining(
                expires_at_unix,
                expires_at_monotonic,
                now_unix().unwrap_or(u64::MAX),
                Instant::now(),
            )
            .is_some()
        },
    )?;
    *slot = None;
    Ok(LinuxGatewayCardReviewOutcome::Approved)
}

fn review_gateway_card_with_gtk(
    pending: &PendingGatewayCard,
) -> Result<Option<bool>, &'static str> {
    let remaining = gateway_review_remaining(
        pending.expires_at_unix,
        pending.expires_at_monotonic,
        now_unix()?,
        Instant::now(),
    )
    .ok_or("ethereum_gateway_review_expired")?;
    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        gtk::MessageType::Warning,
        gtk::ButtonsType::None,
        "Approve Ethereum gateway peer for Sepolia routing?",
    );
    dialog.set_secondary_text(Some(&format!("This unauthenticated card identifies an Ethereum gateway peer for transport routing. Routing is non-authoritative: this peer does not prove chain state, checkpoint trust, balances, or transaction validity, and approval does not grant signing authority.\n\nLXMF destination: 0x{}\nPublic-key fingerprint: 0x{}", encode_hex(&pending.card.destination_hash()), encode_hex(&pending.card.public_key_fingerprint()))));
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    dialog.add_button("Deny gateway", gtk::ResponseType::Reject);
    dialog.add_button("Approve gateway", gtk::ResponseType::Accept);
    dialog.set_default_response(gtk::ResponseType::None);
    let timed_out = Rc::new(Cell::new(false));
    let timed_out_for_timer = Rc::clone(&timed_out);
    let dialog_for_timeout = dialog.clone();
    let timeout = gtk::glib::timeout_add_local_once(remaining, move || {
        timed_out_for_timer.set(true);
        dialog_for_timeout.response(gtk::ResponseType::Cancel);
    });
    let response = dialog.run();
    timeout.remove();
    dialog.close();
    if timed_out.get() {
        return Ok(None);
    }
    Ok(match response {
        gtk::ResponseType::Accept => Some(true),
        gtk::ResponseType::Reject => Some(false),
        _ => None,
    })
}

fn gateway_review_remaining(
    expires_at_unix: u64,
    expires_at_monotonic: Instant,
    now_unix: u64,
    now_monotonic: Instant,
) -> Option<Duration> {
    let wall = Duration::from_secs(expires_at_unix.checked_sub(now_unix)?);
    let monotonic = expires_at_monotonic.checked_duration_since(now_monotonic)?;
    let remaining = wall.min(monotonic);
    (!remaining.is_zero()).then_some(remaining)
}

fn read_manual_checkpoint_file(path: &Path) -> Result<Vec<u8>, &'static str> {
    read_manual_checkpoint_file_with(path, || {}, || {})
}

/// Bounded reader with injectable race hooks for tests.  The hooks are not
/// part of the production path; they make replacement races deterministic.
fn read_manual_checkpoint_file_with(
    path: &Path,
    before_open: impl FnOnce(),
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, &'static str> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_checkpoint_file_unavailable")?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        return Err("ethereum_checkpoint_file_insecure");
    }
    if before.len() == 0 {
        return Err("ethereum_checkpoint_file_empty");
    }
    if before.len() > ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES as u64 {
        return Err("ethereum_checkpoint_file_oversize");
    }
    before_open();

    use rustix::fs::{Mode, OFlags};
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| "ethereum_checkpoint_file_unavailable")?;
    let mut file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| "ethereum_checkpoint_file_unavailable")?;
    if !opened.file_type().is_file()
        || opened.file_type().is_symlink()
        || opened.len() == 0
        || opened.len() > ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES as u64
        || !same_unix_identity(&before, &opened)
        || opened.len() != before.len()
    {
        return Err("ethereum_checkpoint_file_changed");
    }
    after_open();
    let after_open_path =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_checkpoint_file_changed")?;
    if !same_unix_identity(&before, &after_open_path) || after_open_path.len() != before.len() {
        return Err("ethereum_checkpoint_file_changed");
    }

    // Read one byte beyond the bound so a growth race cannot be truncated
    // into an apparently valid card.  A shrink or replacement is rejected by
    // the final descriptor/path metadata checks below.
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take((ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "ethereum_checkpoint_file_unavailable")?;
    let after_read_descriptor = file
        .metadata()
        .map_err(|_| "ethereum_checkpoint_file_changed")?;
    let after_read_path =
        std::fs::symlink_metadata(path).map_err(|_| "ethereum_checkpoint_file_changed")?;
    if bytes.is_empty() {
        return Err("ethereum_checkpoint_file_empty");
    }
    if bytes.len() > ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES
        || bytes.len() as u64 != before.len()
        || after_read_descriptor.len() != before.len()
        || !same_unix_identity(&before, &after_read_descriptor)
        || !same_unix_identity(&before, &after_read_path)
        || after_read_path.len() != before.len()
    {
        return Err("ethereum_checkpoint_file_changed");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_unix_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Review one already-staged manual checkpoint candidate using a native GTK
/// dialog. Checkpoint intake belongs to a native provider adapter; this
/// operation only reviews a candidate that is already staged by policy.
#[allow(dead_code)]
pub(crate) fn review_pending_checkpoint(
    state: &EthereumApplicationState,
) -> Result<LinuxCheckpointReviewOutcome, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_checkpoint_review_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_checkpoint_review_busy")?;
    // Keep the identity lifecycle fixed through candidate selection, the
    // modal dialog, and one-shot resolution. This is the transport-only
    // profile fence; no custody or secret-store state is consulted.
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity = active_identity(&installed.runtime)?;
    state.install_transport_profile_for_identity(
        installed.profile_dir.clone(),
        identity.hash,
        identity.session_generation,
    )?;
    state.ensure_native_identity(identity.hash, identity.session_generation)?;
    let profile_dir = installed
        .profile_dir
        .canonicalize()
        .map_err(|_| "ethereum_profile_unavailable")?;

    // The policy owns staging and resolution. Only its deterministic first
    // redacted snapshot crosses into GTK, and that exact value is passed
    // unchanged back to the resolver after an explicit decision.
    let policy = CheckpointBootstrapPolicy::new(Vec::new())
        .map_err(|_| "ethereum_checkpoint_policy_unavailable")?;
    let review = {
        let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
            .map_err(|_| "ethereum_state_unavailable")?;
        policy
            .pending_manual_checkpoint_reviews(&mut store)
            .map_err(|_| "ethereum_checkpoint_review_unavailable")?
    };
    let Some(review) = review
        .into_iter()
        .take(MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION)
        .next()
    else {
        return Ok(LinuxCheckpointReviewOutcome::NoDecision);
    };
    let Some(decision) = review_checkpoint_with_gtk(&review)? else {
        // Close, cancel, and timeout deliberately do not call the resolver:
        // they leave this durable review pending for a later explicit retry.
        return Ok(LinuxCheckpointReviewOutcome::NoDecision);
    };
    let resolution = {
        // Recheck the active identity immediately before handing the exact
        // snapshot to the policy resolver. The lifecycle lock makes this a
        // stable profile/session decision, while the policy revalidates every
        // private review field transactionally.
        if active_identity(&installed.runtime)? != identity {
            return Err("ethereum_profile_changed");
        }
        state.ensure_native_identity(identity.hash, identity.session_generation)?;
        let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
            .map_err(|_| "ethereum_state_unavailable")?;
        let mut approver = GtkCheckpointApproval { decision };
        policy
            .resolve_manual_checkpoint_review(&mut store, &review, &mut approver)
            .map_err(|_| "ethereum_checkpoint_review_resolution_failed")
    }?;
    Ok(match resolution {
        ManualCheckpointReviewResolution::Approved => {
            LinuxCheckpointReviewOutcome::ResolvedApproved
        }
        ManualCheckpointReviewResolution::Denied => LinuxCheckpointReviewOutcome::ResolvedDenied,
    })
}

#[allow(dead_code)]
const MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION: usize = 1;

#[allow(dead_code)]
struct GtkCheckpointApproval {
    decision: bool,
}

impl NativeCheckpointApproval for GtkCheckpointApproval {
    type Error = ();

    fn review_and_approve(
        &mut self,
        _review: &ManualCheckpointReview<'_>,
    ) -> Result<bool, Self::Error> {
        Ok(self.decision)
    }
}

#[allow(dead_code)]
fn review_checkpoint_with_gtk(
    review: &PendingManualCheckpointReview,
) -> Result<Option<bool>, &'static str> {
    let now = now_unix()?;
    let Some(remaining_seconds) = review.expires_at_unix().checked_sub(now) else {
        return Ok(None);
    };
    if remaining_seconds == 0 {
        return Ok(None);
    }
    let dialog = gtk::Dialog::with_buttons(
        Some("Review pending Sepolia checkpoint"),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Deny checkpoint", gtk::ResponseType::Reject),
            ("Approve checkpoint trust", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_default_response(gtk::ResponseType::None);
    dialog.set_default_size(760, 620);
    dialog.set_resizable(true);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.set_border_width(16);
    let warning = gtk::Label::new(Some(
        "Checkpoint warning: a false checkpoint can make balances, history, and transaction evidence appear wrong or misleading. It cannot sign transactions or spend funds by itself. Approve only when these values match an out-of-band source that you independently trust. Gateway and LXMF observations cannot stage or approve checkpoints.",
    ));
    warning.set_line_wrap(true);
    warning.set_xalign(0.0);
    let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    buffer.set_text(&checkpoint_review_document(review));
    let view = gtk::TextView::with_buffer(&buffer);
    view.set_editable(false);
    view.set_cursor_visible(false);
    view.set_monospace(true);
    view.set_wrap_mode(gtk::WrapMode::WordChar);
    let scroll = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    scroll.set_min_content_height(390);
    scroll.add(&view);
    content.add(&warning);
    content.add(&scroll);
    dialog.content_area().add(&content);
    dialog.show_all();
    let timed_out = Rc::new(Cell::new(false));
    let timed_out_for_timer = Rc::clone(&timed_out);
    let dialog_for_timeout = dialog.clone();
    let timeout = gtk::glib::timeout_add_local_once(
        Duration::from_secs(remaining_seconds.min(CEREMONY_SECONDS)),
        move || {
            timed_out_for_timer.set(true);
            dialog_for_timeout.response(gtk::ResponseType::Cancel);
        },
    );
    let response = dialog.run();
    if !timed_out.get() {
        timeout.remove();
    }
    buffer.set_text("");
    dialog.close();
    Ok(checkpoint_review_decision(response))
}

#[allow(dead_code)]
fn checkpoint_review_decision(response: gtk::ResponseType) -> Option<bool> {
    match response {
        gtk::ResponseType::Accept => Some(true),
        gtk::ResponseType::Reject => Some(false),
        _ => None,
    }
}

#[allow(dead_code)]
fn checkpoint_source_label(source: ManualCheckpointSource) -> &'static str {
    match source {
        ManualCheckpointSource::Url => "Manual URL",
        ManualCheckpointSource::File => "Manual file",
        ManualCheckpointSource::Qr => "Manual QR",
    }
}

#[allow(dead_code)]
fn checkpoint_review_document(review: &PendingManualCheckpointReview) -> String {
    let mut document = String::with_capacity(768);
    let _ = writeln!(document, "Network: Sepolia");
    let _ = writeln!(
        document,
        "Source kind: {}",
        checkpoint_source_label(review.source())
    );
    let _ = writeln!(
        document,
        "Source fingerprint: 0x{}",
        encode_hex(&review.source_fingerprint())
    );
    let _ = writeln!(document, "Checkpoint epoch: {}", review.checkpoint_epoch());
    let _ = writeln!(
        document,
        "Checkpoint root: 0x{}",
        encode_hex(&review.checkpoint_root())
    );
    let _ = writeln!(
        document,
        "Canonical bootstrap hash: 0x{}",
        encode_hex(&review.canonical_bootstrap_hash())
    );
    let _ = writeln!(
        document,
        "Observed at (local time): {}",
        format_local_unix_time(review.observed_at_unix())
    );
    let _ = writeln!(
        document,
        "Valid until (local time): {}",
        format_local_unix_time(review.valid_until_unix())
    );
    let _ = writeln!(
        document,
        "Review expires at (local time): {}",
        format_local_unix_time(review.expires_at_unix())
    );
    let _ = writeln!(document);
    let _ = writeln!(document, "Technical details (raw Unix seconds):");
    let _ = writeln!(
        document,
        "Observed at (Unix seconds): {}",
        review.observed_at_unix()
    );
    let _ = writeln!(
        document,
        "Valid until (Unix seconds): {}",
        review.valid_until_unix()
    );
    let _ = writeln!(
        document,
        "Review expires at (Unix seconds): {}",
        review.expires_at_unix()
    );
    let _ = writeln!(document);
    let _ = writeln!(
        document,
        "Approval establishes local checkpoint trust; it does not verify your out-of-band source."
    );
    let _ = writeln!(
        document,
        "Use Approve only after independently checking the displayed values against that source."
    );
    document
}

/// Render protocol timestamps in the user's local timezone for the primary
/// review view. The raw Unix value remains in the technical-details section
/// so an operator can compare it exactly with an out-of-band source.
fn format_local_unix_time(unix_seconds: u64) -> String {
    let Ok(unix_seconds) = i64::try_from(unix_seconds) else {
        return "local time unavailable".to_string();
    };
    let Ok(date_time) = gtk::glib::DateTime::from_unix_local(unix_seconds) else {
        return "local time unavailable".to_string();
    };
    date_time
        .format("%Y-%m-%d %H:%M:%S %Z")
        .map(|formatted| formatted.to_string())
        .unwrap_or_else(|_| "local time unavailable".to_string())
}

pub(crate) fn launch_native_wallet(
    state: &EthereumApplicationState,
    request: EthereumNativeWalletLaunchRequest,
) -> Result<EthereumNativeWalletLaunchView, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_wallet_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        installed
            .status
            .store(STATUS_UNAVAILABLE, Ordering::Release);
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_wallet_busy")?;
    // Identity changes use this same lock. The GTK ceremony is synchronous on
    // the main thread, so holding it closes the switch-between-checks window.
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity = active_identity(&installed.runtime)?;
    let mut store = EthereumNodeStore::open_in_profile(&installed.profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let account = store
        .wallet_account()
        .map_err(|_| "ethereum_state_unavailable")?;
    let mut generations = generation_store(installed, identity, account.is_some())?;
    match generations
        .state()
        .map_err(|_| "linux_secret_service_unavailable")?
    {
        TrustedGenerationState::NeverInitialized | TrustedGenerationState::Current(_) => {}
        TrustedGenerationState::MissingAfterInitialization | TrustedGenerationState::Corrupt => {
            installed
                .status
                .store(STATUS_UNAVAILABLE, Ordering::Release);
            return Err("linux_wallet_protected_binding_invalid");
        }
    }
    installed.status.store(STATUS_AVAILABLE, Ordering::Release);
    let generation = account
        .map(|account| {
            state.install_profile_binding_for_identity(
                installed.profile_dir.clone(),
                account,
                identity.hash,
                identity.session_generation,
            )
        })
        .transpose()?;

    match request {
        EthereumNativeWalletLaunchRequest::ManageWallet => manage_wallet(
            state,
            installed,
            identity,
            &mut store,
            account,
            &mut generations,
        ),
        #[cfg(test)]
        EthereumNativeWalletLaunchRequest::ClearSigned(_) => {
            Err("native_ethereum_wallet_unavailable")
        }
        EthereumNativeWalletLaunchRequest::Transfer(intent) => {
            let account = account.ok_or("ethereum_wallet_unavailable")?;
            let generation = generation.ok_or("ethereum_profile_unavailable")?;
            let now = now_unix()?;
            let operation_id = state.next_operation_id(
                identity.hash,
                identity.session_generation,
                &intent,
                now,
            )?;
            let expires = now
                .checked_add(CEREMONY_SECONDS)
                .ok_or("clock_unavailable")?;
            let pending = store
                .prepare_native_transfer(
                    account,
                    intent.field_request()?,
                    operation_id,
                    now,
                    expires,
                    MAX_CURRENT_EVIDENCE_AGE_SECONDS,
                )
                .map_err(|_| "ethereum_transfer_not_preparable")?;
            drop(store);
            let result = state.with_linux_profile(
                generation,
                identity.hash,
                identity.session_generation,
                account,
                |profile_dir| {
                    sign_and_persist(
                        profile_dir,
                        installed,
                        identity,
                        account,
                        pending,
                        &mut generations,
                    )
                },
            );
            match result {
                Ok(transaction) => {
                    state.wake_outbound();
                    Ok(EthereumNativeWalletLaunchView::transfer_signed(
                        operation_id,
                        transaction.tx_hash(),
                    ))
                }
                Err(error) => {
                    if let Ok(mut store) =
                        EthereumNodeStore::open_in_profile(&installed.profile_dir)
                    {
                        let _ = store.cancel_operation(operation_id);
                    }
                    Err(error)
                }
            }
        }
    }
}

/// Review only the node-owned, durable bulk-evidence snapshots that are bound
/// to the active native profile's configured gateway. Neither snapshots nor
/// decisions enter the WebView.
pub(crate) fn review_pending_bulk_evidence(
    state: &EthereumApplicationState,
) -> Result<EthereumBulkEvidenceReviewView, &'static str> {
    let installed = INSTALLED
        .get()
        .ok_or("native_ethereum_wallet_unavailable")?;
    if !gtk::is_initialized_main_thread() {
        return Err("linux_gtk_main_thread_required");
    }
    let _ceremony = installed
        .ceremony
        .try_lock()
        .map_err(|_| "native_ethereum_wallet_busy")?;
    // GTK is synchronous. Holding the lifecycle lock prevents an identity
    // switch from changing the native review subject while a dialog is open.
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity = active_identity(&installed.runtime)?;
    state.install_transport_profile_for_identity(
        installed.profile_dir.clone(),
        identity.hash,
        identity.session_generation,
    )?;
    let binding = state
        .transport_binding()?
        .ok_or("ethereum_gateway_unavailable")?;
    if binding.ratspeak_identity_hash != identity.hash
        || binding.identity_session_generation != identity.session_generation
    {
        return Err("ethereum_profile_changed");
    }

    // The returned values are exact private review snapshots. Keep only the
    // deterministic first snapshot alive through the synchronous modal and
    // pass that same value to the node's transactional one-shot resolver.
    let page = state.with_linux_transport_binding(&binding, |profile_dir| {
        let now = now_unix()?;
        let mut store = EthereumNodeStore::open_in_profile(profile_dir)
            .map_err(|_| "ethereum_state_unavailable")?;
        store
            .pending_bulk_evidence_reviews(binding.gateway_destination_hash, now)
            .map_err(|_| "ethereum_bulk_review_unavailable")
    })?;
    let Some(review) = page
        .into_iter()
        .take(MAX_BULK_EVIDENCE_REVIEW_DIALOGS_PER_INVOCATION)
        .next()
    else {
        return Ok(EthereumBulkEvidenceReviewView::new(0, 0, 0));
    };
    let Some(decision) = review_bulk_evidence_with_gtk(&review)? else {
        // Closing, cancelling, or expiring the GTK dialog is deliberately a
        // no-decision: it cannot silently authorize or discard durable data.
        return Ok(EthereumBulkEvidenceReviewView::new(0, 0, 0));
    };
    // Recheck every runtime/native fence immediately before resolving the
    // exact snapshot. The node then compares all snapshot fields
    // transactionally, including expiry and the durable binding digest.
    let resolution = state.with_linux_transport_binding(&binding, |profile_dir| {
        if active_identity(&installed.runtime)? != identity
            || review.expected_gateway_source_hash() != binding.gateway_destination_hash
        {
            return Err("ethereum_profile_changed");
        }
        let now = now_unix()?;
        let mut store = EthereumNodeStore::open_in_profile(profile_dir)
            .map_err(|_| "ethereum_state_unavailable")?;
        store
            .resolve_bulk_evidence_review(&review, decision, now)
            .map_err(|_| "ethereum_bulk_review_resolution_failed")
    })?;
    match resolution {
        ratspeak_eth_node::BulkEvidenceReviewResolution::Approved => {
            // Approval alone may make an outbound authorization ready. No wake
            // occurs for a denial, expiry, or no-decision.
            state.wake_outbound();
            Ok(EthereumBulkEvidenceReviewView::new(1, 1, 0))
        }
        ratspeak_eth_node::BulkEvidenceReviewResolution::Denied => {
            Ok(EthereumBulkEvidenceReviewView::new(1, 0, 1))
        }
    }
}

fn review_bulk_evidence_with_gtk(
    review: &PendingBulkEvidenceReview,
) -> Result<Option<BulkEvidenceReviewDecision>, &'static str> {
    let now = now_unix()?;
    let Some(remaining_seconds) = review.expires_at_unix().checked_sub(now) else {
        return Ok(None);
    };
    if remaining_seconds == 0 {
        return Ok(None);
    }
    let dialog = gtk::Dialog::with_buttons(
        Some("Download Ethereum verification data?"),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Decline", gtk::ResponseType::Reject),
            ("Allow download", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_default_response(gtk::ResponseType::None);
    dialog.set_default_size(760, 620);
    dialog.set_resizable(true);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.set_border_width(16);
    let warning = gtk::Label::new(Some(
        "Your selected Ethereum service is ready to send the requested account or transaction verification data. Allowing the download cannot move funds. Ratspeak will still verify the data locally before showing it as trusted.",
    ));
    warning.set_line_wrap(true);
    warning.set_xalign(0.0);
    let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    buffer.set_text(&bulk_evidence_review_document(review));
    let view = gtk::TextView::with_buffer(&buffer);
    view.set_editable(false);
    view.set_cursor_visible(false);
    view.set_monospace(true);
    view.set_wrap_mode(gtk::WrapMode::WordChar);
    let scroll = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    scroll.set_min_content_height(390);
    scroll.add(&view);
    content.add(&warning);
    content.add(&scroll);
    dialog.content_area().add(&content);
    dialog.show_all();
    let timed_out = Rc::new(Cell::new(false));
    let timed_out_for_timer = Rc::clone(&timed_out);
    let dialog_for_timeout = dialog.clone();
    let timeout = gtk::glib::timeout_add_local_once(
        Duration::from_secs(remaining_seconds.min(CEREMONY_SECONDS)),
        move || {
            timed_out_for_timer.set(true);
            dialog_for_timeout.response(gtk::ResponseType::Cancel);
        },
    );
    let response = dialog.run();
    if !timed_out.get() {
        timeout.remove();
    }
    buffer.set_text("");
    dialog.close();
    Ok(bulk_evidence_review_decision(response))
}

fn bulk_evidence_review_decision(
    response: gtk::ResponseType,
) -> Option<BulkEvidenceReviewDecision> {
    match response {
        gtk::ResponseType::Accept => Some(BulkEvidenceReviewDecision::Approve),
        gtk::ResponseType::Reject => Some(BulkEvidenceReviewDecision::Deny),
        _ => None,
    }
}

fn bulk_evidence_review_document(review: &PendingBulkEvidenceReview) -> String {
    let mut document = String::with_capacity(768);
    let _ = writeln!(document, "Download size: {} bytes", review.encoded_size());
    let _ = writeln!(
        document,
        "Available until: {}",
        format_local_unix_time(review.expires_at_unix())
    );
    let _ = writeln!(document);
    let _ = writeln!(
        document,
        "Ratspeak will verify this data against your approved Sepolia checkpoint."
    );
    let _ = writeln!(
        document,
        "The service cannot sign transactions or make this data trusted by itself."
    );
    let _ = writeln!(document);
    let _ = writeln!(document, "Technical details");
    let _ = writeln!(
        document,
        "Ethereum service: 0x{}",
        encode_hex(&review.expected_gateway_source_hash())
    );
    let _ = writeln!(document, "Evidence type: {:?}", review.kind());
    let _ = writeln!(
        document,
        "Public subject: 0x{}",
        encode_hex(&review.subject())
    );
    if let Some(epoch) = review.checkpoint_epoch() {
        let _ = writeln!(document, "Checkpoint epoch: {epoch}");
    }
    if let Some(root) = review.checkpoint_root() {
        let _ = writeln!(document, "Checkpoint root: 0x{}", encode_hex(&root));
    }
    let _ = writeln!(
        document,
        "Manifest digest: 0x{}",
        encode_hex(&review.manifest_digest())
    );
    let _ = writeln!(
        document,
        "Expires at (Unix seconds): {}",
        review.expires_at_unix()
    );
    let _ = writeln!(document);
    let _ = writeln!(document, "Approval authorizes transport and storage only.");
    let _ = writeln!(
        document,
        "The evidence remains untrusted until local cryptographic verification."
    );
    let _ = writeln!(
        document,
        "Ethereum assurance is unchanged by this decision."
    );
    document
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn manage_wallet(
    state: &EthereumApplicationState,
    installed: &InstalledLinuxWalletEngine,
    identity: IdentityBinding,
    store: &mut EthereumNodeStore,
    account: Option<WalletAccount>,
    generations: &mut SecretServiceGenerationStore,
) -> Result<EthereumNativeWalletLaunchView, &'static str> {
    let wallet_dir = secure_wallet_directory(&installed.profile_dir)?;
    let vault_path = wallet_dir.join(VAULT_FILE);
    let vault_exists = std::fs::symlink_metadata(&vault_path)
        .map(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false);
    let generation_state = generations
        .state()
        .map_err(|_| "linux_secret_service_unavailable")?;
    let protected_exists = matches!(generation_state, TrustedGenerationState::Current(_));
    let dialogs =
        GtkNativeDialogBackend::new(None).map_err(|_| "linux_native_dialog_unavailable")?;
    let choice = dialogs
        .choose_wallet_management(account.is_some(), protected_exists, vault_exists)
        .map_err(|_| "linux_native_dialog_unavailable")?;
    let expires = now_unix()?
        .checked_add(CEREMONY_SECONDS)
        .ok_or("clock_unavailable")?;
    let mut guard = ProfileGuard::new(installed.runtime.clone(), identity);

    let activated = match choice {
        GtkWalletManagementChoice::Create => {
            let mut setup = GtkNativeWalletSetup::new(dialogs, guard, SystemClock, expires);
            let controller = LinuxWalletController::create_generated(
                &vault_path,
                &mut setup,
                generations,
                DEFAULT_KDF_PARAMETERS,
            )
            .map_err(|_| "linux_wallet_setup_failed")?;
            Some(authenticated_account(&controller, generations)?)
        }
        GtkWalletManagementChoice::Restore => {
            let mut setup = GtkNativeWalletSetup::new(dialogs, guard, SystemClock, expires);
            let controller = LinuxWalletController::restore(
                &vault_path,
                &mut setup,
                generations,
                DEFAULT_KDF_PARAMETERS,
            )
            .map_err(|_| "linux_wallet_restore_failed")?;
            Some(authenticated_account(&controller, generations)?)
        }
        GtkWalletManagementChoice::RevealRecovery => {
            let controller = LinuxWalletController::from_vault(
                LinuxWalletVault::at_path(&vault_path)
                    .map_err(|_| "ethereum_wallet_unavailable")?,
            );
            let mut reveal = GtkNativeRecoveryReveal::new(dialogs, guard, SystemClock, expires);
            controller
                .reveal_recovery(&mut reveal, generations)
                .map_err(|_| "linux_wallet_reveal_failed")?;
            account
        }
        GtkWalletManagementChoice::RecoverInterruptedBinding => {
            let controller = LinuxWalletController::from_vault(
                LinuxWalletVault::at_path(&vault_path)
                    .map_err(|_| "ethereum_wallet_unavailable")?,
            );
            let mut dialogs = dialogs;
            let passphrase = dialogs
                .request_unlock_passphrase(CEREMONY_SECONDS as u32)
                .map_err(|_| "linux_native_dialog_unavailable")?
                .ok_or("linux_wallet_cancelled")?;
            guard.ensure_current()?;
            Some(
                controller
                    .wallet_account(&passphrase, generations)
                    .map_err(|_| "linux_wallet_recovery_failed")?
                    .into_value(),
            )
        }
        GtkWalletManagementChoice::Cancel => return Err("linux_wallet_cancelled"),
    };
    if let Some(activated) = activated {
        store
            .install_wallet_account(activated)
            .map_err(|_| "linux_wallet_profile_mismatch")?;
        state.install_profile_binding_for_identity(
            installed.profile_dir.clone(),
            activated,
            identity.hash,
            identity.session_generation,
        )?;
    }
    Ok(EthereumNativeWalletLaunchView::wallet())
}

// Setup already authenticated the secret, but does not retain a passphrase.
// The account is read from the protected binding to initialize public state.
fn authenticated_account(
    _controller: &LinuxWalletController,
    generations: &mut SecretServiceGenerationStore,
) -> Result<WalletAccount, &'static str> {
    match generations
        .state()
        .map_err(|_| "linux_secret_service_unavailable")?
    {
        TrustedGenerationState::Current(binding) => Ok(binding.account()),
        _ => Err("linux_wallet_binding_unavailable"),
    }
}

fn sign_and_persist(
    profile_dir: &Path,
    installed: &InstalledLinuxWalletEngine,
    identity: IdentityBinding,
    account: WalletAccount,
    pending: PreparedFieldTransfer,
    generations: &mut SecretServiceGenerationStore,
) -> Result<ratspeak_eth_node::StoredSignedTransaction, &'static str> {
    let vault = LinuxWalletVault::at_path(secure_wallet_directory(profile_dir)?.join(VAULT_FILE))
        .map_err(|_| "ethereum_wallet_unavailable")?;
    let controller = LinuxWalletController::from_vault(vault);
    let dialogs =
        GtkNativeDialogBackend::new(None).map_err(|_| "linux_native_dialog_unavailable")?;
    let guard = ProfileGuard::new(installed.runtime.clone(), identity);
    let authorizer = GtkNativeTransferAuthorizer::new(dialogs, guard, SystemClock, account);
    let mut custody = LinuxPlatformCustody {
        controller: &controller,
        generations,
        authorizer: Some(authorizer),
        last_failure: None,
    };
    let mut store = EthereumNodeStore::open_in_profile(profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let mut clock = NodeClock;
    let transaction = match store.authorize_and_store(pending, &mut custody, &mut clock) {
        Ok(transaction) => transaction,
        Err(_) => {
            let failure = custody.last_failure.unwrap_or(LinuxCustodyFailure::Failed);
            tracing::warn!(
                reason = failure.code(),
                "Native Ethereum signing did not complete"
            );
            return Err(failure.code());
        }
    };
    if active_identity(&installed.runtime)? != identity {
        return Err("ethereum_profile_changed");
    }
    Ok(transaction)
}

struct LinuxPlatformCustody<'a> {
    controller: &'a LinuxWalletController,
    generations: &'a mut SecretServiceGenerationStore,
    authorizer:
        Option<GtkNativeTransferAuthorizer<GtkNativeDialogBackend, ProfileGuard, SystemClock>>,
    last_failure: Option<LinuxCustodyFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxCustodyFailure {
    Cancelled,
    PasswordInvalid,
    Expired,
    ProfileChanged,
    Failed,
}

impl LinuxCustodyFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "ethereum_transfer_cancelled",
            Self::PasswordInvalid => "ethereum_wallet_password_invalid",
            Self::Expired => "ethereum_transfer_expired",
            Self::ProfileChanged => "ethereum_profile_changed",
            Self::Failed => "ethereum_transfer_authorization_failed",
        }
    }
}

impl PlatformTransferCustody for LinuxPlatformCustody<'_> {
    type Error = LinuxCustodyFailure;
    fn authorize_and_sign(
        &mut self,
        prepared: PreparedTransfer,
    ) -> Result<SignedTransfer, Self::Error> {
        let mut authorizer = self.authorizer.take().ok_or_else(|| {
            self.last_failure = Some(LinuxCustodyFailure::Failed);
            LinuxCustodyFailure::Failed
        })?;
        let mut clock = SystemClock;
        let signed = match self.controller.authorize_and_sign(
            prepared,
            self.generations,
            &mut authorizer,
            &mut clock,
        ) {
            Ok(signed) => signed.into_value(),
            Err(error) => {
                let failure = classify_linux_signing_error(&error);
                self.last_failure = Some(failure);
                return Err(failure);
            }
        };
        let (_, mut guard, _) = authorizer.into_parts();
        if guard.ensure_current().is_err() {
            self.last_failure = Some(LinuxCustodyFailure::ProfileChanged);
            return Err(LinuxCustodyFailure::ProfileChanged);
        }
        Ok(signed)
    }
}

fn classify_linux_signing_error(
    error: &NativeControllerSignError<
        GtkAdapterError<GtkDialogError, &'static str, SystemClockError>,
        SystemClockError,
        SecretServiceStoreError,
    >,
) -> LinuxCustodyFailure {
    match error {
        NativeControllerSignError::Cancelled => LinuxCustodyFailure::Cancelled,
        NativeControllerSignError::Vault(VaultError::AuthenticationFailed) => {
            LinuxCustodyFailure::PasswordInvalid
        }
        NativeControllerSignError::Authorization(GtkAdapterError::Expired) => {
            LinuxCustodyFailure::Expired
        }
        NativeControllerSignError::Authorization(
            GtkAdapterError::ProfileChanged | GtkAdapterError::Profile(_),
        ) => LinuxCustodyFailure::ProfileChanged,
        NativeControllerSignError::Authorization(_) => LinuxCustodyFailure::Failed,
        NativeControllerSignError::Clock(_) => LinuxCustodyFailure::Expired,
        NativeControllerSignError::VaultBoundary(_) => LinuxCustodyFailure::Failed,
        NativeControllerSignError::Vault(_) | NativeControllerSignError::Wallet(_) => {
            LinuxCustodyFailure::Failed
        }
    }
}

struct NodeClock;
impl FieldNodeClock for NodeClock {
    fn now_unix(&mut self) -> u64 {
        now_unix().unwrap_or(0)
    }
}

struct ProfileGuard {
    runtime: Arc<ratspeak_tauri::state::AppState>,
    expected: IdentityBinding,
    invalidated: bool,
}

impl ProfileGuard {
    fn new(runtime: Arc<ratspeak_tauri::state::AppState>, expected: IdentityBinding) -> Self {
        Self {
            runtime,
            expected,
            invalidated: false,
        }
    }
    fn ensure_current(&mut self) -> Result<(), &'static str> {
        if self.invalidated || active_identity(&self.runtime).ok() != Some(self.expected) {
            self.invalidated = true;
            Err("ethereum_profile_changed")
        } else {
            Ok(())
        }
    }
}

impl NativeProfileSessionGuard for ProfileGuard {
    type Error = &'static str;
    fn is_current(&mut self) -> Result<bool, Self::Error> {
        Ok(self.ensure_current().is_ok())
    }
}

fn generation_store(
    installed: &InstalledLinuxWalletEngine,
    identity: IdentityBinding,
    initialized: bool,
) -> Result<SecretServiceGenerationStore, &'static str> {
    use std::os::unix::ffi::OsStrExt;
    let mut material = Vec::with_capacity(32 + installed.profile_dir.as_os_str().as_bytes().len());
    material.extend_from_slice(b"ratspeak.ethereum.linux-profile.v1");
    material.extend_from_slice(&identity.hash);
    material.extend_from_slice(installed.profile_dir.as_os_str().as_bytes());
    let key = SecretServiceProfileKey::from_bytes(keccak256(material).into())
        .map_err(|_| "linux_secret_service_unavailable")?;
    SecretServiceGenerationStore::connect(key, initialized).map_err(|_| {
        installed
            .status
            .store(STATUS_UNAVAILABLE, Ordering::Release);
        "linux_secret_service_unavailable"
    })
}

fn secure_wallet_directory(profile_dir: &Path) -> Result<PathBuf, &'static str> {
    let path = profile_dir.join(WALLET_DIRECTORY);
    match std::fs::create_dir(&path) {
        Ok(()) => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "linux_wallet_directory_unavailable")?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("linux_wallet_directory_unavailable"),
    }
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| "linux_wallet_directory_unavailable")?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("linux_wallet_directory_insecure");
    }
    Ok(path)
}

fn active_identity(
    runtime: &ratspeak_tauri::state::AppState,
) -> Result<IdentityBinding, &'static str> {
    let before = runtime.current_identity_session_generation();
    let encoded = ratspeak_tauri::helpers::active_identity_id(runtime);
    let hash = decode_identity_hash(&encoded).ok_or("ethereum_identity_unavailable")?;
    let after = runtime.current_identity_session_generation();
    if before != after {
        return Err("ethereum_profile_changed");
    }
    Ok(IdentityBinding {
        hash,
        session_generation: before,
    })
}

fn decode_identity_hash(encoded: &str) -> Option<[u8; 16]> {
    if encoded.len() != 32 || !encoded.is_ascii() {
        return None;
    }
    let mut bytes = [0; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    (bytes != [0; 16]).then_some(bytes)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn now_unix() -> Result<u64, &'static str> {
    let mut clock = SystemClock;
    clock.now_unix().map_err(|_| "clock_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_service_import_uses_native_validated_contacts_not_a_file_picker() {
        let source = include_str!("ethereum_linux.rs");
        let start = source.find("pub(crate) fn import_gateway_card(").unwrap();
        let end = source[start..].find("fn gateway_contact_choices(").unwrap();
        let section = &source[start..start + end];
        assert!(section.contains("gateway_contact_choices(&installed.runtime, identity)"));
        assert!(section.contains("pick_gateway_contact("));
        assert!(section.contains("Arc::clone(&installed.runtime)"));
        assert!(section.contains("gateway_card_from_active_contact"));
        assert!(section.contains("identity_switch_lock.lock()"));
        assert!(section.contains("native_transport_profile_binding"));
        assert!(!section.contains("FileDialog"));
        assert!(!section.contains("read_gateway_card_file"));
        assert!(!section.contains("parse_gateway_card"));
    }

    #[test]
    fn gateway_contact_chooser_keeps_card_material_native() {
        let source = include_str!("ethereum_linux.rs");
        let start = source.find("fn pick_gateway_contact(").unwrap();
        let end = source[start..].find("fn decode_hex16(").unwrap();
        let section = &source[start..start + end];
        assert!(section.contains("ListBox"));
        assert!(section.contains("choices.get(index)"));
        assert!(section.contains("destination_hash"));
        assert!(section.contains("timeout_add_local"));
        assert!(section.contains("active_identity(&runtime).ok() != Some(expected_identity)"));
        assert!(!section.contains("public_key"));
        assert!(!section.contains("identity_pubkey"));
    }

    #[test]
    fn gateway_review_expiry_uses_the_shorter_wall_and_monotonic_deadline() {
        let monotonic_now = Instant::now();
        assert_eq!(
            gateway_review_remaining(
                1_010,
                monotonic_now + Duration::from_secs(4),
                1_000,
                monotonic_now,
            ),
            Some(Duration::from_secs(4))
        );
        assert_eq!(
            gateway_review_remaining(
                1_002,
                monotonic_now + Duration::from_secs(10),
                1_000,
                monotonic_now,
            ),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn gateway_review_cannot_revive_after_dialog_expiry_or_wall_rollback() {
        let monotonic_now = Instant::now();
        let monotonic_expiry = monotonic_now + Duration::from_secs(5);
        assert_eq!(
            gateway_review_remaining(1_005, monotonic_expiry, 1_005, monotonic_now),
            None
        );
        assert_eq!(
            gateway_review_remaining(
                1_005,
                monotonic_expiry,
                900,
                monotonic_expiry + Duration::from_millis(1),
            ),
            None
        );
    }

    #[test]
    fn gateway_card_reader_is_bounded_and_rejects_aliases_and_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.rseg1");
        std::fs::write(&path, b"RSEG1:invalid").unwrap();
        let hardlink = directory.path().join("gateway-hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert_eq!(
            read_gateway_card_file(&path),
            Err("ethereum_gateway_card_insecure")
        );
        std::fs::remove_file(hardlink).unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"other-content").unwrap();
        assert_eq!(
            read_gateway_card_file_with(
                &path,
                || std::fs::rename(&replacement, &path).unwrap(),
                || {}
            ),
            Err("ethereum_gateway_card_changed")
        );
        let oversized = directory.path().join("oversized.rseg1");
        std::fs::write(
            &oversized,
            vec![b'x'; crate::ethereum::MAX_GATEWAY_CARD_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            read_gateway_card_file(&oversized),
            Err("ethereum_gateway_card_invalid")
        );
    }

    #[test]
    fn gateway_card_reader_rejects_final_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("gateway.rseg1");
        std::fs::write(&target, b"RSEG1:invalid").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_gateway_card_file(&link),
            Err("ethereum_gateway_card_insecure")
        );
    }

    #[test]
    fn bulk_evidence_review_has_a_single_dialog_bound() {
        assert_eq!(MAX_BULK_EVIDENCE_REVIEW_DIALOGS_PER_INVOCATION, 1);
    }

    #[test]
    fn bulk_evidence_close_and_timeout_are_no_decision_not_silent_denial() {
        for response in [
            gtk::ResponseType::None,
            gtk::ResponseType::Cancel,
            gtk::ResponseType::Close,
            gtk::ResponseType::DeleteEvent,
        ] {
            assert_eq!(bulk_evidence_review_decision(response), None);
        }
        assert_eq!(
            bulk_evidence_review_decision(gtk::ResponseType::Reject),
            Some(BulkEvidenceReviewDecision::Deny)
        );
        assert_eq!(
            bulk_evidence_review_decision(gtk::ResponseType::Accept),
            Some(BulkEvidenceReviewDecision::Approve)
        );
    }

    #[test]
    fn bulk_evidence_gtk_thread_failure_does_not_change_wallet_status() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn review_pending_bulk_evidence(")
            .unwrap();
        let end = source[start..]
            .find("fn review_bulk_evidence_with_gtk(")
            .unwrap();
        assert!(!source[start..start + end].contains("status.store"));
    }

    #[test]
    fn checkpoint_close_timeout_and_unknown_responses_are_no_decision() {
        for response in [
            gtk::ResponseType::None,
            gtk::ResponseType::Cancel,
            gtk::ResponseType::Close,
            gtk::ResponseType::DeleteEvent,
        ] {
            assert_eq!(checkpoint_review_decision(response), None);
        }
        assert_eq!(
            checkpoint_review_decision(gtk::ResponseType::Reject),
            Some(false)
        );
        assert_eq!(
            checkpoint_review_decision(gtk::ResponseType::Accept),
            Some(true)
        );
    }

    #[test]
    fn checkpoint_review_has_one_dialog_bound_and_first_candidate_selection() {
        assert_eq!(MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION, 1);
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn review_pending_checkpoint(")
            .unwrap();
        let end = source[start..]
            .find("const MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION")
            .unwrap();
        let section = &source[start..start + end];
        assert!(section.contains(".take(MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION)"));
        assert!(section.contains("review_checkpoint_with_gtk(&review)"));
        assert!(section.contains("resolve_manual_checkpoint_review(&mut store, &review"));
    }

    #[test]
    fn checkpoint_review_is_transport_only_and_never_logs_or_uses_lxmf() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn review_pending_checkpoint(")
            .unwrap();
        let end = source[start..]
            .find("const MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION")
            .unwrap();
        let section = &source[start..start + end];
        assert!(!section.contains("SecretService"));
        assert!(!section.contains("wallet"));
        assert!(!section.contains("wallet_account"));
        assert!(!section.contains("LinuxWallet"));
        assert!(!section.contains("lxmf"));
        assert!(!section.contains("transport_binding"));
        assert!(!section.contains("stage_manual_candidate"));
        assert!(!section.contains("tracing::"));
        assert!(!section.contains("println!"));
        assert!(!section.contains("eprintln!"));
    }

    #[test]
    fn checkpoint_review_passes_exact_private_snapshot_to_policy() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn review_pending_checkpoint(")
            .unwrap();
        let end = source[start..]
            .find("const MAX_MANUAL_CHECKPOINT_REVIEW_DIALOGS_PER_INVOCATION")
            .unwrap();
        let section = &source[start..start + end];
        assert!(!section.contains("PendingManualCheckpointReview {"));
        assert!(section.contains("let Some(review) = review"));
        assert!(section.contains("&review, &mut approver"));
    }

    #[test]
    fn checkpoint_dialog_document_names_all_trust_fields() {
        let source = include_str!("ethereum_linux.rs");
        let start = source.find("fn checkpoint_review_document(").unwrap();
        let end = source[start..].find("fn manage_wallet(").unwrap();
        let section = &source[start..start + end];
        for label in [
            "Network: Sepolia",
            "Source kind:",
            "Source fingerprint:",
            "Checkpoint epoch:",
            "Checkpoint root:",
            "Canonical bootstrap hash:",
            "Observed at (local time):",
            "Valid until (local time):",
            "Review expires at (local time):",
            "Technical details (raw Unix seconds):",
            "Observed at (Unix seconds):",
            "Valid until (Unix seconds):",
            "Review expires at (Unix seconds):",
            "out-of-band source",
        ] {
            assert!(
                section.contains(label),
                "missing checkpoint dialog label: {label}"
            );
        }
    }

    #[test]
    fn checkpoint_dialog_explains_false_checkpoint_scope_and_gateway_non_authority() {
        let source = include_str!("ethereum_linux.rs");
        assert!(source.contains("false checkpoint can make balances, history, and transaction evidence appear wrong or misleading"));
        assert!(source.contains("It cannot sign transactions or spend funds by itself"));
        assert!(source.contains("Ethereum gateway peer for transport routing"));
        assert!(source.contains("Routing is non-authoritative"));
    }

    #[test]
    fn local_checkpoint_time_formatter_has_safe_fallback() {
        let formatted = format_local_unix_time(0);
        assert_ne!(formatted, "local time unavailable");
        assert!(formatted.len() >= 19);
        let bytes = formatted.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b' ');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        assert_eq!(format_local_unix_time(u64::MAX), "local time unavailable");
    }

    #[test]
    fn checkpoint_file_reader_rejects_empty_directory_and_oversize_inputs() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            read_manual_checkpoint_file(directory.path()),
            Err("ethereum_checkpoint_file_insecure")
        );

        let empty = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        assert_eq!(
            read_manual_checkpoint_file(empty.path()),
            Err("ethereum_checkpoint_file_empty")
        );

        let oversized = directory.path().join("oversized.rsethcf");
        std::fs::write(
            &oversized,
            vec![0u8; ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            read_manual_checkpoint_file(&oversized),
            Err("ethereum_checkpoint_file_oversize")
        );
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_file_reader_rejects_final_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("checkpoint.rsethcf");
        std::fs::write(&target, b"untrusted").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_manual_checkpoint_file(&link),
            Err("ethereum_checkpoint_file_insecure")
        );
    }

    #[test]
    fn checkpoint_file_reader_rejects_replacement_before_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("checkpoint.rsethcf");
        let replacement = directory.path().join("replacement");
        std::fs::write(&path, b"original").unwrap();
        std::fs::write(&replacement, b"replacement").unwrap();
        let result = read_manual_checkpoint_file_with(
            &path,
            || std::fs::rename(&replacement, &path).unwrap(),
            || {},
        );
        assert_eq!(result, Err("ethereum_checkpoint_file_changed"));
    }

    #[test]
    fn checkpoint_file_reader_rejects_replacement_after_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("checkpoint.rsethcf");
        let replacement = directory.path().join("replacement");
        std::fs::write(&path, b"original").unwrap();
        std::fs::write(&replacement, b"original").unwrap();
        let result = read_manual_checkpoint_file_with(
            &path,
            || {},
            || std::fs::rename(&replacement, &path).unwrap(),
        );
        assert_eq!(result, Err("ethereum_checkpoint_file_changed"));
    }

    #[test]
    fn checkpoint_file_import_cancellation_precedes_any_read_or_stage() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn import_manual_checkpoint_file(")
            .unwrap();
        let end = source[start..]
            .find("fn pick_manual_checkpoint_file()")
            .unwrap();
        let section = &source[start..start + end];
        let cancelled = section
            .find("LinuxCheckpointFileImportOutcome::Cancelled")
            .unwrap();
        let read = section.find("read_manual_checkpoint_file(&path)").unwrap();
        let stage = section.find("stage_manual_checkpoint_file").unwrap();
        assert!(cancelled < read && cancelled < stage);
        assert!(section.contains("pick_manual_checkpoint_file()?"));
    }

    #[test]
    fn checkpoint_file_import_does_not_hold_identity_lock_during_picker_or_read() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn import_manual_checkpoint_file(")
            .unwrap();
        let end = source[start..]
            .find("fn pick_manual_checkpoint_file()")
            .unwrap();
        let section = &source[start..start + end];
        let picker = section.find("pick_manual_checkpoint_file()?").unwrap();
        let read = section.find("read_manual_checkpoint_file(&path)").unwrap();
        let lock = section
            .find("identity_switch_lock.lock()")
            .expect("lifecycle lock must fence staging");
        let recheck = section
            .find("if active_identity(&installed.runtime)? != identity")
            .expect("identity must be rechecked after picker/read");
        assert!(picker < read && read < lock && lock < recheck);
    }

    #[test]
    fn checkpoint_file_import_has_no_wallet_gateway_lxmf_or_webview_authority() {
        let source = include_str!("ethereum_linux.rs");
        let start = source
            .find("pub(crate) fn import_manual_checkpoint_file(")
            .unwrap();
        let end = source[start..]
            .find("fn pick_manual_checkpoint_file()")
            .unwrap();
        let section = &source[start..start + end];
        for forbidden in [
            "wallet_account",
            "LinuxWallet",
            "transport_binding",
            "gateway_destination",
            "lxmf",
            "CheckpointCandidate {",
            "checkpoint_root:",
            "checkpoint_epoch:",
        ] {
            assert!(
                !section.contains(forbidden),
                "unexpected authority: {forbidden}"
            );
        }
        assert!(section.contains("stage_manual_checkpoint_file(&mut store, &bytes)"));
    }
}
