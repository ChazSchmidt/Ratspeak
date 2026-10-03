//! GTK3-native custody ceremonies.
//!
//! This module contains no Tauri command or serializable request type. The
//! application must invoke it from trusted native code on GTK's main thread.
//! Owned Rust copies are zeroized and widgets are cleared before dismissal;
//! GTK's internal allocations do not provide a complete zeroization guarantee.

use std::{
    cell::Cell,
    fmt::Write as _,
    rc::Rc,
    time::{Duration, Instant},
};

use gtk::prelude::*;
use ratspeak_eth_wallet::{SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, TransferReview, WalletAccount};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    NativeRecoveryReveal, NativeTransferAuthorization, NativeTransferDecision, NativeWalletSetup,
    RecoveryPhraseInput, RecoveryPhraseView, TrustedClock, VaultPassphrase,
};

/// A GTK adapter is compiled into the Linux custody crate.
pub const LINUX_GTK_DIALOG_ADAPTER_INCLUDED: bool = true;
/// This crate deliberately does not pretend its ordinary filesystem state is
/// an independent rollback-resistant generation counter.
pub const LINUX_PRODUCTION_TRUSTED_COUNTER_INCLUDED: bool = true;
/// No individual native custody prompt remains open longer than five minutes.
pub const MAX_NATIVE_DIALOG_SECONDS: u32 = 5 * 60;
/// Recovery words auto-close even when the caller supplies a longer operation
/// deadline. Shorter trusted deadlines take precedence.
pub const MAX_RECOVERY_REVEAL_SECONDS: u32 = 60;

/// Release availability remains explicit until native application wiring and
/// an independently protected generation-counter backend are both installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxNativeCustodyAvailability {
    UnsupportedPlatform,
    NativeApplicationWiringRequired,
    TrustedGenerationBackendRequired,
    Available,
}

pub const fn linux_native_custody_availability(
    native_application_wired: bool,
    production_counter_installed: bool,
) -> LinuxNativeCustodyAvailability {
    if !cfg!(target_os = "linux") {
        LinuxNativeCustodyAvailability::UnsupportedPlatform
    } else if !native_application_wired {
        LinuxNativeCustodyAvailability::NativeApplicationWiringRequired
    } else if !production_counter_installed {
        LinuxNativeCustodyAvailability::TrustedGenerationBackendRequired
    } else {
        LinuxNativeCustodyAvailability::Available
    }
}

/// Trusted native profile fence captured when an operation starts.
///
/// Implementations compare against application-owned profile state. They must
/// not derive currentness from WebView input or from the vault being opened.
/// Production integration must hold the same native profile-switch lock for
/// the complete controller call; polling this trait alone cannot close the
/// race between a successful check and a profile replacement.
pub trait NativeProfileSessionGuard {
    type Error;

    fn is_current(&mut self) -> std::result::Result<bool, Self::Error>;
}

/// Secret-capable native dialog backend. Implementations must not log, retain,
/// serialize, or send any supplied or returned secret through IPC.
pub trait NativeCustodyDialogs {
    type Error;

    fn request_new_passphrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<VaultPassphrase>, Self::Error>;

    fn confirm_recovery_backup(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
        max_visible_seconds: u32,
    ) -> std::result::Result<bool, Self::Error>;

    fn request_recovery_phrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<RecoveryPhraseInput>, Self::Error>;

    fn review_transfer_and_request_passphrase(
        &mut self,
        review: &TransferReview,
        max_visible_seconds: u32,
    ) -> std::result::Result<NativeTransferDecision, Self::Error>;

    fn request_unlock_passphrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<VaultPassphrase>, Self::Error>;

    fn show_recovery_phrase(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
        max_visible_seconds: u32,
    ) -> std::result::Result<(), Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum GtkAdapterError<D, P, C> {
    #[error("native custody dialog failed")]
    Dialog(D),
    #[error("active profile check failed")]
    Profile(P),
    #[error("trusted clock failed")]
    Clock(C),
    #[error("active profile changed during native custody operation")]
    ProfileChanged,
    #[error("native custody operation expired")]
    Expired,
    #[error("native custody operation was already consumed")]
    Replay,
    #[error("transfer review does not match the active Sepolia wallet")]
    ReviewMismatch,
}

type AdapterResult<T, D, P, C> = Result<T, GtkAdapterError<D, P, C>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupPhase {
    Fresh,
    AwaitingBackup,
    AwaitingPassphrase,
    Finished,
}

/// One native create or restore ceremony fenced to one active profile and a
/// trusted-clock deadline.
pub struct GtkNativeWalletSetup<D, P, C> {
    dialogs: D,
    profile: P,
    clock: C,
    expires_at_unix: u64,
    phase: SetupPhase,
}

impl<D, P, C> GtkNativeWalletSetup<D, P, C> {
    pub const fn new(dialogs: D, profile: P, clock: C, expires_at_unix: u64) -> Self {
        Self {
            dialogs,
            profile,
            clock,
            expires_at_unix,
            phase: SetupPhase::Fresh,
        }
    }

    pub fn into_parts(self) -> (D, P, C) {
        (self.dialogs, self.profile, self.clock)
    }
}

impl<D, P, C> GtkNativeWalletSetup<D, P, C>
where
    D: NativeCustodyDialogs,
    P: NativeProfileSessionGuard,
    C: TrustedClock,
{
    fn validate_fence(&mut self) -> AdapterResult<u64, D::Error, P::Error, C::Error> {
        let now = self.clock.now_unix().map_err(GtkAdapterError::Clock)?;
        if now >= self.expires_at_unix {
            return Err(GtkAdapterError::Expired);
        }
        if !self
            .profile
            .is_current()
            .map_err(GtkAdapterError::Profile)?
        {
            return Err(GtkAdapterError::ProfileChanged);
        }
        Ok(now)
    }

    fn remaining_seconds(&mut self) -> AdapterResult<u32, D::Error, P::Error, C::Error> {
        let now = self.validate_fence()?;
        remaining_seconds(now, self.expires_at_unix, MAX_NATIVE_DIALOG_SECONDS)
            .ok_or(GtkAdapterError::Expired)
    }

    fn fail_closed<T>(
        &mut self,
        result: AdapterResult<T, D::Error, P::Error, C::Error>,
    ) -> AdapterResult<T, D::Error, P::Error, C::Error> {
        if result.is_err() {
            self.phase = SetupPhase::Finished;
        }
        result
    }
}

impl<D, P, C> NativeWalletSetup for GtkNativeWalletSetup<D, P, C>
where
    D: NativeCustodyDialogs,
    P: NativeProfileSessionGuard,
    C: TrustedClock,
{
    type Error = GtkAdapterError<D::Error, P::Error, C::Error>;

    fn request_new_passphrase(
        &mut self,
    ) -> std::result::Result<Option<VaultPassphrase>, Self::Error> {
        let next = match self.phase {
            SetupPhase::Fresh => SetupPhase::AwaitingBackup,
            SetupPhase::AwaitingPassphrase => SetupPhase::Finished,
            _ => return Err(GtkAdapterError::Replay),
        };
        self.phase = next;
        let result = (|| {
            let remaining = self.remaining_seconds()?;
            let passphrase = self
                .dialogs
                .request_new_passphrase(remaining)
                .map_err(GtkAdapterError::Dialog)?;
            self.validate_fence()?;
            Ok(passphrase)
        })();
        if result.as_ref().is_ok_and(Option::is_none) {
            self.phase = SetupPhase::Finished;
        }
        self.fail_closed(result)
    }

    fn confirm_recovery_backup(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
    ) -> std::result::Result<bool, Self::Error> {
        if self.phase != SetupPhase::AwaitingBackup {
            return Err(GtkAdapterError::Replay);
        }
        self.phase = SetupPhase::Finished;
        let result = (|| {
            let remaining = self.remaining_seconds()?;
            let confirmed = self
                .dialogs
                .confirm_recovery_backup(recovery, remaining)
                .map_err(GtkAdapterError::Dialog)?;
            self.validate_fence()?;
            Ok(confirmed)
        })();
        self.fail_closed(result)
    }

    fn request_recovery_phrase(
        &mut self,
    ) -> std::result::Result<Option<RecoveryPhraseInput>, Self::Error> {
        if self.phase != SetupPhase::Fresh {
            return Err(GtkAdapterError::Replay);
        }
        self.phase = SetupPhase::AwaitingPassphrase;
        let result = (|| {
            let remaining = self.remaining_seconds()?;
            let phrase = self
                .dialogs
                .request_recovery_phrase(remaining)
                .map_err(GtkAdapterError::Dialog)?;
            self.validate_fence()?;
            Ok(phrase)
        })();
        if result.as_ref().is_ok_and(Option::is_none) {
            self.phase = SetupPhase::Finished;
        }
        self.fail_closed(result)
    }
}

/// One-shot exact-transfer review fenced to the selected public account and
/// active profile. The prepared transfer itself remains in trusted Rust code.
pub struct GtkNativeTransferAuthorizer<D, P, C> {
    dialogs: D,
    profile: P,
    clock: C,
    expected_account: WalletAccount,
    consumed: bool,
}

impl<D, P, C> GtkNativeTransferAuthorizer<D, P, C> {
    pub const fn new(dialogs: D, profile: P, clock: C, expected_account: WalletAccount) -> Self {
        Self {
            dialogs,
            profile,
            clock,
            expected_account,
            consumed: false,
        }
    }

    pub fn into_parts(self) -> (D, P, C) {
        (self.dialogs, self.profile, self.clock)
    }
}

impl<D, P, C> NativeTransferAuthorization for GtkNativeTransferAuthorizer<D, P, C>
where
    D: NativeCustodyDialogs,
    P: NativeProfileSessionGuard,
    C: TrustedClock,
{
    type Error = GtkAdapterError<D::Error, P::Error, C::Error>;

    fn review_and_request_passphrase(
        &mut self,
        review: &TransferReview,
    ) -> std::result::Result<NativeTransferDecision, Self::Error> {
        if self.consumed {
            return Err(GtkAdapterError::Replay);
        }
        self.consumed = true;
        if review.chain_id() != SEPOLIA_CHAIN_ID
            || review.network() != SEPOLIA_NETWORK
            || review.from() != self.expected_account.address()
            || self.expected_account.chain_id() != SEPOLIA_CHAIN_ID
        {
            return Err(GtkAdapterError::ReviewMismatch);
        }
        let now = validate_session(&mut self.profile, &mut self.clock, review.expires_at_unix())?;
        let remaining = remaining_seconds(now, review.expires_at_unix(), MAX_NATIVE_DIALOG_SECONDS)
            .ok_or(GtkAdapterError::Expired)?;
        let decision = self
            .dialogs
            .review_transfer_and_request_passphrase(review, remaining)
            .map_err(GtkAdapterError::Dialog)?;
        validate_session(&mut self.profile, &mut self.clock, review.expires_at_unix())?;
        Ok(decision)
    }
}

/// One-shot native recovery reveal. The controller authenticates the vault and
/// invokes this adapter with a callback-scoped recovery phrase.
pub struct GtkNativeRecoveryReveal<D, P, C> {
    dialogs: D,
    profile: P,
    clock: C,
    expires_at_unix: u64,
    phase: RevealPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RevealPhase {
    Fresh,
    PassphraseGranted,
    Finished,
}

impl<D, P, C> GtkNativeRecoveryReveal<D, P, C> {
    pub const fn new(dialogs: D, profile: P, clock: C, expires_at_unix: u64) -> Self {
        Self {
            dialogs,
            profile,
            clock,
            expires_at_unix,
            phase: RevealPhase::Fresh,
        }
    }

    pub fn into_parts(self) -> (D, P, C) {
        (self.dialogs, self.profile, self.clock)
    }
}

impl<D, P, C> NativeRecoveryReveal for GtkNativeRecoveryReveal<D, P, C>
where
    D: NativeCustodyDialogs,
    P: NativeProfileSessionGuard,
    C: TrustedClock,
{
    type Error = GtkAdapterError<D::Error, P::Error, C::Error>;

    fn request_passphrase(&mut self) -> std::result::Result<Option<VaultPassphrase>, Self::Error> {
        if self.phase != RevealPhase::Fresh {
            return Err(GtkAdapterError::Replay);
        }
        self.phase = RevealPhase::Finished;
        let now = validate_session(&mut self.profile, &mut self.clock, self.expires_at_unix)?;
        let remaining = remaining_seconds(now, self.expires_at_unix, MAX_RECOVERY_REVEAL_SECONDS)
            .ok_or(GtkAdapterError::Expired)?;
        let passphrase = self
            .dialogs
            .request_unlock_passphrase(remaining)
            .map_err(GtkAdapterError::Dialog)?;
        validate_session(&mut self.profile, &mut self.clock, self.expires_at_unix)?;
        if passphrase.is_some() {
            self.phase = RevealPhase::PassphraseGranted;
        }
        Ok(passphrase)
    }

    fn show_recovery_phrase(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
    ) -> std::result::Result<(), Self::Error> {
        if self.phase != RevealPhase::PassphraseGranted {
            return Err(GtkAdapterError::Replay);
        }
        self.phase = RevealPhase::Finished;
        let now = validate_session(&mut self.profile, &mut self.clock, self.expires_at_unix)?;
        let max_visible_seconds =
            remaining_seconds(now, self.expires_at_unix, MAX_RECOVERY_REVEAL_SECONDS)
                .ok_or(GtkAdapterError::Expired)?;
        self.dialogs
            .show_recovery_phrase(recovery, max_visible_seconds)
            .map_err(GtkAdapterError::Dialog)?;
        validate_session(&mut self.profile, &mut self.clock, self.expires_at_unix).map(|_| ())
    }
}

fn validate_session<P, C, D>(
    profile: &mut P,
    clock: &mut C,
    expires_at_unix: u64,
) -> Result<u64, GtkAdapterError<D, P::Error, C::Error>>
where
    P: NativeProfileSessionGuard,
    C: TrustedClock,
{
    let now = clock.now_unix().map_err(GtkAdapterError::Clock)?;
    if now >= expires_at_unix {
        return Err(GtkAdapterError::Expired);
    }
    if !profile.is_current().map_err(GtkAdapterError::Profile)? {
        return Err(GtkAdapterError::ProfileChanged);
    }
    Ok(now)
}

fn remaining_seconds(now: u64, expires_at_unix: u64, cap: u32) -> Option<u32> {
    let remaining = expires_at_unix.checked_sub(now)?;
    let remaining = remaining.min(u64::from(cap));
    u32::try_from(remaining).ok().filter(|seconds| *seconds > 0)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GtkDialogError {
    #[error("GTK must already be initialized on the main thread")]
    NotOnGtkMainThread,
    #[error("native secret input is invalid")]
    InvalidSecretInput,
    #[error("wallet password confirmation did not match")]
    PassphraseMismatch,
    #[error("native custody dialog lifetime must be at least one second")]
    InvalidDialogLifetime,
}

/// Concrete GTK3 dialog backend. It requires the application's existing GTK
/// main loop and never initializes a second runtime.
pub struct GtkNativeDialogBackend {
    parent: Option<gtk::Window>,
    /// Set only for the restore ceremony, so the following passphrase prompt
    /// can make the accepted recovery-phrase step visible to the user.
    recovery_phrase_entered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GtkWalletManagementChoice {
    Create,
    Restore,
    RevealRecovery,
    RecoverInterruptedBinding,
    Cancel,
}

impl GtkNativeDialogBackend {
    pub fn new(parent: Option<&gtk::Window>) -> Result<Self, GtkDialogError> {
        if !gtk::is_initialized_main_thread() {
            return Err(GtkDialogError::NotOnGtkMainThread);
        }
        Ok(Self {
            parent: parent.cloned(),
            recovery_phrase_entered: false,
        })
    }

    /// Chooses a native-only custody ceremony. The WebView cannot select a
    /// secret-bearing operation or receive its result.
    pub fn choose_wallet_management(
        &self,
        wallet_profile_exists: bool,
        protected_binding_exists: bool,
        vault_exists: bool,
    ) -> Result<GtkWalletManagementChoice, GtkDialogError> {
        // The management prompt has no affirmative action of its own.  Using
        // the normal dialog helper here used to add both its Cancel button and
        // an Accept button also labelled "Cancel", leaving two indistinguishable
        // controls in the native restore prompt.
        let management_buttons = management_dialog_buttons();
        let fresh_setup = !wallet_profile_exists && !protected_binding_exists && !vault_exists;
        let (dialog_title, explanation_text) = wallet_management_copy(
            wallet_profile_exists,
            protected_binding_exists,
            vault_exists,
        );
        let dialog = self.dialog_with_buttons(dialog_title, &management_buttons)?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let explanation = gtk::Label::new(Some(explanation_text));
        explanation.set_line_wrap(true);
        explanation.set_xalign(0.0);
        content.add(&explanation);
        dialog.content_area().add(&content);
        if wallet_profile_exists && protected_binding_exists && vault_exists {
            dialog.add_button("Reveal Secret Recovery Phrase", gtk::ResponseType::Other(1));
        } else if !wallet_profile_exists && protected_binding_exists && vault_exists {
            dialog.add_button(
                "Recover interrupted profile binding",
                gtk::ResponseType::Other(2),
            );
        } else if fresh_setup {
            dialog.add_button("Create wallet", gtk::ResponseType::Other(3));
            dialog.add_button("Import wallet", gtk::ResponseType::Other(4));
        }
        dialog.show_all();
        let response = run_dialog_with_timeout(&dialog, MAX_NATIVE_DIALOG_SECONDS)?;
        dismiss_dialog(&dialog);
        Ok(match response {
            gtk::ResponseType::Other(1) => GtkWalletManagementChoice::RevealRecovery,
            gtk::ResponseType::Other(2) => GtkWalletManagementChoice::RecoverInterruptedBinding,
            gtk::ResponseType::Other(3) => GtkWalletManagementChoice::Create,
            gtk::ResponseType::Other(4) => GtkWalletManagementChoice::Restore,
            _ => GtkWalletManagementChoice::Cancel,
        })
    }

    fn dialog(&self, title: &str, accept_label: &str) -> Result<gtk::Dialog, GtkDialogError> {
        self.dialog_with_buttons(
            title,
            &[
                ("Cancel", gtk::ResponseType::Cancel),
                (accept_label, gtk::ResponseType::Accept),
            ],
        )
    }

    fn dialog_with_buttons(
        &self,
        title: &str,
        buttons: &[(&str, gtk::ResponseType)],
    ) -> Result<gtk::Dialog, GtkDialogError> {
        if !gtk::is_initialized_main_thread() {
            return Err(GtkDialogError::NotOnGtkMainThread);
        }
        let dialog = gtk::Dialog::with_buttons(
            Some(title),
            self.parent.as_ref(),
            gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
            buttons,
        );
        dialog.set_resizable(false);
        dialog.set_default_response(gtk::ResponseType::None);
        Ok(dialog)
    }
}

impl NativeCustodyDialogs for GtkNativeDialogBackend {
    type Error = GtkDialogError;

    fn request_new_passphrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<VaultPassphrase>, Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_NATIVE_DIALOG_SECONDS)?;
        let recovery_phrase_entered = self.recovery_phrase_entered;
        self.recovery_phrase_entered = false;
        let (title, explanation_text) = passphrase_prompt(recovery_phrase_entered);
        let dialog = self.dialog(title, "Continue")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let explanation = gtk::Label::new(Some(explanation_text));
        explanation.set_line_wrap(true);
        explanation.set_xalign(0.0);
        let first = secret_entry("Create wallet password");
        let confirmation = secret_entry("Confirm wallet password");
        let mismatch_hint = gtk::Label::new(Some("Wallet passwords do not match yet."));
        mismatch_hint.set_line_wrap(true);
        mismatch_hint.set_xalign(0.0);
        mismatch_hint.set_no_show_all(true);
        mismatch_hint.set_visible(false);
        content.add(&explanation);
        content.add(&first);
        content.add(&confirmation);
        content.add(&mismatch_hint);
        dialog.content_area().add(&content);

        // Do not let an incomplete or mismatched pair reach the backend. The
        // callbacks retain only weak GTK references, so the entries and their
        // secret-bearing buffers can be released with the dialog.
        let accept_button = dialog
            .widget_for_response(gtk::ResponseType::Accept)
            .expect("passphrase dialog must have an accept button")
            .downcast::<gtk::Button>()
            .expect("passphrase dialog accept response must be a button");
        wire_passphrase_validation(&first, &confirmation, &accept_button, &mismatch_hint);
        dialog.show_all();
        let accepted =
            run_dialog_with_timeout(&dialog, max_visible_seconds)? == gtk::ResponseType::Accept;
        let mut first_value = Zeroizing::new(first.text().to_string());
        let mut confirmation_value = Zeroizing::new(confirmation.text().to_string());
        first.set_text("");
        confirmation.set_text("");
        dismiss_dialog(&dialog);
        if !accepted {
            return Ok(None);
        }
        if first_value.as_str() != confirmation_value.as_str() {
            return Err(GtkDialogError::PassphraseMismatch);
        }
        confirmation_value.zeroize();
        let owned = std::mem::take(&mut *first_value);
        VaultPassphrase::new(owned)
            .map(Some)
            .map_err(|_| GtkDialogError::InvalidSecretInput)
    }

    fn confirm_recovery_backup(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
        max_visible_seconds: u32,
    ) -> std::result::Result<bool, Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_RECOVERY_REVEAL_SECONDS)?;
        let started = Instant::now();
        let reveal = self.dialog("Back up Ethereum Secret Recovery Phrase", "I wrote it down")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let warning = gtk::Label::new(Some(
            "Write this Secret Recovery Phrase down in order and keep it offline. Anyone with it controls this wallet.",
        ));
        warning.set_line_wrap(true);
        warning.set_xalign(0.0);
        let words = gtk::Label::new(Some(recovery.words()));
        words.set_line_wrap(true);
        words.set_selectable(false);
        words.set_xalign(0.0);
        content.add(&warning);
        content.add(&words);
        reveal.content_area().add(&content);
        reveal.show_all();
        let acknowledged = run_dialog_for_remaining(
            &reveal,
            started,
            Duration::from_secs(u64::from(max_visible_seconds)),
        )? == gtk::ResponseType::Accept;
        words.set_text("");
        dismiss_dialog(&reveal);
        if !acknowledged {
            return Ok(false);
        }

        let confirm = self.dialog("Confirm Ethereum recovery backup", "Confirm backup")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let prompt = gtk::Label::new(Some(
            "Enter the complete Secret Recovery Phrase to confirm your written backup.",
        ));
        prompt.set_line_wrap(true);
        prompt.set_xalign(0.0);
        let entry = recovery_entry();
        content.add(&prompt);
        content.add(&entry);
        confirm.content_area().add(&content);
        confirm.show_all();
        let accepted = run_dialog_for_remaining(
            &confirm,
            started,
            Duration::from_secs(u64::from(max_visible_seconds)),
        )? == gtk::ResponseType::Accept;
        let mut entered = Zeroizing::new(entry.text().to_string());
        entry.set_text("");
        dismiss_dialog(&confirm);
        let matches = accepted && entered.as_str().trim() == recovery.words();
        entered.zeroize();
        Ok(matches)
    }

    fn request_recovery_phrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<RecoveryPhraseInput>, Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_RECOVERY_REVEAL_SECONDS)?;
        let dialog = self.dialog("Restore Ethereum wallet", "Restore")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let warning = gtk::Label::new(Some(
            "Enter a standard English BIP-39 Secret Recovery Phrase. It remains in this native dialog and is not sent to the WebView.",
        ));
        warning.set_line_wrap(true);
        warning.set_xalign(0.0);
        let entry = recovery_entry();
        entry.set_visibility(false);
        let show = gtk::CheckButton::with_label("Show Secret Recovery Phrase");
        let entry_for_toggle = entry.clone();
        show.connect_toggled(move |toggle| entry_for_toggle.set_visibility(toggle.is_active()));
        content.add(&warning);
        content.add(&entry);
        content.add(&show);
        dialog.content_area().add(&content);
        dialog.show_all();
        let accepted =
            run_dialog_with_timeout(&dialog, max_visible_seconds)? == gtk::ResponseType::Accept;
        let mut phrase = Zeroizing::new(entry.text().to_string());
        entry.set_text("");
        dismiss_dialog(&dialog);
        if !accepted {
            return Ok(None);
        }
        if phrase.is_empty() || phrase.len() > ratspeak_eth_wallet::MAX_RECOVERY_PHRASE_BYTES {
            return Err(GtkDialogError::InvalidSecretInput);
        }
        self.recovery_phrase_entered = true;
        let owned = std::mem::take(&mut *phrase);
        Ok(Some(RecoveryPhraseInput::new(owned)))
    }

    fn review_transfer_and_request_passphrase(
        &mut self,
        review: &TransferReview,
        max_visible_seconds: u32,
    ) -> std::result::Result<NativeTransferDecision, Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_NATIVE_DIALOG_SECONDS)?;
        let dialog = self.dialog("Review Sepolia transfer", "Sign exact transfer")?;
        dialog.set_default_size(680, 600);
        dialog.set_resizable(true);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let warning = gtk::Label::new(Some(
            "Experimental Sepolia only. Verify every field below. Network delivery or an RPC acknowledgement is not transaction confirmation.",
        ));
        warning.set_line_wrap(true);
        warning.set_xalign(0.0);
        let document = transfer_review_document(review);
        let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        buffer.set_text(&document);
        let view = gtk::TextView::with_buffer(&buffer);
        view.set_editable(false);
        view.set_cursor_visible(false);
        view.set_monospace(true);
        view.set_wrap_mode(gtk::WrapMode::WordChar);
        let scroll = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        scroll.set_min_content_height(390);
        scroll.add(&view);
        let passphrase = secret_entry("Wallet password");
        content.add(&warning);
        content.add(&scroll);
        content.add(&passphrase);
        dialog.content_area().add(&content);
        dialog.show_all();
        let accepted =
            run_dialog_with_timeout(&dialog, max_visible_seconds)? == gtk::ResponseType::Accept;
        let mut secret = Zeroizing::new(passphrase.text().to_string());
        passphrase.set_text("");
        buffer.set_text("");
        dismiss_dialog(&dialog);
        if !accepted {
            return Ok(NativeTransferDecision::Cancel);
        }
        let owned = std::mem::take(&mut *secret);
        let passphrase =
            VaultPassphrase::new(owned).map_err(|_| GtkDialogError::InvalidSecretInput)?;
        Ok(NativeTransferDecision::Approve(passphrase))
    }

    fn request_unlock_passphrase(
        &mut self,
        max_visible_seconds: u32,
    ) -> std::result::Result<Option<VaultPassphrase>, Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_RECOVERY_REVEAL_SECONDS)?;
        let dialog = self.dialog("Unlock wallet", "Unlock wallet")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let warning = gtk::Label::new(Some(
            "The Secret Recovery Phrase gives complete control of this wallet. Ensure nobody can see your screen.",
        ));
        warning.set_line_wrap(true);
        warning.set_xalign(0.0);
        let entry = secret_entry("Wallet password");
        content.add(&warning);
        content.add(&entry);
        dialog.content_area().add(&content);
        dialog.show_all();
        let accepted =
            run_dialog_with_timeout(&dialog, max_visible_seconds)? == gtk::ResponseType::Accept;
        let mut secret = Zeroizing::new(entry.text().to_string());
        entry.set_text("");
        dismiss_dialog(&dialog);
        if !accepted {
            return Ok(None);
        }
        let owned = std::mem::take(&mut *secret);
        VaultPassphrase::new(owned)
            .map(Some)
            .map_err(|_| GtkDialogError::InvalidSecretInput)
    }

    fn show_recovery_phrase(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
        max_visible_seconds: u32,
    ) -> std::result::Result<(), Self::Error> {
        let max_visible_seconds =
            bounded_dialog_seconds(max_visible_seconds, MAX_RECOVERY_REVEAL_SECONDS)?;
        let dialog = self.dialog("Ethereum Secret Recovery Phrase", "Close")?;
        let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
        content.set_border_width(16);
        let warning = gtk::Label::new(Some(
            "Keep this Secret Recovery Phrase offline. Anyone who obtains it controls this wallet.",
        ));
        warning.set_line_wrap(true);
        warning.set_xalign(0.0);
        let words = gtk::Label::new(Some(recovery.words()));
        words.set_line_wrap(true);
        words.set_selectable(false);
        words.set_xalign(0.0);
        content.add(&warning);
        content.add(&words);
        dialog.content_area().add(&content);
        dialog.show_all();
        let _ = run_dialog_with_timeout(&dialog, max_visible_seconds)?;
        words.set_text("");
        dismiss_dialog(&dialog);
        Ok(())
    }
}

fn bounded_dialog_seconds(requested: u32, cap: u32) -> Result<u32, GtkDialogError> {
    let bounded = requested.min(cap);
    if bounded == 0 {
        Err(GtkDialogError::InvalidDialogLifetime)
    } else {
        Ok(bounded)
    }
}

fn passphrase_prompt(recovery_phrase_entered: bool) -> (&'static str, &'static str) {
    if recovery_phrase_entered {
        (
            "Create wallet password",
            "Secret Recovery Phrase accepted. Create a wallet password to encrypt this wallet on this device. This wallet password is not the Secret Recovery Phrase; you will need it for signing or unlocking the Secret Recovery Phrase.",
        )
    } else {
        (
            "Create wallet password",
            "Create a wallet password to encrypt this wallet on this device. This wallet password is not the Secret Recovery Phrase; you will need it for signing or unlocking the Secret Recovery Phrase.",
        )
    }
}

fn management_dialog_buttons() -> [(&'static str, gtk::ResponseType); 1] {
    [("Cancel", gtk::ResponseType::Cancel)]
}

fn wallet_management_copy(
    wallet_profile_exists: bool,
    protected_binding_exists: bool,
    vault_exists: bool,
) -> (&'static str, &'static str) {
    if !wallet_profile_exists && !protected_binding_exists && !vault_exists {
        (
            "Set up Ethereum wallet",
            "Choose Create wallet to generate a new Secret Recovery Phrase, or Import wallet to use an existing phrase. Recovery phrases and wallet passwords stay in this secure system window.",
        )
    } else if !wallet_profile_exists && protected_binding_exists && !vault_exists {
        (
            "Ethereum wallet settings",
            "Wallet setup cannot continue because this profile's encrypted wallet file is missing while its system keyring record still exists. Restore the profile backup or reset this test profile before creating or importing a wallet.",
        )
    } else {
        (
            "Ethereum wallet settings",
            "Use these settings to recover or inspect this profile's Sepolia test wallet. Recovery phrases and wallet passwords stay in this secure system window.",
        )
    }
}

/// `gtk_dialog_run` enters a nested main loop and hides a dialog for ordinary
/// responses, but explicitly hide it as well before returning custody control
/// to the caller.  This keeps cancellation, acceptance, and timeout on the
/// same lifecycle path and prevents a stale native prompt from being left
/// visible while the result is handled.
fn dismiss_dialog(dialog: &gtk::Dialog) {
    dialog.close();
    dialog.hide();
}

fn run_dialog_with_timeout(
    dialog: &gtk::Dialog,
    max_visible_seconds: u32,
) -> Result<gtk::ResponseType, GtkDialogError> {
    let max_visible_seconds = max_visible_seconds.min(MAX_NATIVE_DIALOG_SECONDS);
    if max_visible_seconds == 0 {
        return Ok(gtk::ResponseType::Cancel);
    }
    run_dialog_for_remaining(
        dialog,
        Instant::now(),
        Duration::from_secs(u64::from(max_visible_seconds)),
    )
}

fn run_dialog_for_remaining(
    dialog: &gtk::Dialog,
    started: Instant,
    maximum_duration: Duration,
) -> Result<gtk::ResponseType, GtkDialogError> {
    let Some(remaining) = maximum_duration
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
    else {
        return Ok(gtk::ResponseType::Cancel);
    };
    let timed_out = Rc::new(Cell::new(false));
    let timed_out_for_timer = Rc::clone(&timed_out);
    let dialog_for_timer = dialog.clone();
    let timeout = gtk::glib::timeout_add_local_once(remaining, move || {
        timed_out_for_timer.set(true);
        dialog_for_timer.response(gtk::ResponseType::Cancel);
    });
    let response = dialog.run();
    if !timed_out.get() {
        timeout.remove();
    }
    Ok(response)
}

fn secret_entry(placeholder: &str) -> gtk::Entry {
    let entry = gtk::Entry::new();
    entry.set_placeholder_text(Some(placeholder));
    entry.set_visibility(false);
    entry.set_input_purpose(gtk::InputPurpose::Password);
    entry.set_input_hints(gtk::InputHints::NO_SPELLCHECK | gtk::InputHints::NO_EMOJI);
    entry.set_max_length(crate::MAX_PASSPHRASE_BYTES as i32);
    inhibit_secret_copy(&entry);
    entry
}

fn passphrase_fields_valid(first: &str, confirmation: &str) -> bool {
    !first.is_empty()
        && first.len() <= crate::MAX_PASSPHRASE_BYTES
        && first == confirmation
        && confirmation.len() <= crate::MAX_PASSPHRASE_BYTES
}

fn refresh_passphrase_validation(
    first: &gtk::Entry,
    confirmation: &gtk::Entry,
    accept_button: &gtk::Button,
    mismatch_hint: &gtk::Label,
) {
    let first_value = Zeroizing::new(first.text().to_string());
    let confirmation_value = Zeroizing::new(confirmation.text().to_string());
    let matches = passphrase_fields_valid(first_value.as_str(), confirmation_value.as_str());
    accept_button.set_sensitive(matches);
    mismatch_hint.set_visible(
        !confirmation_value.is_empty() && first_value.as_str() != confirmation_value.as_str(),
    );
}

fn wire_passphrase_validation(
    first: &gtk::Entry,
    confirmation: &gtk::Entry,
    accept_button: &gtk::Button,
    mismatch_hint: &gtk::Label,
) {
    let first_weak = first.downgrade();
    let confirmation_weak = confirmation.downgrade();
    let accept_weak = accept_button.downgrade();
    let hint_weak = mismatch_hint.downgrade();
    first.connect_changed({
        let first_weak = first_weak.clone();
        let confirmation_weak = confirmation_weak.clone();
        let accept_weak = accept_weak.clone();
        let hint_weak = hint_weak.clone();
        move |_| {
            if let (Some(first), Some(confirmation), Some(accept_button), Some(mismatch_hint)) = (
                first_weak.upgrade(),
                confirmation_weak.upgrade(),
                accept_weak.upgrade(),
                hint_weak.upgrade(),
            ) {
                refresh_passphrase_validation(
                    &first,
                    &confirmation,
                    &accept_button,
                    &mismatch_hint,
                );
            }
        }
    });
    confirmation.connect_changed(move |_| {
        if let (Some(first), Some(confirmation), Some(accept_button), Some(mismatch_hint)) = (
            first_weak.upgrade(),
            confirmation_weak.upgrade(),
            accept_weak.upgrade(),
            hint_weak.upgrade(),
        ) {
            refresh_passphrase_validation(&first, &confirmation, &accept_button, &mismatch_hint);
        }
    });
    refresh_passphrase_validation(first, confirmation, accept_button, mismatch_hint);
}

fn recovery_entry() -> gtk::Entry {
    let entry = gtk::Entry::new();
    entry.set_placeholder_text(Some("Secret Recovery Phrase in order"));
    entry.set_input_purpose(gtk::InputPurpose::Password);
    entry.set_input_hints(gtk::InputHints::NO_SPELLCHECK | gtk::InputHints::NO_EMOJI);
    entry.set_max_length(ratspeak_eth_wallet::MAX_RECOVERY_PHRASE_BYTES as i32);
    inhibit_secret_copy(&entry);
    entry
}

fn inhibit_secret_copy(entry: &gtk::Entry) {
    entry.connect_copy_clipboard(|entry| entry.stop_signal_emission_by_name("copy-clipboard"));
    entry.connect_cut_clipboard(|entry| entry.stop_signal_emission_by_name("cut-clipboard"));
}

fn transfer_review_document(review: &TransferReview) -> String {
    let mut document = String::with_capacity(1024);
    let _ = writeln!(
        document,
        "Operation: 0x{}",
        hex_bytes(review.operation_id().as_bytes())
    );
    let _ = writeln!(document, "Network: {}", review.network());
    let _ = writeln!(document, "Chain ID: {}", review.chain_id());
    let _ = writeln!(document, "From: {:#x}", review.from());
    let _ = writeln!(document, "To: {:#x}", review.to());
    let _ = writeln!(document, "Value (wei): {}", review.value());
    let _ = writeln!(document, "Nonce: {}", review.nonce());
    let _ = writeln!(document, "Gas limit: {}", review.gas_limit());
    let _ = writeln!(
        document,
        "Maximum fee per gas (wei): {}",
        review.max_fee_per_gas()
    );
    let _ = writeln!(
        document,
        "Maximum priority fee per gas (wei): {}",
        review.max_priority_fee_per_gas()
    );
    let _ = writeln!(
        document,
        "Maximum total cost (wei): {}",
        review.maximum_total_cost()
    );
    let _ = writeln!(
        document,
        "Prepared at (Unix): {}",
        review.prepared_at_unix()
    );
    let _ = writeln!(document, "Expires at (Unix): {}", review.expires_at_unix());
    let _ = writeln!(
        document,
        "Review context commitment: {:#x}",
        review.review_context().digest()
    );
    let _ = writeln!(document, "Signing hash: {:#x}", review.signing_hash());
    let _ = writeln!(document, "Review digest: {:#x}", review.review_digest());
    document
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use alloy_primitives::{Address, U256};
    use ratspeak_eth_wallet::{OperationId, ReviewContext, TransferIntent, WalletAccount};

    use super::*;

    const RECOVERY_VIEW_TEST_TEXT: &str = "not-a-wallet recovery-view-test";

    fn address(value: &str) -> Address {
        value.parse().unwrap()
    }

    fn account() -> WalletAccount {
        WalletAccount::sepolia(address("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
    }

    fn review() -> TransferReview {
        *account()
            .prepare_transfer(
                TransferIntent::new(
                    SEPOLIA_CHAIN_ID,
                    account().address(),
                    address("1111111111111111111111111111111111111111"),
                    U256::from(42_u64),
                    7,
                    30_000_000_000,
                    1_500_000_000,
                ),
                OperationId::new([9; 16]).unwrap(),
                ReviewContext::from_canonical_bytes(b"verified-state:block-42").unwrap(),
                1_000,
                1_100,
            )
            .unwrap()
            .review()
    }

    struct Guard(VecDeque<bool>);

    impl NativeProfileSessionGuard for Guard {
        type Error = ();

        fn is_current(&mut self) -> Result<bool, Self::Error> {
            self.0.pop_front().ok_or(())
        }
    }

    struct Clock(VecDeque<u64>);

    impl TrustedClock for Clock {
        type Error = ();

        fn now_unix(&mut self) -> Result<u64, Self::Error> {
            self.0.pop_front().ok_or(())
        }
    }

    struct Dialogs {
        next_passphrase: Option<VaultPassphrase>,
        next_recovery: Option<RecoveryPhraseInput>,
        decision: Option<NativeTransferDecision>,
        review_document: Option<String>,
        reveal_max_seconds: Option<u32>,
        calls: usize,
    }

    impl Dialogs {
        fn with_passphrase() -> Self {
            Self {
                next_passphrase: Some(VaultPassphrase::new("correct passphrase".into()).unwrap()),
                next_recovery: None,
                decision: None,
                review_document: None,
                reveal_max_seconds: None,
                calls: 0,
            }
        }
    }

    impl NativeCustodyDialogs for Dialogs {
        type Error = ();

        fn request_new_passphrase(
            &mut self,
            _max_visible_seconds: u32,
        ) -> Result<Option<VaultPassphrase>, Self::Error> {
            self.calls += 1;
            Ok(self.next_passphrase.take())
        }

        fn confirm_recovery_backup(
            &mut self,
            _recovery: RecoveryPhraseView<'_>,
            _max_visible_seconds: u32,
        ) -> Result<bool, Self::Error> {
            self.calls += 1;
            Ok(true)
        }

        fn request_recovery_phrase(
            &mut self,
            _max_visible_seconds: u32,
        ) -> Result<Option<RecoveryPhraseInput>, Self::Error> {
            self.calls += 1;
            Ok(self.next_recovery.take())
        }

        fn review_transfer_and_request_passphrase(
            &mut self,
            review: &TransferReview,
            _max_visible_seconds: u32,
        ) -> Result<NativeTransferDecision, Self::Error> {
            self.calls += 1;
            self.review_document = Some(transfer_review_document(review));
            Ok(self
                .decision
                .take()
                .unwrap_or(NativeTransferDecision::Cancel))
        }

        fn request_unlock_passphrase(
            &mut self,
            _max_visible_seconds: u32,
        ) -> Result<Option<VaultPassphrase>, Self::Error> {
            self.calls += 1;
            Ok(self.next_passphrase.take())
        }

        fn show_recovery_phrase(
            &mut self,
            _recovery: RecoveryPhraseView<'_>,
            max_visible_seconds: u32,
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            self.reveal_max_seconds = Some(max_visible_seconds);
            Ok(())
        }
    }

    #[test]
    fn release_availability_requires_both_owner_wiring_and_trusted_counter() {
        assert_eq!(
            linux_native_custody_availability(false, false),
            LinuxNativeCustodyAvailability::NativeApplicationWiringRequired
        );
        assert_eq!(
            linux_native_custody_availability(true, false),
            LinuxNativeCustodyAvailability::TrustedGenerationBackendRequired
        );
        assert_eq!(
            linux_native_custody_availability(true, true),
            LinuxNativeCustodyAvailability::Available
        );
    }

    #[test]
    fn concrete_dialog_lifetime_contract_rejects_zero_and_clamps_recovery() {
        assert_eq!(
            bounded_dialog_seconds(300, MAX_RECOVERY_REVEAL_SECONDS),
            Ok(MAX_RECOVERY_REVEAL_SECONDS)
        );
        assert_eq!(
            bounded_dialog_seconds(u32::MAX, MAX_NATIVE_DIALOG_SECONDS),
            Ok(MAX_NATIVE_DIALOG_SECONDS)
        );
        assert_eq!(
            bounded_dialog_seconds(0, MAX_RECOVERY_REVEAL_SECONDS),
            Err(GtkDialogError::InvalidDialogLifetime)
        );
    }

    #[test]
    fn restore_passphrase_prompt_reports_that_recovery_words_were_accepted() {
        let (title, explanation) = passphrase_prompt(true);
        assert_eq!(title, "Create wallet password");
        assert!(explanation.starts_with("Secret Recovery Phrase accepted."));
        assert!(explanation.contains("not the Secret Recovery Phrase"));

        let (title, explanation) = passphrase_prompt(false);
        assert_eq!(title, "Create wallet password");
        assert!(!explanation.starts_with("Secret Recovery Phrase accepted."));
        assert!(explanation.contains("not the Secret Recovery Phrase"));
    }

    #[test]
    fn passphrase_validation_requires_nonempty_equal_byte_bounded_values() {
        assert!(!passphrase_fields_valid("", ""));
        assert!(!passphrase_fields_valid("correct", ""));
        assert!(!passphrase_fields_valid("correct", "incorrect"));
        assert!(passphrase_fields_valid("correct", "correct"));

        let too_long = "x".repeat(crate::MAX_PASSPHRASE_BYTES + 1);
        assert!(!passphrase_fields_valid(&too_long, &too_long));
    }

    #[test]
    fn management_prompt_has_one_cancel_button() {
        let buttons = management_dialog_buttons();
        assert_eq!(buttons.len(), 1);
        assert_eq!(buttons[0], ("Cancel", gtk::ResponseType::Cancel));
    }

    #[test]
    fn management_prompt_explains_fresh_setup_and_orphaned_keyring_state() {
        let (title, explanation) = wallet_management_copy(false, false, false);
        assert_eq!(title, "Set up Ethereum wallet");
        assert!(explanation.contains("Create wallet"));
        assert!(explanation.contains("Import wallet"));

        let (title, explanation) = wallet_management_copy(false, true, false);
        assert_eq!(title, "Ethereum wallet settings");
        assert!(explanation.contains("encrypted wallet file is missing"));
        assert!(explanation.contains("system keyring record"));
    }

    #[test]
    fn setup_profile_switch_after_secret_entry_consumes_the_ceremony() {
        let dialogs = Dialogs::with_passphrase();
        let guard = Guard([true, false].into());
        let clock = Clock([1, 2].into());
        let mut setup = GtkNativeWalletSetup::new(dialogs, guard, clock, 10);
        assert!(matches!(
            NativeWalletSetup::request_new_passphrase(&mut setup),
            Err(GtkAdapterError::ProfileChanged)
        ));
        assert!(matches!(
            NativeWalletSetup::request_new_passphrase(&mut setup),
            Err(GtkAdapterError::Replay)
        ));
        let (dialogs, _, _) = setup.into_parts();
        assert_eq!(dialogs.calls, 1);
    }

    #[test]
    fn restore_cancellation_cannot_continue_into_passphrase_setup() {
        let dialogs = Dialogs {
            next_passphrase: Some(VaultPassphrase::new("must not be requested".into()).unwrap()),
            next_recovery: None,
            decision: None,
            review_document: None,
            reveal_max_seconds: None,
            calls: 0,
        };
        let guard = Guard([true, true].into());
        let clock = Clock([1, 2].into());
        let mut setup = GtkNativeWalletSetup::new(dialogs, guard, clock, 10);
        assert!(
            NativeWalletSetup::request_recovery_phrase(&mut setup)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            NativeWalletSetup::request_new_passphrase(&mut setup),
            Err(GtkAdapterError::Replay)
        ));
    }

    #[test]
    fn exact_review_document_contains_every_immutable_field_and_is_one_shot() {
        let expected = review();
        let dialogs = Dialogs {
            next_passphrase: None,
            next_recovery: None,
            decision: Some(NativeTransferDecision::Cancel),
            review_document: None,
            reveal_max_seconds: None,
            calls: 0,
        };
        let guard = Guard([true, true].into());
        let clock = Clock([1_001, 1_002].into());
        let mut authorizer = GtkNativeTransferAuthorizer::new(dialogs, guard, clock, account());
        assert!(matches!(
            authorizer.review_and_request_passphrase(&expected),
            Ok(NativeTransferDecision::Cancel)
        ));
        assert!(matches!(
            authorizer.review_and_request_passphrase(&expected),
            Err(GtkAdapterError::Replay)
        ));
        let (dialogs, _, _) = authorizer.into_parts();
        let document = dialogs.review_document.unwrap();
        for label in [
            "Operation:",
            "Network: sepolia",
            "Chain ID: 11155111",
            "From:",
            "To:",
            "Value (wei): 42",
            "Nonce: 7",
            "Gas limit: 21000",
            "Maximum fee per gas (wei): 30000000000",
            "Maximum priority fee per gas (wei): 1500000000",
            "Maximum total cost (wei):",
            "Prepared at (Unix): 1000",
            "Expires at (Unix): 1100",
            "Review context commitment:",
            "Signing hash:",
            "Review digest:",
        ] {
            assert!(document.contains(label), "missing {label}");
        }
    }

    #[test]
    fn transfer_expiring_during_review_discards_the_collected_passphrase() {
        let expected = review();
        let dialogs = Dialogs {
            next_passphrase: None,
            next_recovery: None,
            decision: Some(NativeTransferDecision::Approve(
                VaultPassphrase::new("correct passphrase".into()).unwrap(),
            )),
            review_document: None,
            reveal_max_seconds: None,
            calls: 0,
        };
        let guard = Guard([true, true].into());
        let clock = Clock([1_001, 1_100].into());
        let mut authorizer = GtkNativeTransferAuthorizer::new(dialogs, guard, clock, account());
        assert!(matches!(
            authorizer.review_and_request_passphrase(&expected),
            Err(GtkAdapterError::Expired)
        ));
        let (dialogs, _, _) = authorizer.into_parts();
        assert_eq!(dialogs.calls, 1);
    }

    #[test]
    fn transfer_profile_or_account_change_never_reaches_signing() {
        let expected = review();
        let dialogs = Dialogs {
            next_passphrase: None,
            next_recovery: None,
            decision: Some(NativeTransferDecision::Approve(
                VaultPassphrase::new("correct passphrase".into()).unwrap(),
            )),
            review_document: None,
            reveal_max_seconds: None,
            calls: 0,
        };
        let guard = Guard([true, false].into());
        let clock = Clock([1_001, 1_002].into());
        let mut authorizer = GtkNativeTransferAuthorizer::new(dialogs, guard, clock, account());
        assert!(matches!(
            authorizer.review_and_request_passphrase(&expected),
            Err(GtkAdapterError::ProfileChanged)
        ));
        let (dialogs, _, _) = authorizer.into_parts();
        assert_eq!(dialogs.calls, 1);

        let wrong_account =
            WalletAccount::sepolia(address("2222222222222222222222222222222222222222"));
        let dialogs = Dialogs::with_passphrase();
        let mut authorizer = GtkNativeTransferAuthorizer::new(
            dialogs,
            Guard(VecDeque::new()),
            Clock(VecDeque::new()),
            wrong_account,
        );
        assert!(matches!(
            authorizer.review_and_request_passphrase(&expected),
            Err(GtkAdapterError::ReviewMismatch)
        ));
        let (dialogs, _, _) = authorizer.into_parts();
        assert_eq!(dialogs.calls, 0);
    }

    #[test]
    fn recovery_reveal_requires_unlock_phase_and_current_profile() {
        let dialogs = Dialogs::with_passphrase();
        let guard = Guard([true, true, false].into());
        let clock = Clock([1, 2, 3].into());
        let mut reveal = GtkNativeRecoveryReveal::new(dialogs, guard, clock, 10);
        let passphrase = NativeRecoveryReveal::request_passphrase(&mut reveal)
            .unwrap()
            .unwrap();
        drop(passphrase);
        assert!(matches!(
            NativeRecoveryReveal::show_recovery_phrase(
                &mut reveal,
                RecoveryPhraseView::from_phrase(RECOVERY_VIEW_TEST_TEXT)
            ),
            Err(GtkAdapterError::ProfileChanged)
        ));
        assert!(matches!(
            NativeRecoveryReveal::show_recovery_phrase(
                &mut reveal,
                RecoveryPhraseView::from_phrase(RECOVERY_VIEW_TEST_TEXT)
            ),
            Err(GtkAdapterError::Replay)
        ));
    }

    #[test]
    fn recovery_reveal_display_is_bounded_by_deadline_and_product_cap() {
        let dialogs = Dialogs::with_passphrase();
        let guard = Guard([true, true, true, true].into());
        let clock = Clock([1, 2, 3, 4].into());
        let mut reveal = GtkNativeRecoveryReveal::new(dialogs, guard, clock, 1_000);
        drop(
            NativeRecoveryReveal::request_passphrase(&mut reveal)
                .unwrap()
                .unwrap(),
        );
        NativeRecoveryReveal::show_recovery_phrase(
            &mut reveal,
            RecoveryPhraseView::from_phrase(RECOVERY_VIEW_TEST_TEXT),
        )
        .unwrap();
        let (dialogs, _, _) = reveal.into_parts();
        assert_eq!(
            dialogs.reveal_max_seconds,
            Some(MAX_RECOVERY_REVEAL_SECONDS)
        );

        let dialogs = Dialogs::with_passphrase();
        let guard = Guard([true, true, true, true].into());
        let clock = Clock([1, 2, 3, 4].into());
        let mut reveal = GtkNativeRecoveryReveal::new(dialogs, guard, clock, 8);
        drop(
            NativeRecoveryReveal::request_passphrase(&mut reveal)
                .unwrap()
                .unwrap(),
        );
        NativeRecoveryReveal::show_recovery_phrase(
            &mut reveal,
            RecoveryPhraseView::from_phrase(RECOVERY_VIEW_TEST_TEXT),
        )
        .unwrap();
        let (dialogs, _, _) = reveal.into_parts();
        assert_eq!(dialogs.reveal_max_seconds, Some(5));
    }
}
