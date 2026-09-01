#![cfg(target_os = "linux")]

use std::{collections::VecDeque, fmt, fs, path::Path};

use alloy_primitives::{Address, U256};
use ratspeak_eth_wallet::{
    OperationId, PreparedTransfer, ReviewContext, SEPOLIA_CHAIN_ID, TransferIntent, TransferReview,
    WalletAccount,
};
use ratspeak_eth_wallet_linux::{
    GtkNativeDialogBackend, LinuxWalletController, LinuxWalletVault, NativeControllerSignError,
    NativeRecoveryReveal, NativeRevealError, NativeSetupError, NativeTransferAuthorization,
    NativeTransferDecision, NativeVaultError, NativeWalletSetup, RecoveryPhraseInput,
    RecoveryPhraseView, TrustedClock, TrustedGenerationCounter, TrustedGenerationState,
    TrustedVaultBinding, VaultError, VaultKdfParameters, VaultPassphrase,
};
use static_assertions::assert_not_impl_any;

const PHRASE: &str = "test test test test test test test test test test test junk";
const ADDRESS: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

assert_not_impl_any!(RecoveryPhraseInput: Clone, fmt::Debug, fmt::Display, serde::Serialize);
assert_not_impl_any!(RecoveryPhraseView<'static>: Clone, fmt::Debug, fmt::Display, serde::Serialize);
assert_not_impl_any!(VaultPassphrase: Clone, serde::Serialize);
assert_not_impl_any!(NativeTransferDecision: Clone, fmt::Debug, serde::Serialize);
assert_not_impl_any!(GtkNativeDialogBackend: Clone, fmt::Debug, serde::Serialize);

fn address(value: &str) -> Address {
    value.parse().unwrap()
}

fn kdf() -> VaultKdfParameters {
    VaultKdfParameters {
        memory_kib: VaultKdfParameters::MIN_MEMORY_KIB,
        iterations: VaultKdfParameters::MIN_ITERATIONS,
        parallelism: 1,
    }
}

fn passphrase(value: &str) -> VaultPassphrase {
    VaultPassphrase::new(value.to_owned()).unwrap()
}

fn vault_path(root: &Path) -> std::path::PathBuf {
    root.join("ethereum").join("wallet.vault")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counter {
    state: TrustedGenerationState,
}

impl Counter {
    fn fresh() -> Self {
        Self {
            state: TrustedGenerationState::NeverInitialized,
        }
    }
}

impl TrustedGenerationCounter for Counter {
    type Error = ();

    fn state(&mut self) -> Result<TrustedGenerationState, Self::Error> {
        Ok(self.state)
    }

    fn initialize(&mut self, binding: TrustedVaultBinding) -> Result<(), Self::Error> {
        if self.state != TrustedGenerationState::NeverInitialized {
            return Err(());
        }
        self.state = TrustedGenerationState::Current(binding);
        Ok(())
    }

    fn advance(
        &mut self,
        expected: TrustedVaultBinding,
        next: TrustedVaultBinding,
    ) -> Result<(), Self::Error> {
        if self.state != TrustedGenerationState::Current(expected)
            || next.generation().get() != expected.generation().get() + 1
            || next.vault_identity() != expected.vault_identity()
            || next.account() != expected.account()
        {
            return Err(());
        }
        self.state = TrustedGenerationState::Current(next);
        Ok(())
    }
}

fn assert_generation(counter: &Counter, expected: u64) {
    match counter.state {
        TrustedGenerationState::Current(binding) => {
            assert_eq!(binding.generation().get(), expected)
        }
        state => panic!("expected current generation, found {state:?}"),
    }
}

struct Setup {
    passphrase: Option<VaultPassphrase>,
    recovery: Option<RecoveryPhraseInput>,
    acknowledge_backup: bool,
    observed_backup_word_count: Option<usize>,
}

impl Setup {
    fn generated(passphrase: Option<VaultPassphrase>, acknowledge_backup: bool) -> Self {
        Self {
            passphrase,
            recovery: None,
            acknowledge_backup,
            observed_backup_word_count: None,
        }
    }

    fn restore(phrase: &str, passphrase: Option<VaultPassphrase>) -> Self {
        Self {
            passphrase,
            recovery: Some(RecoveryPhraseInput::new(phrase.to_owned())),
            acknowledge_backup: false,
            observed_backup_word_count: None,
        }
    }
}

impl NativeWalletSetup for Setup {
    type Error = ();

    fn request_new_passphrase(&mut self) -> Result<Option<VaultPassphrase>, Self::Error> {
        Ok(self.passphrase.take())
    }

    fn confirm_recovery_backup(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
    ) -> Result<bool, Self::Error> {
        self.observed_backup_word_count = Some(recovery.words().split_whitespace().count());
        Ok(self.acknowledge_backup)
    }

    fn request_recovery_phrase(&mut self) -> Result<Option<RecoveryPhraseInput>, Self::Error> {
        Ok(self.recovery.take())
    }
}

struct Clock(VecDeque<u64>);

impl TrustedClock for Clock {
    type Error = ();

    fn now_unix(&mut self) -> Result<u64, Self::Error> {
        self.0.pop_front().ok_or(())
    }
}

struct StrictReview {
    expected: TransferReview,
    passphrase: Option<VaultPassphrase>,
    calls: usize,
}

impl NativeTransferAuthorization for StrictReview {
    type Error = ();

    fn review_and_request_passphrase(
        &mut self,
        review: &TransferReview,
    ) -> Result<NativeTransferDecision, Self::Error> {
        self.calls += 1;
        if *review != self.expected {
            return Ok(NativeTransferDecision::Cancel);
        }
        Ok(self
            .passphrase
            .take()
            .map(NativeTransferDecision::Approve)
            .unwrap_or(NativeTransferDecision::Cancel))
    }
}

struct RecoveryReveal {
    passphrase: Option<VaultPassphrase>,
    observed_word_count: Option<usize>,
}

impl NativeRecoveryReveal for RecoveryReveal {
    type Error = ();

    fn request_passphrase(&mut self) -> Result<Option<VaultPassphrase>, Self::Error> {
        Ok(self.passphrase.take())
    }

    fn show_recovery_phrase(
        &mut self,
        recovery: RecoveryPhraseView<'_>,
    ) -> Result<(), Self::Error> {
        self.observed_word_count = Some(recovery.words().split_whitespace().count());
        Ok(())
    }
}

fn transfer(account: WalletAccount, operation: u8, value: u64) -> PreparedTransfer {
    account
        .prepare_transfer(
            TransferIntent::new(
                SEPOLIA_CHAIN_ID,
                account.address(),
                address("1111111111111111111111111111111111111111"),
                U256::from(value),
                7,
                30_000_000_000,
                1_500_000_000,
            ),
            OperationId::new([operation; 16]).unwrap(),
            ReviewContext::from_canonical_bytes(b"verified-state:block-42").unwrap(),
            1_000,
            1_100,
        )
        .unwrap()
}

fn restored_controller(
    root: &Path,
) -> (
    LinuxWalletController,
    Counter,
    WalletAccount,
    VaultPassphrase,
) {
    let mut setup = Setup::restore(PHRASE, Some(passphrase("correct passphrase")));
    let mut counter = Counter::fresh();
    let controller =
        LinuxWalletController::restore(vault_path(root), &mut setup, &mut counter, kdf()).unwrap();
    let account_passphrase = passphrase("correct passphrase");
    let account = controller
        .wallet_account(&account_passphrase, &mut counter)
        .unwrap()
        .into_value();
    (controller, counter, account, account_passphrase)
}

#[test]
fn generated_setup_requires_native_passphrase_and_backup_acknowledgement() {
    let cancelled_profile = tempfile::tempdir().unwrap();
    let mut cancelled = Setup::generated(None, true);
    let mut counter = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::create_generated(
            vault_path(cancelled_profile.path()),
            &mut cancelled,
            &mut counter,
            kdf(),
        ),
        Err(NativeSetupError::Cancelled)
    ));
    assert_eq!(counter.state, TrustedGenerationState::NeverInitialized);
    assert!(!vault_path(cancelled_profile.path()).exists());

    let rejected_profile = tempfile::tempdir().unwrap();
    let mut rejected = Setup::generated(Some(passphrase("correct passphrase")), false);
    let mut counter = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::create_generated(
            vault_path(rejected_profile.path()),
            &mut rejected,
            &mut counter,
            kdf(),
        ),
        Err(NativeSetupError::BackupNotAcknowledged)
    ));
    assert_eq!(rejected.observed_backup_word_count, Some(12));
    assert_eq!(counter.state, TrustedGenerationState::NeverInitialized);
    assert!(!vault_path(rejected_profile.path()).exists());
}

#[test]
fn restore_reopens_with_the_same_account_and_missing_or_corrupt_counter_fails_closed() {
    let profile = tempfile::tempdir().unwrap();
    let (controller, mut counter, account, _) = restored_controller(profile.path());
    assert_eq!(account.address(), address(ADDRESS));

    let reopened = LinuxWalletController::from_vault(
        LinuxWalletVault::at_path(controller.vault().path()).unwrap(),
    );
    assert_eq!(
        reopened
            .wallet_account(&passphrase("correct passphrase"), &mut counter)
            .unwrap()
            .into_value(),
        account
    );

    counter.state = TrustedGenerationState::MissingAfterInitialization;
    assert!(matches!(
        reopened.wallet_account(&passphrase("correct passphrase"), &mut counter),
        Err(NativeVaultError::GenerationState(
            TrustedGenerationState::MissingAfterInitialization
        ))
    ));
    counter.state = TrustedGenerationState::Corrupt;
    assert!(matches!(
        reopened.wallet_account(&passphrase("correct passphrase"), &mut counter),
        Err(NativeVaultError::GenerationState(
            TrustedGenerationState::Corrupt
        ))
    ));
}

#[test]
fn exact_review_mutation_and_explicit_cancellation_never_sign() {
    let profile = tempfile::tempdir().unwrap();
    let (controller, mut counter, account, _) = restored_controller(profile.path());
    let original = transfer(account, 1, 10);
    let mutated = transfer(account, 2, 11);
    assert_ne!(
        original.review().review_digest(),
        mutated.review().review_digest()
    );
    let mut review = StrictReview {
        expected: *original.review(),
        passphrase: Some(passphrase("correct passphrase")),
        calls: 0,
    };
    let mut clock = Clock([1_001].into());
    assert!(matches!(
        controller.authorize_and_sign(mutated, &mut counter, &mut review, &mut clock),
        Err(NativeControllerSignError::Cancelled)
    ));
    assert_eq!(review.calls, 1);
}

#[test]
fn trusted_generation_rejects_stale_and_rolled_back_vaults() {
    let profile = tempfile::tempdir().unwrap();
    let (controller, mut counter, account, old_passphrase) = restored_controller(profile.path());
    let generation_one = fs::read(controller.vault().path()).unwrap();
    let new_passphrase = passphrase("new correct passphrase");
    controller
        .change_passphrase(&old_passphrase, &new_passphrase, &mut counter, kdf())
        .unwrap();
    assert_generation(&counter, 2);

    fs::write(controller.vault().path(), generation_one).unwrap();
    let prepared = transfer(account, 3, 10);
    let mut review = StrictReview {
        expected: *prepared.review(),
        passphrase: Some(passphrase("correct passphrase")),
        calls: 0,
    };
    let mut clock = Clock([1_001, 1_002].into());
    assert!(matches!(
        controller.authorize_and_sign(prepared, &mut counter, &mut review, &mut clock),
        Err(NativeControllerSignError::Vault(
            VaultError::RollbackDetected {
                found: 1,
                minimum: 2
            }
        ))
    ));
}

#[test]
fn wrong_current_passphrase_does_not_advance_the_trusted_counter() {
    let profile = tempfile::tempdir().unwrap();
    let (controller, mut counter, _, _) = restored_controller(profile.path());
    assert!(matches!(
        controller.change_passphrase(
            &passphrase("wrong current passphrase"),
            &passphrase("new correct passphrase"),
            &mut counter,
            kdf(),
        ),
        Err(NativeVaultError::Vault(VaultError::AuthenticationFailed))
    ));
    assert_generation(&counter, 1);
    assert_eq!(
        controller
            .wallet_account(&passphrase("correct passphrase"), &mut counter)
            .unwrap()
            .into_value()
            .address(),
        address(ADDRESS)
    );
}

#[test]
fn same_generation_vault_replacement_is_rejected_by_trusted_identity() {
    let first_profile = tempfile::tempdir().unwrap();
    let second_profile = tempfile::tempdir().unwrap();
    let (first, mut first_counter, _, _) = restored_controller(first_profile.path());
    let (second, _, _, _) = restored_controller(second_profile.path());
    fs::write(
        first.vault().path(),
        fs::read(second.vault().path()).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        first.wallet_account(&passphrase("correct passphrase"), &mut first_counter),
        Err(NativeVaultError::Vault(VaultError::VaultIdentityMismatch))
    ));
}

#[test]
fn secret_debug_output_is_redacted() {
    let passphrase = passphrase("a phrase that must not be logged");
    let output = format!("{passphrase:?}");
    assert_eq!(output, "VaultPassphrase(\"[REDACTED]\")");
    assert!(!output.contains("must not"));
}

#[test]
fn recovery_reveal_requires_the_bound_vault_and_never_returns_words() {
    let profile = tempfile::tempdir().unwrap();
    let (controller, mut counter, _, _) = restored_controller(profile.path());

    let mut wrong = RecoveryReveal {
        passphrase: Some(passphrase("wrong passphrase")),
        observed_word_count: None,
    };
    assert!(matches!(
        controller.reveal_recovery(&mut wrong, &mut counter),
        Err(NativeRevealError::Vault(VaultError::AuthenticationFailed))
    ));
    assert_eq!(wrong.observed_word_count, None);

    let mut cancelled = RecoveryReveal {
        passphrase: None,
        observed_word_count: None,
    };
    assert!(matches!(
        controller.reveal_recovery(&mut cancelled, &mut counter),
        Err(NativeRevealError::Cancelled)
    ));
    assert_eq!(cancelled.observed_word_count, None);

    let mut reveal = RecoveryReveal {
        passphrase: Some(passphrase("correct passphrase")),
        observed_word_count: None,
    };
    controller
        .reveal_recovery(&mut reveal, &mut counter)
        .unwrap();
    assert_eq!(reveal.observed_word_count, Some(12));
}
