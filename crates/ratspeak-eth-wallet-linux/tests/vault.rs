#![cfg(target_os = "linux")]

use std::{
    cell::Cell,
    collections::VecDeque,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use alloy_primitives::{Address, U256};
use ratspeak_eth_wallet::{
    OperationId, ReviewContext, SEPOLIA_CHAIN_ID, TransferIntent, TransferReview, WalletAccount,
    WalletError,
};
use ratspeak_eth_wallet_linux::{
    GenerationFloor, LinuxWalletController, LinuxWalletVault, MAX_VAULT_BYTES,
    NativeControllerSignError, NativeSetupError, NativeTransferAuthorization,
    NativeTransferDecision, NativeVaultError, NativeWalletSetup, RecoveryPhraseInput,
    RecoveryPhraseView, TrustedClock, TrustedGenerationCounter, TrustedGenerationState,
    TrustedVaultBinding, VaultError, VaultKdfParameters, VaultPassphrase,
};
use rustix::fs::FlockOperation;
use static_assertions::assert_not_impl_any;

const PHRASE: &str = "test test test test test test test test test test test junk";
const ADDRESS: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

assert_not_impl_any!(VaultPassphrase: Clone, serde::Serialize);
static_assertions::assert_impl_all!(argon2::Block: zeroize::Zeroize);

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

fn address(value: &str) -> Address {
    value.parse().unwrap()
}

fn vault_path(root: &Path) -> PathBuf {
    root.join("ethereum").join("wallet.vault")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counter(TrustedGenerationState);

impl Counter {
    fn fresh() -> Self {
        Self(TrustedGenerationState::NeverInitialized)
    }
}

impl TrustedGenerationCounter for Counter {
    type Error = ();

    fn state(&mut self) -> Result<TrustedGenerationState, Self::Error> {
        Ok(self.0)
    }

    fn initialize(&mut self, binding: TrustedVaultBinding) -> Result<(), Self::Error> {
        if self.0 != TrustedGenerationState::NeverInitialized {
            return Err(());
        }
        self.0 = TrustedGenerationState::Current(binding);
        Ok(())
    }

    fn advance(
        &mut self,
        expected: TrustedVaultBinding,
        next: TrustedVaultBinding,
    ) -> Result<(), Self::Error> {
        if self.0 != TrustedGenerationState::Current(expected)
            || next.generation().get() != expected.generation().get() + 1
            || next.vault_identity() != expected.vault_identity()
            || next.account() != expected.account()
        {
            return Err(());
        }
        self.0 = TrustedGenerationState::Current(next);
        Ok(())
    }
}

struct RestoreSetup {
    passphrase: Option<VaultPassphrase>,
    recovery: Option<RecoveryPhraseInput>,
}

impl RestoreSetup {
    fn new(passphrase: &str) -> Self {
        Self {
            passphrase: Some(VaultPassphrase::new(passphrase.to_owned()).unwrap()),
            recovery: Some(RecoveryPhraseInput::new(PHRASE.to_owned())),
        }
    }
}

impl NativeWalletSetup for RestoreSetup {
    type Error = ();

    fn request_new_passphrase(&mut self) -> Result<Option<VaultPassphrase>, Self::Error> {
        Ok(self.passphrase.take())
    }

    fn confirm_recovery_backup(
        &mut self,
        _recovery: RecoveryPhraseView<'_>,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn request_recovery_phrase(&mut self) -> Result<Option<RecoveryPhraseInput>, Self::Error> {
        Ok(self.recovery.take())
    }
}

fn create(root: &Path, passphrase: &str) -> (LinuxWalletController, Counter) {
    let mut setup = RestoreSetup::new(passphrase);
    let mut counter = Counter::fresh();
    let controller =
        LinuxWalletController::restore(vault_path(root), &mut setup, &mut counter, kdf()).unwrap();
    (controller, counter)
}

#[test]
fn fresh_profile_recovery_round_trip_is_private_and_contains_no_plaintext() {
    let profile = tempfile::tempdir().unwrap();
    let pass = passphrase("correct horse battery staple");
    let (controller, mut counter) = create(profile.path(), "correct horse battery staple");
    let parent_mode = fs::metadata(profile.path().join("ethereum"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let file_mode = fs::metadata(controller.vault().path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    let bytes = fs::read(controller.vault().path()).unwrap();
    assert!(bytes.len() <= MAX_VAULT_BYTES);
    assert!(
        !bytes
            .windows(PHRASE.len())
            .any(|window| window == PHRASE.as_bytes())
    );

    let reopened = LinuxWalletController::from_vault(
        LinuxWalletVault::at_path(controller.vault().path()).unwrap(),
    );
    assert_eq!(
        reopened
            .wallet_account(&pass, &mut counter)
            .unwrap()
            .into_value()
            .address(),
        address(ADDRESS)
    );
    let debug = format!("{pass:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("correct horse"));
}

#[test]
fn wrong_passphrase_tamper_truncation_and_oversize_fail_closed() {
    let profile = tempfile::tempdir().unwrap();
    let pass = passphrase("correct passphrase");
    let wrong = passphrase("wrong passphrase");
    let (controller, mut counter) = create(profile.path(), "correct passphrase");
    let original = fs::read(controller.vault().path()).unwrap();
    assert!(matches!(
        controller.wallet_account(&wrong, &mut counter),
        Err(NativeVaultError::Vault(VaultError::AuthenticationFailed))
    ));
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    fs::write(controller.vault().path(), &tampered).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::AuthenticationFailed))
    ));
    fs::write(controller.vault().path(), &original[..original.len() - 1]).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InvalidFormat))
    ));
    fs::write(controller.vault().path(), vec![0u8; MAX_VAULT_BYTES + 1]).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::OversizedVault))
    ));
}

#[test]
fn symlinks_hardlinks_public_modes_and_public_parent_are_rejected() {
    let profile = tempfile::tempdir().unwrap();
    let pass = passphrase("correct passphrase");
    let (controller, mut counter) = create(profile.path(), "correct passphrase");
    let original_path = controller.vault().path();
    let target = profile.path().join("ethereum").join("target.vault");
    fs::rename(&original_path, &target).unwrap();
    symlink(&target, &original_path).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InsecureFile))
    ));
    fs::remove_file(&original_path).unwrap();
    fs::rename(&target, &original_path).unwrap();
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InsecureFile))
    ));
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o4600)).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InsecureFile))
    ));
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = profile.path().join("ethereum").join("wallet-copy.vault");
    fs::hard_link(&original_path, &hardlink).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InsecureFile))
    ));
    fs::remove_file(hardlink).unwrap();
    fs::set_permissions(
        profile.path().join("ethereum"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::InsecureParent))
    ));

    let symlinked_profile = tempfile::tempdir().unwrap();
    let target_parent = symlinked_profile.path().join("real-ethereum");
    fs::create_dir(&target_parent).unwrap();
    fs::set_permissions(&target_parent, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target_parent, symlinked_profile.path().join("ethereum")).unwrap();
    let mut setup = RestoreSetup::new("correct passphrase");
    let mut fresh = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::restore(
            vault_path(symlinked_profile.path()),
            &mut setup,
            &mut fresh,
            kdf(),
        ),
        Err(NativeSetupError::Vault(VaultError::InsecureParent))
    ));

    let lock_profile = tempfile::tempdir().unwrap();
    let lock_parent = lock_profile.path().join("ethereum");
    fs::create_dir(&lock_parent).unwrap();
    fs::set_permissions(&lock_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let lock_target = lock_parent.join("lock-target");
    fs::write(&lock_target, b"").unwrap();
    fs::set_permissions(&lock_target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(
        &lock_target,
        lock_parent.join(".ratspeak-ethereum-wallet.lock"),
    )
    .unwrap();
    let mut setup = RestoreSetup::new("correct passphrase");
    let mut fresh = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::restore(
            vault_path(lock_profile.path()),
            &mut setup,
            &mut fresh,
            kdf(),
        ),
        Err(NativeSetupError::Vault(VaultError::InsecureFile))
    ));
}

#[test]
fn passphrase_rotation_is_generational_and_detects_rollback() {
    let profile = tempfile::tempdir().unwrap();
    let old = passphrase("old correct passphrase");
    let new = passphrase("new correct passphrase");
    let (controller, mut counter) = create(profile.path(), "old correct passphrase");
    let generation_one = fs::read(controller.vault().path()).unwrap();
    let metadata = controller
        .change_passphrase(&old, &new, &mut counter, kdf())
        .unwrap();
    assert_eq!(metadata.generation(), 2);
    assert!(matches!(
        controller.wallet_account(&old, &mut counter),
        Err(NativeVaultError::Vault(VaultError::AuthenticationFailed))
    ));
    assert_eq!(
        controller
            .wallet_account(&new, &mut counter)
            .unwrap()
            .into_value()
            .address(),
        address(ADDRESS)
    );
    fs::write(controller.vault().path(), generation_one).unwrap();
    assert!(matches!(
        controller.wallet_account(&old, &mut counter),
        Err(NativeVaultError::Vault(VaultError::RollbackDetected {
            found: 1,
            minimum: 2
        }))
    ));
}

#[test]
fn invalid_rotation_and_duplicate_creation_leave_existing_vault_usable() {
    let profile = tempfile::tempdir().unwrap();
    let old = passphrase("old correct passphrase");
    let new = passphrase("new correct passphrase");
    let (controller, mut counter) = create(profile.path(), "old correct passphrase");
    let before = fs::read(controller.vault().path()).unwrap();
    let invalid = VaultKdfParameters {
        memory_kib: 1,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        controller.change_passphrase(&old, &new, &mut counter, invalid),
        Err(NativeVaultError::Vault(VaultError::InvalidKdfParameters))
    ));
    assert_eq!(fs::read(controller.vault().path()).unwrap(), before);
    assert_eq!(
        controller
            .wallet_account(&old, &mut counter)
            .unwrap()
            .into_value()
            .address(),
        address(ADDRESS)
    );
    let mut duplicate_setup = RestoreSetup::new("new correct passphrase");
    let mut duplicate_counter = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::restore(
            controller.vault().path(),
            &mut duplicate_setup,
            &mut duplicate_counter,
            kdf(),
        ),
        Err(NativeSetupError::Vault(VaultError::AlreadyExists))
    ));
    assert_eq!(fs::read(controller.vault().path()).unwrap(), before);
}

#[test]
fn a_concurrent_operation_fails_busy_instead_of_blocking() {
    let profile = tempfile::tempdir().unwrap();
    let pass = passphrase("correct passphrase");
    let (controller, mut counter) = create(profile.path(), "correct passphrase");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            profile
                .path()
                .join("ethereum")
                .join(".ratspeak-ethereum-wallet.lock"),
        )
        .unwrap();
    rustix::fs::flock(&lock, FlockOperation::LockExclusive).unwrap();
    assert!(matches!(
        controller.wallet_account(&pass, &mut counter),
        Err(NativeVaultError::Vault(VaultError::Busy))
    ));
}

struct NativeReview {
    passphrase: Option<VaultPassphrase>,
    calls: Cell<usize>,
    observed_digest: Option<[u8; 32]>,
}

struct ScriptedClock {
    times: VecDeque<u64>,
    calls: usize,
}

impl ScriptedClock {
    fn new(times: impl IntoIterator<Item = u64>) -> Self {
        Self {
            times: times.into_iter().collect(),
            calls: 0,
        }
    }
}

impl TrustedClock for ScriptedClock {
    type Error = ();

    fn now_unix(&mut self) -> Result<u64, Self::Error> {
        self.calls += 1;
        self.times.pop_front().ok_or(())
    }
}

impl NativeTransferAuthorization for NativeReview {
    type Error = ();

    fn review_and_request_passphrase(
        &mut self,
        review: &TransferReview,
    ) -> Result<NativeTransferDecision, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        self.observed_digest = Some(review.review_digest().into());
        self.passphrase
            .take()
            .map(NativeTransferDecision::Approve)
            .ok_or(())
    }
}

fn prepared(account: WalletAccount, operation: u8) -> ratspeak_eth_wallet::PreparedTransfer {
    account
        .prepare_transfer(
            TransferIntent::new(
                SEPOLIA_CHAIN_ID,
                account.address(),
                address("1111111111111111111111111111111111111111"),
                U256::from(1_000_000_000_000_000u64),
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

#[test]
fn native_review_boundary_signs_only_the_exact_prepared_transfer_once() {
    let profile = tempfile::tempdir().unwrap();
    let pass = passphrase("correct passphrase");
    let (controller, mut counter) = create(profile.path(), "correct passphrase");
    let account = controller
        .wallet_account(&pass, &mut counter)
        .unwrap()
        .into_value();
    let transfer = prepared(account, 7);
    let expected_digest: [u8; 32] = transfer.review().review_digest().into();
    let mut native = NativeReview {
        passphrase: Some(passphrase("correct passphrase")),
        calls: Cell::new(0),
        observed_digest: None,
    };
    let mut clock = ScriptedClock::new([1_001, 1_002]);
    let signed = controller
        .authorize_and_sign(transfer, &mut counter, &mut native, &mut clock)
        .unwrap();
    assert_eq!(native.calls.get(), 1);
    assert_eq!(clock.calls, 2);
    assert_eq!(native.observed_digest, Some(expected_digest));
    assert_eq!(signed.into_value().review().from(), account.address());

    let mut should_prompt_once = NativeReview {
        passphrase: Some(passphrase("correct passphrase")),
        calls: Cell::new(0),
        observed_digest: None,
    };
    let mut advancing_clock = ScriptedClock::new([1_001, 1_100]);
    assert!(matches!(
        controller.authorize_and_sign(
            prepared(account, 8),
            &mut counter,
            &mut should_prompt_once,
            &mut advancing_clock,
        ),
        Err(NativeControllerSignError::Wallet(WalletError::Expired))
    ));
    assert_eq!(should_prompt_once.calls.get(), 1);

    let mut before_window = NativeReview {
        passphrase: Some(passphrase("correct passphrase")),
        calls: Cell::new(0),
        observed_digest: None,
    };
    let mut early_clock = ScriptedClock::new([999]);
    assert!(matches!(
        controller.authorize_and_sign(
            prepared(account, 9),
            &mut counter,
            &mut before_window,
            &mut early_clock,
        ),
        Err(NativeControllerSignError::Wallet(WalletError::NotYetValid))
    ));
    assert_eq!(before_window.calls.get(), 0);
}

#[test]
fn kdf_passphrase_generation_and_identity_bounds_fail_before_creation() {
    let profile = tempfile::tempdir().unwrap();
    assert!(matches!(
        VaultPassphrase::new(String::new()),
        Err(VaultError::InvalidPassphrase)
    ));
    assert!(matches!(
        VaultPassphrase::new("x".repeat(1025)),
        Err(VaultError::InvalidPassphrase)
    ));
    assert!(matches!(
        GenerationFloor::new(0),
        Err(VaultError::InvalidGenerationFloor)
    ));
    assert!(matches!(
        TrustedVaultBinding::new(
            [0; 32],
            GenerationFloor::INITIAL,
            WalletAccount::sepolia(address(ADDRESS)),
        ),
        Err(VaultError::InvalidVaultIdentity)
    ));
    let weak = VaultKdfParameters {
        memory_kib: VaultKdfParameters::MIN_MEMORY_KIB - 1,
        iterations: VaultKdfParameters::MIN_ITERATIONS,
        parallelism: 1,
    };
    let mut setup = RestoreSetup::new("correct passphrase");
    let mut counter = Counter::fresh();
    assert!(matches!(
        LinuxWalletController::restore(vault_path(profile.path()), &mut setup, &mut counter, weak,),
        Err(NativeSetupError::Vault(VaultError::InvalidKdfParameters))
    ));
    assert_eq!(counter.0, TrustedGenerationState::NeverInitialized);
    assert!(!vault_path(profile.path()).exists());
}
