//! Linux custody primitives for the experimental Sepolia wallet.
//!
//! This crate stores one BIP-39 recovery phrase in a versioned Argon2id and
//! ChaCha20-Poly1305 vault. It keeps decrypted recovery material inside private
//! per-operation scopes. Native dialogs are represented by narrow traits so a
//! GTK adapter can render setup and the exact [`TransferReview`] without
//! sending secrets through WebView IPC. The controller is headless-testable;
//! this crate does not select or initialize a GTK runtime.
//! The caller supplies a trusted profile-root path; the final vault parent and
//! file entries are opened and validated without following symlinks.
//!
//! A valid vault file cannot detect that the whole file was replaced with an
//! older valid copy. [`LinuxWalletController`] therefore requires a generation
//! counter kept in separately protected monotonic storage. Storing that counter
//! beside the vault in ordinary SQLite is not an independent rollback boundary.
//!
//! Owned passphrases, plaintext recovery buffers, and raw KDF output are
//! zeroized on drop. This experimental crate does not claim that every
//! internal allocation made by its cryptographic dependencies is zeroized.

pub const LINUX_CUSTODY_PRIMITIVES_AVAILABLE: bool = cfg!(target_os = "linux");
/// A concrete GTK3 dialog adapter is included. A Linux release must still keep
/// custody unavailable until the application wires it to a trusted profile and
/// installs a separately protected generation store.
pub const LINUX_NATIVE_DIALOG_ADAPTER_INCLUDED: bool = cfg!(target_os = "linux");
/// Plaintext files, environment variables, and in-memory unlocked sessions are
/// not fallback custody modes for this crate.
pub const PLAINTEXT_CUSTODY_FALLBACK_AVAILABLE: bool = false;

#[cfg(target_os = "linux")]
mod format;
#[cfg(target_os = "linux")]
mod gtk_adapter;
#[cfg(target_os = "linux")]
mod secret_service_store;
#[cfg(target_os = "linux")]
mod storage;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::OsString,
        fmt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use ratspeak_eth_wallet::{
        OperationId, PreparedTransfer, SignedTransfer, TransferAuthorizer, TransferReview,
        WalletAccount, WalletError, WalletSecret,
    };
    use zeroize::Zeroizing;

    use crate::{format, storage};

    pub const VAULT_VERSION: u16 = format::VAULT_VERSION;
    pub const MAX_VAULT_BYTES: usize = format::MAX_VAULT_BYTES;
    pub const DEFAULT_KDF_PARAMETERS: VaultKdfParameters = VaultKdfParameters {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    #[derive(Debug, thiserror::Error)]
    pub enum VaultError {
        #[error("vault path must have a normal file name and parent directory")]
        InvalidPath,
        #[error("vault parent directory is missing")]
        MissingParent,
        #[error("vault parent directory must be owned by this user and private")]
        InsecureParent,
        #[error(
            "vault or lock file must be a private, single-link regular file owned by this user"
        )]
        InsecureFile,
        #[error("vault already exists")]
        AlreadyExists,
        #[error("vault does not exist")]
        NotFound,
        #[error("vault is busy in another operation")]
        Busy,
        #[error("vault passphrase must contain between 1 and {MAX_PASSPHRASE_BYTES} UTF-8 bytes")]
        InvalidPassphrase,
        #[error("Argon2id parameters are outside the accepted safety bounds")]
        InvalidKdfParameters,
        #[error("vault is too large")]
        OversizedVault,
        #[error("vault format is malformed or truncated")]
        InvalidFormat,
        #[error("unsupported vault version {0}")]
        UnsupportedVersion(u16),
        #[error("vault authentication failed")]
        AuthenticationFailed,
        #[error("vault contains an invalid recovery phrase")]
        InvalidRecoveryPhrase,
        #[error("wallet account derivation failed")]
        WalletDerivation,
        #[error("vault generation {found} is older than required generation {minimum}")]
        RollbackDetected { found: u64, minimum: u64 },
        #[error("expected vault generation {expected}, found {found}")]
        StaleGeneration { expected: u64, found: u64 },
        #[error("vault generation overflow")]
        GenerationOverflow,
        #[error("vault generation floor must be at least one")]
        InvalidGenerationFloor,
        #[error("vault identity must not be all zeroes")]
        InvalidVaultIdentity,
        #[error("vault identity does not match separately trusted state")]
        VaultIdentityMismatch,
        #[error("secure random generation failed")]
        Randomness,
        #[error("vault persistence failed during {operation}: {source}")]
        Io {
            operation: &'static str,
            #[source]
            source: std::io::Error,
        },
        #[error("vault replacement completed but directory durability could not be confirmed")]
        DurabilityUncertain,
    }

    pub type Result<T> = std::result::Result<T, VaultError>;

    pub const MAX_PASSPHRASE_BYTES: usize = 1024;

    /// An owned passphrase that is redacted and zeroized on drop.
    pub struct VaultPassphrase(Zeroizing<String>);

    impl VaultPassphrase {
        pub fn new(passphrase: String) -> Result<Self> {
            let passphrase = Zeroizing::new(passphrase);
            if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
                return Err(VaultError::InvalidPassphrase);
            }
            Ok(Self(passphrase))
        }

        pub(crate) fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }

    impl fmt::Debug for VaultPassphrase {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("VaultPassphrase")
                .field(&"[REDACTED]")
                .finish()
        }
    }

    /// Recovery words collected by a native secret-entry surface.
    ///
    /// This type is deliberately neither cloneable nor serializable and has no
    /// `Debug` or `Display` implementation. Its allocation is zeroized on drop.
    pub struct RecoveryPhraseInput(Zeroizing<String>);

    impl RecoveryPhraseInput {
        pub fn new(phrase: String) -> Self {
            Self(Zeroizing::new(phrase))
        }

        fn as_str(&self) -> &str {
            self.0.as_str()
        }
    }

    /// Ephemeral recovery words shown only by the native setup surface.
    ///
    /// The view cannot be retained beyond the callback and deliberately has no
    /// formatting or serialization implementation.
    pub struct RecoveryPhraseView<'a>(&'a str);

    impl RecoveryPhraseView<'_> {
        #[cfg(test)]
        pub(crate) const fn from_phrase(phrase: &str) -> RecoveryPhraseView<'_> {
            RecoveryPhraseView(phrase)
        }

        pub fn words(&self) -> &str {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VaultKdfParameters {
        pub memory_kib: u32,
        pub iterations: u32,
        pub parallelism: u32,
    }

    impl VaultKdfParameters {
        pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
        pub const MAX_MEMORY_KIB: u32 = 128 * 1024;
        pub const MIN_ITERATIONS: u32 = 2;
        pub const MAX_ITERATIONS: u32 = 6;
        pub const MAX_PARALLELISM: u32 = 4;

        pub fn validate(self) -> Result<Self> {
            if self.memory_kib < Self::MIN_MEMORY_KIB
                || self.memory_kib > Self::MAX_MEMORY_KIB
                || self.iterations < Self::MIN_ITERATIONS
                || self.iterations > Self::MAX_ITERATIONS
                || self.parallelism == 0
                || self.parallelism > Self::MAX_PARALLELISM
            {
                return Err(VaultError::InvalidKdfParameters);
            }
            Ok(self)
        }
    }

    /// Minimum authenticated generation accepted by an unlock operation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GenerationFloor(u64);

    impl GenerationFloor {
        pub const INITIAL: Self = Self(1);

        pub fn new(generation: u64) -> Result<Self> {
            if generation == 0 {
                return Err(VaultError::InvalidGenerationFloor);
            }
            Ok(Self(generation))
        }

        pub const fn get(self) -> u64 {
            self.0
        }
    }

    /// Stable random identity authenticated inside the vault and pinned by the
    /// separately trusted counter store.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct VaultIdentity([u8; 32]);

    impl VaultIdentity {
        pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
            if bytes == [0; 32] {
                return Err(VaultError::InvalidVaultIdentity);
            }
            Ok(Self(bytes))
        }

        pub const fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }

    impl fmt::Debug for VaultIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("VaultIdentity").field(&"[REDACTED]").finish()
        }
    }

    /// Exact non-secret wallet binding held by separately protected storage.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct TrustedVaultBinding {
        vault_identity: VaultIdentity,
        generation: GenerationFloor,
        account: WalletAccount,
    }

    impl TrustedVaultBinding {
        pub fn new(
            vault_identity: [u8; 32],
            generation: GenerationFloor,
            account: WalletAccount,
        ) -> Result<Self> {
            Ok(Self {
                vault_identity: VaultIdentity::from_bytes(vault_identity)?,
                generation,
                account,
            })
        }

        pub const fn vault_identity(self) -> VaultIdentity {
            self.vault_identity
        }

        pub const fn generation(self) -> GenerationFloor {
            self.generation
        }

        pub const fn account(self) -> WalletAccount {
            self.account
        }
    }

    impl fmt::Debug for TrustedVaultBinding {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TrustedVaultBinding")
                .field("vault_identity", &self.vault_identity)
                .field("generation", &self.generation)
                .field("account", &self.account)
                .finish()
        }
    }

    /// State reported by independently protected monotonic storage.
    ///
    /// `NeverInitialized` is accepted only while creating or restoring a new
    /// profile. Once initialized, deletion and corruption must be represented
    /// explicitly and fail closed rather than silently becoming a fresh store.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TrustedGenerationState {
        NeverInitialized,
        Current(TrustedVaultBinding),
        MissingAfterInitialization,
        Corrupt,
    }

    /// Separately trusted monotonic storage for the authenticated vault version.
    ///
    /// A production implementation should use an OS credential/key store or an
    /// equivalently independent rollback-resistant boundary. Implementations
    /// must make `initialize` and `advance` compare-and-set operations.
    pub trait TrustedGenerationCounter {
        type Error;

        fn state(&mut self) -> std::result::Result<TrustedGenerationState, Self::Error>;

        fn initialize(
            &mut self,
            binding: TrustedVaultBinding,
        ) -> std::result::Result<(), Self::Error>;

        fn advance(
            &mut self,
            expected: TrustedVaultBinding,
            next: TrustedVaultBinding,
        ) -> std::result::Result<(), Self::Error>;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AuthenticatedVaultMetadata {
        generation: u64,
        kdf: VaultKdfParameters,
        vault_identity: VaultIdentity,
    }

    impl AuthenticatedVaultMetadata {
        pub const fn generation(self) -> u64 {
            self.generation
        }

        pub const fn kdf_parameters(self) -> VaultKdfParameters {
            self.kdf
        }

        pub const fn vault_identity(self) -> VaultIdentity {
            self.vault_identity
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct VaultUse<T> {
        value: T,
        metadata: AuthenticatedVaultMetadata,
    }

    impl<T> VaultUse<T> {
        pub fn into_value(self) -> T {
            self.value
        }

        pub const fn metadata(&self) -> AuthenticatedVaultMetadata {
            self.metadata
        }
    }

    /// Handle to a vault path. It never caches an unlocked secret.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LinuxWalletVault {
        parent: PathBuf,
        file_name: OsString,
    }

    impl LinuxWalletVault {
        pub fn at_path(path: impl AsRef<Path>) -> Result<Self> {
            let path = path.as_ref();
            let parent = path.parent().ok_or(VaultError::InvalidPath)?;
            let file_name = path.file_name().ok_or(VaultError::InvalidPath)?;
            if file_name.is_empty() || parent.as_os_str().is_empty() {
                return Err(VaultError::InvalidPath);
            }
            Ok(Self {
                parent: parent.to_path_buf(),
                file_name: file_name.to_os_string(),
            })
        }

        pub fn path(&self) -> PathBuf {
            self.parent.join(&self.file_name)
        }

        /// Creates one private parent directory if it is absent, then creates
        /// the vault without replacing any existing entry.
        fn create_new(
            path: impl AsRef<Path>,
            secret: &WalletSecret,
            passphrase: &VaultPassphrase,
            vault_identity: VaultIdentity,
            kdf: VaultKdfParameters,
        ) -> Result<Self> {
            let vault = Self::at_path(path)?;
            storage::ensure_private_parent(&vault.parent)?;
            let parent = storage::open_private_parent(&vault.parent)?;
            let _lock = storage::lock_exclusive(&parent)?;
            let encoded = secret.with_recovery_phrase(|phrase| {
                format::seal(
                    phrase.as_bytes(),
                    passphrase,
                    *vault_identity.as_bytes(),
                    1,
                    kdf,
                )
            })?;
            storage::install_new(&parent, &vault.file_name, &encoded)?;
            Ok(vault)
        }

        /// Derives the public Sepolia account without exposing a secret handle.
        fn wallet_account(
            &self,
            passphrase: &VaultPassphrase,
            minimum_generation: GenerationFloor,
        ) -> Result<VaultUse<WalletAccount>> {
            let used = self
                .with_wallet_secret(passphrase, minimum_generation, |secret, _| secret.account())?;
            let metadata = used.metadata;
            let account = used.value.map_err(|_| VaultError::WalletDerivation)?;
            Ok(VaultUse {
                value: account,
                metadata,
            })
        }

        /// Internal one-operation secret scope. Deliberately not public: public
        /// callers receive only narrow account/signing operations.
        fn with_wallet_secret<T>(
            &self,
            passphrase: &VaultPassphrase,
            minimum_generation: GenerationFloor,
            use_secret: impl FnOnce(&WalletSecret, AuthenticatedVaultMetadata) -> T,
        ) -> Result<VaultUse<T>> {
            let parent = storage::open_private_parent(&self.parent)?;
            let _lock = storage::lock_shared(&parent)?;
            let encoded = storage::read_vault(&parent, &self.file_name)?;
            let opened = format::open(&encoded, passphrase, minimum_generation.get())?;
            let metadata = AuthenticatedVaultMetadata {
                generation: opened.generation,
                kdf: opened.kdf,
                vault_identity: VaultIdentity::from_bytes(opened.vault_id)?,
            };
            let value = use_secret(&opened.secret, metadata);
            Ok(VaultUse { value, metadata })
        }

        /// Re-encrypts the same recovery phrase under a new passphrase and KDF
        /// configuration. A generation mismatch fails before replacement.
        fn change_passphrase(
            &self,
            current_passphrase: &VaultPassphrase,
            new_passphrase: &VaultPassphrase,
            expected: TrustedVaultBinding,
            new_kdf: VaultKdfParameters,
        ) -> Result<AuthenticatedVaultMetadata> {
            let parent = storage::open_private_parent(&self.parent)?;
            let _lock = storage::lock_exclusive(&parent)?;
            let encoded = storage::read_vault(&parent, &self.file_name)?;
            let opened = format::open(&encoded, current_passphrase, expected.generation().get())?;
            if opened.vault_id != *expected.vault_identity().as_bytes() {
                return Err(VaultError::VaultIdentityMismatch);
            }
            if opened.generation != expected.generation().get() {
                return Err(VaultError::StaleGeneration {
                    expected: expected.generation().get(),
                    found: opened.generation,
                });
            }
            let next_generation = expected
                .generation()
                .get()
                .checked_add(1)
                .ok_or(VaultError::GenerationOverflow)?;
            let replacement = opened.secret.with_recovery_phrase(|phrase| {
                format::seal(
                    phrase.as_bytes(),
                    new_passphrase,
                    opened.vault_id,
                    next_generation,
                    new_kdf,
                )
            })?;
            storage::replace(&parent, &self.file_name, &replacement)?;
            Ok(AuthenticatedVaultMetadata {
                generation: next_generation,
                kdf: new_kdf,
                vault_identity: expected.vault_identity(),
            })
        }

        /// Runs a native review/passphrase prompt and signs without retaining
        /// an unlocked wallet after the operation.
        fn authorize_and_sign<A, C>(
            &self,
            prepared: PreparedTransfer,
            expected: TrustedVaultBinding,
            authorizer: &mut A,
            clock: &mut C,
        ) -> std::result::Result<VaultUse<SignedTransfer>, NativeSignError<A::Error, C::Error>>
        where
            A: NativeTransferAuthorization,
            C: TrustedClock,
        {
            let before_review = clock.now_unix().map_err(NativeSignError::Clock)?;
            if before_review < prepared.review().prepared_at_unix() {
                return Err(NativeSignError::Wallet(WalletError::NotYetValid));
            }
            if before_review >= prepared.review().expires_at_unix() {
                return Err(NativeSignError::Wallet(WalletError::Expired));
            }
            let binding = ReviewBinding::from_review(prepared.review());
            let decision = authorizer
                .review_and_request_passphrase(prepared.review())
                .map_err(NativeSignError::Authorization)?;
            let passphrase = match decision {
                NativeTransferDecision::Approve(passphrase) => passphrase,
                NativeTransferDecision::Cancel => return Err(NativeSignError::Cancelled),
            };
            let used = self
                .with_wallet_secret(&passphrase, expected.generation(), |secret, metadata| {
                    if metadata.vault_identity() != expected.vault_identity() {
                        return Err(NativeSignError::Vault(VaultError::VaultIdentityMismatch));
                    }
                    let account = secret
                        .account()
                        .map_err(|_| NativeSignError::Vault(VaultError::WalletDerivation))?;
                    if account != expected.account() {
                        return Err(NativeSignError::Vault(VaultError::VaultIdentityMismatch));
                    }
                    let immediately_before_sign =
                        clock.now_unix().map_err(NativeSignError::Clock)?;
                    let mut authorization = ConsumedAuthorization::new(binding);
                    prepared
                        .authorize_and_sign(secret, &mut authorization, immediately_before_sign)
                        .map_err(NativeSignError::Wallet)
                })
                .map_err(NativeSignError::Vault)?;
            let metadata = used.metadata;
            let signed = used.value?;
            Ok(VaultUse {
                value: signed,
                metadata,
            })
        }
    }

    /// Native setup contract. Implementations must use native secret widgets;
    /// none of these values may cross WebView IPC or be logged.
    pub trait NativeWalletSetup {
        type Error;

        fn request_new_passphrase(
            &mut self,
        ) -> std::result::Result<Option<VaultPassphrase>, Self::Error>;

        fn confirm_recovery_backup(
            &mut self,
            recovery: RecoveryPhraseView<'_>,
        ) -> std::result::Result<bool, Self::Error>;

        fn request_recovery_phrase(
            &mut self,
        ) -> std::result::Result<Option<RecoveryPhraseInput>, Self::Error>;
    }

    /// Native-only recovery reveal contract. The controller authenticates the
    /// vault and account before it supplies the callback-scoped words.
    pub trait NativeRecoveryReveal {
        type Error;

        fn request_passphrase(
            &mut self,
        ) -> std::result::Result<Option<VaultPassphrase>, Self::Error>;

        fn show_recovery_phrase(
            &mut self,
            recovery: RecoveryPhraseView<'_>,
        ) -> std::result::Result<(), Self::Error>;
    }

    /// Coordinates one native custody operation at a time without retaining an
    /// unlocked secret or passphrase.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LinuxWalletController {
        vault: LinuxWalletVault,
    }

    impl LinuxWalletController {
        pub const fn from_vault(vault: LinuxWalletVault) -> Self {
            Self { vault }
        }

        pub const fn vault(&self) -> &LinuxWalletVault {
            &self.vault
        }

        /// Generates a wallet, requires explicit native backup acknowledgement,
        /// and installs generation one. The counter is initialized before the
        /// vault file so interrupted setup fails closed on the next attempt.
        pub fn create_generated<S, G>(
            path: impl AsRef<Path>,
            setup: &mut S,
            generations: &mut G,
            kdf: VaultKdfParameters,
        ) -> std::result::Result<Self, NativeSetupError<S::Error, G::Error>>
        where
            S: NativeWalletSetup,
            G: TrustedGenerationCounter,
        {
            let kdf = kdf.validate().map_err(NativeSetupError::Vault)?;
            match generations.state().map_err(NativeSetupError::Generation)? {
                TrustedGenerationState::NeverInitialized => {}
                state => return Err(NativeSetupError::GenerationState(state)),
            }
            let passphrase = setup
                .request_new_passphrase()
                .map_err(NativeSetupError::Native)?
                .ok_or(NativeSetupError::Cancelled)?;
            let secret = WalletSecret::generate().map_err(NativeSetupError::Wallet)?;
            let acknowledged = secret.with_recovery_phrase(|phrase| {
                setup.confirm_recovery_backup(RecoveryPhraseView(phrase))
            });
            if !acknowledged.map_err(NativeSetupError::Native)? {
                return Err(NativeSetupError::BackupNotAcknowledged);
            }
            let account = secret.account().map_err(NativeSetupError::Wallet)?;
            let vault_identity = VaultIdentity::from_bytes(
                format::random_vault_id().map_err(NativeSetupError::Vault)?,
            )
            .map_err(NativeSetupError::Vault)?;
            let binding = TrustedVaultBinding {
                vault_identity,
                generation: GenerationFloor::INITIAL,
                account,
            };
            generations
                .initialize(binding)
                .map_err(NativeSetupError::Generation)?;
            let vault =
                LinuxWalletVault::create_new(path, &secret, &passphrase, vault_identity, kdf)
                    .map_err(NativeSetupError::Vault)?;
            Ok(Self::from_vault(vault))
        }

        /// Restores a standard English BIP-39 phrase into a fresh profile.
        pub fn restore<S, G>(
            path: impl AsRef<Path>,
            setup: &mut S,
            generations: &mut G,
            kdf: VaultKdfParameters,
        ) -> std::result::Result<Self, NativeSetupError<S::Error, G::Error>>
        where
            S: NativeWalletSetup,
            G: TrustedGenerationCounter,
        {
            let kdf = kdf.validate().map_err(NativeSetupError::Vault)?;
            match generations.state().map_err(NativeSetupError::Generation)? {
                TrustedGenerationState::NeverInitialized => {}
                state => return Err(NativeSetupError::GenerationState(state)),
            }
            let recovery = setup
                .request_recovery_phrase()
                .map_err(NativeSetupError::Native)?
                .ok_or(NativeSetupError::Cancelled)?;
            let secret = WalletSecret::import_recovery_phrase(recovery.as_str())
                .map_err(NativeSetupError::Wallet)?;
            let passphrase = setup
                .request_new_passphrase()
                .map_err(NativeSetupError::Native)?
                .ok_or(NativeSetupError::Cancelled)?;
            let account = secret.account().map_err(NativeSetupError::Wallet)?;
            let vault_identity = VaultIdentity::from_bytes(
                format::random_vault_id().map_err(NativeSetupError::Vault)?,
            )
            .map_err(NativeSetupError::Vault)?;
            let binding = TrustedVaultBinding {
                vault_identity,
                generation: GenerationFloor::INITIAL,
                account,
            };
            generations
                .initialize(binding)
                .map_err(NativeSetupError::Generation)?;
            let vault =
                LinuxWalletVault::create_new(path, &secret, &passphrase, vault_identity, kdf)
                    .map_err(NativeSetupError::Vault)?;
            Ok(Self::from_vault(vault))
        }

        pub fn wallet_account<G>(
            &self,
            passphrase: &VaultPassphrase,
            generations: &mut G,
        ) -> std::result::Result<VaultUse<WalletAccount>, NativeVaultError<G::Error>>
        where
            G: TrustedGenerationCounter,
        {
            let binding = trusted_binding(generations)?;
            let used = self
                .vault
                .wallet_account(passphrase, binding.generation())
                .map_err(NativeVaultError::Vault)?;
            verify_binding_after_use(generations, binding, used.metadata(), used.value)?;
            Ok(used)
        }

        /// Authenticates this vault against separately trusted state, reveals
        /// recovery words only inside a native callback, then rechecks that
        /// trusted state did not change during the operation.
        pub fn reveal_recovery<R, G>(
            &self,
            reveal: &mut R,
            generations: &mut G,
        ) -> std::result::Result<(), NativeRevealError<R::Error, G::Error>>
        where
            R: NativeRecoveryReveal,
            G: TrustedGenerationCounter,
        {
            let binding = trusted_binding(generations).map_err(NativeRevealError::VaultBoundary)?;
            let passphrase = reveal
                .request_passphrase()
                .map_err(NativeRevealError::Native)?
                .ok_or(NativeRevealError::Cancelled)?;
            let used = self
                .vault
                .with_wallet_secret(&passphrase, binding.generation(), |secret, metadata| {
                    if metadata.vault_identity() != binding.vault_identity() {
                        return Err(NativeRevealError::Vault(VaultError::VaultIdentityMismatch));
                    }
                    let account = secret
                        .account()
                        .map_err(|_| NativeRevealError::Vault(VaultError::WalletDerivation))?;
                    if account != binding.account() {
                        return Err(NativeRevealError::Vault(VaultError::VaultIdentityMismatch));
                    }
                    match generations.state().map_err(NativeRevealError::Generation)? {
                        TrustedGenerationState::Current(current) if current == binding => {}
                        state => return Err(NativeRevealError::GenerationState(state)),
                    }
                    secret.with_recovery_phrase(|phrase| {
                        reveal
                            .show_recovery_phrase(RecoveryPhraseView(phrase))
                            .map_err(NativeRevealError::Native)
                    })
                })
                .map_err(NativeRevealError::Vault)?;
            let metadata = used.metadata();
            used.value?;
            verify_binding_after_use(generations, binding, metadata, binding.account())
                .map_err(NativeRevealError::VaultBoundary)
        }

        /// Advances the trusted counter before replacing the vault. A crash or
        /// write failure can make the vault temporarily unusable, but cannot
        /// silently make an older generation acceptable.
        pub fn change_passphrase<G>(
            &self,
            current_passphrase: &VaultPassphrase,
            new_passphrase: &VaultPassphrase,
            generations: &mut G,
            new_kdf: VaultKdfParameters,
        ) -> std::result::Result<AuthenticatedVaultMetadata, NativeVaultError<G::Error>>
        where
            G: TrustedGenerationCounter,
        {
            let new_kdf = new_kdf.validate().map_err(NativeVaultError::Vault)?;
            let current = trusted_binding(generations)?;
            let authenticated = self
                .vault
                .wallet_account(current_passphrase, current.generation())
                .map_err(NativeVaultError::Vault)?;
            verify_binding_after_use(
                generations,
                current,
                authenticated.metadata(),
                authenticated.value,
            )?;
            let next_generation = current
                .generation()
                .get()
                .checked_add(1)
                .ok_or(NativeVaultError::Vault(VaultError::GenerationOverflow))?;
            let next = TrustedVaultBinding {
                vault_identity: current.vault_identity(),
                generation: GenerationFloor::new(next_generation)
                    .map_err(NativeVaultError::Vault)?,
                account: current.account(),
            };
            generations
                .advance(current, next)
                .map_err(NativeVaultError::Generation)?;
            let metadata = self
                .vault
                .change_passphrase(current_passphrase, new_passphrase, current, new_kdf)
                .map_err(NativeVaultError::Vault)?;
            verify_binding_after_use(generations, next, metadata, current.account())?;
            Ok(metadata)
        }

        pub fn authorize_and_sign<A, C, G>(
            &self,
            prepared: PreparedTransfer,
            generations: &mut G,
            authorizer: &mut A,
            clock: &mut C,
        ) -> NativeControllerSignResult<A::Error, C::Error, G::Error>
        where
            A: NativeTransferAuthorization,
            C: TrustedClock,
            G: TrustedGenerationCounter,
        {
            let binding =
                trusted_binding(generations).map_err(NativeControllerSignError::VaultBoundary)?;
            let used = self
                .vault
                .authorize_and_sign(prepared, binding, authorizer, clock)
                .map_err(|error| match error {
                    NativeSignError::Authorization(error) => {
                        NativeControllerSignError::Authorization(error)
                    }
                    NativeSignError::Clock(error) => NativeControllerSignError::Clock(error),
                    NativeSignError::Vault(error) => NativeControllerSignError::Vault(error),
                    NativeSignError::Wallet(error) => NativeControllerSignError::Wallet(error),
                    NativeSignError::Cancelled => NativeControllerSignError::Cancelled,
                })?;
            verify_binding_after_use(
                generations,
                binding,
                used.metadata(),
                WalletAccount::sepolia(used.value.review().from()),
            )
            .map_err(NativeControllerSignError::VaultBoundary)?;
            Ok(used)
        }
    }

    fn trusted_binding<G: TrustedGenerationCounter>(
        generations: &mut G,
    ) -> std::result::Result<TrustedVaultBinding, NativeVaultError<G::Error>> {
        match generations.state().map_err(NativeVaultError::Generation)? {
            TrustedGenerationState::Current(binding) => Ok(binding),
            state => Err(NativeVaultError::GenerationState(state)),
        }
    }

    fn verify_binding_after_use<G: TrustedGenerationCounter>(
        generations: &mut G,
        expected: TrustedVaultBinding,
        metadata: AuthenticatedVaultMetadata,
        account: WalletAccount,
    ) -> std::result::Result<(), NativeVaultError<G::Error>> {
        if metadata.vault_identity() != expected.vault_identity() || account != expected.account() {
            return Err(NativeVaultError::Vault(VaultError::VaultIdentityMismatch));
        }
        if metadata.generation() != expected.generation().get() {
            return Err(NativeVaultError::Vault(VaultError::StaleGeneration {
                expected: expected.generation().get(),
                found: metadata.generation(),
            }));
        }
        match generations.state().map_err(NativeVaultError::Generation)? {
            TrustedGenerationState::Current(current) if current == expected => Ok(()),
            state => Err(NativeVaultError::GenerationState(state)),
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NativeSetupError<N, G> {
        #[error("native wallet setup failed")]
        Native(N),
        #[error("native wallet setup was cancelled")]
        Cancelled,
        #[error("recovery backup was not acknowledged")]
        BackupNotAcknowledged,
        #[error("trusted generation storage failed")]
        Generation(G),
        #[error("trusted generation storage is not fresh: {0:?}")]
        GenerationState(TrustedGenerationState),
        #[error(transparent)]
        Vault(VaultError),
        #[error(transparent)]
        Wallet(WalletError),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NativeVaultError<G> {
        #[error("trusted generation storage failed")]
        Generation(G),
        #[error("trusted generation storage is unavailable or changed: {0:?}")]
        GenerationState(TrustedGenerationState),
        #[error(transparent)]
        Vault(VaultError),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NativeRevealError<N, G> {
        #[error("native recovery reveal failed")]
        Native(N),
        #[error("native recovery reveal was cancelled")]
        Cancelled,
        #[error("trusted generation storage failed")]
        Generation(G),
        #[error("trusted generation storage changed during recovery reveal: {0:?}")]
        GenerationState(TrustedGenerationState),
        #[error(transparent)]
        Vault(VaultError),
        #[error(transparent)]
        VaultBoundary(NativeVaultError<G>),
    }

    /// Native-only authorization contract. Implementations must display every
    /// field in the supplied immutable review (operation, chain/network,
    /// sender, recipient, value, nonce, gas, fees, maximum cost, validity
    /// window, review-context commitment, signing hash, and review digest) and
    /// collect the passphrase without WebView IPC. `Approve` must follow an
    /// explicit native user gesture; merely opening or rendering a dialog is
    /// not approval.
    pub trait NativeTransferAuthorization {
        type Error;

        fn review_and_request_passphrase(
            &mut self,
            review: &TransferReview,
        ) -> std::result::Result<NativeTransferDecision, Self::Error>;
    }

    /// Native decision for one exact transfer review.
    pub enum NativeTransferDecision {
        Approve(VaultPassphrase),
        Cancel,
    }

    /// Clock boundary owned by trusted native code. Production implementations
    /// must not accept time from a WebView, gateway, or untrusted response.
    pub trait TrustedClock {
        type Error;

        fn now_unix(&mut self) -> std::result::Result<u64, Self::Error>;
    }

    /// Host wall clock for the production Linux adapter.
    #[derive(Debug, Default)]
    pub struct SystemClock;

    impl TrustedClock for SystemClock {
        type Error = SystemClockError;

        fn now_unix(&mut self) -> std::result::Result<u64, Self::Error> {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .map_err(|_| SystemClockError)
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("system clock predates the Unix epoch")]
    pub struct SystemClockError;

    #[derive(Debug, thiserror::Error)]
    pub enum NativeSignError<E, C> {
        #[error("native transfer authorization failed")]
        Authorization(E),
        #[error("trusted clock failed")]
        Clock(C),
        #[error(transparent)]
        Vault(#[from] VaultError),
        #[error(transparent)]
        Wallet(#[from] WalletError),
        #[error("native transfer authorization was cancelled")]
        Cancelled,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NativeControllerSignError<A, C, G> {
        #[error("native transfer authorization failed")]
        Authorization(A),
        #[error("native transfer authorization was cancelled")]
        Cancelled,
        #[error("trusted clock failed")]
        Clock(C),
        #[error(transparent)]
        Vault(VaultError),
        #[error(transparent)]
        Wallet(WalletError),
        #[error(transparent)]
        VaultBoundary(NativeVaultError<G>),
    }

    pub type NativeControllerSignResult<A, C, G> =
        std::result::Result<VaultUse<SignedTransfer>, NativeControllerSignError<A, C, G>>;

    #[derive(Clone, Copy)]
    struct ReviewBinding {
        operation_id: OperationId,
        review_digest: [u8; 32],
    }

    impl ReviewBinding {
        fn from_review(review: &TransferReview) -> Self {
            Self {
                operation_id: review.operation_id(),
                review_digest: review.review_digest().into(),
            }
        }
    }

    struct ConsumedAuthorization {
        binding: ReviewBinding,
        consumed: bool,
    }

    impl ConsumedAuthorization {
        fn new(binding: ReviewBinding) -> Self {
            Self {
                binding,
                consumed: false,
            }
        }
    }

    impl TransferAuthorizer for ConsumedAuthorization {
        type Error = ();

        fn authorize_transfer(
            &mut self,
            review: &TransferReview,
        ) -> std::result::Result<(), Self::Error> {
            if self.consumed
                || self.binding.operation_id != review.operation_id()
                || self.binding.review_digest != <[u8; 32]>::from(review.review_digest())
            {
                return Err(());
            }
            self.consumed = true;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub use gtk_adapter::*;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
pub use secret_service_store::*;
