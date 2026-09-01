//! Separately protected Linux generation-floor storage.
//!
//! Secret Service protects this non-secret binding independently from the
//! wallet vault and SQLite. Its item replacement API is not claimed to be a
//! hardware monotonic counter or atomically rollback-proof. Duplicate,
//! missing-after-initialization, corrupt, and interrupted replacement states
//! are rejected rather than guessed through.

use std::{collections::HashMap, sync::Mutex};

use alloy_primitives::Address;
use ratspeak_eth_wallet::WalletAccount;
use ring::digest::{SHA256, digest};
use secret_service::{EncryptionType, blocking::SecretService};

use crate::{
    GenerationFloor, TrustedGenerationCounter, TrustedGenerationState, TrustedVaultBinding,
};

const ITEM_SCHEMA: &str = "ratspeak.ethereum.trusted-generation.v1";
const ITEM_LABEL: &str = "Ratspeak Ethereum trusted vault generation";
const CONTENT_TYPE: &str = "application/octet-stream";
const RECORD_VERSION: u8 = 1;
const RECORD_BODY_BYTES: usize = 1 + 32 + 8 + 20;
const RECORD_BYTES: usize = RECORD_BODY_BYTES + 32;

static SECRET_SERVICE_OPERATIONS: Mutex<()> = Mutex::new(());

/// Opaque profile namespace used only as a Secret Service search attribute.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretServiceProfileKey([u8; 32]);

impl SecretServiceProfileKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretServiceStoreError> {
        if bytes == [0; 32] {
            return Err(SecretServiceStoreError::InvalidProfileKey);
        }
        Ok(Self(bytes))
    }

    fn encoded(self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

impl std::fmt::Debug for SecretServiceProfileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretServiceProfileKey([REDACTED])")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretServiceStoreError {
    #[error("invalid protected generation profile namespace")]
    InvalidProfileKey,
    #[error("desktop Secret Service is unavailable or denied access")]
    Unavailable,
    #[error("desktop Secret Service returned ambiguous matching items")]
    AmbiguousItems,
    #[error("desktop Secret Service generation item is corrupt")]
    CorruptItem,
    #[error("trusted generation compare-and-set failed")]
    CompareAndSet,
    #[error("trusted generation operation is already in progress")]
    Busy,
}

#[doc(hidden)]
pub trait GenerationItemBackend {
    fn read(
        &mut self,
        profile: SecretServiceProfileKey,
    ) -> Result<Vec<Vec<u8>>, SecretServiceStoreError>;
    fn create(
        &mut self,
        profile: SecretServiceProfileKey,
        value: &[u8],
    ) -> Result<(), SecretServiceStoreError>;
    fn replace(
        &mut self,
        profile: SecretServiceProfileKey,
        value: &[u8],
    ) -> Result<(), SecretServiceStoreError>;
}

#[derive(Default)]
#[doc(hidden)]
pub struct DesktopSecretService;

impl DesktopSecretService {
    fn with_collection<T>(
        operation: impl FnOnce(
            &SecretService<'_>,
            &secret_service::blocking::Collection<'_>,
        ) -> Result<T, secret_service::Error>,
    ) -> Result<T, SecretServiceStoreError> {
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| SecretServiceStoreError::Unavailable)?;
        let collection = service
            .get_default_collection()
            .map_err(|_| SecretServiceStoreError::Unavailable)?;
        collection
            .ensure_unlocked()
            .or_else(|_| collection.unlock())
            .map_err(|_| SecretServiceStoreError::Unavailable)?;
        operation(&service, &collection).map_err(|_| SecretServiceStoreError::Unavailable)
    }
}

fn attributes(profile: SecretServiceProfileKey) -> HashMap<&'static str, String> {
    HashMap::from([
        ("application", "org.ratspeak.Ratspeak".to_owned()),
        ("schema", ITEM_SCHEMA.to_owned()),
        ("profile", profile.encoded()),
    ])
}

fn borrowed_attributes<'a>(
    attributes: &'a HashMap<&'static str, String>,
) -> HashMap<&'a str, &'a str> {
    attributes
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect()
}

impl GenerationItemBackend for DesktopSecretService {
    fn read(
        &mut self,
        profile: SecretServiceProfileKey,
    ) -> Result<Vec<Vec<u8>>, SecretServiceStoreError> {
        Self::with_collection(|service, _| {
            let attributes = attributes(profile);
            let mut found = service.search_items(borrowed_attributes(&attributes))?;
            for item in &found.locked {
                item.unlock()?;
            }
            found.unlocked.append(&mut found.locked);
            found
                .unlocked
                .iter()
                .map(|item| item.get_secret())
                .collect()
        })
    }

    fn create(
        &mut self,
        profile: SecretServiceProfileKey,
        value: &[u8],
    ) -> Result<(), SecretServiceStoreError> {
        Self::with_collection(|_, collection| {
            let attributes = attributes(profile);
            collection.create_item(
                ITEM_LABEL,
                borrowed_attributes(&attributes),
                value,
                false,
                CONTENT_TYPE,
            )?;
            Ok(())
        })
    }

    fn replace(
        &mut self,
        profile: SecretServiceProfileKey,
        value: &[u8],
    ) -> Result<(), SecretServiceStoreError> {
        Self::with_collection(|_, collection| {
            let attributes = attributes(profile);
            collection.create_item(
                ITEM_LABEL,
                borrowed_attributes(&attributes),
                value,
                true,
                CONTENT_TYPE,
            )?;
            Ok(())
        })
    }
}

/// Production `TrustedGenerationCounter` backed by the user's Secret Service.
///
/// `profile_was_initialized` comes from the public wallet binding. It is not
/// trusted as a generation floor; it only ensures deletion of the protected
/// item cannot be mistaken for a fresh wallet profile.
pub struct SecretServiceGenerationStore<B = DesktopSecretService> {
    profile: SecretServiceProfileKey,
    profile_was_initialized: bool,
    backend: B,
}

impl SecretServiceGenerationStore {
    pub fn connect(
        profile: SecretServiceProfileKey,
        profile_was_initialized: bool,
    ) -> Result<Self, SecretServiceStoreError> {
        // Probe the protected service now so availability reporting is truthful.
        let mut store = Self {
            profile,
            profile_was_initialized,
            backend: DesktopSecretService,
        };
        let _ = store.read_state()?;
        Ok(store)
    }
}

impl<B: GenerationItemBackend> SecretServiceGenerationStore<B> {
    #[cfg(test)]
    fn with_backend(
        profile: SecretServiceProfileKey,
        profile_was_initialized: bool,
        backend: B,
    ) -> Self {
        Self {
            profile,
            profile_was_initialized,
            backend,
        }
    }

    fn read_state(&mut self) -> Result<TrustedGenerationState, SecretServiceStoreError> {
        let items = self.backend.read(self.profile)?;
        match items.as_slice() {
            [] if self.profile_was_initialized => {
                Ok(TrustedGenerationState::MissingAfterInitialization)
            }
            [] => Ok(TrustedGenerationState::NeverInitialized),
            [item] => decode_binding(item)
                .map(TrustedGenerationState::Current)
                .or(Ok(TrustedGenerationState::Corrupt)),
            _ => Err(SecretServiceStoreError::AmbiguousItems),
        }
    }

    fn verify_exact(
        &mut self,
        expected: TrustedVaultBinding,
    ) -> Result<(), SecretServiceStoreError> {
        match self.read_state()? {
            TrustedGenerationState::Current(found) if found == expected => Ok(()),
            _ => Err(SecretServiceStoreError::CompareAndSet),
        }
    }
}

impl<B: GenerationItemBackend> TrustedGenerationCounter for SecretServiceGenerationStore<B> {
    type Error = SecretServiceStoreError;

    fn state(&mut self) -> Result<TrustedGenerationState, Self::Error> {
        let _guard = SECRET_SERVICE_OPERATIONS
            .lock()
            .map_err(|_| SecretServiceStoreError::Busy)?;
        self.read_state()
    }

    fn initialize(&mut self, binding: TrustedVaultBinding) -> Result<(), Self::Error> {
        let _guard = SECRET_SERVICE_OPERATIONS
            .lock()
            .map_err(|_| SecretServiceStoreError::Busy)?;
        if self.read_state()? != TrustedGenerationState::NeverInitialized {
            return Err(SecretServiceStoreError::CompareAndSet);
        }
        self.backend
            .create(self.profile, &encode_binding(binding))?;
        self.verify_exact(binding)?;
        self.profile_was_initialized = true;
        Ok(())
    }

    fn advance(
        &mut self,
        expected: TrustedVaultBinding,
        next: TrustedVaultBinding,
    ) -> Result<(), Self::Error> {
        let _guard = SECRET_SERVICE_OPERATIONS
            .lock()
            .map_err(|_| SecretServiceStoreError::Busy)?;
        self.verify_exact(expected)?;
        if next.vault_identity() != expected.vault_identity()
            || next.account() != expected.account()
            || next.generation().get() != expected.generation().get().saturating_add(1)
        {
            return Err(SecretServiceStoreError::CompareAndSet);
        }
        self.backend.replace(self.profile, &encode_binding(next))?;
        self.verify_exact(next)
    }
}

fn encode_binding(binding: TrustedVaultBinding) -> [u8; RECORD_BYTES] {
    let mut encoded = [0u8; RECORD_BYTES];
    encoded[0] = RECORD_VERSION;
    encoded[1..33].copy_from_slice(binding.vault_identity().as_bytes());
    encoded[33..41].copy_from_slice(&binding.generation().get().to_be_bytes());
    encoded[41..61].copy_from_slice(binding.account().address().as_slice());
    let checksum = digest(&SHA256, &encoded[..RECORD_BODY_BYTES]);
    encoded[RECORD_BODY_BYTES..].copy_from_slice(checksum.as_ref());
    encoded
}

fn decode_binding(encoded: &[u8]) -> Result<TrustedVaultBinding, SecretServiceStoreError> {
    if encoded.len() != RECORD_BYTES || encoded[0] != RECORD_VERSION {
        return Err(SecretServiceStoreError::CorruptItem);
    }
    let expected = digest(&SHA256, &encoded[..RECORD_BODY_BYTES]);
    if expected.as_ref() != &encoded[RECORD_BODY_BYTES..] {
        return Err(SecretServiceStoreError::CorruptItem);
    }
    let vault_identity = encoded[1..33]
        .try_into()
        .map_err(|_| SecretServiceStoreError::CorruptItem)?;
    let generation = u64::from_be_bytes(
        encoded[33..41]
            .try_into()
            .map_err(|_| SecretServiceStoreError::CorruptItem)?,
    );
    let address = Address::from_slice(&encoded[41..61]);
    TrustedVaultBinding::new(
        vault_identity,
        GenerationFloor::new(generation).map_err(|_| SecretServiceStoreError::CorruptItem)?,
        WalletAccount::sepolia(address),
    )
    .map_err(|_| SecretServiceStoreError::CorruptItem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct MockBackend {
        items: Vec<Vec<u8>>,
        fail_replace: bool,
        reads: VecDeque<Vec<Vec<u8>>>,
    }

    impl GenerationItemBackend for MockBackend {
        fn read(
            &mut self,
            _: SecretServiceProfileKey,
        ) -> Result<Vec<Vec<u8>>, SecretServiceStoreError> {
            Ok(self.reads.pop_front().unwrap_or_else(|| self.items.clone()))
        }
        fn create(
            &mut self,
            _: SecretServiceProfileKey,
            value: &[u8],
        ) -> Result<(), SecretServiceStoreError> {
            self.items.push(value.to_vec());
            Ok(())
        }
        fn replace(
            &mut self,
            _: SecretServiceProfileKey,
            value: &[u8],
        ) -> Result<(), SecretServiceStoreError> {
            if self.fail_replace {
                return Err(SecretServiceStoreError::Unavailable);
            }
            self.items = vec![value.to_vec()];
            Ok(())
        }
    }

    fn profile() -> SecretServiceProfileKey {
        SecretServiceProfileKey::from_bytes([7; 32]).unwrap()
    }

    fn binding(generation: u64) -> TrustedVaultBinding {
        TrustedVaultBinding::new(
            [9; 32],
            GenerationFloor::new(generation).unwrap(),
            WalletAccount::sepolia(Address::repeat_byte(3)),
        )
        .unwrap()
    }

    #[test]
    fn fresh_initialize_and_exact_advance_round_trip() {
        let mut store =
            SecretServiceGenerationStore::with_backend(profile(), false, MockBackend::default());
        assert_eq!(
            store.state().unwrap(),
            TrustedGenerationState::NeverInitialized
        );
        store.initialize(binding(1)).unwrap();
        store.advance(binding(1), binding(2)).unwrap();
        assert_eq!(
            store.state().unwrap(),
            TrustedGenerationState::Current(binding(2))
        );
    }

    #[test]
    fn missing_known_profile_duplicate_corrupt_and_rollback_fail_closed() {
        let mut missing =
            SecretServiceGenerationStore::with_backend(profile(), true, MockBackend::default());
        assert_eq!(
            missing.state().unwrap(),
            TrustedGenerationState::MissingAfterInitialization
        );

        let duplicate = MockBackend {
            items: vec![encode_binding(binding(1)).to_vec(); 2],
            ..Default::default()
        };
        let mut store = SecretServiceGenerationStore::with_backend(profile(), true, duplicate);
        assert!(matches!(
            store.state(),
            Err(SecretServiceStoreError::AmbiguousItems)
        ));

        let corrupt = MockBackend {
            items: vec![vec![1, 2, 3]],
            ..Default::default()
        };
        let mut store = SecretServiceGenerationStore::with_backend(profile(), true, corrupt);
        assert_eq!(store.state().unwrap(), TrustedGenerationState::Corrupt);

        let rollback = MockBackend {
            items: vec![encode_binding(binding(1)).to_vec()],
            ..Default::default()
        };
        let mut store = SecretServiceGenerationStore::with_backend(profile(), true, rollback);
        assert!(matches!(
            store.advance(binding(2), binding(3)),
            Err(SecretServiceStoreError::CompareAndSet)
        ));
    }

    #[test]
    fn replacement_failure_and_concurrent_change_never_report_success() {
        let backend = MockBackend {
            items: vec![encode_binding(binding(1)).to_vec()],
            fail_replace: true,
            ..Default::default()
        };
        let mut store = SecretServiceGenerationStore::with_backend(profile(), true, backend);
        assert!(matches!(
            store.advance(binding(1), binding(2)),
            Err(SecretServiceStoreError::Unavailable)
        ));

        let backend = MockBackend {
            items: vec![encode_binding(binding(1)).to_vec()],
            reads: VecDeque::from([
                vec![encode_binding(binding(1)).to_vec()],
                vec![encode_binding(binding(3)).to_vec()],
            ]),
            ..Default::default()
        };
        let mut store = SecretServiceGenerationStore::with_backend(profile(), true, backend);
        assert!(matches!(
            store.advance(binding(1), binding(2)),
            Err(SecretServiceStoreError::CompareAndSet)
        ));
    }
}
