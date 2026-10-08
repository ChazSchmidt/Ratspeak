//! Native Android wallet engine and JNI boundary.
//!
//! Kotlin owns hardware-backed custody and the biometric review ceremony.
//! Rust owns derivation, exact prepared-transfer matching, signing, sender
//! recovery, and atomic field-node persistence. None of these functions are
//! Tauri commands or WebView interfaces.

#![cfg_attr(all(test, not(target_os = "android")), allow(dead_code))]

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "android")]
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "android")]
use std::path::PathBuf;
#[cfg(target_os = "android")]
use std::sync::OnceLock;

#[cfg(target_os = "android")]
use ratspeak_eth_node::{
    BulkEvidenceReviewDecision, BulkEvidenceReviewResolution, CheckpointBootstrapPolicy,
    ManualCheckpointReviewResolution, ManualCheckpointSource, MessagingEvidenceKind,
    NativeCheckpointApproval, PendingBulkEvidenceReview, PendingManualCheckpointReview,
};
use ratspeak_eth_node::{
    EthereumNodeStore, FieldNodeClock, PlatformTransferCustody, PreparedFieldTransfer,
    StoredSignedTransaction,
};
#[cfg(target_os = "android")]
use ratspeak_eth_wallet::MAX_PREPARED_LIFETIME_SECONDS;
use ratspeak_eth_wallet::{
    ClearSignAuthorizer, OperationId, PreparedClearSignedOperation, PreparedTransfer,
    SignedTransfer, TransferAuthorizer, WalletAccount, WalletError, WalletSecret,
};
#[cfg(target_os = "android")]
use tauri::Manager;

#[cfg(target_os = "android")]
use crate::ethereum::EthereumGatewayCard;
use crate::ethereum::{
    EthereumApplicationState, NativeClearSignedCandidate, NativeExactTransferCandidate,
};
#[cfg(target_os = "android")]
use crate::ethereum::{EthereumNativeTransportProfileBinding, EthereumProfileGeneration};
#[cfg(any(target_os = "android", target_os = "linux", test))]
use crate::ethereum::EthereumClearSignedOperationRequest;
#[cfg(target_os = "android")]
use crate::ethereum::{
    EthereumNativeWalletLaunchRequest, EthereumNativeWalletLaunchView,
    MAX_CURRENT_EVIDENCE_AGE_SECONDS,
};

const MAX_PENDING_WALLETS: usize = 4;
const ADDRESS_BYTES: usize = 42;
const MAX_NATIVE_FRAME_BYTES: usize = 8 * 1024;
const MAX_BULK_REVIEW_SESSION_SECONDS: u64 = 5 * 60;
const MAX_CHECKPOINT_REVIEW_SESSION_SECONDS: u64 = 5 * 60;
const MAX_CHECKPOINT_FILE_IMPORT_SESSION_SECONDS: u64 = 5 * 60;
const MAX_GATEWAY_CARD_IMPORT_SESSION_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineFailure {
    Unavailable = 1,
    InvalidRecoveryPhrase = 2,
    InvalidWalletMaterial = 3,
    ReviewMismatch = 4,
    SigningFailed = 5,
    OperationFailed = 6,
}

struct SecretBytes(Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl SecretBytes {
    fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct CreatedWallet {
    handle: u64,
    address: String,
    recovery_phrase: SecretBytes,
    custody_secret: SecretBytes,
}

#[derive(Clone, Copy)]
struct PendingWallet {
    account: WalletAccount,
    identity: AndroidIdentityBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AndroidIdentityBinding {
    hash: [u8; 16],
    session_generation: u64,
}

struct AndroidWalletEngineCore {
    handle_state: RandomState,
    handle_nonce: AtomicU64,
    pending: Mutex<HashMap<u64, PendingWallet>>,
}

impl AndroidWalletEngineCore {
    fn new() -> Self {
        Self {
            handle_state: RandomState::new(),
            handle_nonce: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn create_wallet(
        &self,
        profile_dir: &Path,
        identity: AndroidIdentityBinding,
    ) -> Result<CreatedWallet, EngineFailure> {
        let secret = WalletSecret::generate().map_err(map_wallet_material_error)?;
        self.stage_wallet(profile_dir, identity, secret)
    }

    fn restore_wallet(
        &self,
        profile_dir: &Path,
        identity: AndroidIdentityBinding,
        recovery_phrase: &[u8],
    ) -> Result<CreatedWallet, EngineFailure> {
        let phrase = std::str::from_utf8(recovery_phrase)
            .map_err(|_| EngineFailure::InvalidRecoveryPhrase)?;
        let secret =
            WalletSecret::import_recovery_phrase(phrase).map_err(map_wallet_material_error)?;
        self.stage_wallet(profile_dir, identity, secret)
    }

    fn stage_wallet(
        &self,
        profile_dir: &Path,
        identity: AndroidIdentityBinding,
        secret: WalletSecret,
    ) -> Result<CreatedWallet, EngineFailure> {
        let account = secret.account().map_err(map_wallet_material_error)?;
        if EthereumNodeStore::open_in_profile(profile_dir)
            .map_err(|_| EngineFailure::OperationFailed)?
            .wallet_account()
            .map_err(|_| EngineFailure::OperationFailed)?
            .is_some_and(|installed| installed != account)
        {
            return Err(EngineFailure::InvalidWalletMaterial);
        }
        let phrase =
            secret.with_recovery_phrase(|phrase| SecretBytes::from_slice(phrase.as_bytes()));
        let custody_secret = SecretBytes::from_slice(phrase.as_slice());
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if pending.len() >= MAX_PENDING_WALLETS {
            return Err(EngineFailure::OperationFailed);
        }
        let handle = self.random_pending_handle(&pending, account)?;
        pending.insert(handle, PendingWallet { account, identity });
        Ok(CreatedWallet {
            handle,
            address: format!("{:#x}", account.address()),
            recovery_phrase: phrase,
            custody_secret,
        })
    }

    fn discard_pending_wallet(&self, handle: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&handle);
        }
    }

    fn activate_wallet(
        &self,
        state: &EthereumApplicationState,
        profile_dir: &Path,
        identity: AndroidIdentityBinding,
        handle: u64,
        expected_address: Option<&str>,
    ) -> Result<String, EngineFailure> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?
            .remove(&handle)
            .ok_or(EngineFailure::InvalidWalletMaterial)?;
        let address = format!("{:#x}", pending.account.address());
        if pending.identity != identity {
            return Err(EngineFailure::OperationFailed);
        }
        if expected_address.is_some_and(|expected| !addresses_equal(expected, &address)) {
            return Err(EngineFailure::InvalidWalletMaterial);
        }
        let mut store = EthereumNodeStore::open_in_profile(profile_dir)
            .map_err(|_| EngineFailure::OperationFailed)?;
        store
            .install_wallet_account(pending.account)
            .map_err(|_| EngineFailure::InvalidWalletMaterial)?;
        state
            .install_profile_binding_for_identity(
                profile_dir.to_owned(),
                pending.account,
                identity.hash,
                identity.session_generation,
            )
            .map_err(|_| EngineFailure::OperationFailed)?;
        Ok(address)
    }

    fn reveal_recovery_phrase(
        &self,
        state: &EthereumApplicationState,
        identity: AndroidIdentityBinding,
        custody_secret: &[u8],
    ) -> Result<SecretBytes, EngineFailure> {
        let secret = import_custody_secret(custody_secret)?;
        let account = secret.account().map_err(map_wallet_material_error)?;
        let binding = state
            .native_profile_binding()
            .map_err(|_| EngineFailure::OperationFailed)?
            .ok_or(EngineFailure::Unavailable)?;
        if binding.public_account != account {
            return Err(EngineFailure::InvalidWalletMaterial);
        }
        if binding.ratspeak_identity_hash != identity.hash
            || binding.identity_session_generation != identity.session_generation
        {
            return Err(EngineFailure::OperationFailed);
        }
        Ok(secret.with_recovery_phrase(|phrase| SecretBytes::from_slice(phrase.as_bytes())))
    }

    fn sign_exact_transfer(
        &self,
        state: &EthereumApplicationState,
        identity: AndroidIdentityBinding,
        candidate: NativeExactTransferCandidate,
        custody_secret: &[u8],
    ) -> Result<StoredSignedTransaction, EngineFailure> {
        let secret = import_custody_secret(custody_secret)?;
        let account = secret.account().map_err(map_wallet_material_error)?;
        if candidate.sender != format!("{:#x}", account.address()) {
            return Err(EngineFailure::InvalidWalletMaterial);
        }
        let stored = state
            .with_native_transfer(
                identity.hash,
                identity.session_generation,
                account,
                &candidate,
                |profile_dir, pending| authorize_and_persist(profile_dir, pending, secret),
            )
            .map_err(|_| EngineFailure::ReviewMismatch)??;
        state.wake_outbound();
        Ok(stored)
    }

    fn sign_clear_signed_operation(
        &self,
        state: &EthereumApplicationState,
        identity: AndroidIdentityBinding,
        candidate: NativeClearSignedCandidate,
        custody_secret: &[u8],
    ) -> Result<StoredSignedTransaction, EngineFailure> {
        let secret = import_custody_secret(custody_secret)?;
        let account = secret.account().map_err(map_wallet_material_error)?;
        if candidate.sender != format!("{:#x}", account.address()) {
            return Err(EngineFailure::InvalidWalletMaterial);
        }
        let stored = state
            .with_native_clear_signed_operation(
                identity.hash,
                identity.session_generation,
                account,
                &candidate,
                |profile_dir, pending| {
                    authorize_clear_signed_and_persist(profile_dir, pending, secret)
                },
            )
            .map_err(|_| EngineFailure::ReviewMismatch)??;
        let now_unix = wall_clock_now_unix();
        if let Err(error) = state.plan_signed_relay_if_configured(
            identity.hash,
            identity.session_generation,
            &stored,
            now_unix,
        ) {
            tracing::warn!(
                reason = error,
                chain_id = stored.chain_id(),
                "ClearSign transaction persisted but relay planning was deferred"
            );
        }
        state.wake_outbound();
        Ok(stored)
    }

    fn random_pending_handle(
        &self,
        pending: &HashMap<u64, PendingWallet>,
        account: WalletAccount,
    ) -> Result<u64, EngineFailure> {
        for _ in 0..8 {
            let nonce = self.handle_nonce.fetch_add(1, Ordering::Relaxed);
            let mut hasher = self.handle_state.build_hasher();
            hasher.write(account.address().as_slice());
            hasher.write_u64(nonce);
            let handle = hasher.finish() & i64::MAX as u64;
            if handle != 0 && !pending.contains_key(&handle) {
                return Ok(handle);
            }
        }
        Err(EngineFailure::OperationFailed)
    }
}

fn import_custody_secret(bytes: &[u8]) -> Result<WalletSecret, EngineFailure> {
    let phrase = std::str::from_utf8(bytes).map_err(|_| EngineFailure::InvalidWalletMaterial)?;
    WalletSecret::import_recovery_phrase(phrase).map_err(map_wallet_material_error)
}

fn map_wallet_material_error(error: WalletError) -> EngineFailure {
    match error {
        WalletError::InvalidMnemonic | WalletError::RecoveryPhraseTooLong => {
            EngineFailure::InvalidRecoveryPhrase
        }
        _ => EngineFailure::InvalidWalletMaterial,
    }
}

fn addresses_equal(first: &str, second: &str) -> bool {
    first.len() == ADDRESS_BYTES && first.eq_ignore_ascii_case(second)
}

struct NativeApprovedCustody {
    secret: WalletSecret,
}

impl PlatformTransferCustody for NativeApprovedCustody {
    type Error = WalletError;

    fn authorize_and_sign(
        &mut self,
        prepared: PreparedTransfer,
    ) -> Result<SignedTransfer, Self::Error> {
        let mut authorizer = NativeReviewAlreadyApproved;
        prepared.authorize_and_sign(&self.secret, &mut authorizer, wall_clock_now_unix())
    }
}

struct NativeReviewAlreadyApproved;

impl TransferAuthorizer for NativeReviewAlreadyApproved {
    type Error = ();

    fn authorize_transfer(
        &mut self,
        _review: &ratspeak_eth_wallet::TransferReview,
    ) -> Result<(), Self::Error> {
        // Rust cannot independently attest the preceding BiometricPrompt.
        // This private adapter is confined to the native JNI sign path, which
        // also requires the unwrapped custody secret and one unique Rust-owned
        // prepared transfer matching every displayed field and signing byte.
        Ok(())
    }
}

struct NativeClearSignReviewAlreadyApproved;

impl ClearSignAuthorizer for NativeClearSignReviewAlreadyApproved {
    type Error = ();

    fn authorize_clear_signed_operation(
        &mut self,
        _review: &ratspeak_eth_wallet::ClearSignedTransferReview,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn authorize_clear_signed_and_persist(
    profile_dir: &Path,
    pending: PreparedClearSignedOperation,
    secret: WalletSecret,
) -> Result<StoredSignedTransaction, EngineFailure> {
    let expected_sender = pending.review().from.into_array();
    let review_digest = pending.review().review_digest.0;
    let mut authorizer = NativeClearSignReviewAlreadyApproved;
    let signed = pending
        .authorize_and_sign(&secret, &mut authorizer, wall_clock_now_unix())
        .map_err(|_| EngineFailure::SigningFailed)?;
    let mut store = EthereumNodeStore::open_in_profile(profile_dir)
        .map_err(|_| EngineFailure::OperationFailed)?;
    store
        .record_clear_signed_transaction(
            signed.raw_transaction(),
            expected_sender,
            review_digest,
            wall_clock_now_unix(),
        )
        .map(|(_, stored)| stored)
        .map_err(|_| EngineFailure::SigningFailed)
}

struct SystemClock;

impl FieldNodeClock for SystemClock {
    fn now_unix(&mut self) -> u64 {
        wall_clock_now_unix()
    }
}

fn wall_clock_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn authorize_and_persist(
    profile_dir: &Path,
    pending: PreparedFieldTransfer,
    secret: WalletSecret,
) -> Result<StoredSignedTransaction, EngineFailure> {
    let mut store = EthereumNodeStore::open_in_profile(profile_dir)
        .map_err(|_| EngineFailure::OperationFailed)?;
    let mut custody = NativeApprovedCustody { secret };
    let mut clock = SystemClock;
    store
        .authorize_and_store(pending, &mut custody, &mut clock)
        .map_err(|_| EngineFailure::SigningFailed)
}

fn failure_frame(failure: EngineFailure) -> Vec<u8> {
    vec![failure as u8]
}

fn public_value_frame(value: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + value.len());
    frame.push(0);
    frame.extend_from_slice(value.as_bytes());
    frame
}

fn created_wallet_frame(created: &CreatedWallet) -> Result<Vec<u8>, EngineFailure> {
    let phrase_len = u16::try_from(created.recovery_phrase.as_slice().len())
        .map_err(|_| EngineFailure::InvalidWalletMaterial)?;
    let secret_len = u16::try_from(created.custody_secret.as_slice().len())
        .map_err(|_| EngineFailure::InvalidWalletMaterial)?;
    if created.address.len() != ADDRESS_BYTES {
        return Err(EngineFailure::InvalidWalletMaterial);
    }
    let mut frame = Vec::with_capacity(
        1 + 8 + ADDRESS_BYTES + 2 + usize::from(phrase_len) + 2 + usize::from(secret_len),
    );
    frame.push(0);
    frame.extend_from_slice(&created.handle.to_be_bytes());
    frame.extend_from_slice(created.address.as_bytes());
    frame.extend_from_slice(&phrase_len.to_be_bytes());
    frame.extend_from_slice(created.recovery_phrase.as_slice());
    frame.extend_from_slice(&secret_len.to_be_bytes());
    frame.extend_from_slice(created.custody_secret.as_slice());
    Ok(frame)
}

fn secret_value_frame(value: &SecretBytes) -> Result<Vec<u8>, EngineFailure> {
    let length =
        u16::try_from(value.as_slice().len()).map_err(|_| EngineFailure::InvalidWalletMaterial)?;
    let mut frame = Vec::with_capacity(3 + usize::from(length));
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(value.as_slice());
    Ok(frame)
}

struct NativeFrameReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NativeFrameReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, EngineFailure> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_FRAME_BYTES {
            return Err(EngineFailure::ReviewMismatch);
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], EngineFailure> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(EngineFailure::ReviewMismatch)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, EngineFailure> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, EngineFailure> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| EngineFailure::ReviewMismatch)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, EngineFailure> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| EngineFailure::ReviewMismatch)?,
        ))
    }

    fn u128(&mut self) -> Result<u128, EngineFailure> {
        Ok(u128::from_be_bytes(
            self.take(16)?
                .try_into()
                .map_err(|_| EngineFailure::ReviewMismatch)?,
        ))
    }

    fn ascii(&mut self, length: usize) -> Result<String, EngineFailure> {
        let bytes = self.take(length)?;
        if !bytes.is_ascii() {
            return Err(EngineFailure::ReviewMismatch);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| EngineFailure::ReviewMismatch)
    }

    fn finish(self) -> Result<(), EngineFailure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EngineFailure::ReviewMismatch)
        }
    }
}

fn parse_review_frame(bytes: &[u8]) -> Result<NativeExactTransferCandidate, EngineFailure> {
    let mut reader = NativeFrameReader::new(bytes)?;
    if reader.take(1)? != [2] {
        return Err(EngineFailure::ReviewMismatch);
    }
    let operation_id = reader
        .take(16)?
        .try_into()
        .map_err(|_| EngineFailure::ReviewMismatch)?;
    if operation_id == [0; 16] {
        return Err(EngineFailure::ReviewMismatch);
    }
    let chain_id = reader.u64()?;
    let sender = canonical_address(reader.ascii(ADDRESS_BYTES)?)?;
    let recipient = canonical_address(reader.ascii(ADDRESS_BYTES)?)?;
    let value_len = usize::from(reader.u16()?);
    let value_wei = canonical_decimal(reader.ascii(value_len)?)?;
    let nonce = reader.u64()?;
    let gas_limit = reader.u64()?;
    let max_fee_per_gas_wei = reader.u128()?;
    let max_priority_fee_per_gas_wei = reader.u128()?;
    let expires_at_epoch_millis = reader.u64()?;
    if expires_at_epoch_millis == 0 || expires_at_epoch_millis % 1_000 != 0 {
        return Err(EngineFailure::ReviewMismatch);
    }
    let payload_len = usize::from(reader.u16()?);
    let canonical_signing_payload = reader.take(payload_len)?.to_vec();
    reader.finish()?;
    if canonical_signing_payload.is_empty()
        || canonical_signing_payload.len() > 4_096
        || max_priority_fee_per_gas_wei > max_fee_per_gas_wei
    {
        return Err(EngineFailure::ReviewMismatch);
    }
    Ok(NativeExactTransferCandidate {
        operation_id,
        chain_id,
        sender,
        recipient,
        value_wei,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        expires_at_unix: expires_at_epoch_millis / 1_000,
        canonical_signing_payload,
    })
}

fn parse_clear_signed_review_frame(
    bytes: &[u8],
) -> Result<NativeClearSignedCandidate, EngineFailure> {
    let mut reader = NativeFrameReader::new(bytes)?;
    if reader.u8()? != 3 {
        return Err(EngineFailure::ReviewMismatch);
    }
    let operation_id: [u8; 16] = reader
        .take(16)?
        .try_into()
        .map_err(|_| EngineFailure::ReviewMismatch)?;
    if operation_id == [0; 16] {
        return Err(EngineFailure::ReviewMismatch);
    }
    let chain_id = reader.u64()?;
    let sender = canonical_address(reader.ascii(ADDRESS_BYTES)?)?;
    let network_len = usize::from(reader.u16()?);
    let network = reader.ascii(network_len)?;
    let definition_hash: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| EngineFailure::ReviewMismatch)?;
    let operation_hash: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| EngineFailure::ReviewMismatch)?;
    let symbol_len = usize::from(reader.u16()?);
    let asset_symbol = reader.ascii(symbol_len)?;
    let asset_decimals = reader.u8()?;
    let recipient = canonical_address(reader.ascii(ADDRESS_BYTES)?)?;
    let amount_len = usize::from(reader.u16()?);
    let amount = canonical_decimal(reader.ascii(amount_len)?)?;
    let nonce = reader.u64()?;
    let gas_limit = reader.u64()?;
    let max_fee_per_gas_wei = reader.u128()?;
    let max_priority_fee_per_gas_wei = reader.u128()?;
    let expires_at_epoch_millis = reader.u64()?;
    if chain_id == 0
        || network.is_empty()
        || network.len() > 64
        || definition_hash == [0; 32]
        || operation_hash == [0; 32]
        || asset_symbol.is_empty()
        || asset_symbol.len() > 32
        || asset_decimals > 36
        || expires_at_epoch_millis == 0
        || expires_at_epoch_millis % 1_000 != 0
        || max_priority_fee_per_gas_wei > max_fee_per_gas_wei
    {
        return Err(EngineFailure::ReviewMismatch);
    }
    let payload_len = usize::from(reader.u16()?);
    let canonical_signing_payload = reader.take(payload_len)?.to_vec();
    reader.finish()?;
    if canonical_signing_payload.is_empty() || canonical_signing_payload.len() > 4_096 {
        return Err(EngineFailure::ReviewMismatch);
    }
    Ok(NativeClearSignedCandidate {
        operation_id,
        chain_id,
        sender,
        network,
        definition_hash,
        operation_hash,
        asset_symbol,
        asset_decimals,
        recipient,
        amount,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        expires_at_unix: expires_at_epoch_millis / 1_000,
        canonical_signing_payload,
    })
}

fn canonical_address(mut value: String) -> Result<String, EngineFailure> {
    if value.len() != ADDRESS_BYTES
        || !value.starts_with("0x")
        || !value.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(EngineFailure::ReviewMismatch);
    }
    value.make_ascii_lowercase();
    Ok(value)
}

fn canonical_decimal(value: String) -> Result<String, EngineFailure> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(EngineFailure::ReviewMismatch);
    }
    Ok(value)
}

#[cfg(target_os = "android")]
struct InstalledAndroidWalletEngine {
    app_handle: tauri::AppHandle,
    profile_dir: PathBuf,
    runtime: Arc<ratspeak_tauri::state::AppState>,
    wallet_ceremony_identity: Mutex<Option<AndroidIdentityBinding>>,
    bulk_review: Mutex<Option<AndroidBulkEvidenceReviewSession>>,
    checkpoint_review: Mutex<Option<AndroidCheckpointReviewSession>>,
    checkpoint_file_import: Mutex<Option<AndroidCheckpointFileImportSession>>,
    gateway_card_import: Mutex<Option<AndroidGatewayCardImportSession>>,
    gateway_card_review: Mutex<Option<AndroidGatewayCardReviewSession>>,
    core: AndroidWalletEngineCore,
}

/// Rust-owned, one-shot authority for a native bulk-evidence review.
///
/// The projection sent to Android is intentionally derived from `review` and
/// is never used for resolution. The exact private snapshot, canonical
/// profile binding, identity session, gateway, and expiry remain here until
/// the opaque token is consumed.
#[cfg(target_os = "android")]
struct AndroidBulkEvidenceReviewSession {
    token: String,
    review: PendingBulkEvidenceReview,
    binding: crate::ethereum::EthereumTransportBinding,
    expires_at_unix: u64,
    monotonic_deadline: Instant,
}

/// Rust-owned, one-shot authority for a native manual-checkpoint review.
///
/// The Android side receives only the public display projection. The exact
/// durable review, transport/profile identity binding, wall deadline, and
/// monotonic deadline remain here until the opaque token is consumed.
#[cfg(target_os = "android")]
struct AndroidCheckpointReviewSession {
    token: String,
    review: PendingManualCheckpointReview,
    binding: AndroidCheckpointProfileBinding,
    expires_at_unix: u64,
    monotonic_deadline: Instant,
}

/// Rust-owned, one-shot capability for a native-selected checkpoint card.
/// The Android document URI never enters this state; only the opaque token
/// and the bounded bytes returned by the system picker reach Rust.
#[cfg(target_os = "android")]
struct AndroidCheckpointFileImportSession {
    token: String,
    binding: AndroidCheckpointProfileBinding,
    expires_at_unix: u64,
    monotonic_deadline: Instant,
}

/// Rust-owned capability for the Android-selected public gateway card. The
/// system document URI and its bytes never enter this session.
#[cfg(target_os = "android")]
struct AndroidGatewayCardImportSession {
    token: String,
    binding: EthereumNativeTransportProfileBinding,
    expires_at_unix: u64,
    monotonic_deadline: Instant,
}

/// Rust-owned, one-shot approval session for an imported RSEG1 card. The
/// parsed card remains private until the native Activity consumes the token.
#[cfg(target_os = "android")]
struct AndroidGatewayCardReviewSession {
    token: String,
    binding: EthereumNativeTransportProfileBinding,
    card: EthereumGatewayCard,
    expires_at_unix: u64,
    monotonic_deadline: Instant,
}

#[cfg(target_os = "android")]
#[derive(Clone)]
struct AndroidCheckpointProfileBinding {
    profile_dir: PathBuf,
    profile_generation: EthereumProfileGeneration,
    identity: AndroidIdentityBinding,
}

#[cfg(target_os = "android")]
static INSTALLED_ENGINE: OnceLock<InstalledAndroidWalletEngine> = OnceLock::new();

#[cfg(target_os = "android")]
static ANDROID_CLASS_LOADER: OnceLock<jni::objects::GlobalRef> = OnceLock::new();

#[cfg(target_os = "android")]
pub(crate) fn install(
    app_handle: tauri::AppHandle,
    profile_dir: PathBuf,
    runtime: Arc<ratspeak_tauri::state::AppState>,
) -> Result<(), &'static str> {
    let mut store = EthereumNodeStore::open_in_profile(&profile_dir)
        .map_err(|_| "android_ethereum_store_unavailable")?;
    store
        .reconcile_interrupted_operations()
        .map_err(|_| "android_ethereum_store_reconciliation_failed")?;
    let restored_account = store
        .wallet_account()
        .map_err(|_| "android_ethereum_wallet_profile_invalid")?;
    if let Ok(identity) = active_identity_binding(&runtime) {
        let state = app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or("android_ethereum_state_unavailable")?;
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
    INSTALLED_ENGINE
        .set(InstalledAndroidWalletEngine {
            app_handle,
            profile_dir,
            runtime,
            wallet_ceremony_identity: Mutex::new(None),
            bulk_review: Mutex::new(None),
            checkpoint_review: Mutex::new(None),
            checkpoint_file_import: Mutex::new(None),
            gateway_card_import: Mutex::new(None),
            gateway_card_review: Mutex::new(None),
            core: AndroidWalletEngineCore::new(),
        })
        .map_err(|_| "android_ethereum_engine_already_installed")
}

#[cfg(target_os = "android")]
fn active_identity_binding(
    runtime: &ratspeak_tauri::state::AppState,
) -> Result<AndroidIdentityBinding, EngineFailure> {
    let before = runtime.current_identity_session_generation();
    let encoded = ratspeak_tauri::helpers::active_identity_id(runtime);
    let hash = decode_identity_hash(&encoded).ok_or(EngineFailure::Unavailable)?;
    let after = runtime.current_identity_session_generation();
    if before != after {
        return Err(EngineFailure::OperationFailed);
    }
    Ok(AndroidIdentityBinding {
        hash,
        session_generation: before,
    })
}

#[cfg(target_os = "android")]
fn begin_wallet_ceremony(
    installed: &InstalledAndroidWalletEngine,
    identity: AndroidIdentityBinding,
) -> Result<(), &'static str> {
    let mut active = installed
        .wallet_ceremony_identity
        .lock()
        .map_err(|_| "native_ethereum_wallet_unavailable")?;
    if active.is_some() {
        return Err("native_ethereum_wallet_busy");
    }
    *active = Some(identity);
    Ok(())
}

#[cfg(target_os = "android")]
fn end_wallet_ceremony(installed: &InstalledAndroidWalletEngine, identity: AndroidIdentityBinding) {
    if let Ok(mut active) = installed.wallet_ceremony_identity.lock() {
        if *active == Some(identity) {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn active_wallet_ceremony_identity(
    installed: &InstalledAndroidWalletEngine,
) -> Result<AndroidIdentityBinding, EngineFailure> {
    let current = active_identity_binding(&installed.runtime)?;
    let mut active = installed
        .wallet_ceremony_identity
        .lock()
        .map_err(|_| EngineFailure::OperationFailed)?;
    match *active {
        Some(expected) if expected == current => Ok(current),
        Some(_) => {
            // Once any profile change is observed, switching back cannot revive
            // the old native ceremony.
            *active = None;
            Err(EngineFailure::OperationFailed)
        }
        None => Err(EngineFailure::Unavailable),
    }
}

fn decode_identity_hash(encoded: &str) -> Option<[u8; 16]> {
    if encoded.len() != 32 || !encoded.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    (bytes != [0; 16]).then_some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(target_os = "android")]
pub(crate) fn launch_native_wallet(
    state: &EthereumApplicationState,
    request: EthereumNativeWalletLaunchRequest,
) -> Result<EthereumNativeWalletLaunchView, &'static str> {
    state.retry_native_cancellations();
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_wallet_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    let mut store = EthereumNodeStore::open_in_profile(&installed.profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let account = store
        .wallet_account()
        .map_err(|_| "ethereum_state_unavailable")?;
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
        EthereumNativeWalletLaunchRequest::ManageWallet => {
            let active_address = account.map(|account| format!("{:#x}", account.address()));
            begin_wallet_ceremony(installed, identity)?;
            if !android_launch_wallet(identity, active_address.as_deref()) {
                end_wallet_ceremony(installed, identity);
                return Err("native_ethereum_wallet_unavailable");
            }
            if active_identity_binding(&installed.runtime).ok() != Some(identity) {
                end_wallet_ceremony(installed, identity);
                return Err("ethereum_profile_changed");
            }
            Ok(EthereumNativeWalletLaunchView::wallet())
        }
        EthereumNativeWalletLaunchRequest::Transfer(intent) => {
            let account = account.ok_or("ethereum_wallet_unavailable")?;
            let generation = generation.ok_or("ethereum_profile_unavailable")?;
            let now_unix = wall_clock_now_unix();
            if now_unix == 0 {
                return Err("clock_unavailable");
            }
            let operation_id = state.next_operation_id(
                identity.hash,
                identity.session_generation,
                &intent,
                now_unix,
            )?;
            let expires_at_unix = now_unix
                .checked_add(MAX_PREPARED_LIFETIME_SECONDS)
                .ok_or("clock_unavailable")?;
            let pending = store
                .prepare_native_transfer(
                    account,
                    intent.field_request()?,
                    operation_id,
                    now_unix,
                    expires_at_unix,
                    MAX_CURRENT_EVIDENCE_AGE_SECONDS,
                )
                .map_err(|_| "ethereum_transfer_not_preparable")?;
            let launch = match AndroidTransferLaunch::from_pending(identity, &pending) {
                Ok(launch) => launch,
                Err(error) => {
                    let _ = store.cancel_operation(operation_id);
                    return Err(error);
                }
            };
            if let Err(error) = state.register_prepared_transfer(generation, pending) {
                let _ = store.cancel_operation(operation_id);
                return Err(error);
            }
            if active_identity_binding(&installed.runtime).ok() != Some(identity)
                || !android_launch_exact_transfer(&launch)
            {
                let _ = state.cancel_native_transfer(
                    identity.hash,
                    identity.session_generation,
                    *operation_id.as_bytes(),
                );
                return Err("native_ethereum_wallet_unavailable");
            }
            if active_identity_binding(&installed.runtime).ok() != Some(identity)
                || state
                    .ensure_native_identity(identity.hash, identity.session_generation)
                    .is_err()
            {
                let _ = state.cancel_native_transfer(
                    identity.hash,
                    identity.session_generation,
                    *operation_id.as_bytes(),
                );
                return Err("ethereum_profile_changed");
            }
            Ok(EthereumNativeWalletLaunchView::transfer_launched(
                operation_id,
            ))
        }
    }
}

#[cfg(target_os = "android")]
pub(crate) fn launch_native_clear_signed_operation(
    state: &EthereumApplicationState,
    request: EthereumClearSignedOperationRequest,
) -> Result<OperationId, &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_wallet_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    let store = EthereumNodeStore::open_in_profile(&installed.profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let account = store
        .wallet_account()
        .map_err(|_| "ethereum_state_unavailable")?
        .ok_or("ethereum_wallet_unavailable")?;
    let generation = state.install_profile_binding_for_identity(
        installed.profile_dir.clone(),
        account,
        identity.hash,
        identity.session_generation,
    )?;
    let now_unix = trusted_android_now_unix()?;
    let expires_at_unix = now_unix
        .checked_add(MAX_PREPARED_LIFETIME_SECONDS)
        .ok_or("clock_unavailable")?;
    let candidate = state.prepare_clear_signed_operation_for_native(
        generation,
        identity.hash,
        identity.session_generation,
        &request,
        now_unix,
        expires_at_unix,
    )?;
    let operation_id = OperationId::new(candidate.operation_id)
        .map_err(|_| "ethereum_operation_id_unavailable")?;
    let launch = AndroidClearSignedLaunch::from_candidate(identity, &candidate)?;
    if active_identity_binding(&installed.runtime).ok() != Some(identity)
        || !android_launch_clear_signed_operation(&launch)
    {
        let _ = state.cancel_native_clear_signed_operation(
            identity.hash,
            identity.session_generation,
            candidate.operation_id,
        );
        return Err("native_ethereum_wallet_unavailable");
    }
    if active_identity_binding(&installed.runtime).ok() != Some(identity)
        || state
            .ensure_native_identity(identity.hash, identity.session_generation)
            .is_err()
    {
        let _ = state.cancel_native_clear_signed_operation(
            identity.hash,
            identity.session_generation,
            candidate.operation_id,
        );
        return Err("ethereum_profile_changed");
    }
    Ok(operation_id)
}

#[cfg(any(target_os = "linux", test))]
#[allow(dead_code)]
pub(crate) fn launch_native_clear_signed_operation(
    _state: &EthereumApplicationState,
    _request: EthereumClearSignedOperationRequest,
) -> Result<OperationId, &'static str> {
    Err("native_ethereum_wallet_unavailable")
}

/// Begins the native Android review for the next exact durable bulk-evidence
/// manifest. This is the narrow platform seam intended for a later common
/// no-argument launcher; it is not a Tauri command and accepts no display
/// fields from a WebView.
#[cfg(target_os = "android")]
pub(crate) fn launch_native_bulk_evidence_review(
    state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_bulk_review_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    state.install_transport_profile_for_identity(
        installed.profile_dir.clone(),
        identity.hash,
        identity.session_generation,
    )?;
    let binding = state
        .transport_binding()?
        .ok_or("ethereum_profile_unavailable")?;
    let now_unix = trusted_android_now_unix()?;
    let mut store = EthereumNodeStore::open_in_profile(&binding.profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let review = store
        .pending_bulk_evidence_reviews(binding.gateway_destination_hash, now_unix)
        .map_err(|_| "ethereum_bulk_review_unavailable")?
        .into_iter()
        .next()
        .ok_or("ethereum_bulk_review_unavailable")?;
    if !state.transport_binding_is_current(&binding)? {
        return Err("ethereum_profile_changed");
    }
    launch_native_bulk_evidence_review_snapshot(state, binding, review)
}

/// Internal snapshot-taking seam. The snapshot remains private to Rust after
/// this call and is never reconstructed from Android's display projection.
#[cfg(target_os = "android")]
fn launch_native_bulk_evidence_review_snapshot(
    state: &EthereumApplicationState,
    binding: crate::ethereum::EthereumTransportBinding,
    review: PendingBulkEvidenceReview,
) -> Result<(), &'static str> {
    if !state.transport_binding_is_current(&binding)? {
        return Err("ethereum_profile_changed");
    }
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_bulk_review_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    if binding.ratspeak_identity_hash != identity.hash
        || binding.identity_session_generation != identity.session_generation
        || binding.profile_dir.canonicalize().ok().as_ref() != Some(&binding.profile_dir)
        || binding.gateway_destination_hash == [0; 16]
        || review.expected_gateway_source_hash() != binding.gateway_destination_hash
    {
        return Err("ethereum_profile_changed");
    }
    let now_unix = trusted_android_now_unix()?;
    if review.expires_at_unix() <= now_unix {
        return Err("ethereum_bulk_review_expired");
    }
    let monotonic_now = Instant::now();
    if let Ok(mut active) = installed.bulk_review.lock() {
        if active.as_ref().is_some_and(|session| {
            session.expires_at_unix <= now_unix || monotonic_now >= session.monotonic_deadline
        }) {
            // Timeout leaves the durable row pending for a bounded retry; it
            // never creates an approval and cannot starve the next review.
            *active = None;
        }
    }
    let (monotonic_deadline, deadline_unix) =
        bounded_bulk_review_deadline(Instant::now(), now_unix, review.expires_at_unix())?;
    let token = new_bulk_review_token()?;
    let session = AndroidBulkEvidenceReviewSession {
        token: token.clone(),
        expires_at_unix: deadline_unix,
        monotonic_deadline,
        review,
        binding,
    };
    let mut projection = bulk_review_projection_frame(&session.review, deadline_unix)?;
    {
        let mut active = installed
            .bulk_review
            .lock()
            .map_err(|_| "native_ethereum_bulk_review_unavailable")?;
        if active.is_some() {
            return Err("native_ethereum_bulk_review_busy");
        }
        *active = Some(session);
    }
    if !android_launch_bulk_review(&token, &projection) {
        projection_cleanup(&mut projection);
        abort_bulk_review_session(installed, &token);
        return Err("native_ethereum_bulk_review_unavailable");
    }
    projection_cleanup(&mut projection);
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn launch_native_bulk_evidence_review(
    _state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    Err("native_ethereum_bulk_review_unavailable")
}

/// Begins the native Android review for the next validated manual checkpoint.
/// Checkpoint trust is a local, out-of-band decision and is deliberately
/// independent of wallet custody. The transport-only profile/identity binding
/// is used as a lifecycle fence; no gateway value is displayed or treated as
/// checkpoint authority.
#[cfg(target_os = "android")]
pub(crate) fn launch_native_checkpoint_review(
    state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_checkpoint_review_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    state.install_transport_profile_for_identity(
        installed.profile_dir.clone(),
        identity.hash,
        identity.session_generation,
    )?;
    state
        .ensure_native_identity(identity.hash, identity.session_generation)
        .map_err(|_| "ethereum_profile_changed")?;
    let mut store = EthereumNodeStore::open_in_profile(&installed.profile_dir)
        .map_err(|_| "ethereum_state_unavailable")?;
    let policy = CheckpointBootstrapPolicy::new(Vec::new())
        .map_err(|_| "ethereum_checkpoint_policy_unavailable")?;
    let review = policy
        .pending_manual_checkpoint_reviews(&mut store)
        .map_err(|_| "ethereum_checkpoint_review_unavailable")?
        .into_iter()
        .next()
        .ok_or("ethereum_checkpoint_review_unavailable")?;
    let profile_generation = state
        .native_transport_profile_binding()?
        .ok_or("ethereum_profile_unavailable")?
        .generation;
    let binding = AndroidCheckpointProfileBinding {
        profile_dir: installed.profile_dir.clone(),
        profile_generation,
        identity,
    };
    launch_native_checkpoint_review_snapshot(state, binding, review)
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn launch_native_checkpoint_review(
    _state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    Err("native_ethereum_checkpoint_review_unavailable")
}

/// Begins a native Android picker for one user-selected checkpoint card.
/// Wallet custody and gateway configuration are intentionally unnecessary:
/// the card remains untrusted until the separate native checkpoint review.
#[cfg(target_os = "android")]
pub(crate) fn launch_native_checkpoint_file_import(
    state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_checkpoint_file_unavailable")?;
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    let profile_dir = installed
        .profile_dir
        .canonicalize()
        .map_err(|_| "ethereum_profile_unavailable")?;
    let account = EthereumNodeStore::open_in_profile(&profile_dir)
        .and_then(|store| store.wallet_account())
        .map_err(|_| "ethereum_state_unavailable")?;
    let binding = state.ensure_native_transport_profile_binding(
        profile_dir.clone(),
        account,
        identity.hash,
        identity.session_generation,
    )?;
    let now_unix = trusted_android_now_unix()?;
    let (monotonic_deadline, expires_at_unix) =
        bounded_checkpoint_file_import_deadline(Instant::now(), now_unix)?;
    let token = new_checkpoint_review_token()?;
    let session = AndroidCheckpointFileImportSession {
        token: token.clone(),
        binding: AndroidCheckpointProfileBinding {
            profile_dir,
            profile_generation: binding.generation,
            identity,
        },
        expires_at_unix,
        monotonic_deadline,
    };
    {
        let mut active = installed
            .checkpoint_file_import
            .lock()
            .map_err(|_| "native_ethereum_checkpoint_file_unavailable")?;
        if active.as_ref().is_some_and(|session| {
            session.expires_at_unix <= now_unix || Instant::now() >= session.monotonic_deadline
        }) {
            *active = None;
        }
        if active.is_some() {
            return Err("native_ethereum_checkpoint_file_busy");
        }
        *active = Some(session);
    }
    if !android_launch_checkpoint_file_import(&token) {
        abort_checkpoint_file_import_session(installed, &token);
        return Err("native_ethereum_checkpoint_file_unavailable");
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn launch_native_checkpoint_file_import(
    _state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    Err("native_ethereum_checkpoint_file_unavailable")
}

#[cfg(target_os = "android")]
pub(crate) fn native_checkpoint_file_import_available() -> bool {
    INSTALLED_ENGINE.get().is_some()
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn native_checkpoint_file_import_available() -> bool {
    false
}

#[cfg(target_os = "android")]
pub(crate) fn native_gateway_pairing_available() -> bool {
    INSTALLED_ENGINE.get().is_some()
}

#[cfg(target_os = "android")]
pub(crate) fn pending_gateway_card_review(
    identity_hash: [u8; 16],
    identity_session_generation: u64,
) -> Result<bool, &'static str> {
    let Some(installed) = INSTALLED_ENGINE.get() else {
        return Ok(false);
    };
    let pending = installed
        .gateway_card_review
        .lock()
        .map_err(|_| "native_ethereum_gateway_review_unavailable")?;
    let Some(pending) = pending.as_ref() else {
        return Ok(false);
    };
    let now_unix = trusted_android_now_unix()?;
    Ok(pending.binding.ratspeak_identity_hash == identity_hash
        && pending.binding.identity_session_generation == identity_session_generation
        && now_unix < pending.expires_at_unix
        && Instant::now() < pending.monotonic_deadline)
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn pending_gateway_card_review(
    _identity_hash: [u8; 16],
    _identity_session_generation: u64,
) -> Result<bool, &'static str> {
    Ok(false)
}

#[cfg(target_os = "android")]
pub(crate) fn launch_native_gateway_card_import(
    state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_gateway_card_unavailable")?;
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    let profile_dir = installed
        .profile_dir
        .canonicalize()
        .map_err(|_| "ethereum_profile_unavailable")?;
    let account = EthereumNodeStore::open_in_profile(&profile_dir)
        .and_then(|store| store.wallet_account())
        .map_err(|_| "ethereum_state_unavailable")?;
    let binding = state.ensure_native_transport_profile_binding(
        profile_dir,
        account,
        identity.hash,
        identity.session_generation,
    )?;
    let now_unix = trusted_android_now_unix()?;
    let (monotonic_deadline, expires_at_unix) =
        bounded_gateway_card_import_deadline(Instant::now(), now_unix)?;
    let token = new_gateway_card_token()?;
    let session = AndroidGatewayCardImportSession {
        token: token.clone(),
        binding,
        expires_at_unix,
        monotonic_deadline,
    };
    {
        let mut active = installed
            .gateway_card_import
            .lock()
            .map_err(|_| "native_ethereum_gateway_card_unavailable")?;
        if active.as_ref().is_some_and(|session| {
            session.expires_at_unix <= now_unix || Instant::now() >= session.monotonic_deadline
        }) {
            *active = None;
        }
        if active.is_some() {
            return Err("native_ethereum_gateway_card_busy");
        }
        *active = Some(session);
    }
    if !android_launch_gateway_card_import(&token) {
        abort_gateway_card_import_session(installed, &token);
        return Err("native_ethereum_gateway_card_unavailable");
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn launch_native_gateway_card_import(
    _state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    Err("native_ethereum_gateway_card_unavailable")
}

#[cfg(target_os = "android")]
pub(crate) fn launch_native_gateway_card_review(
    state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_gateway_review_unavailable")?;
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    let now_unix = trusted_android_now_unix()?;
    let mut pending = installed
        .gateway_card_review
        .lock()
        .map_err(|_| "native_ethereum_gateway_review_unavailable")?;
    let Some(existing) = pending.as_ref() else {
        return Err("native_ethereum_gateway_review_unavailable");
    };
    if existing.expires_at_unix <= now_unix || Instant::now() >= existing.monotonic_deadline {
        *pending = None;
        return Err("ethereum_gateway_review_expired");
    }
    let current = state
        .native_transport_profile_binding()
        .map_err(|_| "ethereum_profile_changed")?
        .filter(|binding| binding == &existing.binding)
        .ok_or("ethereum_profile_changed")?;
    if current.profile_dir
        != installed
            .profile_dir
            .canonicalize()
            .map_err(|_| "ethereum_profile_changed")?
        || current.ratspeak_identity_hash != identity.hash
        || current.identity_session_generation != identity.session_generation
    {
        return Err("ethereum_profile_changed");
    }
    if current != existing.binding {
        return Err("ethereum_profile_changed");
    }
    if !crate::ethereum::gateway_card_matches_active_contact(&installed.runtime, &existing.card) {
        return Err("ethereum_gateway_contact_required");
    }
    let token = existing.token.clone();
    let projection = gateway_card_review_projection_frame(existing)?;
    drop(pending);
    if !android_launch_gateway_card_review(&token, &projection) {
        abort_gateway_card_review_session(installed, &token);
        return Err("native_ethereum_gateway_review_unavailable");
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn launch_native_gateway_card_review(
    _state: &EthereumApplicationState,
) -> Result<(), &'static str> {
    Err("native_ethereum_gateway_review_unavailable")
}

#[cfg(target_os = "android")]
fn launch_native_checkpoint_review_snapshot(
    state: &EthereumApplicationState,
    binding: AndroidCheckpointProfileBinding,
    review: PendingManualCheckpointReview,
) -> Result<(), &'static str> {
    let installed = INSTALLED_ENGINE
        .get()
        .ok_or("native_ethereum_checkpoint_review_unavailable")?;
    let identity =
        active_identity_binding(&installed.runtime).map_err(|_| "ethereum_identity_unavailable")?;
    if binding.identity != identity
        || binding.profile_dir != installed.profile_dir
        || binding.profile_dir.canonicalize().ok().as_ref() != Some(&binding.profile_dir)
        || state
            .native_transport_profile_binding()
            .ok()
            .flatten()
            .map(|current| current.generation != binding.profile_generation)
            .unwrap_or(true)
        || state
            .ensure_native_identity(identity.hash, identity.session_generation)
            .is_err()
    {
        return Err("ethereum_profile_changed");
    }
    let now_unix = trusted_android_now_unix()?;
    if review.expires_at_unix() <= now_unix {
        return Err("ethereum_checkpoint_review_expired");
    }
    let monotonic_now = Instant::now();
    if let Ok(mut active) = installed.checkpoint_review.lock() {
        if active.as_ref().is_some_and(|session| {
            session.expires_at_unix <= now_unix || monotonic_now >= session.monotonic_deadline
        }) {
            *active = None;
        }
    }
    let (monotonic_deadline, deadline_unix) =
        bounded_checkpoint_review_deadline(Instant::now(), now_unix, review.expires_at_unix())?;
    let token = new_checkpoint_review_token()?;
    let session = AndroidCheckpointReviewSession {
        token: token.clone(),
        review,
        binding,
        expires_at_unix: deadline_unix,
        monotonic_deadline,
    };
    let mut projection = checkpoint_review_projection_frame(&session.review, deadline_unix)?;
    {
        let mut active = installed
            .checkpoint_review
            .lock()
            .map_err(|_| "native_ethereum_checkpoint_review_unavailable")?;
        if active.is_some() {
            return Err("native_ethereum_checkpoint_review_busy");
        }
        *active = Some(session);
    }
    if !android_launch_checkpoint_review(&token, &projection) {
        projection_cleanup(&mut projection);
        abort_checkpoint_review_session(installed, &token);
        return Err("native_ethereum_checkpoint_review_unavailable");
    }
    projection_cleanup(&mut projection);
    Ok(())
}

#[cfg(target_os = "android")]
pub(crate) fn native_bulk_evidence_review_available() -> bool {
    // Evidence transfer approval has no wallet, custody, or biometric
    // prerequisite. Launching still requires the native bridge.
    INSTALLED_ENGINE.get().is_some()
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn native_bulk_evidence_review_available() -> bool {
    false
}

#[cfg(target_os = "android")]
pub(crate) fn native_checkpoint_review_available() -> bool {
    // Manual checkpoint review has no wallet, gateway, custody, or biometric
    // prerequisite. Candidate acquisition and staging remain a separate
    // native-only operation.
    INSTALLED_ENGINE.get().is_some()
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn native_checkpoint_review_available() -> bool {
    false
}

#[cfg(target_os = "android")]
fn trusted_android_now_unix() -> Result<u64, &'static str> {
    let now = wall_clock_now_unix();
    (now != 0).then_some(now).ok_or("clock_unavailable")
}

fn bounded_bulk_review_deadline(
    monotonic_now: Instant,
    wall_now_unix: u64,
    manifest_expires_at_unix: u64,
) -> Result<(Instant, u64), &'static str> {
    let remaining_secs = manifest_expires_at_unix
        .checked_sub(wall_now_unix)
        .ok_or("ethereum_bulk_review_expired")?;
    let bounded_secs = remaining_secs.min(MAX_BULK_REVIEW_SESSION_SECONDS);
    if bounded_secs == 0 {
        return Err("ethereum_bulk_review_expired");
    }
    let monotonic_deadline = monotonic_now
        .checked_add(Duration::from_secs(bounded_secs))
        .ok_or("ethereum_bulk_review_expiry_invalid")?;
    let wall_deadline_unix = wall_now_unix
        .checked_add(bounded_secs)
        .ok_or("ethereum_bulk_review_expiry_invalid")?;
    Ok((monotonic_deadline, wall_deadline_unix))
}

fn bounded_checkpoint_review_deadline(
    monotonic_now: Instant,
    wall_now_unix: u64,
    review_expires_at_unix: u64,
) -> Result<(Instant, u64), &'static str> {
    let remaining_secs = review_expires_at_unix
        .checked_sub(wall_now_unix)
        .ok_or("ethereum_checkpoint_review_expired")?;
    let bounded_secs = remaining_secs.min(MAX_CHECKPOINT_REVIEW_SESSION_SECONDS);
    if bounded_secs == 0 {
        return Err("ethereum_checkpoint_review_expired");
    }
    let monotonic_deadline = monotonic_now
        .checked_add(Duration::from_secs(bounded_secs))
        .ok_or("ethereum_checkpoint_review_expiry_invalid")?;
    let wall_deadline_unix = wall_now_unix
        .checked_add(bounded_secs)
        .ok_or("ethereum_checkpoint_review_expiry_invalid")?;
    Ok((monotonic_deadline, wall_deadline_unix))
}

#[cfg(target_os = "android")]
fn bounded_checkpoint_file_import_deadline(
    monotonic_now: Instant,
    wall_now_unix: u64,
) -> Result<(Instant, u64), &'static str> {
    let monotonic_deadline = monotonic_now
        .checked_add(Duration::from_secs(
            MAX_CHECKPOINT_FILE_IMPORT_SESSION_SECONDS,
        ))
        .ok_or("ethereum_checkpoint_file_expiry_invalid")?;
    let wall_deadline_unix = wall_now_unix
        .checked_add(MAX_CHECKPOINT_FILE_IMPORT_SESSION_SECONDS)
        .ok_or("ethereum_checkpoint_file_expiry_invalid")?;
    Ok((monotonic_deadline, wall_deadline_unix))
}

#[cfg(target_os = "android")]
fn bounded_gateway_card_import_deadline(
    monotonic_now: Instant,
    wall_now_unix: u64,
) -> Result<(Instant, u64), &'static str> {
    let monotonic_deadline = monotonic_now
        .checked_add(Duration::from_secs(MAX_GATEWAY_CARD_IMPORT_SESSION_SECONDS))
        .ok_or("ethereum_gateway_card_expiry_invalid")?;
    let wall_deadline_unix = wall_now_unix
        .checked_add(MAX_GATEWAY_CARD_IMPORT_SESSION_SECONDS)
        .ok_or("ethereum_gateway_card_expiry_invalid")?;
    Ok((monotonic_deadline, wall_deadline_unix))
}

#[cfg(target_os = "android")]
fn new_bulk_review_token() -> Result<String, &'static str> {
    // getrandom delegates to Android's OS CSPRNG. A launch must fail closed
    // if the operating system cannot provide all 32 capability bytes.
    let mut token = [0u8; 32];
    if getrandom::fill(&mut token).is_err() {
        token.fill(0);
        return Err("ethereum_bulk_review_random_unavailable");
    }
    let encoded = encode_hex(&token);
    token.fill(0);
    Ok(encoded)
}

#[cfg(target_os = "android")]
fn new_checkpoint_review_token() -> Result<String, &'static str> {
    // getrandom delegates to Android's OS CSPRNG. The capability is opaque to
    // Android and is never reused after the Rust session is consumed.
    let mut token = [0u8; 32];
    if getrandom::fill(&mut token).is_err() {
        token.fill(0);
        return Err("ethereum_checkpoint_review_random_unavailable");
    }
    let encoded = encode_hex(&token);
    token.fill(0);
    Ok(encoded)
}

#[cfg(target_os = "android")]
fn new_gateway_card_token() -> Result<String, &'static str> {
    let mut token = [0u8; 32];
    if getrandom::fill(&mut token).is_err() {
        token.fill(0);
        return Err("ethereum_gateway_card_random_unavailable");
    }
    let encoded = encode_hex(&token);
    token.fill(0);
    Ok(encoded)
}

#[cfg(target_os = "android")]
fn abort_bulk_review_session(installed: &InstalledAndroidWalletEngine, token: &str) {
    if let Ok(mut active) = installed.bulk_review.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn abort_checkpoint_review_session(installed: &InstalledAndroidWalletEngine, token: &str) {
    if let Ok(mut active) = installed.checkpoint_review.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn abort_checkpoint_file_import_session(installed: &InstalledAndroidWalletEngine, token: &str) {
    if let Ok(mut active) = installed.checkpoint_file_import.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn abort_gateway_card_import_session(installed: &InstalledAndroidWalletEngine, token: &str) {
    if let Ok(mut active) = installed.gateway_card_import.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn abort_gateway_card_review_session(installed: &InstalledAndroidWalletEngine, token: &str) {
    if let Ok(mut active) = installed.gateway_card_review.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

/// Consumes the import capability before validating the file or opening
/// SQLite. A second callback, replay, expiry, profile switch, or invalid card
/// therefore cannot reuse the native import authority.
#[cfg(target_os = "android")]
fn import_native_checkpoint_file(
    installed: &InstalledAndroidWalletEngine,
    token: &str,
    bytes: &[u8],
) -> Result<bool, EngineFailure> {
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineFailure::ReviewMismatch);
    }
    let session = {
        let mut active = installed
            .checkpoint_file_import
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if active
            .as_ref()
            .map_or(true, |session| session.token != token)
        {
            return Err(EngineFailure::ReviewMismatch);
        }
        active.take().ok_or(EngineFailure::ReviewMismatch)?
    };
    let now_unix = trusted_android_now_unix().map_err(|_| EngineFailure::OperationFailed)?;
    if Instant::now() >= session.monotonic_deadline
        || now_unix >= session.expires_at_unix
        || active_identity_binding(&installed.runtime)
            .map_err(|_| EngineFailure::OperationFailed)?
            != session.binding.identity
        || session.binding.profile_dir != installed.profile_dir
        || session.binding.profile_dir.canonicalize().ok().as_ref()
            != Some(&session.binding.profile_dir)
    {
        return Err(EngineFailure::OperationFailed);
    }
    let state = installed
        .app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or(EngineFailure::Unavailable)?;
    state
        .ensure_native_identity(
            session.binding.identity.hash,
            session.binding.identity.session_generation,
        )
        .map_err(|_| EngineFailure::OperationFailed)?;
    let current_binding = state
        .native_transport_profile_binding()
        .map_err(|_| EngineFailure::OperationFailed)?
        .ok_or(EngineFailure::OperationFailed)?;
    if current_binding.profile_dir != session.binding.profile_dir
        || current_binding.generation != session.binding.profile_generation
        || current_binding.ratspeak_identity_hash != session.binding.identity.hash
        || current_binding.identity_session_generation
            != session.binding.identity.session_generation
    {
        return Err(EngineFailure::OperationFailed);
    }
    if bytes.is_empty() || bytes.len() > ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES {
        return Ok(false);
    }
    let mut store = EthereumNodeStore::open_in_profile(&session.binding.profile_dir)
        .map_err(|_| EngineFailure::OperationFailed)?;
    let policy =
        CheckpointBootstrapPolicy::new(Vec::new()).map_err(|_| EngineFailure::OperationFailed)?;
    Ok(policy
        .stage_manual_checkpoint_file(&mut store, bytes)
        .is_ok())
}

/// Consumes the picker capability before parsing or opening SQLite. A URI or
/// byte buffer is never retained after this function returns.
#[cfg(target_os = "android")]
fn import_native_gateway_card(
    installed: &InstalledAndroidWalletEngine,
    token: &str,
    bytes: &[u8],
) -> Result<bool, EngineFailure> {
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineFailure::ReviewMismatch);
    }
    let session = {
        let mut active = installed
            .gateway_card_import
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if active
            .as_ref()
            .map_or(true, |session| session.token != token)
        {
            return Err(EngineFailure::ReviewMismatch);
        }
        active.take().ok_or(EngineFailure::ReviewMismatch)?
    };
    let now_unix = trusted_android_now_unix().map_err(|_| EngineFailure::OperationFailed)?;
    if Instant::now() >= session.monotonic_deadline
        || now_unix >= session.expires_at_unix
        || active_identity_binding(&installed.runtime)
            .map_err(|_| EngineFailure::OperationFailed)?
            .hash
            != session.binding.ratspeak_identity_hash
        || session.binding.profile_dir
            != installed
                .profile_dir
                .canonicalize()
                .map_err(|_| EngineFailure::OperationFailed)?
        || installed
            .app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or(EngineFailure::Unavailable)?
            .native_transport_profile_binding()
            .map_err(|_| EngineFailure::OperationFailed)?
            .as_ref()
            != Some(&session.binding)
    {
        return Err(EngineFailure::OperationFailed);
    }
    if bytes.is_empty() || bytes.len() > crate::ethereum::MAX_GATEWAY_CARD_BYTES {
        return Ok(false);
    }
    let card =
        crate::ethereum::parse_gateway_card(bytes).map_err(|_| EngineFailure::ReviewMismatch)?;
    let review_token = new_gateway_card_token().map_err(|_| EngineFailure::OperationFailed)?;
    let review = AndroidGatewayCardReviewSession {
        token: review_token,
        binding: session.binding,
        card,
        expires_at_unix: session.expires_at_unix,
        monotonic_deadline: session.monotonic_deadline,
    };
    let mut active = installed
        .gateway_card_review
        .lock()
        .map_err(|_| EngineFailure::OperationFailed)?;
    if active.is_some() {
        return Ok(false);
    }
    *active = Some(review);
    Ok(true)
}

#[cfg(target_os = "android")]
fn resolve_native_gateway_card_review(
    installed: &InstalledAndroidWalletEngine,
    token: &str,
    approved: bool,
) -> Result<(), EngineFailure> {
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineFailure::ReviewMismatch);
    }
    let session = {
        let mut active = installed
            .gateway_card_review
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if active
            .as_ref()
            .map_or(true, |session| session.token != token)
        {
            return Err(EngineFailure::ReviewMismatch);
        }
        active.take().ok_or(EngineFailure::ReviewMismatch)?
    };
    let now_unix = trusted_android_now_unix().map_err(|_| EngineFailure::ReviewMismatch)?;
    let state = installed
        .app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or(EngineFailure::Unavailable)?;
    if Instant::now() >= session.monotonic_deadline
        || now_unix >= session.expires_at_unix
        || active_identity_binding(&installed.runtime)
            .map_err(|_| EngineFailure::OperationFailed)?
            .hash
            != session.binding.ratspeak_identity_hash
        || session.binding.profile_dir
            != installed
                .profile_dir
                .canonicalize()
                .map_err(|_| EngineFailure::OperationFailed)?
        || state
            .native_transport_profile_binding()
            .map_err(|_| EngineFailure::OperationFailed)?
            .as_ref()
            != Some(&session.binding)
    {
        return Err(EngineFailure::OperationFailed);
    }
    if !approved {
        return Ok(());
    }
    if !crate::ethereum::gateway_card_matches_active_contact(&installed.runtime, &session.card) {
        return Err(EngineFailure::OperationFailed);
    }
    let expires_at_unix = session.expires_at_unix;
    let monotonic_deadline = session.monotonic_deadline;
    state
        .persist_gateway_source_hash(
            session.binding.generation,
            session.card.destination_hash(),
            now_unix,
            || {
                Instant::now() < monotonic_deadline
                    && trusted_android_now_unix()
                        .map(|now| now < expires_at_unix)
                        .unwrap_or(false)
            },
        )
        .map_err(|_| EngineFailure::OperationFailed)
}

#[cfg(target_os = "android")]
fn projection_cleanup(projection: &mut [u8]) {
    // Kept as a named boundary so the display frame cannot remain in Rust or
    // JNI temporary storage after the launch call returns.
    projection.fill(0);
}

#[cfg(target_os = "android")]
fn bulk_review_projection_frame(
    review: &PendingBulkEvidenceReview,
    expires_at_unix: u64,
) -> Result<Vec<u8>, &'static str> {
    let kind = match review.kind() {
        MessagingEvidenceKind::ExecutionHeader => "execution_header",
        MessagingEvidenceKind::AccountProof => "account_proof",
        MessagingEvidenceKind::ReceiptProof => "receipt_proof",
        MessagingEvidenceKind::Consensus => "consensus",
        MessagingEvidenceKind::AccountStatePackage => "account_state_package",
        MessagingEvidenceKind::FinalizedReceiptPackage => "finalized_receipt_package",
    };
    let gateway = encode_hex(&review.expected_gateway_source_hash());
    let subject = encode_hex(&review.subject());
    let digest = encode_hex(&review.manifest_digest());
    let checkpoint_epoch = review.checkpoint_epoch();
    let checkpoint_root = review.checkpoint_root();
    let expiry_millis = review
        .expires_at_unix()
        .min(expires_at_unix)
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or("ethereum_bulk_review_expiry_invalid")?;
    let encoded_size = review.encoded_size();
    if gateway.len() != 32
        || subject.len() != 64
        || digest.len() != 64
        || encoded_size == 0
        || expiry_millis <= 0
    {
        return Err("ethereum_bulk_review_invalid");
    }
    let mut frame = Vec::with_capacity(256);
    frame.extend_from_slice(b"RSETHBR1");
    append_ascii_field(&mut frame, &gateway)?;
    append_ascii_field(&mut frame, kind)?;
    append_ascii_field(&mut frame, &subject)?;
    match (checkpoint_epoch, checkpoint_root) {
        (Some(epoch), Some(root)) => {
            frame.push(1);
            frame.extend_from_slice(&epoch.to_be_bytes());
            frame.extend_from_slice(encode_hex(&root).as_bytes());
        }
        (None, None) => frame.push(0),
        _ => return Err("ethereum_bulk_review_checkpoint_invalid"),
    }
    append_ascii_field(&mut frame, &digest)?;
    frame.extend_from_slice(&encoded_size.to_be_bytes());
    frame.extend_from_slice(&expiry_millis.to_be_bytes());
    Ok(frame)
}

#[cfg(target_os = "android")]
fn checkpoint_review_projection_frame(
    review: &PendingManualCheckpointReview,
    expires_at_unix: u64,
) -> Result<Vec<u8>, &'static str> {
    let source = match review.source() {
        ManualCheckpointSource::Url => "url",
        ManualCheckpointSource::File => "file",
        ManualCheckpointSource::Qr => "qr",
    };
    let source_fingerprint = encode_hex(&review.source_fingerprint());
    let checkpoint_root = encode_hex(&review.checkpoint_root());
    let bootstrap_hash = encode_hex(&review.canonical_bootstrap_hash());
    if source_fingerprint.len() != 64
        || checkpoint_root.len() != 64
        || bootstrap_hash.len() != 64
        || review.checkpoint_epoch() == 0
        || review.observed_at_unix() == 0
        || review.valid_until_unix() == 0
        || expires_at_unix == 0
    {
        return Err("ethereum_checkpoint_review_projection_invalid");
    }
    let mut frame = Vec::with_capacity(192);
    frame.extend_from_slice(b"RSETHCP1");
    append_ascii_field(&mut frame, "sepolia")?;
    append_ascii_field(&mut frame, source)?;
    append_ascii_field(&mut frame, &source_fingerprint)?;
    frame.extend_from_slice(&review.checkpoint_epoch().to_be_bytes());
    frame.extend_from_slice(checkpoint_root.as_bytes());
    frame.extend_from_slice(bootstrap_hash.as_bytes());
    frame.extend_from_slice(&review.observed_at_unix().to_be_bytes());
    frame.extend_from_slice(&review.valid_until_unix().to_be_bytes());
    frame.extend_from_slice(&expires_at_unix.to_be_bytes());
    Ok(frame)
}

#[cfg(target_os = "android")]
fn gateway_card_review_projection_frame(
    review: &AndroidGatewayCardReviewSession,
) -> Result<Vec<u8>, &'static str> {
    let destination = encode_hex(&review.card.destination_hash());
    let fingerprint = encode_hex(&review.card.public_key_fingerprint());
    if destination.len() != 32 || fingerprint.len() != 64 || review.expires_at_unix == 0 {
        return Err("ethereum_gateway_review_projection_invalid");
    }
    let mut frame = Vec::with_capacity(8 + 32 + 64 + 8);
    frame.extend_from_slice(b"RSETHGR1");
    frame.extend_from_slice(destination.as_bytes());
    frame.extend_from_slice(fingerprint.as_bytes());
    frame.extend_from_slice(&review.expires_at_unix.to_be_bytes());
    Ok(frame)
}

#[cfg(target_os = "android")]
fn append_ascii_field(frame: &mut Vec<u8>, value: &str) -> Result<(), &'static str> {
    if value.is_empty() || !value.is_ascii() || value.len() > u8::MAX as usize {
        return Err("ethereum_bulk_review_projection_invalid");
    }
    frame.push(value.len() as u8);
    frame.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(target_os = "android")]
fn android_launch_bulk_review(token: &str, projection: &[u8]) -> bool {
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let token = env.new_string(token)?;
        let projection = env.byte_array_from_slice(projection)?;
        env.call_static_method(
            class,
            "launchBulkEvidenceReview",
            "(Ljava/lang/String;[B)Z",
            &[
                JValue::Object(JObject::from(token)),
                JValue::Object(JObject::from(projection)),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_checkpoint_review(token: &str, projection: &[u8]) -> bool {
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let token = env.new_string(token)?;
        let projection = env.byte_array_from_slice(projection)?;
        env.call_static_method(
            class,
            "launchCheckpointReview",
            "(Ljava/lang/String;[B)Z",
            &[
                JValue::Object(JObject::from(token)),
                JValue::Object(JObject::from(projection)),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_checkpoint_file_import(token: &str) -> bool {
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let token = env.new_string(token)?;
        env.call_static_method(
            class,
            "launchCheckpointFileImport",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(JObject::from(token))],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_gateway_card_import(token: &str) -> bool {
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let token = env.new_string(token)?;
        env.call_static_method(
            class,
            "launchGatewayCardImport",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(JObject::from(token))],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_gateway_card_review(token: &str, projection: &[u8]) -> bool {
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let token = env.new_string(token)?;
        let projection = env.byte_array_from_slice(projection)?;
        env.call_static_method(
            class,
            "launchGatewayCardReview",
            "(Ljava/lang/String;[B)Z",
            &[
                JValue::Object(JObject::from(token)),
                JValue::Object(JObject::from(projection)),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
struct AndroidTransferLaunch {
    identity: AndroidIdentityBinding,
    operation_id: [u8; 16],
    sender: String,
    recipient: String,
    value_wei: String,
    nonce: String,
    max_fee_per_gas_wei: String,
    max_priority_fee_per_gas_wei: String,
    expires_at_epoch_millis: i64,
    canonical_signing_payload: Vec<u8>,
}

#[cfg(target_os = "android")]
impl AndroidTransferLaunch {
    fn from_pending(
        identity: AndroidIdentityBinding,
        pending: &PreparedFieldTransfer,
    ) -> Result<Self, &'static str> {
        let review = pending.review();
        let expires_at_epoch_millis = review
            .expires_at_unix()
            .checked_mul(1_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or("ethereum_transfer_expiry_invalid")?;
        Ok(Self {
            identity,
            operation_id: *pending.operation_id().as_bytes(),
            sender: format!("{:#x}", review.from()),
            recipient: format!("{:#x}", review.to()),
            value_wei: review.value().to_string(),
            nonce: review.nonce().to_string(),
            max_fee_per_gas_wei: review.max_fee_per_gas().to_string(),
            max_priority_fee_per_gas_wei: review.max_priority_fee_per_gas().to_string(),
            expires_at_epoch_millis,
            canonical_signing_payload: pending.canonical_signing_bytes().to_vec(),
        })
    }
}

#[cfg(target_os = "android")]
struct AndroidClearSignedLaunch {
    identity: AndroidIdentityBinding,
    operation_id: [u8; 16],
    chain_id: i64,
    sender: String,
    network: String,
    definition_hash: [u8; 32],
    operation_hash: [u8; 32],
    asset_symbol: String,
    asset_decimals: i32,
    recipient: String,
    amount: String,
    nonce: String,
    gas_limit: i64,
    max_fee_per_gas_wei: String,
    max_priority_fee_per_gas_wei: String,
    expires_at_epoch_millis: i64,
    canonical_signing_payload: Vec<u8>,
}

#[cfg(target_os = "android")]
impl AndroidClearSignedLaunch {
    fn from_candidate(
        identity: AndroidIdentityBinding,
        candidate: &NativeClearSignedCandidate,
    ) -> Result<Self, &'static str> {
        let expires_at_epoch_millis = candidate
            .expires_at_unix
            .checked_mul(1_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or("ethereum_transfer_expiry_invalid")?;
        Ok(Self {
            identity,
            operation_id: candidate.operation_id,
            chain_id: i64::try_from(candidate.chain_id)
                .map_err(|_| "unsupported_ethereum_chain")?,
            sender: candidate.sender.clone(),
            network: candidate.network.clone(),
            definition_hash: candidate.definition_hash,
            operation_hash: candidate.operation_hash,
            asset_symbol: candidate.asset_symbol.clone(),
            asset_decimals: i32::from(candidate.asset_decimals),
            recipient: candidate.recipient.clone(),
            amount: candidate.amount.clone(),
            nonce: candidate.nonce.to_string(),
            gas_limit: i64::try_from(candidate.gas_limit)
                .map_err(|_| "invalid_ethereum_gas_limit")?,
            max_fee_per_gas_wei: candidate.max_fee_per_gas_wei.to_string(),
            max_priority_fee_per_gas_wei: candidate
                .max_priority_fee_per_gas_wei
                .to_string(),
            expires_at_epoch_millis,
            canonical_signing_payload: candidate.canonical_signing_payload.clone(),
        })
    }
}

#[cfg(target_os = "android")]
fn android_launch_wallet(identity: AndroidIdentityBinding, active_address: Option<&str>) -> bool {
    let Ok(session_generation) = i64::try_from(identity.session_generation) else {
        return false;
    };
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let identity_hash = env.byte_array_from_slice(&identity.hash)?;
        let address = active_address
            .map(|value| env.new_string(value))
            .transpose()?;
        let address = address.map(JObject::from).unwrap_or_else(JObject::null);
        env.call_static_method(
            class,
            "launchWallet",
            "([BJLjava/lang/String;)Z",
            &[
                JValue::Object(JObject::from(identity_hash)),
                JValue::Long(session_generation),
                JValue::Object(address),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
pub(crate) fn native_wallet_available() -> bool {
    with_android_wallet_bridge(|env, class| {
        env.call_static_method(class, "isAvailable", "()Z", &[])?
            .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_exact_transfer(launch: &AndroidTransferLaunch) -> bool {
    let Ok(session_generation) = i64::try_from(launch.identity.session_generation) else {
        return false;
    };
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let identity = env.byte_array_from_slice(&launch.identity.hash)?;
        let operation = env.byte_array_from_slice(&launch.operation_id)?;
        let sender = env.new_string(&launch.sender)?;
        let recipient = env.new_string(&launch.recipient)?;
        let value = env.new_string(&launch.value_wei)?;
        let nonce = env.new_string(&launch.nonce)?;
        let max_fee = env.new_string(&launch.max_fee_per_gas_wei)?;
        let priority_fee = env.new_string(&launch.max_priority_fee_per_gas_wei)?;
        let payload = env.byte_array_from_slice(&launch.canonical_signing_payload)?;
        env.call_static_method(
            class,
            "launchExactTransfer",
            "([BJ[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J[B)Z",
            &[
                JValue::Object(JObject::from(identity)),
                JValue::Long(session_generation),
                JValue::Object(JObject::from(operation)),
                JValue::Object(JObject::from(sender)),
                JValue::Object(JObject::from(recipient)),
                JValue::Object(JObject::from(value)),
                JValue::Object(JObject::from(nonce)),
                JValue::Object(JObject::from(max_fee)),
                JValue::Object(JObject::from(priority_fee)),
                JValue::Long(launch.expires_at_epoch_millis),
                JValue::Object(JObject::from(payload)),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn android_launch_clear_signed_operation(launch: &AndroidClearSignedLaunch) -> bool {
    let Ok(session_generation) = i64::try_from(launch.identity.session_generation) else {
        return false;
    };
    with_android_wallet_bridge(|env, class| {
        use jni::objects::{JObject, JValue};
        let identity = env.byte_array_from_slice(&launch.identity.hash)?;
        let operation = env.byte_array_from_slice(&launch.operation_id)?;
        let sender = env.new_string(&launch.sender)?;
        let network = env.new_string(&launch.network)?;
        let definition_hash = env.byte_array_from_slice(&launch.definition_hash)?;
        let operation_hash = env.byte_array_from_slice(&launch.operation_hash)?;
        let symbol = env.new_string(&launch.asset_symbol)?;
        let recipient = env.new_string(&launch.recipient)?;
        let amount = env.new_string(&launch.amount)?;
        let nonce = env.new_string(&launch.nonce)?;
        let max_fee = env.new_string(&launch.max_fee_per_gas_wei)?;
        let priority_fee = env.new_string(&launch.max_priority_fee_per_gas_wei)?;
        let payload = env.byte_array_from_slice(&launch.canonical_signing_payload)?;
        env.call_static_method(
            class,
            "launchClearSignedOperation",
            "([BJ[BJLjava/lang/String;Ljava/lang/String;[B[BLjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;J[B)Z",
            &[
                JValue::Object(JObject::from(identity)),
                JValue::Long(session_generation),
                JValue::Object(JObject::from(operation)),
                JValue::Long(launch.chain_id),
                JValue::Object(JObject::from(sender)),
                JValue::Object(JObject::from(network)),
                JValue::Object(JObject::from(definition_hash)),
                JValue::Object(JObject::from(operation_hash)),
                JValue::Object(JObject::from(symbol)),
                JValue::Int(launch.asset_decimals),
                JValue::Object(JObject::from(recipient)),
                JValue::Object(JObject::from(amount)),
                JValue::Object(JObject::from(nonce)),
                JValue::Long(launch.gas_limit),
                JValue::Object(JObject::from(max_fee)),
                JValue::Object(JObject::from(priority_fee)),
                JValue::Long(launch.expires_at_epoch_millis),
                JValue::Object(JObject::from(payload)),
            ],
        )?
        .z()
    })
    .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn with_android_wallet_bridge<F, T>(call: F) -> Option<T>
where
    F: FnOnce(&jni::JNIEnv, jni::objects::JClass) -> jni::errors::Result<T>,
{
    let vm = rns_interface::android_usb::java_vm()?;
    let env = vm.attach_current_thread().ok()?;
    let class = find_android_class(
        &env,
        "org.ratspeak.android.ethereum.EthereumNativeWalletBridge",
    )
    .ok()?;
    match call(&env, class) {
        Ok(value) => Some(value),
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            None
        }
    }
}

#[cfg(target_os = "android")]
fn find_android_class<'a>(
    env: &'a jni::JNIEnv,
    class_name: &str,
) -> jni::errors::Result<jni::objects::JClass<'a>> {
    use jni::objects::{JClass, JValue};
    if ANDROID_CLASS_LOADER.get().is_none() {
        let thread = env.find_class("android/app/ActivityThread")?;
        let app = env
            .call_static_method(
                thread,
                "currentApplication",
                "()Landroid/app/Application;",
                &[],
            )?
            .l()?;
        let loader = env
            .call_method(app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
            .l()?;
        let _ = ANDROID_CLASS_LOADER.set(env.new_global_ref(loader)?);
    }
    let loader = ANDROID_CLASS_LOADER
        .get()
        .expect("Android class loader initialized");
    let name = env.new_string(class_name)?;
    let class = env
        .call_method(
            loader.as_obj(),
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(name.into())],
        )?
        .l()?;
    Ok(JClass::from(class))
}

#[cfg(target_os = "android")]
fn with_installed_state<T>(
    operation: impl FnOnce(
        &InstalledAndroidWalletEngine,
        &EthereumApplicationState,
    ) -> Result<T, EngineFailure>,
) -> Result<T, EngineFailure> {
    let installed = INSTALLED_ENGINE.get().ok_or(EngineFailure::Unavailable)?;
    let state = installed
        .app_handle
        .try_state::<EthereumApplicationState>()
        .ok_or(EngineFailure::Unavailable)?;
    operation(installed, &state)
}

/// Consumes a native bulk-review token before opening SQLite or changing any
/// durable state. A forged token, replay, expiry, profile switch, gateway
/// rotation, or identity-session race therefore cannot authorize delivery.
#[cfg(target_os = "android")]
fn resolve_native_bulk_evidence_review(
    installed: &InstalledAndroidWalletEngine,
    token: &str,
    approved: bool,
) -> Result<BulkEvidenceReviewResolution, EngineFailure> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineFailure::ReviewMismatch);
    }
    let session = {
        let mut active = installed
            .bulk_review
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if active
            .as_ref()
            .map_or(true, |session| session.token != token)
        {
            return Err(EngineFailure::ReviewMismatch);
        }
        active.take().ok_or(EngineFailure::ReviewMismatch)?
    };
    let now_unix = trusted_android_now_unix().map_err(|_| EngineFailure::ReviewMismatch)?;
    if Instant::now() >= session.monotonic_deadline
        || now_unix >= session.expires_at_unix
        || active_identity_binding(&installed.runtime)
            .map_err(|_| EngineFailure::OperationFailed)?
            != (AndroidIdentityBinding {
                hash: session.binding.ratspeak_identity_hash,
                session_generation: session.binding.identity_session_generation,
            })
        || installed
            .app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or(EngineFailure::Unavailable)?
            .transport_binding_is_current(&session.binding)
            .map_err(|_| EngineFailure::OperationFailed)?
            == false
    {
        return Err(EngineFailure::OperationFailed);
    }
    if session.binding.profile_dir.canonicalize().ok().as_ref()
        != Some(&session.binding.profile_dir)
    {
        return Err(EngineFailure::OperationFailed);
    }
    let mut store = EthereumNodeStore::open_in_profile(&session.binding.profile_dir)
        .map_err(|_| EngineFailure::OperationFailed)?;
    let decision = if approved {
        BulkEvidenceReviewDecision::Approve
    } else {
        BulkEvidenceReviewDecision::Deny
    };
    let result = store
        .resolve_bulk_evidence_review(&session.review, decision, now_unix)
        .map_err(|_| EngineFailure::ReviewMismatch)?;
    if result == BulkEvidenceReviewResolution::Approved {
        installed
            .app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or(EngineFailure::Unavailable)?
            .wake_outbound();
    }
    Ok(result)
}

struct NativeCheckpointDecision(bool);

#[cfg(target_os = "android")]
impl NativeCheckpointApproval for NativeCheckpointDecision {
    type Error = ();

    fn review_and_approve(
        &mut self,
        _review: &ratspeak_eth_node::ManualCheckpointReview<'_>,
    ) -> Result<bool, Self::Error> {
        // The Android callback carries only this explicit decision. Rust's
        // policy revalidates the exact durable review before installing trust.
        Ok(self.0)
    }
}

/// Consumes a checkpoint capability before opening SQLite. Resolution uses
/// the private PendingManualCheckpointReview snapshot held by Rust; Android's
/// public projection is never parsed back into a candidate.
#[cfg(target_os = "android")]
fn resolve_native_checkpoint_review(
    installed: &InstalledAndroidWalletEngine,
    token: &str,
    approved: bool,
) -> Result<ManualCheckpointReviewResolution, EngineFailure> {
    // Hold the same lifecycle fence used by the Linux native adapter across
    // every identity/profile check and the resolver's SQLite transaction. A
    // same-identity profile switch cannot race a valid token into another
    // profile while this immediate native callback is resolving it.
    let _identity_lifecycle =
        tauri::async_runtime::block_on(installed.runtime.identity_switch_lock.lock());
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineFailure::ReviewMismatch);
    }
    let session = {
        let mut active = installed
            .checkpoint_review
            .lock()
            .map_err(|_| EngineFailure::OperationFailed)?;
        if active
            .as_ref()
            .map_or(true, |session| session.token != token)
        {
            return Err(EngineFailure::ReviewMismatch);
        }
        active.take().ok_or(EngineFailure::ReviewMismatch)?
    };
    let now_unix = trusted_android_now_unix().map_err(|_| EngineFailure::ReviewMismatch)?;
    if Instant::now() >= session.monotonic_deadline
        || now_unix >= session.expires_at_unix
        || active_identity_binding(&installed.runtime)
            .map_err(|_| EngineFailure::OperationFailed)?
            != session.binding.identity
        || session.binding.profile_dir != installed.profile_dir
        || installed
            .app_handle
            .try_state::<EthereumApplicationState>()
            .ok_or(EngineFailure::Unavailable)?
            .ensure_native_identity(
                session.binding.identity.hash,
                session.binding.identity.session_generation,
            )
            .is_err()
    {
        return Err(EngineFailure::OperationFailed);
    }
    if session.binding.profile_dir.canonicalize().ok().as_ref()
        != Some(&session.binding.profile_dir)
    {
        return Err(EngineFailure::OperationFailed);
    }
    let mut store = EthereumNodeStore::open_in_profile(&session.binding.profile_dir)
        .map_err(|_| EngineFailure::OperationFailed)?;
    let policy =
        CheckpointBootstrapPolicy::new(Vec::new()).map_err(|_| EngineFailure::OperationFailed)?;
    let mut decision = NativeCheckpointDecision(approved);
    policy
        .resolve_manual_checkpoint_review(&mut store, &session.review, &mut decision)
        .map_err(|_| EngineFailure::ReviewMismatch)
}

/// Drops only the process-memory checkpoint session. Back, background,
/// rotation, process loss, and timeout leave the durable review pending.
#[cfg(target_os = "android")]
fn abandon_native_checkpoint_review(installed: &InstalledAndroidWalletEngine, token: &str) {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return;
    }
    if let Ok(mut active) = installed.checkpoint_review.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

/// Drops a backgrounded/rotated native session without touching the durable
/// request. A subsequent bounded retry obtains a fresh token and snapshot.
#[cfg(target_os = "android")]
fn abandon_native_bulk_evidence_review(installed: &InstalledAndroidWalletEngine, token: &str) {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return;
    }
    if let Ok(mut active) = installed.bulk_review.lock() {
        if active
            .as_ref()
            .is_some_and(|session| session.token == token)
        {
            *active = None;
        }
    }
}

#[cfg(target_os = "android")]
fn jni_result(env: &jni::JNIEnv, result: Result<Vec<u8>, EngineFailure>) -> jni::sys::jbyteArray {
    let mut frame = result.unwrap_or_else(failure_frame);
    let output = env
        .byte_array_from_slice(&frame)
        .unwrap_or(std::ptr::null_mut());
    frame.fill(0);
    output
}

#[cfg(target_os = "android")]
fn jni_bytes(env: &jni::JNIEnv, value: jni::sys::jbyteArray) -> Result<SecretBytes, EngineFailure> {
    if value.is_null() {
        return Err(EngineFailure::InvalidWalletMaterial);
    }
    let bytes = env
        .convert_byte_array(value)
        .map_err(|_| EngineFailure::InvalidWalletMaterial)?;
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_FRAME_BYTES {
        return Err(EngineFailure::InvalidWalletMaterial);
    }
    Ok(SecretBytes(bytes))
}

#[cfg(target_os = "android")]
fn jni_checkpoint_file_bytes(
    env: &jni::JNIEnv,
    value: jni::sys::jbyteArray,
) -> Result<Vec<u8>, EngineFailure> {
    if value.is_null() {
        return Err(EngineFailure::OperationFailed);
    }
    let length = env
        .get_array_length(value.into())
        .map_err(|_| EngineFailure::OperationFailed)?;
    let length = usize::try_from(length).map_err(|_| EngineFailure::OperationFailed)?;
    if length == 0 || length > ratspeak_eth_node::MAX_MANUAL_CHECKPOINT_FILE_BYTES {
        return Err(EngineFailure::OperationFailed);
    }
    env.convert_byte_array(value)
        .map_err(|_| EngineFailure::OperationFailed)
}

#[cfg(target_os = "android")]
fn jni_gateway_card_bytes(
    env: &jni::JNIEnv,
    value: jni::sys::jbyteArray,
) -> Result<Vec<u8>, EngineFailure> {
    if value.is_null() {
        return Err(EngineFailure::OperationFailed);
    }
    let length = env
        .get_array_length(value.into())
        .map_err(|_| EngineFailure::OperationFailed)?;
    let length = usize::try_from(length).map_err(|_| EngineFailure::OperationFailed)?;
    if length == 0 || length > crate::ethereum::MAX_GATEWAY_CARD_BYTES {
        return Err(EngineFailure::OperationFailed);
    }
    env.convert_byte_array(value)
        .map_err(|_| EngineFailure::OperationFailed)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeIsAvailable(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jboolean {
    u8::from(INSTALLED_ENGINE.get().is_some())
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeCreateWallet(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jbyteArray {
    let result = INSTALLED_ENGINE
        .get()
        .ok_or(EngineFailure::Unavailable)
        .and_then(|installed| {
            let identity_hash = active_wallet_ceremony_identity(installed)?;
            installed
                .core
                .create_wallet(&installed.profile_dir, identity_hash)
        })
        .and_then(|created| created_wallet_frame(&created));
    jni_result(&env, result)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeRestoreWallet(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    recovery_phrase: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let result = jni_bytes(&env, recovery_phrase).and_then(|phrase| {
        let installed = INSTALLED_ENGINE.get().ok_or(EngineFailure::Unavailable)?;
        let identity_hash = active_wallet_ceremony_identity(installed)?;
        installed
            .core
            .restore_wallet(&installed.profile_dir, identity_hash, phrase.as_slice())
    });
    jni_result(
        &env,
        result.and_then(|created| created_wallet_frame(&created)),
    )
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeActivateWallet(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    handle: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    let result = u64::try_from(handle)
        .map_err(|_| EngineFailure::InvalidWalletMaterial)
        .and_then(|handle| {
            with_installed_state(|installed, state| {
                let identity_hash = active_wallet_ceremony_identity(installed)?;
                installed.core.activate_wallet(
                    state,
                    &installed.profile_dir,
                    identity_hash,
                    handle,
                    None,
                )
            })
        })
        .map(|address| public_value_frame(&address));
    jni_result(&env, result)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeRecoverWallet(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    handle: jni::sys::jlong,
    expected_address: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    let expected = if expected_address.is_null() {
        Err(EngineFailure::InvalidWalletMaterial)
    } else {
        env.get_string(expected_address.into())
            .map(|value| value.to_string_lossy().into_owned())
            .map_err(|_| EngineFailure::InvalidWalletMaterial)
    };
    let result = expected
        .and_then(canonical_address)
        .and_then(|expected| {
            let handle = u64::try_from(handle).map_err(|_| EngineFailure::InvalidWalletMaterial)?;
            with_installed_state(|installed, state| {
                let identity_hash = active_wallet_ceremony_identity(installed)?;
                installed.core.activate_wallet(
                    state,
                    &installed.profile_dir,
                    identity_hash,
                    handle,
                    Some(&expected),
                )
            })
        })
        .map(|address| public_value_frame(&address));
    jni_result(&env, result)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeDiscardPendingWallet(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    handle: jni::sys::jlong,
) {
    if let (Ok(handle), Some(installed)) = (u64::try_from(handle), INSTALLED_ENGINE.get()) {
        installed.core.discard_pending_wallet(handle);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeRevealRecoveryPhrase(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    custody_secret: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let result = jni_bytes(&env, custody_secret).and_then(|secret| {
        with_installed_state(|installed, state| {
            let identity_hash = active_wallet_ceremony_identity(installed)?;
            installed
                .core
                .reveal_recovery_phrase(state, identity_hash, secret.as_slice())
        })
    });
    jni_result(&env, result.and_then(|phrase| secret_value_frame(&phrase)))
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeSignExactTransfer(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    review_frame: jni::sys::jbyteArray,
    custody_secret: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let result = jni_bytes(&env, review_frame)
        .and_then(|frame| parse_review_frame(frame.as_slice()))
        .and_then(|candidate| {
            let secret = jni_bytes(&env, custody_secret)?;
            with_installed_state(|installed, state| {
                let identity = active_identity_binding(&installed.runtime)?;
                installed
                    .core
                    .sign_exact_transfer(state, identity, candidate, secret.as_slice())
            })
        })
        .map(|stored| public_value_frame(&format!("0x{}", encode_hex(&stored.tx_hash()))));
    jni_result(&env, result)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeSignClearSignedOperation(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    review_frame: jni::sys::jbyteArray,
    custody_secret: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let result = jni_bytes(&env, review_frame)
        .and_then(|frame| parse_clear_signed_review_frame(frame.as_slice()))
        .and_then(|candidate| {
            let secret = jni_bytes(&env, custody_secret)?;
            with_installed_state(|installed, state| {
                let identity = active_identity_binding(&installed.runtime)?;
                installed
                    .core
                    .sign_clear_signed_operation(state, identity, candidate, secret.as_slice())
            })
        })
        .map(|stored| public_value_frame(&format!("0x{}", encode_hex(&stored.tx_hash()))));
    jni_result(&env, result)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeCancelClearSignedOperation(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    identity_hash: jni::sys::jbyteArray,
    identity_session_generation: jni::sys::jlong,
    operation_id: jni::sys::jbyteArray,
) {
    let identity = jni_bytes(&env, identity_hash);
    let operation = jni_bytes(&env, operation_id);
    let (Ok(identity), Ok(operation)) = (identity, operation) else {
        return;
    };
    let (Ok(identity_hash), Ok(session_generation), Ok(operation)) = (
        <[u8; 16]>::try_from(identity.as_slice()),
        u64::try_from(identity_session_generation),
        <[u8; 16]>::try_from(operation.as_slice()),
    ) else {
        return;
    };
    let identity = AndroidIdentityBinding {
        hash: identity_hash,
        session_generation,
    };
    let _ = with_installed_state(|installed, state| {
        if active_identity_binding(&installed.runtime)? != identity {
            return Err(EngineFailure::OperationFailed);
        }
        state
            .cancel_native_clear_signed_operation(
                identity.hash,
                identity.session_generation,
                operation,
            )
            .map_err(|_| EngineFailure::OperationFailed)
    });
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeCancelExactTransfer(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    identity_hash: jni::sys::jbyteArray,
    identity_session_generation: jni::sys::jlong,
    operation_id: jni::sys::jbyteArray,
) {
    let identity = jni_bytes(&env, identity_hash);
    let operation = jni_bytes(&env, operation_id);
    let (Ok(identity), Ok(operation)) = (identity, operation) else {
        return;
    };
    let (Ok(identity_hash), Ok(session_generation), Ok(operation)) = (
        <[u8; 16]>::try_from(identity.as_slice()),
        u64::try_from(identity_session_generation),
        <[u8; 16]>::try_from(operation.as_slice()),
    ) else {
        return;
    };
    let identity = AndroidIdentityBinding {
        hash: identity_hash,
        session_generation,
    };
    let _ = with_installed_state(|installed, state| {
        if active_identity_binding(&installed.runtime)? != identity {
            return Err(EngineFailure::OperationFailed);
        }
        state
            .cancel_native_transfer(identity.hash, identity.session_generation, operation)
            .map_err(|_| EngineFailure::OperationFailed)
    });
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeEndWalletCeremony(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    identity_hash: jni::sys::jbyteArray,
    identity_session_generation: jni::sys::jlong,
) {
    let Ok(identity) = jni_bytes(&env, identity_hash) else {
        return;
    };
    let (Ok(hash), Ok(session_generation)) = (
        <[u8; 16]>::try_from(identity.as_slice()),
        u64::try_from(identity_session_generation),
    ) else {
        return;
    };
    if let Some(installed) = INSTALLED_ENGINE.get() {
        end_wallet_ceremony(
            installed,
            AndroidIdentityBinding {
                hash,
                session_generation,
            },
        );
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeResolveBulkEvidenceReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
    approved: jni::sys::jboolean,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        let _ = resolve_native_bulk_evidence_review(installed, &token, approved != 0);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeAbandonBulkEvidenceReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        abandon_native_bulk_evidence_review(installed, &token);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeResolveCheckpointReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
    approved: jni::sys::jboolean,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        let _ = resolve_native_checkpoint_review(installed, &token, approved != 0);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeAbandonCheckpointReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        abandon_native_checkpoint_review(installed, &token);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeImportCheckpointFile(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
    bytes: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    let Ok(token) = env.get_string(token.into()) else {
        return 0;
    };
    let token = token.to_string_lossy().into_owned();
    let Ok(mut bytes) = jni_checkpoint_file_bytes(&env, bytes) else {
        return 0;
    };
    let staged = INSTALLED_ENGINE
        .get()
        .and_then(|installed| import_native_checkpoint_file(installed, &token, &bytes).ok())
        .unwrap_or(false);
    bytes.fill(0);
    if staged {
        1
    } else {
        0
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeAbandonCheckpointFileImport(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        abort_checkpoint_file_import_session(installed, &token);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeImportGatewayCard(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
    bytes: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    let Ok(token) = env.get_string(token.into()) else {
        return 0;
    };
    let token = token.to_string_lossy().into_owned();
    let Ok(mut bytes) = jni_gateway_card_bytes(&env, bytes) else {
        return 0;
    };
    let staged = INSTALLED_ENGINE
        .get()
        .and_then(|installed| import_native_gateway_card(installed, &token, &bytes).ok())
        .unwrap_or(false);
    bytes.fill(0);
    u8::from(staged)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeAbandonGatewayCardImport(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        abort_gateway_card_import_session(installed, &token);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeResolveGatewayCardReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
    approved: jni::sys::jboolean,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        let _ = resolve_native_gateway_card_review(installed, &token, approved != 0);
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_org_ratspeak_android_ethereum_RustEthereumNativeWalletEngine_nativeAbandonGatewayCardReview(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    token: jni::sys::jstring,
) {
    let Ok(token) = env.get_string(token.into()) else {
        return;
    };
    let token = token.to_string_lossy().into_owned();
    if let Some(installed) = INSTALLED_ENGINE.get() {
        abort_gateway_card_review_session(installed, &token);
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARDHAT_PHRASE: &[u8] = b"test test test test test test test test test test test junk";
    const HARDHAT_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const TEST_BINDING: AndroidIdentityBinding = AndroidIdentityBinding {
        hash: [0x44; 16],
        session_generation: 7,
    };
    const OTHER_BINDING: AndroidIdentityBinding = AndroidIdentityBinding {
        hash: [0x45; 16],
        session_generation: 8,
    };

    // Host-side integration of the real Rust engine. Custody uses a public
    // fixture key; Android UI, biometric hardware and network delivery are not
    // simulated or claimed by these tests.
    fn exercise_base_clearsign_engine(usdc: bool, gateway_at_sign: bool) {
        use ratspeak_eth_node::{OutboundMessageBinding, OutboundMessageKind};

        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let state = EthereumApplicationState::new();
        core.activate_wallet(&state, profile.path(), TEST_BINDING, restored.handle, None)
            .unwrap();
        let account = EthereumNodeStore::open_in_profile(profile.path())
            .unwrap()
            .wallet_account()
            .unwrap()
            .unwrap();
        let generation = state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                account,
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
            )
            .unwrap();
        let gateway = [0x61; 16];
        if gateway_at_sign {
            state
                .configure_gateway_source_hash(generation, gateway)
                .unwrap();
        }

        let recipient = "0x2222222222222222222222222222222222222222";
        let amount = if usdc { "5000000" } else { "1000000000000000" };
        let request = EthereumClearSignedOperationRequest {
            chain_id: ratspeak_eth_verifier::BASE_SEPOLIA_CHAIN_ID,
            target: if usdc {
                "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_owned()
            } else {
                recipient.to_owned()
            },
            value_wei: if usdc { "0" } else { amount }.to_owned(),
            calldata_hex: if usdc {
                format!("0xa9059cbb{:0>64}{:064x}", &recipient[2..], 5_000_000u64)
            } else {
                "0x".to_owned()
            },
            nonce: 7,
            gas_limit: if usdc { 65_000 } else { 21_000 },
            max_fee_per_gas_wei: "2000000000".to_owned(),
            max_priority_fee_per_gas_wei: "1000000000".to_owned(),
        };
        let now = wall_clock_now_unix();
        if usdc {
            assert!(state
                .prepare_clear_signed_operation_for_native(
                    generation,
                    TEST_BINDING.hash,
                    TEST_BINDING.session_generation,
                    &request,
                    now,
                    now + 300,
                )
                .is_err());
            ratspeak_eth_clearsign::DefinitionRegistry::install_base_sepolia_usdc_bundle_files(
                &profile
                    .path()
                    .join(ratspeak_eth_node::ETHEREUM_STORE_DIRECTORY)
                    .join("definitions"),
            )
            .unwrap();
        }
        let candidate = state
            .prepare_clear_signed_operation_for_native(
                generation,
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
                &request,
                now,
                now + 300,
            )
            .unwrap();
        assert_eq!(candidate.network, "Base Sepolia");
        assert_eq!(candidate.asset_symbol, if usdc { "USDC" } else { "ETH" });
        assert_eq!(candidate.asset_decimals, if usdc { 6 } else { 18 });
        assert_eq!(candidate.recipient, recipient);
        assert_eq!(candidate.amount, amount);
        assert_eq!(candidate.max_fee_per_gas_wei, 2_000_000_000);
        assert_eq!(candidate.nonce, 7);

        // A changed projection or changed signing bytes cannot become a new
        // authorization; neither rejection consumes the valid retained one.
        let mut changed = candidate.clone();
        changed.amount = "1".to_owned();
        assert_eq!(
            core.sign_clear_signed_operation(&state, TEST_BINDING, changed, HARDHAT_PHRASE,)
                .unwrap_err(),
            EngineFailure::ReviewMismatch
        );
        let mut changed = candidate.clone();
        changed.canonical_signing_payload[0] ^= 1;
        assert_eq!(
            core.sign_clear_signed_operation(&state, TEST_BINDING, changed, HARDHAT_PHRASE,)
                .unwrap_err(),
            EngineFailure::ReviewMismatch
        );
        assert!(EthereumNodeStore::open_in_profile(profile.path())
            .unwrap()
            .latest_signed_transaction_any_chain()
            .unwrap()
            .is_none());

        let signed = core
            .sign_clear_signed_operation(&state, TEST_BINDING, candidate.clone(), HARDHAT_PHRASE)
            .unwrap();
        assert_eq!(signed.chain_id(), 84532);
        assert_eq!(
            signed.signing_hash(),
            alloy_primitives::keccak256(&candidate.canonical_signing_payload,).0
        );
        assert_eq!(
            core.sign_clear_signed_operation(&state, TEST_BINDING, candidate, HARDHAT_PHRASE,)
                .unwrap_err(),
            EngineFailure::ReviewMismatch
        );

        // Reopen the store before observing the relay: persistence precedes
        // transport planning, and a fresh connection reads its exact bytes.
        let mut reopened = EthereumNodeStore::open_in_profile(profile.path()).unwrap();
        let persisted = reopened
            .signed_transaction_by_hash(signed.tx_hash())
            .unwrap()
            .unwrap();
        assert_eq!(persisted.raw_transaction(), signed.raw_transaction());
        let binding = OutboundMessageBinding::new(
            gateway,
            TEST_BINDING.hash,
            TEST_BINDING.session_generation,
        )
        .unwrap();
        if !gateway_at_sign {
            assert!(reopened
                .lease_next_outbound_message(binding, now + 1, 30)
                .unwrap()
                .is_none());
            state
                .configure_gateway_source_hash(generation, gateway)
                .unwrap();
            assert!(state
                .plan_signed_relay_if_configured(
                    TEST_BINDING.hash,
                    TEST_BINDING.session_generation,
                    &persisted,
                    now + 1,
                )
                .unwrap());
        }
        assert!(!state
            .plan_signed_relay_if_configured(
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
                &persisted,
                now + 1,
            )
            .unwrap());
        let relay = reopened
            .lease_next_outbound_message(binding, now + 1, 30)
            .unwrap()
            .unwrap();
        assert_eq!(relay.kind(), OutboundMessageKind::SignedTransactionRelay);
        assert_eq!(relay.destination_hash(), gateway);
        assert_eq!(&relay.attachment()[8..16], &84532u64.to_le_bytes());
        assert!(relay.attachment().ends_with(persisted.raw_transaction()));
    }

    #[test]
    fn base_eth_retained_engine_signs_persists_and_queues_exact_relay() {
        exercise_base_clearsign_engine(false, true);
    }

    #[test]
    fn base_usdc_retained_engine_signs_offline_and_later_queues_exact_relay() {
        exercise_base_clearsign_engine(true, false);
    }

    #[test]
    fn encode_hex_accepts_fixed_width_public_values() {
        assert_eq!(encode_hex(&[0xab; 16]), "abababababababababababababababab");
        assert_eq!(encode_hex(&[0xcd; 32]).len(), 64);
    }

    #[test]
    fn bulk_review_deadline_is_monotonic_and_bounded() {
        let now = Instant::now();
        let (deadline, wall_deadline) = bounded_bulk_review_deadline(now, 100, 10_000).unwrap();
        assert_eq!(wall_deadline, 100 + MAX_BULK_REVIEW_SESSION_SECONDS);
        assert!(
            deadline.duration_since(now) <= Duration::from_secs(MAX_BULK_REVIEW_SESSION_SECONDS)
        );
        assert_eq!(
            bounded_bulk_review_deadline(now, 100, 100),
            Err("ethereum_bulk_review_expired")
        );
    }

    #[test]
    fn checkpoint_review_deadline_is_monotonic_bounded_and_expires() {
        let now = Instant::now();
        let (deadline, wall_deadline) =
            bounded_checkpoint_review_deadline(now, 100, 10_000).unwrap();
        assert_eq!(wall_deadline, 100 + MAX_CHECKPOINT_REVIEW_SESSION_SECONDS);
        assert!(
            deadline.duration_since(now)
                <= Duration::from_secs(MAX_CHECKPOINT_REVIEW_SESSION_SECONDS)
        );
        assert_eq!(
            bounded_checkpoint_review_deadline(now, 100, 100),
            Err("ethereum_checkpoint_review_expired")
        );
    }

    #[test]
    fn checkpoint_file_import_source_contract_is_bounded_and_native_only() {
        let source = include_str!("ethereum_android.rs");
        let start = source
            .find("pub(crate) fn launch_native_checkpoint_file_import(")
            .expect("checkpoint file launcher source contract");
        let end = source
            .find("fn launch_native_checkpoint_review_snapshot(")
            .expect("checkpoint file launcher boundary");
        let launcher = &source[start..end];
        assert!(launcher.contains("native_transport_profile_binding"));
        assert!(!launcher.contains("install_transport_profile_for_identity"));
        assert!(!launcher.contains("ensure_native_identity"));
        assert!(launcher.contains("bounded_checkpoint_file_import_deadline"));
        assert!(launcher.contains("new_checkpoint_review_token"));
        assert!(launcher.contains("android_launch_checkpoint_file_import"));
        assert!(!launcher.contains("EthereumTransportBinding"));

        let deadline = source
            .find("fn bounded_checkpoint_file_import_deadline(")
            .expect("checkpoint file deadline source contract");
        let deadline_end = source[deadline..]
            .find("fn new_bulk_review_token(")
            .map(|offset| deadline + offset)
            .expect("checkpoint file deadline boundary");
        assert!(
            source[deadline..deadline_end].contains("MAX_CHECKPOINT_FILE_IMPORT_SESSION_SECONDS")
        );

        let import = source
            .find("fn import_native_checkpoint_file(")
            .expect("checkpoint file importer source contract");
        let import_end = source
            .find("fn projection_cleanup(")
            .expect("checkpoint file importer boundary");
        let importer = &source[import..import_end];
        assert!(importer.contains("active.take()"));
        assert!(importer.contains("open_in_profile"));
        assert!(importer.contains("stage_manual_checkpoint_file"));
        assert!(importer.contains("canonicalize"));
        assert!(importer.contains("MAX_MANUAL_CHECKPOINT_FILE_BYTES"));
        assert!(!importer.contains("uri: "));
        assert!(!importer.contains("android.net.Uri"));
        assert!(!importer.contains("ContentResolver"));
        let kotlin = include_str!(
            "../gen/android/app/src/main/java/org/ratspeak/android/ethereum/EthereumCheckpointFileImport.kt"
        );
        assert!(!kotlin.contains("uri: Uri"));
        assert!(!kotlin.contains("Uri?"));
        assert!(!kotlin.contains(".takePersistableUriPermission("));
    }

    #[test]
    fn checkpoint_resolution_source_contract_holds_identity_fence() {
        let source = include_str!("ethereum_android.rs");
        let start = source
            .find("fn resolve_native_checkpoint_review(")
            .expect("checkpoint resolver source contract");
        let end = source
            .find("fn abandon_native_checkpoint_review(")
            .expect("checkpoint abandon source contract");
        let resolver = &source[start..end];
        assert!(resolver.contains("identity_switch_lock.lock()"));
        assert!(resolver.contains("active_identity_binding"));
        assert!(resolver.contains("open_in_profile"));
        assert!(resolver.contains("resolve_manual_checkpoint_review"));
    }

    #[test]
    fn gateway_pairing_source_contract_is_native_bounded_and_one_shot() {
        let source = include_str!("ethereum_android.rs");
        let import = source
            .find("fn import_native_gateway_card(")
            .expect("gateway importer source contract");
        let resolve = source
            .find("fn resolve_native_gateway_card_review(")
            .expect("gateway resolver source contract");
        let importer = &source[import..resolve];
        assert!(importer.contains("active.take()"));
        assert!(importer.contains("MAX_GATEWAY_CARD_BYTES"));
        assert!(importer.contains("parse_gateway_card"));
        assert!(importer.contains("native_transport_profile_binding"));
        assert!(!importer.contains("ContentResolver"));
        assert!(!importer.contains("Uri"));
        let kotlin = include_str!(
            "../gen/android/app/src/main/java/org/ratspeak/android/ethereum/EthereumGatewayPairing.kt"
        );
        assert!(kotlin.contains("ACTION_OPEN_DOCUMENT"));
        assert!(kotlin.contains("MAX_FILE_BYTES = 256"));
        assert!(!kotlin.contains("takePersistableUriPermission"));
        assert!(!kotlin.contains("Uri"));
        assert!(kotlin.contains("RSETHGR1"));
        assert!(kotlin.contains("FLAG_SECURE"));
    }

    #[test]
    fn restore_stages_only_valid_standard_wallet_material() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        assert_eq!(restored.address, HARDHAT_ADDRESS);
        assert_eq!(restored.recovery_phrase.as_slice(), HARDHAT_PHRASE);
        assert_eq!(restored.custody_secret.as_slice(), HARDHAT_PHRASE);
        assert!(core
            .restore_wallet(profile.path(), TEST_BINDING, b"not a valid phrase")
            .is_err());
    }

    #[test]
    fn generated_wallet_is_standard_and_bounded() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let generated = core.create_wallet(profile.path(), TEST_BINDING).unwrap();
        assert_eq!(generated.address.len(), ADDRESS_BYTES);
        assert_eq!(
            generated
                .recovery_phrase
                .as_slice()
                .split(|byte| *byte == b' ')
                .count(),
            12
        );
        assert_eq!(
            generated.recovery_phrase.as_slice(),
            generated.custody_secret.as_slice()
        );
        let frame = created_wallet_frame(&generated).unwrap();
        assert_eq!(frame[0], 0);
        assert!(frame.len() < 1_024);
    }

    #[test]
    fn discarded_handle_cannot_activate() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        core.discard_pending_wallet(restored.handle);
        let state = EthereumApplicationState::new();
        assert_eq!(
            core.activate_wallet(&state, profile.path(), TEST_BINDING, restored.handle, None,)
                .unwrap_err(),
            EngineFailure::InvalidWalletMaterial
        );
        assert!(state.native_profile_binding().unwrap().is_none());
    }

    #[test]
    fn recovery_address_mismatch_never_installs_binding() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let state = EthereumApplicationState::new();
        assert_eq!(
            core.activate_wallet(
                &state,
                profile.path(),
                TEST_BINDING,
                restored.handle,
                Some("0x1111111111111111111111111111111111111111"),
            )
            .unwrap_err(),
            EngineFailure::InvalidWalletMaterial
        );
        assert!(state.native_profile_binding().unwrap().is_none());
    }

    #[test]
    fn profile_switch_invalidates_a_staged_wallet() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let state = EthereumApplicationState::new();

        assert_eq!(
            core.activate_wallet(&state, profile.path(), OTHER_BINDING, restored.handle, None,)
                .unwrap_err(),
            EngineFailure::OperationFailed
        );
        assert!(state.native_profile_binding().unwrap().is_none());
        assert_eq!(
            core.activate_wallet(&state, profile.path(), TEST_BINDING, restored.handle, None,)
                .unwrap_err(),
            EngineFailure::InvalidWalletMaterial
        );
    }

    #[test]
    fn bulk_review_snapshot_binding_cannot_survive_profile_switch() {
        let first_profile = tempfile::tempdir().unwrap();
        let second_profile = tempfile::tempdir().unwrap();
        let account =
            WalletSecret::import_recovery_phrase(std::str::from_utf8(HARDHAT_PHRASE).unwrap())
                .unwrap()
                .account()
                .unwrap();
        let state = EthereumApplicationState::new();
        let generation = state
            .install_profile_binding_for_identity(
                first_profile.path().to_owned(),
                account,
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
            )
            .unwrap();
        state
            .configure_gateway_source_hash(generation, [0x55; 16])
            .unwrap();
        let first_binding = state.transport_binding().unwrap().unwrap();
        assert!(state.transport_binding_is_current(&first_binding).unwrap());

        state
            .install_profile_binding_for_identity(
                second_profile.path().to_owned(),
                account,
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
            )
            .unwrap();

        // The review fetched under the first binding must be rejected rather
        // than paired with the later profile, even if a gateway were reused.
        assert!(!state.transport_binding_is_current(&first_binding).unwrap());
    }

    #[test]
    fn reveal_requires_secret_for_active_address() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let state = EthereumApplicationState::new();
        core.activate_wallet(&state, profile.path(), TEST_BINDING, restored.handle, None)
            .unwrap();
        assert_eq!(
            core.reveal_recovery_phrase(&state, TEST_BINDING, HARDHAT_PHRASE)
                .unwrap()
                .as_slice(),
            HARDHAT_PHRASE
        );
        assert_eq!(
            core.reveal_recovery_phrase(
                &state,
                TEST_BINDING,
                b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .unwrap_err(),
            EngineFailure::InvalidWalletMaterial
        );
        assert_eq!(
            core.reveal_recovery_phrase(&state, OTHER_BINDING, HARDHAT_PHRASE)
                .unwrap_err(),
            EngineFailure::OperationFailed
        );
    }

    #[test]
    fn public_wallet_binding_restores_after_process_restart() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let first_state = EthereumApplicationState::new();
        core.activate_wallet(
            &first_state,
            profile.path(),
            TEST_BINDING,
            restored.handle,
            None,
        )
        .unwrap();

        let account = EthereumNodeStore::open_in_profile(profile.path())
            .unwrap()
            .wallet_account()
            .unwrap()
            .unwrap();
        let restarted_state = EthereumApplicationState::new();
        restarted_state
            .install_profile_binding_for_identity(
                profile.path().to_owned(),
                account,
                TEST_BINDING.hash,
                TEST_BINDING.session_generation,
            )
            .unwrap();
        assert_eq!(
            core.reveal_recovery_phrase(&restarted_state, TEST_BINDING, HARDHAT_PHRASE)
                .unwrap()
                .as_slice(),
            HARDHAT_PHRASE
        );
    }

    #[test]
    fn staged_wallet_cannot_replace_the_profile_account() {
        let core = AndroidWalletEngineCore::new();
        let profile = tempfile::tempdir().unwrap();
        let restored = core
            .restore_wallet(profile.path(), TEST_BINDING, HARDHAT_PHRASE)
            .unwrap();
        let state = EthereumApplicationState::new();
        core.activate_wallet(&state, profile.path(), TEST_BINDING, restored.handle, None)
            .unwrap();

        assert!(matches!(
            core.restore_wallet(
                profile.path(),
                TEST_BINDING,
                b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ),
            Err(EngineFailure::InvalidWalletMaterial)
        ));
    }

    #[test]
    fn review_frame_is_strict_and_canonical() {
        let frame = review_frame(2_000, "1000000000000000", 2_000_000_000, 1_000_000_000);
        let parsed = parse_review_frame(&frame).unwrap();
        assert_eq!(parsed.operation_id, [7; 16]);
        assert_eq!(parsed.chain_id, 11_155_111);
        assert_eq!(parsed.sender, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(parsed.expires_at_unix, 2);
        assert_eq!(parsed.canonical_signing_payload, [2, 1, 0, 0]);

        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            parse_review_frame(&trailing).unwrap_err(),
            EngineFailure::ReviewMismatch
        );
        assert_eq!(
            parse_review_frame(&review_frame(2_001, "1", 2, 1)).unwrap_err(),
            EngineFailure::ReviewMismatch
        );
        assert_eq!(
            parse_review_frame(&review_frame(2_000, "01", 2, 1)).unwrap_err(),
            EngineFailure::ReviewMismatch
        );
        assert_eq!(
            parse_review_frame(&review_frame(2_000, "1", 1, 2)).unwrap_err(),
            EngineFailure::ReviewMismatch
        );
    }

    fn review_frame(expiry_millis: u64, value: &str, max_fee: u128, priority: u128) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(2);
        frame.extend_from_slice(&[7; 16]);
        frame.extend_from_slice(&11_155_111u64.to_be_bytes());
        frame.extend_from_slice(b"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        frame.extend_from_slice(b"0x1111111111111111111111111111111111111111");
        frame.extend_from_slice(&(value.len() as u16).to_be_bytes());
        frame.extend_from_slice(value.as_bytes());
        frame.extend_from_slice(&7u64.to_be_bytes());
        frame.extend_from_slice(&21_000u64.to_be_bytes());
        frame.extend_from_slice(&max_fee.to_be_bytes());
        frame.extend_from_slice(&priority.to_be_bytes());
        frame.extend_from_slice(&expiry_millis.to_be_bytes());
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(&[2, 1, 0, 0]);
        frame
    }
}
