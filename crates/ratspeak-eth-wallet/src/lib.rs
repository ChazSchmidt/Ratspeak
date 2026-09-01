//! Platform-neutral Ethereum wallet policy.
//!
//! This crate derives one standard Ethereum account and signs only reviewed,
//! plain Sepolia EIP-1559 value transfers. Platform custody and user-presence
//! authorization belong outside this crate.
//!
//! # Custody security boundary
//!
//! The secret type prevents ordinary cloning and serialization, redacts its
//! debug output, and zeroizes temporary recovery-phrase strings allocated by
//! this crate. It does **not** claim complete process-memory zeroization: the
//! upstream BIP-39/BIP-32 signing derivation path and its intermediates have not
//! yet been audited for that property. A production platform custody adapter
//! must resolve that boundary. Durable authorization and replay state belongs
//! to the platform custody adapter and field-node store.

use std::fmt;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::{Decodable2718, eip2930::AccessList};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
pub const SEPOLIA_NETWORK: &str = "sepolia";
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
pub const NATIVE_TRANSFER_GAS_LIMIT: u64 = 21_000;
pub const GENERATED_MNEMONIC_WORDS: usize = 12;
pub const MAX_RECOVERY_PHRASE_BYTES: usize = 256;
pub const MAX_PREPARED_LIFETIME_SECONDS: u64 = 5 * 60;
pub const MAX_REVIEW_CONTEXT_BYTES: usize = 4 * 1024;

/// Public statement of the custody guarantee provided by this proof of concept.
///
/// In particular, this crate does not claim that upstream derivation or signing
/// intermediates are completely zeroized. Production custody requires the
/// platform boundary to audit or replace that path and to enforce native
/// user-presence authorization. Durable operation replay protection belongs to
/// the platform custody adapter and field-node store rather than this in-memory
/// core.
pub const CUSTODY_SECURITY_BOUNDARY: &str = "recovery-phrase allocations made by this crate are zeroized, but complete zeroization of upstream derivation intermediates is not yet audited or guaranteed; production custody requires a native platform authorizer and field-node durable replay protection";

const REVIEW_CONTEXT_DOMAIN: &[u8] = b"ratspeak.ethereum.review-context.v1";
const TRANSFER_REVIEW_DOMAIN: &[u8] = b"ratspeak.ethereum.transfer-review.v1";

pub type Result<T> = std::result::Result<T, WalletError>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WalletError {
    #[error("invalid English BIP-39 recovery phrase")]
    InvalidMnemonic,
    #[error("recovery phrase exceeds the {MAX_RECOVERY_PHRASE_BYTES}-byte limit")]
    RecoveryPhraseTooLong,
    #[error("Ethereum account derivation failed")]
    Derivation,
    #[error("operation identifier must not be all zeroes")]
    InvalidOperationId,
    #[error("review context is empty")]
    EmptyReviewContext,
    #[error("review context exceeds the {MAX_REVIEW_CONTEXT_BYTES}-byte limit")]
    OversizedReviewContext,
    #[error("unsupported Ethereum chain id {0}")]
    UnsupportedChain(u64),
    #[error("transfer sender does not match the selected wallet account")]
    SenderMismatch,
    #[error("transfer value must be greater than zero")]
    ZeroValue,
    #[error("maximum fee per gas must be greater than zero")]
    ZeroMaximumFee,
    #[error("maximum priority fee exceeds maximum fee per gas")]
    PriorityFeeExceedsMaximum,
    #[error("maximum transfer cost overflows uint256")]
    MaximumCostOverflow,
    #[error("prepared transfer expiry must be in the future")]
    InvalidExpiry,
    #[error("prepared transfer lifetime exceeds {MAX_PREPARED_LIFETIME_SECONDS} seconds")]
    ExpiryTooFar,
    #[error("prepared transfer is not valid yet")]
    NotYetValid,
    #[error("prepared transfer has expired")]
    Expired,
    #[error("transfer authorization was rejected")]
    AuthorizationRejected,
    #[error("wallet secret does not control the reviewed sender")]
    WrongSigner,
    #[error("prepared signing bytes or review digest changed")]
    PreparedTransferChanged,
    #[error("Ethereum signing failed")]
    Signing,
    #[error("signed transaction failed to decode")]
    InvalidSignedTransaction,
    #[error("signed transaction field changed: {0}")]
    SignedFieldMismatch(&'static str),
    #[error("signed transaction sender recovery failed")]
    Recovery,
}

/// A BIP-39 secret. It deliberately has no serialization or cloning surface.
///
/// See [`CUSTODY_SECURITY_BOUNDARY`]; this type does not claim complete
/// zeroization of upstream derivation and signing intermediates.
pub struct WalletSecret {
    mnemonic: Mnemonic,
}

impl fmt::Debug for WalletSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletSecret")
            .field("recovery_phrase", &"[REDACTED]")
            .finish()
    }
}

impl WalletSecret {
    /// Generates a new 12-word English BIP-39 recovery phrase with the crate's
    /// operating-system-backed random source.
    pub fn generate() -> Result<Self> {
        let mnemonic = Mnemonic::generate_in(Language::English, GENERATED_MNEMONIC_WORDS)
            .map_err(|_| WalletError::InvalidMnemonic)?;
        Ok(Self { mnemonic })
    }

    /// Imports any standard English BIP-39 word count with a valid checksum.
    pub fn import_recovery_phrase(phrase: &str) -> Result<Self> {
        // Bound attacker-controlled bytes before bip39 performs Unicode
        // normalization or parsing. English phrases fit comfortably below it.
        if phrase.len() > MAX_RECOVERY_PHRASE_BYTES {
            return Err(WalletError::RecoveryPhraseTooLong);
        }
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| WalletError::InvalidMnemonic)?;
        Ok(Self { mnemonic })
    }

    pub fn word_count(&self) -> usize {
        self.mnemonic.word_count()
    }

    /// Gives a native custody surface temporary access to the recovery words.
    /// The UTF-8 allocation made here is zeroized when the callback returns;
    /// this makes no broader process-memory guarantee.
    pub fn with_recovery_phrase<T>(&self, expose: impl FnOnce(&str) -> T) -> T {
        let phrase = Zeroizing::new(self.mnemonic.to_string());
        expose(phrase.as_str())
    }

    pub fn account(&self) -> Result<WalletAccount> {
        let signer = self.signer()?;
        Ok(WalletAccount::sepolia(signer.address()))
    }

    fn signer(&self) -> Result<PrivateKeySigner> {
        let phrase = Zeroizing::new(self.mnemonic.to_string());
        let builder = MnemonicBuilder::<English>::default()
            .phrase(phrase.as_str())
            .derivation_path(DEFAULT_DERIVATION_PATH)
            .map_err(|_| WalletError::Derivation)?;
        builder.build().map_err(|_| WalletError::Derivation)
    }

    #[cfg(test)]
    fn from_test_entropy(entropy: &[u8]) -> Self {
        Self {
            mnemonic: Mnemonic::from_entropy_in(Language::English, entropy).unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletAccount {
    address: Address,
}

impl WalletAccount {
    /// Reconstructs the public account descriptor stored by the application.
    /// Signing still proves that a supplied secret controls this address.
    pub const fn sepolia(address: Address) -> Self {
        Self { address }
    }

    pub const fn address(&self) -> Address {
        self.address
    }

    pub const fn chain_id(&self) -> u64 {
        SEPOLIA_CHAIN_ID
    }

    pub const fn network(&self) -> &'static str {
        SEPOLIA_NETWORK
    }

    pub const fn derivation_path(&self) -> &'static str {
        DEFAULT_DERIVATION_PATH
    }

    pub fn prepare_transfer(
        &self,
        intent: TransferIntent,
        operation_id: OperationId,
        review_context: ReviewContext,
        prepared_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<PreparedTransfer> {
        validate_intent(self, &intent)?;
        validate_expiry(prepared_at_unix, expires_at_unix)?;

        let maximum_fee = U256::from(NATIVE_TRANSFER_GAS_LIMIT)
            .checked_mul(U256::from(intent.max_fee_per_gas))
            .ok_or(WalletError::MaximumCostOverflow)?;
        let maximum_total_cost = intent
            .value
            .checked_add(maximum_fee)
            .ok_or(WalletError::MaximumCostOverflow)?;
        let tx = TxEip1559 {
            chain_id: intent.chain_id,
            nonce: intent.nonce,
            gas_limit: NATIVE_TRANSFER_GAS_LIMIT,
            max_fee_per_gas: intent.max_fee_per_gas,
            max_priority_fee_per_gas: intent.max_priority_fee_per_gas,
            to: TxKind::Call(intent.to),
            value: intent.value,
            access_list: AccessList::default(),
            input: Bytes::new(),
        };
        let signing_bytes = tx.encoded_for_signing();
        let signing_hash = keccak256(&signing_bytes);
        if signing_hash != tx.signature_hash() {
            return Err(WalletError::PreparedTransferChanged);
        }
        let review = TransferReview {
            operation_id,
            chain_id: intent.chain_id,
            network: SEPOLIA_NETWORK,
            from: intent.from,
            to: intent.to,
            value: intent.value,
            nonce: intent.nonce,
            gas_limit: NATIVE_TRANSFER_GAS_LIMIT,
            max_fee_per_gas: intent.max_fee_per_gas,
            max_priority_fee_per_gas: intent.max_priority_fee_per_gas,
            maximum_total_cost,
            prepared_at_unix,
            expires_at_unix,
            review_context,
            signing_hash,
            review_digest: B256::ZERO,
        };
        let review_digest = compute_review_digest(&review, &signing_bytes);
        let review = TransferReview {
            review_digest,
            ..review
        };
        Ok(PreparedTransfer {
            tx,
            signing_bytes,
            review,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub fn new(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] {
            return Err(WalletError::InvalidOperationId);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReviewContext {
    digest: B256,
}

impl ReviewContext {
    /// Commits to canonical, service-owned review context without retaining it.
    pub fn from_canonical_bytes(context: &[u8]) -> Result<Self> {
        if context.is_empty() {
            return Err(WalletError::EmptyReviewContext);
        }
        if context.len() > MAX_REVIEW_CONTEXT_BYTES {
            return Err(WalletError::OversizedReviewContext);
        }
        let mut commitment = Vec::with_capacity(REVIEW_CONTEXT_DOMAIN.len() + 8 + context.len());
        commitment.extend_from_slice(REVIEW_CONTEXT_DOMAIN);
        commitment.extend_from_slice(&(context.len() as u64).to_be_bytes());
        commitment.extend_from_slice(context);
        Ok(Self {
            digest: keccak256(commitment),
        })
    }

    pub const fn digest(&self) -> B256 {
        self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferIntent {
    chain_id: u64,
    from: Address,
    to: Address,
    value: U256,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl TransferIntent {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        chain_id: u64,
        from: Address,
        to: Address,
        value: U256,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Self {
        Self {
            chain_id,
            from,
            to,
            value,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferReview {
    operation_id: OperationId,
    chain_id: u64,
    network: &'static str,
    from: Address,
    to: Address,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    maximum_total_cost: U256,
    prepared_at_unix: u64,
    expires_at_unix: u64,
    review_context: ReviewContext,
    signing_hash: B256,
    review_digest: B256,
}

impl TransferReview {
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub const fn network(&self) -> &'static str {
        self.network
    }
    pub const fn from(&self) -> Address {
        self.from
    }
    pub const fn to(&self) -> Address {
        self.to
    }
    pub const fn value(&self) -> U256 {
        self.value
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }
    pub const fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }
    pub const fn maximum_total_cost(&self) -> U256 {
        self.maximum_total_cost
    }
    pub const fn prepared_at_unix(&self) -> u64 {
        self.prepared_at_unix
    }
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub const fn review_context(&self) -> ReviewContext {
        self.review_context
    }
    pub const fn signing_hash(&self) -> B256 {
        self.signing_hash
    }
    pub const fn review_digest(&self) -> B256 {
        self.review_digest
    }
}

/// Immutable reviewed transaction. Signing or cancellation consumes it.
pub struct PreparedTransfer {
    tx: TxEip1559,
    signing_bytes: Vec<u8>,
    review: TransferReview,
}

impl fmt::Debug for PreparedTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedTransfer")
            .field("review", &self.review)
            .finish_non_exhaustive()
    }
}

impl PreparedTransfer {
    pub const fn review(&self) -> &TransferReview {
        &self.review
    }

    /// Canonical EIP-1559 signing bytes bound into [`TransferReview`].
    ///
    /// This is exposed only so a native review surface can prove that the
    /// bytes it displayed are the exact bytes this one-shot value will sign.
    /// It does not add an arbitrary signing entry point.
    pub fn canonical_signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    pub fn cancel(self) -> CancelledTransfer {
        CancelledTransfer {
            operation_id: self.review.operation_id,
            review_digest: self.review.review_digest,
        }
    }

    /// Requests immediate authorization, signs exactly the reviewed transaction,
    /// and consumes the prepared transfer regardless of the result.
    ///
    /// The authorizer is invoked only after policy, time, and immutable-byte
    /// checks pass. Implementing [`TransferAuthorizer`] is not itself proof of
    /// native user presence; a platform custody adapter must supply that
    /// production authority, and the field-node store must durably reject
    /// operation replay across process restarts.
    pub fn authorize_and_sign<A: TransferAuthorizer>(
        self,
        secret: &WalletSecret,
        authorizer: &mut A,
        now_unix: u64,
    ) -> Result<SignedTransfer> {
        if now_unix < self.review.prepared_at_unix {
            return Err(WalletError::NotYetValid);
        }
        if now_unix >= self.review.expires_at_unix {
            return Err(WalletError::Expired);
        }
        let recomputed_signing_bytes = self.tx.encoded_for_signing();
        let recomputed_signing_hash = keccak256(&recomputed_signing_bytes);
        if recomputed_signing_bytes != self.signing_bytes
            || recomputed_signing_hash != self.review.signing_hash
            || recomputed_signing_hash != self.tx.signature_hash()
            || compute_review_digest(&self.review, &recomputed_signing_bytes)
                != self.review.review_digest
        {
            return Err(WalletError::PreparedTransferChanged);
        }

        authorizer
            .authorize_transfer(&self.review)
            .map_err(|_| WalletError::AuthorizationRejected)?;

        let signer = secret.signer()?;
        if signer.address() != self.review.from {
            return Err(WalletError::WrongSigner);
        }
        let signature = signer
            .sign_hash_sync(&self.review.signing_hash)
            .map_err(|_| WalletError::Signing)?;
        let signed = self.tx.into_signed(signature);
        let tx_hash = *signed.hash();
        let mut raw_transaction = Vec::with_capacity(signed.eip2718_encoded_length());
        signed.eip2718_encode(&mut raw_transaction);
        verify_signed_transaction(&raw_transaction, &self.review, tx_hash)?;

        Ok(SignedTransfer {
            review: self.review,
            raw_transaction,
            tx_hash,
        })
    }
}

/// Immediate authorization boundary for one prepared transfer.
///
/// Production implementations must synchronously obtain native user presence
/// and compare the displayed review with this exact value. This trait issues no
/// reusable approval token and provides no durable replay protection; those are
/// platform custody adapter and field-node responsibilities.
pub trait TransferAuthorizer {
    type Error;

    fn authorize_transfer(
        &mut self,
        review: &TransferReview,
    ) -> std::result::Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelledTransfer {
    operation_id: OperationId,
    review_digest: B256,
}

impl CancelledTransfer {
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn review_digest(&self) -> B256 {
        self.review_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransfer {
    review: TransferReview,
    raw_transaction: Vec<u8>,
    tx_hash: B256,
}

impl SignedTransfer {
    pub const fn review(&self) -> &TransferReview {
        &self.review
    }
    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }
    pub const fn tx_hash(&self) -> B256 {
        self.tx_hash
    }
}

fn validate_intent(account: &WalletAccount, intent: &TransferIntent) -> Result<()> {
    if intent.chain_id != SEPOLIA_CHAIN_ID {
        return Err(WalletError::UnsupportedChain(intent.chain_id));
    }
    if intent.from != account.address {
        return Err(WalletError::SenderMismatch);
    }
    if intent.value == U256::ZERO {
        return Err(WalletError::ZeroValue);
    }
    if intent.max_fee_per_gas == 0 {
        return Err(WalletError::ZeroMaximumFee);
    }
    if intent.max_priority_fee_per_gas > intent.max_fee_per_gas {
        return Err(WalletError::PriorityFeeExceedsMaximum);
    }
    Ok(())
}

fn validate_expiry(prepared_at_unix: u64, expires_at_unix: u64) -> Result<()> {
    let lifetime = expires_at_unix
        .checked_sub(prepared_at_unix)
        .ok_or(WalletError::InvalidExpiry)?;
    if lifetime == 0 {
        return Err(WalletError::InvalidExpiry);
    }
    if lifetime > MAX_PREPARED_LIFETIME_SECONDS {
        return Err(WalletError::ExpiryTooFar);
    }
    Ok(())
}

fn compute_review_digest(review: &TransferReview, signing_bytes: &[u8]) -> B256 {
    let mut bytes = Vec::with_capacity(
        TRANSFER_REVIEW_DOMAIN.len() + signing_bytes.len() + MAX_REVIEW_CONTEXT_BYTES.min(128),
    );
    bytes.extend_from_slice(TRANSFER_REVIEW_DOMAIN);
    bytes.extend_from_slice(review.operation_id.as_bytes());
    bytes.extend_from_slice(&(signing_bytes.len() as u64).to_be_bytes());
    bytes.extend_from_slice(signing_bytes);
    bytes.extend_from_slice(&review.chain_id.to_be_bytes());
    bytes.extend_from_slice(review.from.as_slice());
    bytes.extend_from_slice(review.to.as_slice());
    bytes.extend_from_slice(&review.value.to_be_bytes::<32>());
    bytes.extend_from_slice(&review.nonce.to_be_bytes());
    bytes.extend_from_slice(&review.gas_limit.to_be_bytes());
    bytes.extend_from_slice(&review.max_fee_per_gas.to_be_bytes());
    bytes.extend_from_slice(&review.max_priority_fee_per_gas.to_be_bytes());
    bytes.extend_from_slice(&review.prepared_at_unix.to_be_bytes());
    bytes.extend_from_slice(&review.expires_at_unix.to_be_bytes());
    bytes.extend_from_slice(review.review_context.digest.as_slice());
    bytes.extend_from_slice(review.signing_hash.as_slice());
    keccak256(bytes)
}

fn verify_signed_transaction(
    raw_transaction: &[u8],
    review: &TransferReview,
    expected_tx_hash: B256,
) -> Result<()> {
    let mut remaining = raw_transaction;
    let envelope = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|_| WalletError::InvalidSignedTransaction)?;
    if !remaining.is_empty() {
        return Err(WalletError::InvalidSignedTransaction);
    }
    let signed = envelope
        .as_eip1559()
        .ok_or(WalletError::SignedFieldMismatch("transaction type"))?;
    let tx = signed.tx();
    if tx.chain_id != review.chain_id {
        return Err(WalletError::SignedFieldMismatch("chain id"));
    }
    if tx.nonce != review.nonce {
        return Err(WalletError::SignedFieldMismatch("nonce"));
    }
    if tx.gas_limit != review.gas_limit {
        return Err(WalletError::SignedFieldMismatch("gas limit"));
    }
    if tx.max_fee_per_gas != review.max_fee_per_gas {
        return Err(WalletError::SignedFieldMismatch("maximum fee"));
    }
    if tx.max_priority_fee_per_gas != review.max_priority_fee_per_gas {
        return Err(WalletError::SignedFieldMismatch("priority fee"));
    }
    if tx.to != TxKind::Call(review.to) {
        return Err(WalletError::SignedFieldMismatch("recipient"));
    }
    if tx.value != review.value {
        return Err(WalletError::SignedFieldMismatch("value"));
    }
    if !tx.access_list.is_empty() {
        return Err(WalletError::SignedFieldMismatch("access list"));
    }
    if !tx.input.is_empty() {
        return Err(WalletError::SignedFieldMismatch("calldata"));
    }
    if signed.signature_hash() != review.signing_hash {
        return Err(WalletError::SignedFieldMismatch("signing hash"));
    }
    if *signed.hash() != expected_tx_hash {
        return Err(WalletError::SignedFieldMismatch("transaction hash"));
    }
    let recovered = signed.recover_signer().map_err(|_| WalletError::Recovery)?;
    if recovered != review.from {
        return Err(WalletError::SignedFieldMismatch("recovered sender"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    const HARDHAT_PHRASE: &str = "test test test test test test test test test test test junk";
    const HARDHAT_ADDRESS: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const OTHER_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    assert_impl_all!(WalletSecret: fmt::Debug, Send, Sync);
    assert_not_impl_any!(WalletSecret: Clone, Copy, serde::Serialize);
    assert_not_impl_any!(PreparedTransfer: Clone, Copy, serde::Serialize);

    fn address(hex_value: &str) -> Address {
        hex_value.parse().unwrap()
    }

    fn secret() -> WalletSecret {
        WalletSecret::import_recovery_phrase(HARDHAT_PHRASE).unwrap()
    }

    fn account() -> WalletAccount {
        secret().account().unwrap()
    }

    fn operation(byte: u8) -> OperationId {
        OperationId::new([byte; 16]).unwrap()
    }

    fn context(label: &[u8]) -> ReviewContext {
        ReviewContext::from_canonical_bytes(label).unwrap()
    }

    fn intent(account: WalletAccount) -> TransferIntent {
        TransferIntent::new(
            SEPOLIA_CHAIN_ID,
            account.address(),
            address("1111111111111111111111111111111111111111"),
            U256::from(1_000_000_000_000_000u64),
            7,
            30_000_000_000,
            1_500_000_000,
        )
    }

    fn prepared_with(
        account: WalletAccount,
        intent: TransferIntent,
        op: OperationId,
        review_context: ReviewContext,
        expiry: u64,
    ) -> PreparedTransfer {
        account
            .prepare_transfer(intent, op, review_context, 1_000, expiry)
            .unwrap()
    }

    struct TestAuthorizer {
        operation_id: OperationId,
        review_digest: B256,
        used: bool,
        calls: usize,
    }

    impl TestAuthorizer {
        fn for_prepared(prepared: &PreparedTransfer) -> Self {
            Self {
                operation_id: prepared.review().operation_id(),
                review_digest: prepared.review().review_digest(),
                used: false,
                calls: 0,
            }
        }
    }

    impl TransferAuthorizer for TestAuthorizer {
        type Error = ();

        fn authorize_transfer(
            &mut self,
            review: &TransferReview,
        ) -> std::result::Result<(), Self::Error> {
            self.calls += 1;
            if self.used
                || self.operation_id != review.operation_id()
                || self.review_digest != review.review_digest()
            {
                return Err(());
            }
            self.used = true;
            Ok(())
        }
    }

    #[test]
    fn hardhat_derivation_vector_matches() {
        let secret = secret();
        assert_eq!(secret.word_count(), 12);
        assert_eq!(
            secret.account().unwrap().address(),
            address(HARDHAT_ADDRESS)
        );
    }

    #[test]
    fn generated_phrase_is_twelve_valid_english_words() {
        let secret = WalletSecret::generate().unwrap();
        assert_eq!(secret.word_count(), GENERATED_MNEMONIC_WORDS);
        secret.with_recovery_phrase(|phrase| {
            let reparsed = WalletSecret::import_recovery_phrase(phrase).unwrap();
            assert_eq!(reparsed.account().unwrap(), secret.account().unwrap());
        });
    }

    #[test]
    fn imports_every_standard_word_count() {
        for entropy_len in [16usize, 20, 24, 28, 32] {
            let entropy = vec![entropy_len as u8; entropy_len];
            let expected = WalletSecret::from_test_entropy(&entropy);
            expected.with_recovery_phrase(|phrase| {
                let imported = WalletSecret::import_recovery_phrase(phrase).unwrap();
                assert_eq!(imported.word_count(), (entropy_len * 3) / 4);
                assert_eq!(imported.account().unwrap(), expected.account().unwrap());
            });
        }
    }

    #[test]
    fn invalid_checksum_and_non_english_phrase_are_rejected() {
        let invalid = "test test test test test test test test test test test test";
        assert!(matches!(
            WalletSecret::import_recovery_phrase(invalid),
            Err(WalletError::InvalidMnemonic)
        ));
        assert!(matches!(
            WalletSecret::import_recovery_phrase("legal winner thank year wave sausage"),
            Err(WalletError::InvalidMnemonic)
        ));
    }

    #[test]
    fn oversized_recovery_phrases_are_rejected_before_parsing() {
        let oversized_ascii = "a".repeat(MAX_RECOVERY_PHRASE_BYTES + 1);
        assert!(matches!(
            WalletSecret::import_recovery_phrase(&oversized_ascii),
            Err(WalletError::RecoveryPhraseTooLong)
        ));

        // Multi-byte input exercises the byte limit before Unicode
        // normalization inside the upstream parser.
        let oversized_unicode = "é".repeat(MAX_RECOVERY_PHRASE_BYTES);
        assert!(oversized_unicode.len() > MAX_RECOVERY_PHRASE_BYTES);
        assert!(matches!(
            WalletSecret::import_recovery_phrase(&oversized_unicode),
            Err(WalletError::RecoveryPhraseTooLong)
        ));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = secret();
        let debug = format!("{secret:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("test test"));
    }

    #[test]
    fn policy_rejects_wrong_chain_sender_and_invalid_value_or_fees() {
        let account = account();
        let base = intent(account);
        let prepare = |candidate| {
            account.prepare_transfer(candidate, operation(1), context(b"verified"), 1, 2)
        };

        let mut candidate = base.clone();
        candidate.chain_id = 1;
        assert!(matches!(
            prepare(candidate),
            Err(WalletError::UnsupportedChain(1))
        ));
        let mut candidate = base.clone();
        candidate.from = Address::ZERO;
        assert!(matches!(
            prepare(candidate),
            Err(WalletError::SenderMismatch)
        ));
        let mut candidate = base.clone();
        candidate.value = U256::ZERO;
        assert!(matches!(prepare(candidate), Err(WalletError::ZeroValue)));
        let mut candidate = base.clone();
        candidate.max_fee_per_gas = 0;
        assert!(matches!(
            prepare(candidate),
            Err(WalletError::ZeroMaximumFee)
        ));
        let mut candidate = base;
        candidate.max_priority_fee_per_gas = candidate.max_fee_per_gas + 1;
        assert!(matches!(
            prepare(candidate),
            Err(WalletError::PriorityFeeExceedsMaximum)
        ));
    }

    #[test]
    fn operation_and_context_inputs_are_bounded() {
        assert_eq!(
            OperationId::new([0; 16]),
            Err(WalletError::InvalidOperationId)
        );
        assert_eq!(
            ReviewContext::from_canonical_bytes(&[]),
            Err(WalletError::EmptyReviewContext)
        );
        assert_eq!(
            ReviewContext::from_canonical_bytes(&vec![0; MAX_REVIEW_CONTEXT_BYTES + 1]),
            Err(WalletError::OversizedReviewContext)
        );
    }

    #[test]
    fn expiry_is_future_and_bounded() {
        let account = account();
        let base = intent(account);
        let prepare = |expires| {
            account.prepare_transfer(
                base.clone(),
                operation(1),
                context(b"verified"),
                1_000,
                expires,
            )
        };
        assert!(matches!(prepare(999), Err(WalletError::InvalidExpiry)));
        assert!(matches!(prepare(1_000), Err(WalletError::InvalidExpiry)));
        assert!(matches!(
            prepare(1_000 + MAX_PREPARED_LIFETIME_SECONDS + 1),
            Err(WalletError::ExpiryTooFar)
        ));
        assert!(prepare(1_000 + MAX_PREPARED_LIFETIME_SECONDS).is_ok());
    }

    #[test]
    fn review_digest_changes_with_every_mutable_intent_field() {
        let account = account();
        let base = intent(account);
        let base_digest = prepared_with(
            account,
            base.clone(),
            operation(1),
            context(b"verified-a"),
            1_100,
        )
        .review()
        .review_digest();
        let mut mutations = Vec::new();
        let mut changed = base.clone();
        changed.to = address("2222222222222222222222222222222222222222");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.value += U256::from(1);
        mutations.push(changed);
        let mut changed = base.clone();
        changed.nonce += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.max_fee_per_gas += 1;
        mutations.push(changed);
        let mut changed = base;
        changed.max_priority_fee_per_gas += 1;
        mutations.push(changed);
        for changed in mutations {
            let digest = prepared_with(
                account,
                changed,
                operation(1),
                context(b"verified-a"),
                1_100,
            )
            .review()
            .review_digest();
            assert_ne!(digest, base_digest);
        }

        let changed_expiry = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified-a"),
            1_101,
        );
        assert_ne!(changed_expiry.review().review_digest(), base_digest);
        let changed_context = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified-b"),
            1_100,
        );
        assert_ne!(changed_context.review().review_digest(), base_digest);
        let changed_operation = prepared_with(
            account,
            intent(account),
            operation(2),
            context(b"verified-a"),
            1_100,
        );
        assert_ne!(changed_operation.review().review_digest(), base_digest);
    }

    #[test]
    fn signs_exact_reviewed_eip1559_transfer_and_recovers_sender() {
        let secret = secret();
        let account = secret.account().unwrap();
        let prepared = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified-state:block-42"),
            1_100,
        );
        let mut authorizer = TestAuthorizer::for_prepared(&prepared);
        let signed = prepared
            .authorize_and_sign(&secret, &mut authorizer, 1_001)
            .unwrap();
        assert!(authorizer.used);
        assert_eq!(authorizer.calls, 1);
        assert_eq!(signed.review().from(), account.address());
        assert_eq!(signed.review().gas_limit(), NATIVE_TRANSFER_GAS_LIMIT);
        assert_eq!(signed.raw_transaction()[0], 0x02);
        assert_eq!(
            signed.tx_hash(),
            "08aca7aebd909496c106684d0b5c402dafa9ecb7ed3032f281f636d6e396c543"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            alloy_primitives::hex::encode(signed.raw_transaction()),
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725"
        );
    }

    #[test]
    fn wrong_secret_cannot_sign_reviewed_sender() {
        let first = secret();
        let account = first.account().unwrap();
        let prepared = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        let mut authorizer = TestAuthorizer::for_prepared(&prepared);
        let other = WalletSecret::import_recovery_phrase(OTHER_PHRASE).unwrap();
        assert_eq!(
            prepared.authorize_and_sign(&other, &mut authorizer, 1_001),
            Err(WalletError::WrongSigner)
        );
    }

    #[test]
    fn authorizer_is_bound_to_operation_and_digest_and_rejects_replay() {
        let secret = secret();
        let account = secret.account().unwrap();
        let first = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        let mut authorizer = TestAuthorizer::for_prepared(&first);
        let second = prepared_with(
            account,
            intent(account),
            operation(2),
            context(b"verified"),
            1_100,
        );
        assert_eq!(
            second.authorize_and_sign(&secret, &mut authorizer, 1_001),
            Err(WalletError::AuthorizationRejected)
        );
        assert!(!authorizer.used);

        let first = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        first
            .authorize_and_sign(&secret, &mut authorizer, 1_001)
            .unwrap();
        let replay = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        assert_eq!(
            replay.authorize_and_sign(&secret, &mut authorizer, 1_001),
            Err(WalletError::AuthorizationRejected)
        );
    }

    #[test]
    fn expired_or_rejected_authorization_produces_no_signature() {
        let secret = secret();
        let account = secret.account().unwrap();
        let expired = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        let mut expired_authorizer = TestAuthorizer::for_prepared(&expired);
        let not_yet_valid = prepared_with(
            account,
            intent(account),
            operation(2),
            context(b"verified"),
            1_100,
        );
        let mut not_yet_valid_authorizer = TestAuthorizer::for_prepared(&not_yet_valid);
        assert_eq!(
            not_yet_valid.authorize_and_sign(&secret, &mut not_yet_valid_authorizer, 999),
            Err(WalletError::NotYetValid)
        );
        assert_eq!(
            expired.authorize_and_sign(&secret, &mut expired_authorizer, 1_100),
            Err(WalletError::Expired)
        );
        assert_eq!(not_yet_valid_authorizer.calls, 0);
        assert_eq!(expired_authorizer.calls, 0);

        let mismatched = prepared_with(
            account,
            intent(account),
            operation(1),
            context(b"verified"),
            1_100,
        );
        let mut wrong = TestAuthorizer {
            operation_id: operation(1),
            review_digest: B256::repeat_byte(0xff),
            used: false,
            calls: 0,
        };
        assert_eq!(
            mismatched.authorize_and_sign(&secret, &mut wrong, 1_001),
            Err(WalletError::AuthorizationRejected)
        );
    }

    #[test]
    fn cancellation_reports_only_public_commitments() {
        let account = account();
        let prepared = prepared_with(
            account,
            intent(account),
            operation(3),
            context(b"verified"),
            1_100,
        );
        let expected = *prepared.review();
        let authorizer = TestAuthorizer::for_prepared(&prepared);
        let cancelled = prepared.cancel();
        assert!(!authorizer.used);
        assert_eq!(authorizer.calls, 0);
        assert_eq!(cancelled.operation_id(), expected.operation_id());
        assert_eq!(cancelled.review_digest(), expected.review_digest());
    }

    #[test]
    fn internal_transaction_mutation_invalidates_the_review() {
        let secret = secret();
        let account = secret.account().unwrap();
        let mut prepared = prepared_with(
            account,
            intent(account),
            operation(5),
            context(b"verified"),
            1_100,
        );
        let mut authorizer = TestAuthorizer::for_prepared(&prepared);
        prepared.tx.nonce += 1;
        assert_eq!(
            prepared.authorize_and_sign(&secret, &mut authorizer, 1_001),
            Err(WalletError::PreparedTransferChanged)
        );
        assert_eq!(authorizer.calls, 0);
    }

    #[test]
    fn maximum_total_cost_overflow_is_rejected() {
        let account = account();
        let candidate = TransferIntent::new(
            SEPOLIA_CHAIN_ID,
            account.address(),
            address("1111111111111111111111111111111111111111"),
            U256::MAX,
            0,
            1,
            0,
        );
        assert!(matches!(
            account.prepare_transfer(candidate, operation(1), context(b"verified"), 1, 2),
            Err(WalletError::MaximumCostOverflow)
        ));
    }

    #[test]
    fn recovery_phrase_recreates_identical_account_and_signature() {
        let original = secret();
        let restored = original
            .with_recovery_phrase(|phrase| WalletSecret::import_recovery_phrase(phrase).unwrap());
        let account = original.account().unwrap();
        assert_eq!(restored.account().unwrap(), account);

        let prepare = || {
            prepared_with(
                account,
                intent(account),
                operation(4),
                context(b"verified"),
                1_100,
            )
        };
        let original_prepared = prepare();
        let mut original_authorizer = TestAuthorizer::for_prepared(&original_prepared);
        let original_signed = original_prepared
            .authorize_and_sign(&original, &mut original_authorizer, 1_001)
            .unwrap();
        let restored_prepared = prepare();
        let mut restored_authorizer = TestAuthorizer::for_prepared(&restored_prepared);
        let restored_signed = restored_prepared
            .authorize_and_sign(&restored, &mut restored_authorizer, 1_001)
            .unwrap();
        assert_eq!(restored_signed, original_signed);
    }
}
