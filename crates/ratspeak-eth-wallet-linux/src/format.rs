use argon2::{Algorithm, Argon2, Block, Params, Version};
use ratspeak_eth_wallet::WalletSecret;
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

use crate::{VaultError, VaultKdfParameters, VaultPassphrase, linux::MAX_PASSPHRASE_BYTES};

pub(crate) const VAULT_VERSION: u16 = 2;
const MAGIC: &[u8; 8] = b"RSETHVLT";
const KDF_ARGON2ID: u8 = 1;
const AEAD_CHACHA20_POLY1305: u8 = 1;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const VAULT_ID_LEN: usize = 32;
const HEADER_LEN: usize = 96;
const KEY_LEN: usize = 32;
const MAX_RECOVERY_PHRASE_BYTES: usize = 256;
pub(crate) const MAX_VAULT_BYTES: usize = HEADER_LEN + MAX_RECOVERY_PHRASE_BYTES + TAG_LEN;

pub(crate) fn random_vault_id() -> Result<[u8; VAULT_ID_LEN], VaultError> {
    let mut vault_id = [0u8; VAULT_ID_LEN];
    SystemRandom::new()
        .fill(&mut vault_id)
        .map_err(|_| VaultError::Randomness)?;
    if vault_id == [0; VAULT_ID_LEN] {
        return Err(VaultError::Randomness);
    }
    Ok(vault_id)
}

pub(crate) struct OpenedVault {
    pub(crate) secret: WalletSecret,
    pub(crate) vault_id: [u8; VAULT_ID_LEN],
    pub(crate) generation: u64,
    pub(crate) kdf: VaultKdfParameters,
}

struct Header {
    bytes: [u8; HEADER_LEN],
    generation: u64,
    kdf: VaultKdfParameters,
    vault_id: [u8; VAULT_ID_LEN],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

pub(crate) fn seal(
    recovery_phrase: &[u8],
    passphrase: &VaultPassphrase,
    vault_id: [u8; VAULT_ID_LEN],
    generation: u64,
    kdf: VaultKdfParameters,
) -> Result<Vec<u8>, VaultError> {
    if generation == 0
        || recovery_phrase.is_empty()
        || recovery_phrase.len() > MAX_RECOVERY_PHRASE_BYTES
        || passphrase.as_bytes().len() > MAX_PASSPHRASE_BYTES
    {
        return Err(VaultError::InvalidFormat);
    }
    let kdf = kdf.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let random = SystemRandom::new();
    random.fill(&mut salt).map_err(|_| VaultError::Randomness)?;
    random
        .fill(&mut nonce)
        .map_err(|_| VaultError::Randomness)?;

    let ciphertext_len = recovery_phrase
        .len()
        .checked_add(TAG_LEN)
        .ok_or(VaultError::OversizedVault)?;
    if vault_id == [0; VAULT_ID_LEN] {
        return Err(VaultError::InvalidFormat);
    }
    let header = encode_header(generation, kdf, vault_id, salt, nonce, ciphertext_len)?;
    let key_bytes = derive_key(passphrase, &salt, kdf)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key_bytes.as_ref())
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    let mut ciphertext = Zeroizing::new(recovery_phrase.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(header.as_slice()),
        &mut *ciphertext,
    )
    .map_err(|_| VaultError::AuthenticationFailed)?;

    let mut encoded = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

pub(crate) fn open(
    encoded: &[u8],
    passphrase: &VaultPassphrase,
    minimum_generation: u64,
) -> Result<OpenedVault, VaultError> {
    let header = decode_header(encoded)?;
    let key_bytes = derive_key(passphrase, &header.salt, header.kdf)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key_bytes.as_ref())
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    let mut plaintext = Zeroizing::new(encoded[HEADER_LEN..].to_vec());
    let opened_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(header.nonce),
            Aad::from(header.bytes.as_slice()),
            &mut plaintext,
        )
        .map_err(|_| VaultError::AuthenticationFailed)?
        .len();
    plaintext.truncate(opened_len);

    // The generation is authenticated as AAD; only compare it after AEAD open.
    if header.generation < minimum_generation {
        return Err(VaultError::RollbackDetected {
            found: header.generation,
            minimum: minimum_generation,
        });
    }
    let phrase = std::str::from_utf8(&plaintext).map_err(|_| VaultError::InvalidRecoveryPhrase)?;
    let secret = WalletSecret::import_recovery_phrase(phrase)
        .map_err(|_| VaultError::InvalidRecoveryPhrase)?;
    Ok(OpenedVault {
        secret,
        vault_id: header.vault_id,
        generation: header.generation,
        kdf: header.kdf,
    })
}

fn derive_key(
    passphrase: &VaultPassphrase,
    salt: &[u8; SALT_LEN],
    kdf: VaultKdfParameters,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::InvalidKdfParameters)?;
    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // argon2 0.5's convenience API leaves its password-derived working Vec
    // to the allocator. Owning it here ensures every 1 KiB Block is zeroized.
    let mut memory = Zeroizing::new(vec![Block::default(); block_count]);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            key.as_mut(),
            memory.as_mut_slice(),
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(key)
}

fn encode_header(
    generation: u64,
    kdf: VaultKdfParameters,
    vault_id: [u8; VAULT_ID_LEN],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext_len: usize,
) -> Result<[u8; HEADER_LEN], VaultError> {
    let ciphertext_len = u32::try_from(ciphertext_len).map_err(|_| VaultError::OversizedVault)?;
    let mut bytes = [0u8; HEADER_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VAULT_VERSION.to_be_bytes());
    bytes[10] = KDF_ARGON2ID;
    bytes[11] = AEAD_CHACHA20_POLY1305;
    bytes[12..20].copy_from_slice(&generation.to_be_bytes());
    bytes[20..24].copy_from_slice(&kdf.memory_kib.to_be_bytes());
    bytes[24..28].copy_from_slice(&kdf.iterations.to_be_bytes());
    bytes[28..32].copy_from_slice(&kdf.parallelism.to_be_bytes());
    bytes[32..64].copy_from_slice(&vault_id);
    bytes[64..80].copy_from_slice(&salt);
    bytes[80..92].copy_from_slice(&nonce);
    bytes[92..96].copy_from_slice(&ciphertext_len.to_be_bytes());
    Ok(bytes)
}

fn decode_header(encoded: &[u8]) -> Result<Header, VaultError> {
    if encoded.len() > MAX_VAULT_BYTES {
        return Err(VaultError::OversizedVault);
    }
    if encoded.len() < HEADER_LEN + TAG_LEN {
        return Err(VaultError::InvalidFormat);
    }
    let bytes: [u8; HEADER_LEN] = encoded[..HEADER_LEN]
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    if &bytes[..8] != MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let version = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
    if version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    if bytes[10] != KDF_ARGON2ID || bytes[11] != AEAD_CHACHA20_POLY1305 {
        return Err(VaultError::InvalidFormat);
    }
    let generation = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    if generation == 0 {
        return Err(VaultError::InvalidFormat);
    }
    let kdf = VaultKdfParameters {
        memory_kib: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
        iterations: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
        parallelism: u32::from_be_bytes(bytes[28..32].try_into().unwrap()),
    }
    .validate()?;
    let vault_id = bytes[32..64].try_into().unwrap();
    if vault_id == [0; VAULT_ID_LEN] {
        return Err(VaultError::InvalidFormat);
    }
    let salt = bytes[64..80].try_into().unwrap();
    let nonce = bytes[80..92].try_into().unwrap();
    let ciphertext_len = u32::from_be_bytes(bytes[92..96].try_into().unwrap()) as usize;
    if !(TAG_LEN + 1..=MAX_RECOVERY_PHRASE_BYTES + TAG_LEN).contains(&ciphertext_len)
        || encoded.len() != HEADER_LEN + ciphertext_len
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Header {
        bytes,
        generation,
        kdf,
        vault_id,
        salt,
        nonce,
    })
}
