import { Identity } from '@reticulum/core';

const DATABASE = 'ratspeak-web-identity-v1';
const STORE = 'vault';
const RECORD = 'identity';
const TYPE = 'ratspeak-encrypted-identity';
const ITERATIONS = 600_000;
const MAX_FILE_LENGTH = 4096;
const encoder = new TextEncoder();

function cryptoApi() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Identity protection requires Web Crypto on HTTPS or localhost.');
  }
  return globalThis.crypto;
}

function checkPassphrase(passphrase, creating = false) {
  if (typeof passphrase !== 'string' || passphrase.length > 1024 ||
      passphrase.length < (creating ? 12 : 1)) {
    throw new Error(creating
      ? 'Use a passphrase of at least 12 characters (maximum 1024).'
      : 'Enter the passphrase used to protect this identity.');
  }
}

function encode(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function decode(value, length) {
  if (typeof value !== 'string' || value.length !== 4 * Math.ceil(length / 3) ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('Invalid encrypted identity format.');
  }
  let bytes;
  try {
    bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  } catch {
    throw new Error('Invalid encrypted identity format.');
  }
  if (bytes.length !== length || encode(bytes) !== value) {
    throw new Error('Invalid encrypted identity format.');
  }
  return bytes;
}

function parseEnvelope(text) {
  if (typeof text !== 'string' || text.length > MAX_FILE_LENGTH) {
    throw new Error('Encrypted identity file is too large or invalid.');
  }
  let data;
  try { data = JSON.parse(text); } catch {
    throw new Error('Invalid encrypted identity JSON.');
  }
  const keys = ['type', 'version', 'kdf', 'hash', 'iterations', 'cipher', 'salt', 'iv', 'ciphertext'];
  if (!data || typeof data !== 'object' || Array.isArray(data) ||
      Object.keys(data).length !== keys.length ||
      !keys.every((key) => Object.hasOwn(data, key)) ||
      data.type !== TYPE || data.version !== 1 || data.kdf !== 'PBKDF2' ||
      data.hash !== 'SHA-256' || data.iterations !== ITERATIONS ||
      data.cipher !== 'AES-256-GCM') {
    throw new Error('Unsupported encrypted identity format or parameters.');
  }
  decode(data.salt, 16);
  decode(data.iv, 12);
  decode(data.ciphertext, 80);
  return data;
}

function authenticatedHeader(data) {
  return encoder.encode(JSON.stringify({
    type: data.type, version: data.version, kdf: data.kdf, hash: data.hash,
    iterations: data.iterations, cipher: data.cipher, salt: data.salt, iv: data.iv,
  }));
}

async function deriveKey(passphrase, salt, usage) {
  const crypto = cryptoApi();
  const passwordBytes = encoder.encode(passphrase);
  try {
    const material = await crypto.subtle.importKey(
      'raw', passwordBytes, 'PBKDF2', false, ['deriveKey'],
    );
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
      material, { name: 'AES-GCM', length: 256 }, false, [usage],
    );
  } finally {
    passwordBytes.fill(0);
  }
}

/** Export only a versioned, passphrase-encrypted 64-byte Reticulum identity. */
export async function exportIdentity(identity, passphrase) {
  checkPassphrase(passphrase, true);
  const crypto = cryptoApi();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = {
    type: TYPE, version: 1, kdf: 'PBKDF2', hash: 'SHA-256',
    iterations: ITERATIONS, cipher: 'AES-256-GCM',
    salt: encode(salt), iv: encode(iv),
  };
  const privateBytes = await identity.getPrivateKey();
  try {
    if (!(privateBytes instanceof Uint8Array) || privateBytes.length !== 64) {
      throw new Error('Expected a canonical 64-byte Reticulum private identity.');
    }
    const key = await deriveKey(passphrase, salt, 'encrypt');
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: authenticatedHeader(data), tagLength: 128 },
      key, privateBytes,
    );
    data.ciphertext = encode(new Uint8Array(encrypted));
    return JSON.stringify(data);
  } finally {
    // Best effort only: JavaScript strings/CryptoKey internals cannot be reliably erased.
    privateBytes.fill(0);
  }
}

/** Decode without writing storage. A failed import can never replace the saved vault. */
export async function importIdentity(encryptedJSON, passphrase) {
  checkPassphrase(passphrase);
  const data = parseEnvelope(encryptedJSON);
  const key = await deriveKey(passphrase, decode(data.salt, 16), 'decrypt');
  let plaintext;
  try {
    plaintext = new Uint8Array(await cryptoApi().subtle.decrypt(
      {
        name: 'AES-GCM', iv: decode(data.iv, 12),
        additionalData: authenticatedHeader(data), tagLength: 128,
      }, key, decode(data.ciphertext, 80),
    ));
  } catch {
    throw new Error('Unable to unlock identity: incorrect passphrase or damaged backup.');
  }
  try {
    const identity = await Identity.fromPrivateKey(plaintext);
    if (!identity) throw new Error('Invalid Reticulum identity in encrypted backup.');
    return identity;
  } finally {
    plaintext.fill(0);
  }
}

async function openDatabase() {
  if (!globalThis.indexedDB) {
    throw new Error('Encrypted identity storage is unavailable in this browser.');
  }
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Cannot open encrypted identity storage.'));
    request.onblocked = () => reject(new Error('Identity storage is blocked; close other Ratspeak tabs.'));
  });
}

async function storageOperation(mode, operation) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE, mode);
      const request = operation(transaction.objectStore(STORE));
      let result;
      request.onsuccess = () => { result = request.result; };
      transaction.oncomplete = () => resolve(result);
      transaction.onabort = transaction.onerror = () => reject(
        new Error('Encrypted identity storage failed. Your saved identity was not replaced.'),
      );
    });
  } finally {
    database.close();
  }
}

export async function hasSavedIdentity() {
  return (await storageOperation('readonly', (store) => store.get(RECORD))) !== undefined;
}

export async function saveIdentity(identity, passphrase) {
  // Complete encryption before opening the write transaction: failure preserves the old record.
  const encryptedJSON = await exportIdentity(identity, passphrase);
  await storageOperation('readwrite', (store) => store.put(encryptedJSON, RECORD));
}

export async function unlockIdentity(passphrase) {
  const encryptedJSON = await storageOperation('readonly', (store) => store.get(RECORD));
  if (encryptedJSON === undefined) throw new Error('No saved identity exists in this browser.');
  return importIdentity(encryptedJSON, passphrase);
}
