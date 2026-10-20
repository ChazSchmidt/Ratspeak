import test from 'node:test';
import assert from 'node:assert/strict';
import { Identity, Reticulum, toHex } from '@reticulum/core';
import { LXMRouter } from '@reticulum/lxmf';
import { exportIdentity, importIdentity } from '../src/identity-vault.js';

const passphrase = 'separate words for a private identity';

async function address(identity) {
  const router = new LXMRouter(identity, new Reticulum());
  await router.init();
  return toHex(router.deliveryDest.destinationHash);
}

test('encrypted backup preserves identity, signing, and LXMF address', async () => {
  const original = await Identity.generate();
  const before = await address(original);
  const encrypted = await exportIdentity(original, passphrase);
  const restored = await importIdentity(encrypted, passphrase);
  assert.equal(toHex(restored.identityHash), toHex(original.identityHash));
  assert.equal(await address(restored), before);
  assert.match(before, /^[0-9a-f]{32}$/);
  const message = new TextEncoder().encode('Vault roundtrip signature');
  const signature = await restored.sign(message);
  assert.equal(await original.validate(signature, message), true);
  const raw = await original.getPrivateKey();
  assert.equal(encrypted.includes(Buffer.from(raw).toString('base64')), false);
  raw.fill(0);
});

test('fresh salt and nonce give distinct backups for the same key/passphrase', async () => {
  const original = await Identity.generate();
  const first = JSON.parse(await exportIdentity(original, passphrase));
  const second = JSON.parse(await exportIdentity(original, passphrase));
  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ciphertext, second.ciphertext);
});

test('wrong passwords and ciphertext/metadata tampering fail closed', async () => {
  const original = await Identity.generate();
  const encrypted = await exportIdentity(original, passphrase);
  await assert.rejects(importIdentity(encrypted, 'this is the wrong password'), /Unable to unlock/);
  for (const field of ['ciphertext', 'salt', 'iv']) {
    const data = JSON.parse(encrypted);
    const bytes = Buffer.from(data[field], 'base64');
    bytes[0] ^= 1;
    data[field] = bytes.toString('base64');
    await assert.rejects(importIdentity(JSON.stringify(data), passphrase), /Unable to unlock/);
  }
});

test('malformed files and unbounded KDF parameters are rejected before derivation', async () => {
  const original = await Identity.generate();
  const encrypted = JSON.parse(await exportIdentity(original, passphrase));
  for (const value of [
    null, [], {}, { ...encrypted, version: 2 },
    { ...encrypted, iterations: 1 }, { ...encrypted, iterations: 1e12 },
    { ...encrypted, cipher: 'AES-CBC' }, { ...encrypted, extra: 'unknown' },
    { ...encrypted, ciphertext: 'AA==' }, { ...encrypted, salt: '!'.repeat(24) },
  ]) {
    await assert.rejects(importIdentity(JSON.stringify(value), passphrase));
  }
  await assert.rejects(importIdentity(' '.repeat(4097), passphrase), /too large/);
  await assert.rejects(importIdentity('{bad json', passphrase), /Invalid/);
  await assert.rejects(exportIdentity(original, 'short'), /12 characters/);
});
