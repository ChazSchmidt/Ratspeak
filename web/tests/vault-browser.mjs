// Run against a local Vite server:
// VITE_TEST_URL=http://127.0.0.1:5178 node tests/vault-browser.mjs
// Requires Playwright and its Chromium browser in the test environment.
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createServer } from 'vite';
import { pathToFileURL } from 'node:url';

export async function testVault(browser, url) {
  const context = await browser.newContext();
  const other = await browser.newContext();
  try {
  const page = await context.newPage();
  await page.goto(url);
  const before = await page.evaluate(async () => {
    const { Identity, Reticulum, toHex } = await import('/node_modules/@reticulum/core/src/index.js');
    const { LXMRouter } = await import('/node_modules/@reticulum/lxmf/src/index.js');
    const vault = await import('/src/identity-vault.js');
    const passphrase = 'a browser-only test identity password';
    if (await vault.hasSavedIdentity()) throw new Error('Expected an empty isolated browser profile');
    const identity = await Identity.generate();
    const router = new LXMRouter(identity, new Reticulum());
    await router.init();
    await vault.saveIdentity(identity, passphrase);
    if (!await vault.hasSavedIdentity()) throw new Error('Saved vault not found');
    return { hash: toHex(identity.identityHash), address: toHex(router.deliveryDest.destinationHash) };
  });
  await page.reload();
  const after = await page.evaluate(async () => {
    const { Reticulum, toHex } = await import('/node_modules/@reticulum/core/src/index.js');
    const { LXMRouter } = await import('/node_modules/@reticulum/lxmf/src/index.js');
    const vault = await import('/src/identity-vault.js');
    const passphrase = 'a browser-only test identity password';
    if (!await vault.hasSavedIdentity()) throw new Error('Vault disappeared on reload');
    let rejected = false;
    try { await vault.unlockIdentity('incorrect passphrase'); } catch { rejected = true; }
    if (!rejected) throw new Error('Wrong password unlocked the vault');
    rejected = false;
    try { await vault.importIdentity('{"malformed":"backup"}', passphrase); } catch { rejected = true; }
    if (!rejected) throw new Error('Malformed import was accepted');
    const identity = await vault.unlockIdentity(passphrase);
    const router = new LXMRouter(identity, new Reticulum());
    await router.init();
    const encrypted = await vault.exportIdentity(identity, passphrase);
    // Inspect actual IndexedDB record: its only value must be an encrypted envelope.
    const record = await new Promise((resolve, reject) => {
      const request = indexedDB.open('ratspeak-web-identity-v1', 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction('vault', 'readonly');
        const read = tx.objectStore('vault').get('identity');
        read.onsuccess = () => resolve(read.result);
        read.onerror = () => reject(read.error);
        tx.oncomplete = () => db.close();
      };
    });
    const stored = JSON.parse(record);
    if (stored.type !== 'ratspeak-encrypted-identity' || !stored.ciphertext ||
        Object.keys(stored).some(key => /private|passphrase/i.test(key))) {
      throw new Error('Storage is not an encrypted-only envelope');
    }
    // A validly encoded ciphertext bit flip must fail authentication and preserve storage.
    const tampered = JSON.parse(encrypted);
    const bytes = Uint8Array.from(atob(tampered.ciphertext), char => char.charCodeAt(0));
    bytes[0] ^= 1;
    tampered.ciphertext = btoa(String.fromCharCode(...bytes));
    rejected = false;
    try { await vault.importIdentity(JSON.stringify(tampered), passphrase); } catch { rejected = true; }
    if (!rejected) throw new Error('Tampered backup was accepted');
    const preserved = await vault.unlockIdentity(passphrase);
    if (toHex(preserved.identityHash) !== toHex(identity.identityHash)) throw new Error('Failed imports changed the saved identity');
    return {
      hash: toHex(identity.identityHash), address: toHex(router.deliveryDest.destinationHash),
      encrypted,
    };
  });
  assert.equal(after.hash, before.hash);
  assert.equal(after.address, before.address);
  // A separate, empty browser session can import the backup but does not autosave.
  const otherPage = await other.newPage();
  await otherPage.goto(url);
  const imported = await otherPage.evaluate(async encrypted => {
    const { toHex } = await import('/node_modules/@reticulum/core/src/index.js');
    const vault = await import('/src/identity-vault.js');
    if (await vault.hasSavedIdentity()) throw new Error('Expected an empty independent context');
    let rejected = false;
    try { await vault.importIdentity(encrypted, 'wrong backup password'); } catch { rejected = true; }
    if (!rejected || await vault.hasSavedIdentity()) throw new Error('Wrong backup password failed unsafely');
    const identity = await vault.importIdentity(encrypted, 'a browser-only test identity password');
    if (await vault.hasSavedIdentity()) throw new Error('Import unexpectedly wrote storage');
    await vault.saveIdentity(identity, 'independent context saved password');
    return toHex(identity.identityHash);
  }, after.encrypted);
  assert.equal(imported, before.hash);
  await otherPage.reload();
  const restoredAddress = await otherPage.evaluate(async () => {
    const { Reticulum, toHex } = await import('/node_modules/@reticulum/core/src/index.js');
    const { LXMRouter } = await import('/node_modules/@reticulum/lxmf/src/index.js');
    const vault = await import('/src/identity-vault.js');
    const identity = await vault.unlockIdentity('independent context saved password');
    const router = new LXMRouter(identity, new Reticulum());
    await router.init();
    return toHex(router.deliveryDest.destinationHash);
  });
  assert.equal(restoredAddress, before.address);
  console.log('PASS: real Chromium IndexedDB encrypted envelope, refresh/unlock, wrong vault/backup passwords, malformed/tampered backup rejection, saved identity preservation, and independent-context import/save/refresh with LXMF address continuity.');
  } finally {
  await context.close();
  await other.close();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  let browser, vite;
  try {
    if (!process.env.VITE_TEST_URL) {
      vite = await createServer({ server: { host: '127.0.0.1', port: 5178, strictPort: true } });
      await vite.listen();
    }
    browser = await chromium.launch({ headless: process.env.HEADED !== '1',
      ...(process.env.CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}) });
    await testVault(browser, process.env.VITE_TEST_URL || 'http://127.0.0.1:5178');
  } finally {
    await browser?.close();
    await vite?.close();
  }
}
