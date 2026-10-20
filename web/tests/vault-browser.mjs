// Run against a local Vite server:
// VITE_TEST_URL=http://127.0.0.1:5178 node tests/vault-browser.mjs
// Requires Playwright and its Chromium browser in the test environment.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_EXECUTABLE_PATH
    ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}),
});
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(process.env.VITE_TEST_URL || 'http://127.0.0.1:5178');
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
    return {
      hash: toHex(identity.identityHash), address: toHex(router.deliveryDest.destinationHash),
      encrypted,
    };
  });
  assert.equal(after.hash, before.hash);
  assert.equal(after.address, before.address);
  // A separate, empty browser session can import the backup but does not autosave.
  const other = await browser.newContext();
  const otherPage = await other.newPage();
  await otherPage.goto(process.env.VITE_TEST_URL || 'http://127.0.0.1:5178');
  const imported = await otherPage.evaluate(async encrypted => {
    const { toHex } = await import('/node_modules/@reticulum/core/src/index.js');
    const vault = await import('/src/identity-vault.js');
    const identity = await vault.importIdentity(encrypted, 'a browser-only test identity password');
    if (await vault.hasSavedIdentity()) throw new Error('Import unexpectedly wrote storage');
    return toHex(identity.identityHash);
  }, after.encrypted);
  assert.equal(imported, before.hash);
  console.log('PASS: real Chromium IndexedDB, refresh/unlock, wrong password, failed import preservation, independent-context backup import, and LXMF address continuity.');
  await context.close();
  await other.close();
} finally {
  await browser.close();
}
