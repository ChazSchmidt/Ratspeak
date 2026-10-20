// Real UI integration, not a mock: two Chromium contexts through native Python RNS.
// PYTHON=/path/to/venv/bin/python CHROMIUM_EXECUTABLE_PATH=/path/to/chromium npm run test:browser
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createServer } from 'vite';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBridge } from '../scripts/reticulum-bridge.mjs';
import { testVault } from './vault-browser.mjs';
import { testFarcasterSmoke } from './farcaster-browser-smoke.mjs';
const browser = await chromium.launch({ headless: process.env.HEADED !== '1', ...(process.env.CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}) });
console.log(`Browser: Chromium ${browser.version()}`);
let vite, bridge, native, directory;
const pageErrors = [], frames = [];
try {
  vite = await createServer({ server: { host: '127.0.0.1', port: 5173, strictPort: true } }); await vite.listen();
  directory = await mkdtemp(join(tmpdir(), 'ratspeak-browser-'));
  native = spawn(process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3'), [fileURLToPath(new URL('./native-peer.py', import.meta.url)), '--directory', directory, '--port', '14242'], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Native transport startup timed out')), 15000);
    let buffer = '';
    native.stdout.on('data', data => { buffer += data; if (buffer.includes('"event": "ready"')) { clearTimeout(timer); resolve(); } });
    native.once('error', error => { clearTimeout(timer); reject(error); });
    native.once('exit', code => { clearTimeout(timer); reject(new Error(`Native peer exited ${code}`)); });
  });
  bridge = await startBridge({ port: 18787, tcpPort: 14242, onPacket: (_direction, data) => frames.push(Buffer.from(data)) });
  const pages = [];
  for (const name of ['Browser A', 'Browser B']) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); const page = await context.newPage();
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.goto('http://127.0.0.1:5173');
    await page.locator('#display-name').fill(name);
    await page.locator('#passphrase').fill('temporary browser fixture password');
    await page.locator('#create').click();
    await page.waitForFunction(() => /^[0-9a-f]{32}$/.test(document.querySelector('#address').textContent));
    const address = await page.locator('#address').textContent();
    await page.reload();
    await page.locator('#passphrase').fill('wrong browser fixture password');
    await page.locator('#unlock').click();
    await page.getByText('Unable to unlock identity: incorrect passphrase or damaged backup.', { exact: true }).waitFor();
    assert.equal(await page.locator('#address').textContent(), '');
    assert.equal(await page.locator('#connect').isDisabled(), true);
    await page.locator('#passphrase').fill('temporary browser fixture password');
    await page.locator('#unlock').click();
    await page.waitForFunction(value => document.querySelector('#address').textContent === value, address);
    await page.locator('#gateway').fill('ws://127.0.0.1:18787'); await page.locator('#connect').click();
    await page.waitForFunction(() => document.querySelector('#connection-status').textContent.startsWith('Gateway connected'));
    pages.push({ page, address });
  }
  assert.notEqual(pages[0].address, pages[1].address);
  for (let i = 0; i < 2; ++i) {
    const page = pages[i].page;
    await page.locator('#contact-name').fill('Other browser');
    await page.locator('#contact-address').fill(pages[1-i].address);
    await page.locator('#contact-form button').click();
  }
  const marker = 'browser-private-' + crypto.randomUUID();
  await pages[0].page.locator('#message-text').fill(marker); await pages[0].page.locator('#send').click();
  await pages[1].page.getByText(marker, { exact: true }).waitFor({ timeout: 25000 });
  const assertVerified = async (page, content) => {
    const row = page.locator('.msg-row.inbound').filter({ has: page.getByText(content, { exact: true }) });
    assert.match(await row.locator('.msg-meta').textContent(), /signature verified/);
    assert.doesNotMatch(await row.locator('.msg-meta').textContent(), /unverified/);
  };
  await assertVerified(pages[1].page, marker);
  await pages[1].page.locator('#message-text').fill('Reply ' + marker); await pages[1].page.locator('#send').click();
  await pages[0].page.getByText('Reply ' + marker, { exact: true }).waitFor({ timeout: 25000 });
  await assertVerified(pages[0].page, 'Reply ' + marker);
  await pages[0].page.locator('#disconnect').click();
  await pages[0].page.waitForFunction(() => document.querySelector('#connection-status').textContent === 'disconnected');
  assert.equal(await pages[0].page.locator('#send').isDisabled(), true);
  await pages[0].page.locator('#connect').click();
  await pages[0].page.waitForFunction(() => document.querySelector('#connection-status').textContent.startsWith('Gateway connected'));
  assert.equal(await pages[0].page.locator('#address').textContent(), pages[0].address);
  await pages[1].page.locator('#announce').click();
  await pages[1].page.locator('#message-text').fill('Reconnected ' + marker);
  await pages[1].page.locator('#send').click();
  await pages[0].page.getByText('Reconnected ' + marker, { exact: true }).waitFor({ timeout: 25000 });
  await assertVerified(pages[0].page, 'Reconnected ' + marker);
  assert.ok(frames.length > 0);
  assert.ok(frames.every(data => !data.includes(Buffer.from(marker))), 'Test plaintext must be absent from raw bridge packets');
  // Exercise the actual backup download/file-input UI in a third empty context.
  const source = pages[0].page;
  await source.locator('#passphrase').fill('temporary browser fixture password');
  const downloadReady = source.waitForEvent('download');
  await source.locator('#export').click();
  const download = await downloadReady;
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  const backup = Buffer.concat(chunks);
  assert.equal(JSON.parse(backup.toString()).type, 'ratspeak-encrypted-identity');
  const importedContext = await browser.newContext();
  try {
    const imported = await importedContext.newPage();
    imported.on('pageerror', error => pageErrors.push(error.message));
    await imported.goto('http://127.0.0.1:5173');
    await imported.locator('#passphrase').fill('wrong backup password');
    await imported.locator('#import').setInputFiles({ name: 'disposable-encrypted.json', mimeType: 'application/json', buffer: backup });
    await imported.getByText('Unable to unlock identity: incorrect passphrase or damaged backup.', { exact: true }).waitFor();
    assert.equal(await imported.locator('#address').textContent(), '');
    assert.equal(await imported.locator('#connect').isDisabled(), true);
    // Reset the input so selecting the same backup dispatches change again.
    await imported.locator('#import').setInputFiles([]);
    await imported.locator('#passphrase').fill('temporary browser fixture password');
    await imported.locator('#import').setInputFiles({ name: 'disposable-encrypted.json', mimeType: 'application/json', buffer: backup });
    await imported.waitForFunction(address => document.querySelector('#address').textContent === address, pages[0].address);
    await imported.reload();
    await imported.locator('#passphrase').fill('temporary browser fixture password');
    await imported.locator('#unlock').click();
    await imported.waitForFunction(address => document.querySelector('#address').textContent === address, pages[0].address);
  } finally { await importedContext.close(); }
  if (process.env.BROWSER_SCREENSHOT_DIR) {
    await mkdir(process.env.BROWSER_SCREENSHOT_DIR, { recursive: true });
    for (let i = 0; i < pages.length; i++) {
      await pages[i].page.screenshot({ path: join(process.env.BROWSER_SCREENSHOT_DIR, `browser-${i ? 'b' : 'a'}.png`), fullPage: true });
    }
    await pages[0].page.setViewportSize({ width: 390, height: 844 });
    await pages[0].page.screenshot({ path: join(process.env.BROWSER_SCREENSHOT_DIR, 'browser-mobile.png'), fullPage: true });
    assert.equal(await pages[0].page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Mobile UI must not overflow horizontally');
  }
  await testVault(browser, 'http://127.0.0.1:5173');
  await testFarcasterSmoke(browser, 'http://127.0.0.1:5173');
  assert.deepEqual(pageErrors, [], 'No uncaught application errors');
  console.log(JSON.stringify({ pass: true, separateBrowserIdentities: true, refreshUnlock: true, wrongPassphraseLocked: true, bidirectionalNativeLXMF: true, incomingSignaturesVerified: true, reconnect: true, uiEncryptedExportImport: true, plaintextAbsentFromBridgeFrames: true, frameCount: frames.length, uncaughtPageErrors: pageErrors.length }));
} finally {
  await browser.close();
  if (bridge) { for (const client of bridge.clients) client.terminate(); await new Promise(resolve => bridge.close(resolve)); }
  await vite?.close();
  if (native) { const exited = new Promise(resolve => native.once('exit', resolve)); native.kill('SIGTERM'); await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 1000))]); if (native.exitCode === null) native.kill('SIGKILL'); }
  if (directory) await rm(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
}
