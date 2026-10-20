// Real UI integration, not a mock: two Chromium contexts through native Python RNS.
// PYTHON=/path/to/venv/bin/python CHROMIUM_EXECUTABLE_PATH=/path/to/chromium npm run test:browser
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createServer } from 'vite';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBridge } from '../scripts/reticulum-bridge.mjs';
const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}) });
let vite, bridge, native, directory;
try {
  vite = await createServer({ server: { host: '127.0.0.1', port: 5173, strictPort: true } }); await vite.listen();
  directory = await mkdtemp(join(tmpdir(), 'ratspeak-browser-'));
  native = spawn(process.env.PYTHON || 'python3', [fileURLToPath(new URL('./native-peer.py', import.meta.url)), '--directory', directory, '--port', '14242']);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Native transport startup timed out')), 15000);
    let buffer = '';
    native.stdout.on('data', data => { buffer += data; if (buffer.includes('"event": "ready"')) { clearTimeout(timer); resolve(); } });
    native.once('error', reject); native.once('exit', code => reject(new Error(`Native peer exited ${code}`)));
  });
  bridge = await startBridge({ port: 18787, tcpPort: 14242 });
  const pages = [];
  for (const name of ['Browser A', 'Browser B']) {
    const context = await browser.newContext(); const page = await context.newPage();
    await page.goto('http://127.0.0.1:5173');
    await page.locator('#display-name').fill(name);
    await page.locator('#passphrase').fill('temporary browser fixture password');
    await page.locator('#create').click();
    await page.waitForFunction(() => /^[0-9a-f]{32}$/.test(document.querySelector('#address').textContent));
    const address = await page.locator('#address').textContent();
    await page.reload(); await page.locator('#passphrase').fill('temporary browser fixture password');
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
  await pages[1].page.locator('#message-text').fill('Reply ' + marker); await pages[1].page.locator('#send').click();
  await pages[0].page.getByText('Reply ' + marker, { exact: true }).waitFor({ timeout: 25000 });
  console.log('PASS: two independent browser identities, encrypted local refresh/unlock, and bidirectional LXMF over native Reticulum.');
} finally {
  await browser.close();
  if (bridge) { for (const client of bridge.clients) client.terminate(); await new Promise(resolve => bridge.close(resolve)); }
  await vite?.close();
  if (native) { const exited = new Promise(resolve => native.once('exit', resolve)); native.kill('SIGTERM'); await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 1000))]); if (native.exitCode === null) native.kill('SIGKILL'); }
  if (directory) await rm(directory, { recursive: true, force: true });
}
