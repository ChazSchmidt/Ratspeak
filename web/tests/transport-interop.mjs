// Integration fixture: real TCP RNS transport and independent Python LXMF peer.
// PYTHON=/path/to/venv/bin/python node tests/transport-interop.mjs
// Requires independently installed rns==1.5.7 and lxmf==1.2.1.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';
import { Identity } from '@reticulum/core';
import { MessagingClient } from '../src/messaging-client.js';
import { startBridge } from '../scripts/reticulum-bridge.mjs';

const directory = await mkdtemp(path.join(tmpdir(), 'ratspeak-interop-'));
const native = spawn(process.env.PYTHON || 'python3', [fileURLToPath(new URL('./native-peer.py', import.meta.url)), '--directory', directory, '--port', '14242'], { stdio: ['ignore', 'pipe', 'inherit'] });
const nativeEvents = [];
const nativeAddress = await new Promise((resolve, reject) => {
 const timer = setTimeout(() => { native.kill('SIGTERM'); reject(new Error('Native startup timed out')); }, 15000);
 let buffer = ''; 
 native.stdout.on('data', chunk => { buffer += chunk; let end; while ((end = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0,end); buffer = buffer.slice(end+1); try { const event = JSON.parse(line); nativeEvents.push(event); if (event.event === 'ready') { clearTimeout(timer); resolve(event.address); } } catch {} } });
 native.once('error', error => { clearTimeout(timer); reject(error); }); native.once('exit', code => { clearTimeout(timer); reject(new Error('Native peer exited: ' + code)); });
});
assert.match(nativeAddress, /^[0-9a-f]{32}$/);
const ORIGIN = 'http://127.0.0.1:5173';
globalThis.WebSocket = class extends WebSocket { constructor(url) { super(url, { origin: ORIGIN }); } };
const frames = [];
const bridge = await startBridge({ port: 18787, tcpPort: 14242, onPacket: (direction, data) => frames.push({direction,data}) });
const clients = [];
const timeout = setTimeout(() => { console.error('Integration test timed out'); process.exit(1); }, 45000);
async function client() {
  const result = await new MessagingClient(await Identity.generate()).init();
  result.messages = [];
  result.addEventListener('message', event => result.messages.push(event.detail));
  result.addEventListener('error', event => console.error('Adapter error:', event.detail.message));
  clients.push(result);
  await result.connect('ws://127.0.0.1:18787', 'Isolated adapter test');
  assert.equal(result.state, 'connected');
  return result;
}
const waitFor = async (predicate, label) => {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > 20000) throw new Error('Timed out: ' + label);
    await new Promise(r => setTimeout(r, 100));
  }
};
try {
  const a = await client(), b = await client();
  assert.notEqual(a.address, b.address);
  const secret = 'rts-private-' + crypto.randomUUID();
  const send = (peer, address, content) => peer.send(address, content);
  // Two separate JS stacks, real RNS transport between their TCP connections.
  await send(a, b.address, secret);
  await waitFor(() => b.messages.some(m => m.content === secret), 'A to B');
  // Different protocol implementation receives, verifies, and replies.
  await send(a, nativeAddress, secret + '-native');
  await waitFor(() => a.messages.some(m => m.content === 'Python echo: ' + secret + '-native'), 'Python echo');
  assert.ok(nativeEvents.some(e => e.event === 'received' && e.content === secret + '-native' && e.signature_validated));
  assert.ok(b.messages.find(m => m.content === secret).verified, 'Adapter authenticates JS sender');
  assert.ok(a.messages.find(m => m.content === 'Python echo: ' + secret + '-native').verified, 'Adapter authenticates Python sender');
  // Reattach a fresh bearer without replacing the user's identity or router.
  const originalAddress = a.address;
  await a.disconnect(); assert.equal(a.state, 'disconnected');
  await a.connect('ws://127.0.0.1:18787', 'Reconnected adapter');
  assert.equal(a.address, originalAddress);
  await b.announce();
  await send(b, a.address, secret + '-reconnected');
  await waitFor(() => a.messages.some(m => m.content === secret + '-reconnected'), 'Delivery after reconnect');
  assert.ok(a.messages.find(m => m.content === secret + '-reconnected').verified);
  assert.ok(frames.length > 0);
  assert.ok(frames.every(({data}) => !data.includes(Buffer.from(secret))), 'Bridge must not see test plaintext');
  console.log(JSON.stringify({pass: true, actualMessagingClientAdapter: true, nodeStackPair: true, adapterSignatureVerified: true, independentPythonEcho: true, reconnect: true, pythonSignatureValidated: true, plaintextAbsentFromBridgeFrames: true, frameCount: frames.length, addresses: clients.map(c => c.address)}));
} catch (error) {
  console.error(error); process.exitCode = 1;
} finally {
  await Promise.race([Promise.all(clients.map(c => c.close())), new Promise(resolve => setTimeout(resolve, 2000))]);
  for (const ws of bridge.clients) ws.terminate();
  await new Promise(resolve => bridge.close(resolve));
  const stopped = new Promise(resolve => native.once('exit', resolve));
  native.kill('SIGTERM');
  await Promise.race([stopped, new Promise(resolve => setTimeout(() => { native.kill('SIGKILL'); resolve(); }, 3000))]);
  await rm(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
  clearTimeout(timeout);
  process.exit(process.exitCode || 0);
}
