import test from 'node:test';
import assert from 'node:assert/strict';
import { hdlcEncode, hdlcDecoder } from '../scripts/reticulum-bridge.mjs';

test('HDLC escapes delimiters and restores fragmented/coalesced frames', () => {
  const packets = [Buffer.from([0, 0x7e, 0x7d, 255]), Buffer.from([1, 2, 3])];
  const decoded = [];
  const read = hdlcDecoder(p => decoded.push(p));
  const bytes = Buffer.concat(packets.map(hdlcEncode));
  for (let i = 0; i < bytes.length; i += 2) read(bytes.subarray(i, i + 2));
  assert.deepEqual(decoded, packets);
});
test('HDLC drops noise and empty frames; bounds unclosed frames', () => {
  const decoded = [];
  const read = hdlcDecoder(p => decoded.push(p), 3);
  read(Buffer.from([1, 2, 0x7e, 0x7e]));
  assert.deepEqual(decoded, []);
  assert.throws(() => read(Buffer.from([1, 2, 3, 4])), /exceeds/);
});

test('bridge rejects foreign origins and text packets, forwards binary packets', async () => {
  const { default: net } = await import('node:net');
  const { WebSocket } = await import('ws');
  const { startBridge } = await import('../scripts/reticulum-bridge.mjs');
  const tcp = net.createServer(socket => socket.pipe(socket));
  await new Promise(resolve => tcp.listen(0, '127.0.0.1', resolve));
  const bridge = await startBridge({ port: 0, tcpPort: tcp.address().port, allowedOrigins: ['http://localhost:5173'] });
  const url = `ws://127.0.0.1:${bridge.address().port}`;
  try {
    await new Promise((resolve, reject) => {
      const bad = new WebSocket(url, { origin: 'https://untrusted.invalid' });
      bad.once('open', () => { bad.terminate(); reject(new Error('Unexpected origin accepted')); });
      bad.once('error', error => { try { assert.match(error.message, /401/); resolve(); } catch (error) { reject(error); } });
    });
    const ws = new WebSocket(url, { origin: 'http://localhost:5173' });
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    const packet = Buffer.alloc(24, 0x7e); packet[1] = 0x7d;
    const reply = new Promise(resolve => ws.once('message', resolve));
    ws.send(packet); assert.deepEqual(await reply, packet);
    const closed = new Promise(resolve => ws.once('close', resolve));
    ws.send('not a Reticulum packet'); assert.equal(await closed, 1003);
  } finally {
    for (const ws of bridge.clients) ws.terminate();
    await new Promise(resolve => bridge.close(resolve));
    await new Promise(resolve => tcp.close(resolve));
  }
});
