/** Ratspeak Web raw-RNS WebSocket ↔ native Reticulum HDLC TCP bridge.
 * No Reticulum identity, LXMF parsing, keys, or message storage lives here.
 * Keep loopback by default; terminate TLS at a reverse proxy for remote clients.
 */
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';

export const MAX_PACKET = 65536;
const MAX_BUFFERED = 1024 * 1024;
export function hdlcEncode(packet) {
  const out = [0x7e];
  for (const b of packet) {
    if (b === 0x7e || b === 0x7d) out.push(0x7d, b ^ 0x20);
    else out.push(b);
  }
  out.push(0x7e);
  return Buffer.from(out);
}

export function hdlcDecoder(onPacket, maxPacket = MAX_PACKET) {
  let frame = [], active = false, escaped = false;
  return (chunk) => {
    for (const b of chunk) {
      if (b === 0x7e) {
        if (active && frame.length && !escaped) onPacket(Buffer.from(frame));
        frame = []; active = true; escaped = false;
      } else if (active) {
        if (escaped) { frame.push(b ^ 0x20); escaped = false; }
        else if (b === 0x7d) escaped = true;
        else frame.push(b);
        if (frame.length > maxPacket) throw new Error('Reticulum TCP frame exceeds limit');
      }
    }
  };
}

export async function startBridge({
  host = '127.0.0.1', port = 8787,
  tcpHost = '127.0.0.1', tcpPort = 4242,
  allowedOrigins = ['http://127.0.0.1:5173', 'http://localhost:5173', 'http://127.0.0.1:4173', 'http://localhost:4173'],
  onPacket = null, // Test-only observer; production does not log packet contents.
} = {}) {
  const origins = new Set(allowedOrigins);
  const server = new WebSocketServer({
    host, port, maxPayload: MAX_PACKET, perMessageDeflate: false,
    verifyClient: ({ origin }) => origins.has(origin),
  });
  server.on('connection', (ws) => {
    const tcp = net.createConnection({ host: tcpHost, port: tcpPort });
    tcp.setNoDelay(true);
    let connected = false;
    const pending = [];
    let pendingBytes = 0;
    const close = (code = 1011, reason = 'Reticulum connection closed') => {
      pending.length = 0;
      if (ws.readyState === WebSocket.OPEN) ws.close(code, reason);
      tcp.destroy();
    };
    const writePacket = (packet) => {
      if (tcp.writableLength > MAX_BUFFERED) return close(1013, 'Reticulum transport is busy');
      onPacket?.('browser-to-reticulum', Buffer.from(packet));
      tcp.write(hdlcEncode(packet));
    };
    tcp.setTimeout(10000, () => { if (!connected) close(1013, 'Reticulum connection timed out'); });
    tcp.on('connect', () => {
      connected = true; tcp.setTimeout(0);
      for (const packet of pending) writePacket(packet);
      pending.length = 0; pendingBytes = 0;
    });
    const decode = hdlcDecoder((packet) => {
      if (packet.length < 19) return;
      if (ws.readyState !== WebSocket.OPEN) return;
      if (ws.bufferedAmount > MAX_BUFFERED) return close(1013, 'Browser transport is busy');
      onPacket?.('reticulum-to-browser', Buffer.from(packet));
      ws.send(packet, { binary: true });
    });
    tcp.on('data', (data) => { try { decode(data); } catch { close(1009, 'Invalid Reticulum frame'); } });
    tcp.on('error', () => close(1011, 'Cannot reach the configured Reticulum node'));
    tcp.on('close', () => close());
    ws.on('error', () => tcp.destroy());
    ws.on('close', () => tcp.destroy());
    ws.on('message', (packet, binary) => {
      if (!binary || packet.length < 19 || packet.length > MAX_PACKET) {
        close(1003, 'Expected a binary Reticulum packet'); return;
      }
      if (connected) writePacket(packet);
      else {
        pendingBytes += packet.length;
        if (pendingBytes > MAX_BUFFERED) return close(1013, 'Reticulum transport is busy');
        pending.push(Buffer.from(packet));
      }
    });
  });
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  return server;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const port = Number(process.env.BRIDGE_PORT || 8787);
  const tcpPort = Number(process.env.RNS_TCP_PORT || 4242);
  if (![port, tcpPort].every(p => Number.isInteger(p) && p > 0 && p < 65536)) throw new Error('Invalid port');
  const options = { host: process.env.BRIDGE_HOST || '127.0.0.1', port,
    tcpHost: process.env.RNS_TCP_HOST || '127.0.0.1', tcpPort };
  if (process.env.ALLOWED_ORIGINS) options.allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(x => x.trim());
  const server = await startBridge(options);
  console.log(`Ratspeak packet bridge listening on ${options.host}:${port}; native RNS at ${options.tcpHost}:${tcpPort}`);
  const stop = () => { for (const ws of server.clients) ws.terminate(); server.close(() => process.exit(0)); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
