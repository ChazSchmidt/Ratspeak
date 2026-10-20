import { Reticulum, fromHex, toHex } from '@reticulum/core';
import { LXMRouter, LXMessage } from '@reticulum/lxmf';
import { WebSocketClientInterface } from '@reticulum/core/src/interfaces/websocket.js';

export function validateAddress(value) {
  const address = String(value).trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(address)) throw new Error('Enter a 32-character hexadecimal LXMF address.');
  return address;
}

export function validateGateway(value, pageProtocol = globalThis.location?.protocol) {
  const url = new URL(value);
  if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password || url.hash)
    throw new Error('Use a ws:// or wss:// gateway URL without credentials or a fragment.');
  if (pageProtocol === 'https:' && url.protocol !== 'wss:')
    throw new Error('An HTTPS page requires a secure wss:// gateway.');
  return url.href;
}

/** Browser-only adapter. Keys and decrypted messages never leave this object for a server. */
export class MessagingClient extends EventTarget {
  constructor(identity) {
    super();
    this.identity = identity;
    this.rns = new Reticulum({ logLevel: 'ERROR' });
    this.router = new LXMRouter(identity, this.rns);
    this.interface = null;
    this.state = 'disconnected';
    this.displayName = 'Ratspeak Web';
    this.connectionGeneration = 0;
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  setState(state) { this.state = state; this.emit('state', { state }); }
  async init() {
    await this.rns.ready();
    await this.router.init();
    this.address = toHex(this.router.deliveryDest.destinationHash);
    this.router.addEventListener('peer', (event) => {
      const peer = event.detail;
      this.emit('peer', { address: toHex(peer.destinationHash), name: peer.appData?.displayName || '' });
    });
    this.router.addEventListener('message', async (event) => {
      try {
        const message = event.detail.message;
        // A received/decrypted message is not automatically an authenticated sender.
        const sender = await this.rns.transport.recallIdentity(message.sourceHash);
        const verified = Boolean(sender && await message.verifySignature(sender));
        this.emit('message', {
          address: toHex(message.sourceHash), content: String(message.content ?? ''),
          title: String(message.title ?? ''), timestamp: message.timestamp,
          id: message.messageId ? toHex(message.messageId) : crypto.randomUUID(), verified,
        });
      } catch (error) { this.emit('error', { message: `Cannot verify incoming message: ${error.message}` }); }
    });
    return this;
  }
  async connect(value, displayName = 'Ratspeak Web') {
    if (this.interface) throw new Error('Disconnect the current gateway before connecting another.');
    const url = validateGateway(value);
    const generation = ++this.connectionGeneration;
    this.displayName = displayName.trim().slice(0, 64) || 'Ratspeak Web';
    const iface = new WebSocketClientInterface({ url, autoReconnect: false, connectTimeout: 10 });
    this.interface = iface;
    this.setState('connecting');
    iface.addEventListener('disconnected', () => {
      if (this.interface === iface) this.disconnect().catch(error => this.emit('error', { message: error.message }));
    });
    try {
      // Register the stream before dialing so initial frames cannot race the transport reader.
      this.rns.addInterface(iface);
      await iface.connect();
      if (generation !== this.connectionGeneration || this.interface !== iface) {
        await iface.disconnect();
        throw new Error('Connection cancelled.');
      }
      this.setState('connected');
      await this.router.announce(this.displayName, null);
      if (generation !== this.connectionGeneration) throw new Error('Connection cancelled.');
      this.announceTimer = setInterval(() => {
        if (this.state === 'connected') this.router.announce(this.displayName, null).catch(error => this.emit('error', { message: error.message }));
      }, 120_000);
    } catch (error) {
      if (this.interface === iface) await this.disconnect();
      throw new Error(`Gateway connection failed: ${error.message}`);
    }
  }
  async announce() {
    if (this.state !== 'connected') throw new Error('Connect to a gateway first.');
    await this.router.announce(this.displayName, null);
  }
  async send(address, content) {
    if (this.state !== 'connected') throw new Error('Connect to a gateway first.');
    address = validateAddress(address);
    if (!content.trim()) throw new Error('Write a message first.');
    if (new TextEncoder().encode(content).length > 4096) throw new Error('This proof of concept limits text to 4,096 UTF-8 bytes.');
    if (address === this.address) throw new Error('Choose another identity, not your own address.');
    const message = new LXMessage({ sourceHash: this.router.deliveryDest.destinationHash,
      destinationHash: fromHex(address), title: '', content });
    await this.router.send(message, this.identity, { fallback: 'none', timeoutMs: 15_000 });
    // DIRECT send completion is a transport write, not a read or LXMF delivery receipt.
    return { id: toHex(message.messageId), state: 'sent' };
  }
  async disconnect() {
    ++this.connectionGeneration;
    clearInterval(this.announceTimer);
    const iface = this.interface;
    this.interface = null;
    this.setState('disconnecting');
    // Close incoming as well as outgoing links while the bearer can still
    // deliver LINKCLOSE. Otherwise a peer can reuse its stale reply link after
    // we reconnect, while our local link still points to the removed interface.
    const links = new Set([...this.rns.transport.activeLinks.values(), ...this.router.directLinks.values()]);
    for (const link of links) { try { await link.teardown(); } catch {} }
    this.router.directLinks.clear();
    if (iface) {
      this.rns.removeInterface(iface);
      await iface.disconnect();
    }
    this.setState('disconnected');
  }
  async close() { await this.disconnect(); await this.rns.stop(); }
}
