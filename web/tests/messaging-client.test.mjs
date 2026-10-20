import test from 'node:test';
import assert from 'node:assert/strict';
import { MessagingClient, validateAddress, validateGateway } from '../src/messaging-client.js';

test('addresses are canonical and malformed peers are rejected', () => {
  assert.equal(validateAddress(' A'.trim().repeat(32)), 'a'.repeat(32));
  for (const value of ['', 'ab', 'g'.repeat(32), 'a'.repeat(33)]) assert.throws(() => validateAddress(value));
});
test('HTTPS requires WSS and gateway credentials are rejected', () => {
  assert.equal(validateGateway('wss://example.org/rns', 'https:'), 'wss://example.org/rns');
  assert.throws(() => validateGateway('ws://localhost:8787', 'https:'));
  for (const value of ['https://example.org', 'wss://user:secret@example.org', 'wss://example.org/#token']) assert.throws(() => validateGateway(value));
});
test('send rejects disconnected, self, empty and oversized messages before transport', async () => {
  const target = { state: 'disconnected', address: 'a'.repeat(32) };
  await assert.rejects(MessagingClient.prototype.send.call(target, 'b'.repeat(32), 'hello'), /Connect/);
  target.state = 'connected';
  await assert.rejects(MessagingClient.prototype.send.call(target, 'bad', 'hello'), /32-character/);
  await assert.rejects(MessagingClient.prototype.send.call(target, 'a'.repeat(32), 'hello'), /own address/);
  await assert.rejects(MessagingClient.prototype.send.call(target, 'b'.repeat(32), ' '), /Write/);
  await assert.rejects(MessagingClient.prototype.send.call(target, 'b'.repeat(32), '🦀'.repeat(1025)), /4,096/);
});
test('disconnect invalidates pending connection and discards cached links', async () => {
  let removed = false, disconnected = false, tornDown = false;
  const iface = { async disconnect() { disconnected = true; } };
  const target = { connectionGeneration: 3, interface: iface,
    rns: { removeInterface(value) { assert.equal(value, iface); removed = true; } },
    router: { directLinks: new Map([['peer', { async teardown() { tornDown = true; } }]]) },
    setState(state) { this.state = state; } };
  await MessagingClient.prototype.disconnect.call(target);
  assert.equal(target.connectionGeneration, 4); assert.equal(target.interface, null);
  assert.ok(removed && disconnected && tornDown); assert.equal(target.router.directLinks.size, 0);
  assert.equal(target.state, 'disconnected');
});
