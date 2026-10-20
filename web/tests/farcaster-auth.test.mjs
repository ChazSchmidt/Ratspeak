import test from 'node:test';
import assert from 'node:assert/strict';
import { createFarcasterAuth } from '../src/farcaster-auth.js';
const address = 'ab'.repeat(16);
function fixture() {
  let clock = Date.parse('2026-10-20T18:00:00Z'), calls = 0, params;
  const data = { state: 'completed', message: 'test fixture, not a real SIWF signature', signature: '0xab', fid: 999 };
  const verified = { success: true, fid: 42, data: null };
  const client = {
    async createChannel(value) {
      calls++; params = value;
      verified.data = { domain: value.domain, uri: value.siweUri, nonce: value.nonce, chainId: 10,
        issuedAt: new Date(clock), notBefore: new Date(value.notBefore), expirationTime: new Date(value.expirationTime) };
      return { data: { channelToken: 'test-channel', url: 'https://farcaster.xyz/~/siwf?channelToken=test-channel' } };
    },
    async status() { return { data }; },
    async verifySignInMessage(value) { assert.equal(value.nonce, params.nonce); assert.equal(value.domain, params.domain); return verified; },
  };
  const auth = createFarcasterAuth({ getClient: async () => { calls++; return client; }, now: () => clock });
  return { auth, data, verified, client, get calls() { return calls; }, get params() { return params; }, advance() { clock += 300001; },
    begin: () => auth.begin({ address, pageUrl: 'https://example.com/ratspeak/?secret=do-not-send#contact=private', consent: true }) };
}
test('no external work before consent; rejects unsafe origin or address', async () => {
  const f = fixture();
  await assert.rejects(f.auth.begin({ address, pageUrl: 'https://example.com', consent: false }), /Consent/);
  await assert.rejects(f.auth.begin({ address, pageUrl: 'http://example.com', consent: true }), /HTTPS/);
  await assert.rejects(f.auth.begin({ address: 'bad', pageUrl: 'https://example.com', consent: true }), /LXMF/);
  assert.equal(f.calls, 0);
});
test('signs canonical URI address binding; ignores relay FID; successful request cannot replay', async () => {
  const f = fixture(); await f.begin();
  assert.equal(f.params.siweUri, `https://example.com/ratspeak/?ratspeak_lxmf=${address}`);
  assert.match(f.params.nonce, /^[a-f0-9]{48}$/);
  const binding = await f.auth.check();
  assert.equal(binding.fid, '42'); assert.equal(binding.address, address);
  await assert.rejects(f.auth.check(), /Start/);
});
test('pending is not verification; cancel and expiry prevent acceptance', async () => {
  const f = fixture(); await f.begin(); f.data.state = 'pending';
  assert.equal(await f.auth.check(), null); f.auth.cancel(); await assert.rejects(f.auth.check(), /Start/);
  await f.begin(); f.advance(); await assert.rejects(f.auth.check(), /expired/);
});
for (const [field, value] of [ ['uri', 'https://example.com/other'], ['nonce', 'wrong'], ['domain', 'attacker.example'], ['chainId', 1], ['expirationTime', new Date(0)], ['notBefore', new Date(0)], ['issuedAt', new Date('2099-01-01')] ]) {
  test(`rejects mismatched signed ${field}`, async () => {
    const f = fixture(); await f.begin(); f.verified.data[field] = value;
    await assert.rejects(f.auth.check(), /did not verify/);
    await assert.rejects(f.auth.check(), /Start/);
  });
}
test('rejects SDK failure and malformed FID rather than trusting relay profile', async () => {
  for (const invalid of [{ success: false }, { isError: true }, { fid: 0 }, { fid: 1.5 }, { fid: Number.MAX_SAFE_INTEGER + 1 }]) {
    const f = fixture(); await f.begin(); Object.assign(f.verified, invalid); await assert.rejects(f.auth.check(), /did not verify/);
  }
});
test('cancellation during verification cannot reactivate an identity association', async () => {
  const f = fixture(); await f.begin();
  f.client.verifySignInMessage = async () => { f.auth.cancel(); return f.verified; };
  await assert.rejects(f.auth.check(), /cancelled/);
});
test('rejects unexpected sign-in host and relay errors', async () => {
  const f = fixture(); f.client.createChannel = async () => ({ data: { url: 'https://attacker.example/login', channelToken: 'x' } });
  await assert.rejects(f.begin(), /unexpected/);
  f.client.createChannel = async () => ({ response: { ok: false }, data: { error: 'unavailable' } });
  await assert.rejects(f.begin(), /failed/);
});
