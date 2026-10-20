// Real signature verification with a synthetic account and injected registry.
// This does not establish ownership of any live Farcaster FID.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAppClient } from '@farcaster/auth-client';
import { createPublicClient, custom } from 'viem';
import { optimism } from 'viem/chains';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';

test('official SDK verifies real SIWF signatures and rejects custody, signature, domain, nonce and chain mismatches', async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const impostor = privateKeyToAccount(generatePrivateKey());
  const publicClient = createPublicClient({ chain: optimism, transport: custom({ request: async () => { throw new Error('No network permitted in this fixture'); } }) });
  let ownerFid = 42n;
  const app = createAppClient({ ethereum: { publicClient, getFid: async () => ownerFid, isValidAuthAddress: async () => false } });
  const options = { nonce: '0123456789abcdef', domain: 'example.com', acceptAuthAddress: false };
  const values = { address: account.address, chainId: 10, domain: options.domain, nonce: options.nonce,
    uri: `https://example.com/?ratspeak_lxmf=${'ab'.repeat(16)}`, version: '1', statement: 'Farcaster Auth', resources: ['farcaster://fid/42'],
    issuedAt: new Date(), expirationTime: new Date(Date.now() + 300_000) };
  const message = createSiweMessage(values);
  const signature = await account.signMessage({ message });
  const verify = extra => app.verifySignInMessage({ ...options, message, signature, ...extra });
  assert.equal((await verify()).success, true);
  assert.equal((await verify()).fid, 42);
  for (const changes of [{ nonce: 'wrongnonce' }, { domain: 'wrong.example' }, { signature: await impostor.signMessage({ message }) }]) {
    assert.notEqual((await verify(changes)).success, true);
  }
  const wrongChainMessage = createSiweMessage({ ...values, chainId: 1 });
  assert.notEqual((await verify({ message: wrongChainMessage, signature: await account.signMessage({ message: wrongChainMessage }) })).success, true);
  ownerFid = 43n;
  assert.notEqual((await verify()).success, true);
});
