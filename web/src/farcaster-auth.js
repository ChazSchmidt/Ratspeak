/** Optional SIWF experiment. No relay/RPC requests until explicitly begun. */
export const FARCASTER_RELAY = 'https://relay.farcaster.xyz';
export const FARCASTER_RPC = 'https://mainnet.optimism.io';
const TTL = 5 * 60_000;

async function defaultClient() {
  const { createAppClient, viemConnector } = await import('@farcaster/auth-client');
  return createAppClient({ relay: FARCASTER_RELAY, ethereum: viemConnector({ rpcUrl: FARCASTER_RPC }) });
}
function requireConsent(consent) {
  if (consent !== true) throw new Error('Consent is required to link your public FID and LXMF address through Farcaster authentication.');
}
function resultData(result, operation) {
  if (result?.isError || !result?.data || result.response?.ok === false) {
    throw new Error(`Farcaster ${operation} failed. The relay or Optimism RPC may be unavailable; retry later.`);
  }
  return result.data;
}
function dateValue(value) {
  const number = new Date(value).getTime();
  return Number.isFinite(number) ? number : NaN;
}

/** Factory injection is for isolated tests, never for treating relay data as verified. */
export function createFarcasterAuth({ getClient = defaultClient, now = () => Date.now(), random = crypto } = {}) {
  let active = null;
  function cancel() { if (active) active.cancelled = true; active = null; }
  function assertActive(request) {
    if (active !== request || request.cancelled) throw new Error('Farcaster sign-in was cancelled or replaced.');
    if (now() >= request.expires) { cancel(); throw new Error('Farcaster sign-in expired. Start again.'); }
  }
  async function begin({ address, pageUrl, consent }) {
    requireConsent(consent);
    if (typeof address !== 'string' || !/^[0-9a-f]{32}$/.test(address)) throw new Error('Unlock a valid LXMF identity first.');
    const page = new URL(pageUrl);
    if (page.protocol !== 'https:' && !(page.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(page.hostname))) {
      throw new Error('Farcaster authentication requires HTTPS (or local development).');
    }
    if (page.username || page.password) throw new Error('Invalid application URL.');
    cancel();
    const nonce = Array.from(random.getRandomValues(new Uint8Array(24)), byte => byte.toString(16).padStart(2, '0')).join('');
    // This exact URI is signed by the Farcaster account, not merely supplied by the relay.
    const uri = new URL(page.pathname, page.origin);
    uri.searchParams.set('ratspeak_lxmf', address);
    const request = { address, nonce, domain: page.host, uri: uri.href, issued: now(), expires: now() + TTL, cancelled: false, checking: false };
    active = request;
    try {
      request.client = await getClient(); assertActive(request);
      const data = resultData(await request.client.createChannel({
        domain: request.domain, siweUri: request.uri, nonce,
        notBefore: new Date(request.issued).toISOString(), expirationTime: new Date(request.expires).toISOString(),
      }), 'request');
      assertActive(request);
      const signInUrl = new URL(data.url);
      if (signInUrl.protocol !== 'https:' || signInUrl.hostname !== 'farcaster.xyz' || signInUrl.pathname !== '/~/siwf' || signInUrl.port || signInUrl.username || signInUrl.password) {
        throw new Error('The Farcaster relay returned an unexpected sign-in destination.');
      }
      if (typeof data.channelToken !== 'string' || !data.channelToken || data.channelToken.length > 1024) throw new Error('Invalid Farcaster channel response.');
      request.token = data.channelToken;
      return Object.freeze({ url: signInUrl.href, expiresAt: request.expires, address });
    } catch (error) { if (active === request) cancel(); throw error; }
  }
  async function check() {
    const request = active;
    if (!request?.token) throw new Error('Start Farcaster sign-in first.');
    assertActive(request);
    if (request.checking) throw new Error('A Farcaster status check is already running.');
    request.checking = true;
    try {
      const response = resultData(await request.client.status({ channelToken: request.token }), 'status check');
      assertActive(request);
      if (response.state === 'pending') return null;
      if (response.state !== 'completed' || typeof response.message !== 'string' || response.message.length > 16_384 || !/^0x[0-9a-fA-F]+$/.test(response.signature || '') || response.signature.length > 16_384) {
        throw new Error('Invalid Farcaster sign-in response.');
      }
      // SDK verifies SIWE signature, nonce/domain, chain 10, FID resource and on-chain
      // custody/auth-address authorization. Relay-supplied FID/profile are untrusted.
      const verified = await request.client.verifySignInMessage({ nonce: request.nonce, domain: request.domain, message: response.message, signature: response.signature, acceptAuthAddress: true });
      assertActive(request);
      const signed = verified?.data;
      if (verified?.isError || verified?.success !== true || !Number.isSafeInteger(verified.fid) || verified.fid <= 0 ||
          signed?.uri !== request.uri || signed?.nonce !== request.nonce || signed?.domain !== request.domain || signed?.chainId !== 10 ||
          dateValue(signed.expirationTime) !== request.expires || dateValue(signed.notBefore) !== request.issued ||
          !Number.isFinite(dateValue(signed.issuedAt)) || dateValue(signed.issuedAt) > now() || dateValue(signed.issuedAt) < request.issued - 60_000) {
        throw new Error('Farcaster proof did not verify for this address, origin, and sign-in request.');
      }
      const binding = Object.freeze({ type: 'ratspeak-farcaster-local-verification-v1', fid: String(verified.fid), address: request.address,
        verifiedAt: new Date(now()).toISOString(), expiresAt: new Date(request.expires).toISOString(),
        message: response.message, signature: response.signature });
      cancel(); // Single use. No login token or account session is persisted.
      return binding;
    } catch (error) { if (active === request) cancel(); throw error; }
    finally { request.checking = false; }
  }
  return Object.freeze({ begin, check, cancel });
}
