import './farcaster-onboarding.css';
import { createFarcasterAuth } from './farcaster-auth.js';

/** Mount only inside the optional Farcaster dialog. No remote calls on mount. */
export function mountFarcasterOnboarding(container, { getAddress, pageUrl = location.href }) {
  const auth = createFarcasterAuth();
  const section = document.createElement('section'); section.className = 'farcaster-verification';
  const title = document.createElement('h3'); title.textContent = 'Verify a Farcaster account (experimental)';
  const explanation = document.createElement('p');
  explanation.textContent = 'Sign In With Farcaster can verify account control and a signed association with your unlocked LXMF address. This does not publish a directory listing, find followers, or verify existing contact cards. No real-account end-to-end test has been completed yet.';
  const label = document.createElement('label'), consent = document.createElement('input');
  consent.type = 'checkbox'; consent.id = 'farcaster-consent';
  label.append(consent, document.createTextNode(' I agree to correlate my public Farcaster FID and LXMF address. Farcaster’s authentication relay and wallet receive the address and sign-in request; the public Optimism RPC receives account-verification queries. These services can observe my IP and timing. No Reticulum private keys or message contents are sent.'));
  const start = document.createElement('button'); start.type = 'button'; start.textContent = 'Start Farcaster sign-in'; start.id = 'farcaster-start';
  const link = document.createElement('a'); link.textContent = 'Approve in Farcaster'; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.hidden = true; link.id = 'farcaster-auth-link';
  const check = document.createElement('button'); check.type = 'button'; check.textContent = 'Check approval'; check.hidden = true; check.id = 'farcaster-check';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel / clear verification'; cancel.id = 'farcaster-cancel';
  const status = document.createElement('p'); status.setAttribute('role', 'status'); status.id = 'farcaster-auth-status';
  status.textContent = 'Optional. You can use encrypted messaging without a Farcaster account.';
  section.append(title, explanation, label, start, link, check, cancel, status); container.append(section);
  let requestAddress = '', generation = 0, expiryTimer;
  function reset(message = 'Farcaster verification cleared locally. No directory listing was created.', preserveConsent = false) {
    generation++; auth.cancel(); clearTimeout(expiryTimer); requestAddress = '';
    if (!preserveConsent) consent.checked = false;
    link.hidden = true; link.removeAttribute('href'); check.hidden = true; start.disabled = false; check.disabled = false; status.textContent = message;
  }
  cancel.addEventListener('click', () => reset());
  consent.addEventListener('change', () => { if (!consent.checked) reset(); });
  start.addEventListener('click', async () => {
    reset('Preparing Farcaster sign-in…', true);
    const current = generation; start.disabled = true;
    try {
      requestAddress = getAddress();
      const request = await auth.begin({ address: requestAddress, pageUrl, consent: consent.checked });
      if (current !== generation) return;
      if (getAddress() !== requestAddress) { reset('Your LXMF identity changed. Start Farcaster sign-in again.'); return; }
      link.href = request.url; link.hidden = false; check.hidden = false;
      expiryTimer = setTimeout(() => reset('The short-lived Farcaster proof expired. Start again to recheck account control.'), Math.max(0, request.expiresAt - Date.now()));
      status.textContent = 'Open “Approve in Farcaster”, review the signed request, then check approval here. This request expires in five minutes.';
    } catch (error) { if (current === generation) reset(error.message); }
    finally { if (current === generation) start.disabled = false; }
  });
  check.addEventListener('click', async () => {
    const current = generation; check.disabled = true;
    try {
      if (getAddress() !== requestAddress) { reset('Your LXMF identity changed. Start Farcaster sign-in again.'); return; }
      const binding = await auth.check();
      if (current !== generation) return;
      if (getAddress() !== requestAddress) { reset('Your LXMF identity changed. Verification discarded.'); return; }
      if (!binding) { status.textContent = 'Approval is still pending. Approve in Farcaster, then check again.'; return; }
      link.hidden = true; link.removeAttribute('href'); check.hidden = true;
      status.textContent = `Verified now: Farcaster FID ${binding.fid} signed an association with LXMF ${binding.address}. This local, short-lived check is not a public listing or a verification of other contacts. Existing invitations remain self-declared.`;
    } catch (error) { if (current === generation) reset(error.message); }
    finally { if (current === generation) check.disabled = false; }
  });
  return Object.freeze({ reset, destroy() { reset(); section.remove(); } });
}
