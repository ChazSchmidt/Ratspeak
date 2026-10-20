import { Identity } from '@reticulum/core';
import { MessagingClient, validateAddress } from './messaging-client.js';
import { hasSavedIdentity, saveIdentity, unlockIdentity, exportIdentity, importIdentity } from './identity-vault.js';
import './style.css';

const $ = id => document.getElementById(id);
const CONTACTS_KEY = 'ratspeak-web-contacts-v2';
let client = null, selected = '', busy = false, sending = false, saved = false;
let farcasterOnboarding = null, farcasterLoading = null;
const messages = new Map(), peers = new Map();
const normalizeFid = value => /^\d{1,12}$/.test(value.trim()) ? value.trim() : null;
function status(id, text, error = false) {
  $(id).textContent = text; $(id).classList.toggle('error', error);
}
function readContacts(key) {
  try {
    const items = JSON.parse(localStorage.getItem(key) || '[]');
    if (!Array.isArray(items)) return [];
    return items.filter(item => item && typeof item.address === 'string' && /^[0-9a-f]{32}$/i.test(item.address))
      .slice(0, 500).map(item => ({ address: item.address.toLowerCase(),
        name: String(item.name || item.handle || '').slice(0, 64),
        fid: normalizeFid(String(item.fid || '')), handle: String(item.handle || '').slice(0, 64) }));
  } catch { return []; }
}
let contacts = readContacts(CONTACTS_KEY);
if (!contacts.length) contacts = readContacts('ratspeak-web-experiment-contacts-v1');

function updateControls() {
  const unlocked = Boolean(client);
  $('create').hidden = saved || unlocked;
  $('unlock').hidden = !saved || unlocked;
  $('create').disabled = busy; $('unlock').disabled = busy;
  $('lock').disabled = !unlocked || busy || sending;
  $('export').disabled = !unlocked || busy;
  $('copy-address').disabled = !unlocked;
  $('import').disabled = busy || sending || unlocked;
  $('share').disabled = !unlocked;
  $('connect').disabled = !unlocked || busy || client.state === 'connected' || client.state === 'connecting';
  $('disconnect').disabled = !unlocked || (busy && client.state !== 'connecting') || (!client.interface && client.state === 'disconnected');
  $('announce').disabled = !unlocked || client.state !== 'connected';
  $('send').disabled = !unlocked || client.state !== 'connected' || !selected || sending;
  $('message-text').disabled = !unlocked || !selected;
}
function renderContacts() {
  $('conversation-list').replaceChildren(); $('contacts').replaceChildren();
  for (const contact of contacts) {
    const li = document.createElement('li'), button = document.createElement('button');
    button.type = 'button';
    button.textContent = contact.name || contact.handle || contact.address.slice(0, 12);
    button.setAttribute('aria-current', String(selected === contact.address));
    const small = document.createElement('small'); small.textContent = contact.address;
    button.append(small);
    button.addEventListener('click', () => selectContact(contact.address));
    li.append(button); $('conversation-list').append(li);
    if (contact.fid) {
      const card = document.createElement('li'), address = document.createElement('small');
      card.textContent = `FID ${contact.fid}${contact.handle ? ' · @' + contact.handle : ''}`;
      address.textContent = `${contact.address} · self-declared`;
      card.append(address); $('contacts').append(card);
    }
  }
}
function addContact(contact) {
  contact.address = validateAddress(contact.address);
  if (client?.address === contact.address) throw new Error('This is your own address.');
  const next = contacts.filter(item => item.address !== contact.address);
  if (next.length >= 500) throw new Error('This prototype supports up to 500 local contacts.');
  next.push(contact);
  localStorage.setItem(CONTACTS_KEY, JSON.stringify(next));
  contacts = next; renderContacts();
}
function selectContact(address) {
  selected = address;
  const contact = contacts.find(item => item.address === address);
  $('recipient-name').textContent = contact?.name || contact?.handle || 'LXMF contact';
  $('recipient-address').textContent = address;
  renderContacts(); renderMessages(); updateControls();
}
function renderMessages() {
  $('message-list').replaceChildren();
  const items = messages.get(selected) || [];
  if (!items.length) {
    const empty = document.createElement('p'); empty.className = 'empty-state';
    empty.textContent = selected ? 'No messages in this tab yet.' : 'Select a contact to start an encrypted LXMF conversation.';
    $('message-list').append(empty);
  }
  for (const item of items) {
    const row = document.createElement('div'), body = document.createElement('div'), meta = document.createElement('span');
    row.className = `msg-row ${item.outbound ? 'outbound' : 'inbound'}`;
    body.className = 'lxmf-msg'; body.textContent = item.content;
    meta.className = 'msg-meta' + (item.state === 'failed' ? ' error' : '');
    meta.textContent = `${new Date(item.timestamp * 1000).toLocaleTimeString()} · ${item.label}`;
    row.append(body, meta); $('message-list').append(row);
  }
  $('message-list').scrollTop = $('message-list').scrollHeight;
}
function appendMessage(address, item) {
  const items = messages.get(address) || [];
  if (items.some(existing => existing.id === item.id)) return;
  items.push(item); if (items.length > 200) items.shift();
  messages.set(address, items);
  if (selected === address) renderMessages();
}
async function activate(identity) {
  farcasterOnboarding?.reset();
  client = await new MessagingClient(identity).init();
  const activeClient = client;
  $('address').textContent = client.address;
  client.addEventListener('state', event => {
    status('connection-status', event.detail.state === 'connected' ? 'Gateway connected · messages use end-to-end encryption' : event.detail.state);
    $('connection-status').classList.toggle('online', event.detail.state === 'connected');
    updateControls();
  });
  client.addEventListener('error', event => status('message-status', event.detail.message, true));
  client.addEventListener('peer', event => {
    if (client !== activeClient) return;
    const peer = event.detail;
    if (peer.address === client.address || peers.size >= 200) return;
    peers.set(peer.address, peer); $('discovered').replaceChildren();
    for (const item of peers.values()) {
      const li = document.createElement('li'), button = document.createElement('button');
      button.type = 'button'; button.textContent = `${item.name || 'LXMF peer'} · ${item.address}`;
      button.addEventListener('click', () => {
        $('contact-address').value = item.address; $('contact-name').value = item.name;
        status('contact-status', 'Review this address before adding.');
      });
      li.append(button); $('discovered').append(li);
    }
  });
  client.addEventListener('message', event => {
    if (client !== activeClient) return;
    const message = event.detail;
    if (!contacts.some(item => item.address === message.address)) {
      try { addContact({ address: message.address, name: 'New contact' }); }
      catch (error) { status('contact-status', error.message, true); }
    }
    appendMessage(message.address, { ...message, outbound: false, state: 'received',
      label: message.verified ? 'Received · signature verified' : 'Received · sender signature unverified' });
    if (!selected) selectContact(message.address);
    status('message-status', message.verified ? 'Encrypted message received and signature verified.' : 'Message received, but sender signature is not verified.', !message.verified);
  });
  status('status', 'Identity unlocked locally. Connect to a gateway to exchange messages.');
  updateControls();
}
async function identityAction(action) {
  if (busy) return;
  busy = true; updateControls();
  try { await action(); $('passphrase').value = ''; }
  catch (error) { status('status', error.message, true); }
  finally { busy = false; updateControls(); }
}
$('create').addEventListener('click', () => identityAction(async () => {
  if (await hasSavedIdentity()) throw new Error('An identity is already stored. Unlock it instead of replacing it.');
  const identity = await Identity.generate();
  await saveIdentity(identity, $('passphrase').value); saved = true; await activate(identity);
}));
$('unlock').addEventListener('click', () => identityAction(async () => activate(await unlockIdentity($('passphrase').value))));
$('lock').addEventListener('click', () => identityAction(async () => {
  farcasterOnboarding?.reset();
  await client.close(); client = null; messages.clear(); peers.clear();
  $('discovered').replaceChildren(); $('address').textContent = '';
  renderMessages(); status('status', 'Identity locked. Enter your passphrase to unlock it.');
}));
$('export').addEventListener('click', () => identityAction(async () => {
  const data = await exportIdentity(client.identity, $('passphrase').value);
  const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url; link.download = `ratspeak-${client.address}-encrypted.json`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  status('status', 'Encrypted backup exported. Keep its passphrase separately.');
}));
$('import').addEventListener('change', () => identityAction(async () => {
  const file = $('import').files?.[0]; if (!file) return;
  if (file.size > 16_384) throw new Error('Identity backup is too large.');
  const identity = await importIdentity(await file.text(), $('passphrase').value);
  if (await hasSavedIdentity() && !confirm('Replace the locally stored identity with this backup? Export the existing identity first if you need to keep it.')) return;
  await saveIdentity(identity, $('passphrase').value); saved = true;
  await activate(identity); $('import').value = '';
}));
$('copy-address').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(client.address); status('status', 'Public LXMF address copied.'); }
  catch { status('status', 'Clipboard unavailable. Select and copy your displayed address.'); }
});
$('connect').addEventListener('click', async () => {
  if (busy || !client) return;
  busy = true; updateControls();
  try { await client.disconnect(); await client.connect($('gateway').value, $('display-name').value); }
  catch (error) { status('connection-status', error.message, true); }
  finally { busy = false; updateControls(); }
});
$('disconnect').addEventListener('click', async () => {
  try { await client?.disconnect(); }
  catch (error) { status('connection-status', error.message, true); }
  finally { updateControls(); }
});
$('announce').addEventListener('click', async () => {
  try { await client.announce(); status('connection-status', 'Connected · public address announced.'); }
  catch (error) { status('connection-status', error.message, true); }
});
$('contact-form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const address = validateAddress($('contact-address').value);
    addContact({ address, name: $('contact-name').value.trim().slice(0, 64) });
    selectContact(address); status('contact-status', 'Contact saved locally. Verify the address out of band.');
  } catch (error) { status('contact-status', error.message, true); }
});
$('message-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (sending || !client || !selected) return;
  const content = $('message-text').value, address = selected;
  if (!content.trim()) { status('message-status', 'Write a message first.', true); return; }
  const item = { id: crypto.randomUUID(), content, timestamp: Date.now() / 1000, outbound: true, state: 'sending', label: 'Sending…' };
  sending = true; updateControls(); appendMessage(address, item);
  try {
    await client.send(address, content); item.state = 'sent'; item.label = 'Sent to encrypted link · not delivery-confirmed';
    $('message-text').value = ''; status('message-status', 'Sent. Waiting for a reply is not a delivery receipt.');
  } catch (error) {
    item.state = 'failed'; item.label = `Not confirmed: ${error.message}`;
    status('message-status', 'Send failed or could not be confirmed. Check the gateway and recipient before retrying.', true);
  } finally { sending = false; renderMessages(); updateControls(); }
});
function parseCard(value) {
  let card;
  if (value.length > 8192) throw new Error('Contact invitation is too large.');
  if (/^https?:/.test(value)) {
    const url = new URL(value);
    const payload = new URLSearchParams(url.hash.slice(1)).get('contact') || url.searchParams.get('contact');
    if (!payload) throw new Error('No contact in this link.');
    card = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  } else card = JSON.parse(value);
  if (!card || card.type !== 'ratspeak-web-contact-v1' || !normalizeFid(String(card.fid))) throw new Error('Invalid Farcaster contact card.');
  const handle = String(card.handle || '');
  if (handle && !/^[a-zA-Z0-9_.-]{1,64}$/.test(handle)) throw new Error('Invalid handle.');
  return { fid: String(card.fid), handle, name: handle, address: validateAddress(card.address) };
}
$('share').addEventListener('click', async () => {
  const fid = normalizeFid($('fid').value), handle = $('handle').value.trim().replace(/^@/, '');
  if (!client || !fid || (handle && !/^[a-zA-Z0-9_.-]{1,64}$/.test(handle))) {
    status('feedback', 'Unlock your identity, then enter a valid numeric FID and optional handle.', true); return;
  }
  const card = { type: 'ratspeak-web-contact-v1', fid, handle, address: client.address };
  const payload = btoa(JSON.stringify(card)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const link = new URL(location.href); link.search = ''; link.hash = `contact=${payload}`;
  try { await navigator.clipboard.writeText(link.href); status('feedback', 'Public, self-declared invitation copied.'); }
  catch { status('feedback', `Copy this public invitation: ${link.href}`); }
});
$('add').addEventListener('click', () => {
  try { addContact(parseCard($('invite').value.trim())); status('feedback', 'Contact saved locally. Farcaster ownership is not verified.'); }
  catch (error) { status('feedback', error.message, true); }
});
const incoming = new URLSearchParams(location.hash.slice(1)).get('contact') || new URL(location.href).searchParams.get('contact');
if (incoming) { $('invite').value = location.href; status('feedback', 'Incoming public contact card. Review it before adding.'); }
const dialog = $('farcaster-dialog');
$('open-farcaster').addEventListener('click', async () => {
  dialog.showModal();
  if (farcasterOnboarding) return;
  try {
    farcasterLoading ??= import('./farcaster-onboarding.js');
    const { mountFarcasterOnboarding } = await farcasterLoading;
    farcasterOnboarding ??= mountFarcasterOnboarding($('farcaster-verification'), { getAddress: () => client?.address });
    if (!dialog.open) farcasterOnboarding.reset();
  } catch {
    farcasterLoading = null;
    status('feedback', 'Optional Farcaster verification could not load. Messaging and self-declared invitations still work.', true);
  }
});
dialog.addEventListener('close', () => farcasterOnboarding?.reset());
$('close-farcaster').addEventListener('click', () => dialog.close());
dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
renderContacts();
try {
  saved = await hasSavedIdentity();
  status('status', saved ? 'Identity locked. Enter your passphrase to restore it.' : 'Create a locally protected identity to begin.');
} catch (error) { status('status', `Identity storage unavailable: ${error.message}`, true); }
updateControls();
