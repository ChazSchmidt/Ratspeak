import { Identity } from '@reticulum/core';
import { MessagingClient, validateAddress } from './messaging-client.js';
import { hasSavedIdentity, saveIdentity, unlockIdentity, exportIdentity, importIdentity } from './identity-vault.js';
import './style.css';
import { identityAvatar } from './native/identity-avatar.js';

const $ = id => document.getElementById(id);
const CONTACTS_KEY = 'ratspeak-web-contacts-v2';
let client = null, selected = '', busy = false, sending = false, saved = false;
let farcasterOnboarding = null, farcasterLoading = null;
const messages = new Map(), peers = new Map(), drafts = new Map();
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
  $('msg-profile-name').textContent = unlocked ? $('display-name').value : 'Identity locked';
  $('profile-address').textContent = client?.address || 'Open Identity to get started';
  $('sidebar-identity-name').textContent = unlocked ? $('display-name').value : 'Identity';
  $('sidebar-identity-hash').textContent = client?.address?.slice(0, 12) || 'Locked';
  $('msg-profile-avatar').replaceChildren(avatar(client?.address || '', 36));
  $('sidebar-identity-icon').replaceChildren(avatar(client?.address || '', 28));
  $('header-mobile-name').textContent = unlocked ? $('display-name').value : 'Identity locked';
  $('header-mobile-avatar').replaceChildren(avatar(client?.address || '', 28));
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
function node(tag, className, text) {
  const el = document.createElement(tag); el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
function avatar(address, size) {
  const el = node('span', '');
  // The native helper receives only a validated public hexadecimal address, never HTML input.
  el.innerHTML = identityAvatar(/^[0-9a-f]{32}$/i.test(address) ? address : '', size);
  return el;
}
function renderContacts() {
  $('conversation-list').replaceChildren(); $('contacts').replaceChildren(); $('contacts-list').replaceChildren();
  const query = $('msg-search-input').value.toLowerCase();
  const ordered = [...contacts].sort((a, b) => (messages.get(b.address)?.at(-1)?.timestamp || 0) - (messages.get(a.address)?.at(-1)?.timestamp || 0));
  for (const contact of ordered) {
    const name = contact.name || contact.handle || contact.address.slice(0, 12);
    const last = messages.get(contact.address)?.at(-1);
    if ((last || selected === contact.address) && `${name} ${contact.address} ${last?.content || ''}`.toLowerCase().includes(query)) {
      const row = node('div', 'conv-row' + (selected === contact.address ? ' active' : ''));
      row.setAttribute('role', 'button'); row.tabIndex = 0;
      row.setAttribute('aria-current', String(selected === contact.address));
      const icon = node('div', 'conv-avatar-wrap'); icon.append(avatar(contact.address, 40));
      const content = node('div', 'conv-row-content'), top = node('div', 'conv-row-top'), bottom = node('div', 'conv-row-bottom');
      top.append(node('span', 'conv-name', name), node('span', 'conv-time', last ? new Date(last.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''));
      bottom.append(node('span', 'conv-preview', last ? `${last.outbound ? 'You: ' : ''}${last.content}` : 'New conversation'));
      content.append(top, bottom); row.append(icon, content);
      row.addEventListener('click', () => selectContact(contact.address));
      row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectContact(contact.address); } });
      $('conversation-list').append(row);
    }
    const row = node('div', 'contacts-row'); row.tabIndex = 0; row.setAttribute('role', 'button');
    const content = node('div', 'contacts-row-content');
    content.append(node('span', 'contacts-row-name', name), node('span', 'contacts-row-hash', contact.address));
    const contactAvatar = node('div', 'contacts-avatar'); contactAvatar.append(avatar(contact.address, 40));
    row.append(contactAvatar, content);
    row.addEventListener('click', () => openContactDetail(contact));
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openContactDetail(contact); } });
    $('contacts-list').append(row);
    if (contact.fid) {
      const card = document.createElement('li'), address = document.createElement('small');
      card.textContent = `FID ${contact.fid}${contact.handle ? ' · @' + contact.handle : ''}`;
      address.textContent = `${contact.address} · self-declared`;
      card.append(address); $('contacts').append(card);
    }
  }
  if (!$('conversation-list').childElementCount) {
    const empty = node('div', 'empty-state');
    empty.append(node('span', 'empty-state-primary', query ? 'No matching conversations' : 'No conversations yet'), node('span', 'empty-state-hint', 'Tap the compose button to start messaging'));
    $('conversation-list').append(empty);
  }
  const contactQuery = $('contacts-search').value.toLowerCase();
  let group = '';
  for (const row of [...$('contacts-list').children].sort((a, b) => a.textContent.localeCompare(b.textContent))) {
    if (!row.textContent.toLowerCase().includes(contactQuery)) { row.remove(); continue; }
    const letter = row.querySelector('.contacts-row-name').textContent[0]?.toUpperCase() || '#';
    if (letter !== group) { $('contacts-list').append(node('div', 'contacts-group-header', letter)); group = letter; }
    $('contacts-list').append(row);
  }
  $('contacts-count').textContent = `${contacts.length} contacts`;
  if (!$('contacts-list').childElementCount) $('contacts-list').append(node('div', 'empty-state', contacts.length ? 'No matching contacts' : 'No contacts yet'));
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
  if (selected && selected !== address) drafts.set(selected, $('message-text').value);
  if (selected !== address) $('message-text').value = drafts.get(address) || '';
  selected = address;
  const contact = contacts.find(item => item.address === address);
  $('recipient-name').textContent = contact?.name || contact?.handle || 'LXMF contact';
  $('recipient-address').textContent = address;
  showView('message');
  document.querySelector('.lxmf-layout').classList.add('view-chat-detail');
  document.body.classList.add('view-chat-detail');
  $('lxmf-contact-avatar').replaceChildren(avatar(address, 40));
  renderContacts(); renderMessages(); updateControls();
}
function renderMessages() {
  $('message-list').replaceChildren();
  $('lxmf-chat-header').style.display = selected ? '' : 'none';
  $('message-form').hidden = !selected;
  const items = messages.get(selected) || [];
  if (!items.length) {
    const empty = node('div', selected ? 'lxmf-empty-conv' : 'lxmf-empty');
    if (selected) empty.append(avatar(selected, 48));
    empty.append(node('span', selected ? 'lxmf-empty-conv-name' : 'empty-state-primary', selected ? $('recipient-name').textContent : 'Your messages'), node('span', selected ? 'lxmf-empty-conv-hint' : 'empty-state-hint', selected ? 'This is the beginning of your encrypted conversation.' : 'Select a conversation or start a new one'));
    $('message-list').append(empty);
  }
  let date = '';
  for (const [index, item] of items.entries()) {
    const day = new Date(item.timestamp * 1000).toLocaleDateString();
    if (day !== date) { const separator = node('div', 'msg-date-separator'); separator.append(node('span', '', day)); $('message-list').append(separator); date = day; }
    const direction = item.outbound ? 'outbound' : 'inbound';
    const adjacent = other => other && other.outbound === item.outbound && Math.abs(other.timestamp - item.timestamp) < 180 && new Date(other.timestamp * 1000).toLocaleDateString() === day;
    const before = adjacent(items[index - 1]), after = adjacent(items[index + 1]);
    const row = node('div', `msg-row ${direction}`), body = node('div', `lxmf-msg ${direction}`);
    if (before || after) row.classList.add(before && after ? 'msg-group-middle' : before ? 'msg-group-last' : 'msg-group-first');
    const meta = node('div', 'lxmf-msg-meta' + (item.state === 'failed' ? ' error' : ''));
    meta.append(node('span', '', `${new Date(item.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · ${item.label}`));
    body.append(node('div', 'lxmf-msg-content', item.content), meta);
    row.append(body); $('message-list').append(row);
  }
  $('message-list').scrollTop = $('message-list').scrollHeight;
}
function appendMessage(address, item) {
  const items = messages.get(address) || [];
  if (items.some(existing => existing.id === item.id)) return;
  items.push(item); if (items.length > 200) items.shift();
  messages.set(address, items);
  if (selected === address) renderMessages();
  renderContacts();
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
        $('contact-dialog').showModal();
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
  await client.close(); client = null; messages.clear(); peers.clear(); drafts.clear();
  selected = ''; $('message-text').value = '';
  $('recipient-name').textContent = ''; $('recipient-address').textContent = '';
  status('message-status', '');
  document.querySelector('.lxmf-layout').classList.remove('view-chat-detail');
  document.body.classList.remove('view-chat-detail');
  renderContacts();
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
    selectContact(address); $('contact-dialog').close(); status('contact-status', 'Contact saved locally. Verify the address out of band.');
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
    if (selected === address && $('message-text').value === content) $('message-text').value = '';
    if (drafts.get(address) === content) drafts.delete(address);
    status('message-status', 'Sent. Waiting for a reply is not a delivery receipt.');
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

function showView(view) {
  for (const el of document.querySelectorAll('.view')) el.classList.toggle('active', el.id === `view-${view}`);
  for (const el of document.querySelectorAll('[data-view]')) el.classList.toggle('active', el.dataset.view === view);
  $('sidebar').classList.remove('open'); $('sidebar-overlay').classList.remove('active');
  $('bottom-sheet').classList.remove('open'); $('bottom-sheet-overlay').classList.remove('active');
  document.body.classList.toggle('view-chat-detail', view === 'message' && Boolean(selected) && document.querySelector('.lxmf-layout').classList.contains('view-chat-detail'));
}
for (const el of document.querySelectorAll('[data-view]')) el.addEventListener('click', event => { event.preventDefault(); showView(el.dataset.view); });
function newConversation() { $('contact-dialog').showModal(); $('contact-address').focus(); }
for (const id of ['lxmf-send-message-btn', 'lxmf-send-fab', 'new-contact', 'contacts-add-fab']) $(id).addEventListener('click', newConversation);
$('close-contact').addEventListener('click', () => $('contact-dialog').close());
$('msg-search-input').addEventListener('input', renderContacts);
$('msg-profile-name').addEventListener('click', () => showView('identity'));
$('profile-address').addEventListener('click', () => client ? $('copy-address').click() : showView('identity'));
$('sidebar-identity').addEventListener('click', () => showView('identity'));
$('sidebar-identity').addEventListener('keydown', event => { if (event.key === 'Enter') showView('identity'); });
$('lxmf-back-btn').addEventListener('click', () => { document.querySelector('.lxmf-layout').classList.remove('view-chat-detail'); document.body.classList.remove('view-chat-detail'); });
function toggleSidebar(open) {
  if (matchMedia('(max-width: 768px)').matches) { $('bottom-sheet').classList.toggle('open', open); $('bottom-sheet-overlay').classList.toggle('active', open); }
  else { $('sidebar').classList.toggle('open', open); $('sidebar-overlay').classList.toggle('active', open); }
}
$('hamburger-btn').addEventListener('click', () => toggleSidebar(true));
$('sidebar-close-btn').addEventListener('click', () => toggleSidebar(false));
$('sidebar-overlay').addEventListener('click', () => toggleSidebar(false));
$('sidebar-collapse-btn').addEventListener('click', () => $('sidebar').classList.toggle('collapsed'));
$('message-text').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && matchMedia('(min-width: 769px)').matches) { event.preventDefault(); if (!$('send').disabled) $('message-form').requestSubmit(); } });
$('message-text').addEventListener('input', event => { event.target.style.height = 'auto'; event.target.style.height = `${Math.min(event.target.scrollHeight, 160)}px`; });
renderMessages();

$('bottom-bar-hamburger').addEventListener('click', () => toggleSidebar(true));

$('bottom-sheet-overlay').addEventListener('click', () => toggleSidebar(false));

$('header-mobile-identity').addEventListener('click', () => showView('identity'));
$('header-mobile-identity').addEventListener('keydown', event => { if (event.key === 'Enter') showView('identity'); });

$('contacts-search').addEventListener('input', renderContacts);
for (const button of document.querySelectorAll('[data-settings-panel]')) button.addEventListener('click', () => {
  for (const nav of document.querySelectorAll('[data-settings-panel]')) { nav.classList.toggle('active', nav === button); if (nav === button) nav.setAttribute('aria-current', 'page'); else nav.removeAttribute('aria-current'); }
  for (const panel of document.querySelectorAll('.settings-panel')) { const active = panel.id === button.dataset.settingsPanel; panel.hidden = !active; panel.classList.toggle('settings-panel-selected', active); }
  $('settings-detail-title').textContent = button.dataset.settingsTitle; $('settings-mobile-detail-title').textContent = button.dataset.settingsTitle;
  $('settings-detail-desc').textContent = button.dataset.settingsDesc;
  document.querySelector('#view-settings .settings-page').classList.add('settings-detail-mode', 'settings-mobile-detail-active');
});
$('settings-mobile-back-btn').addEventListener('click', () => document.querySelector('#view-settings .settings-page').classList.remove('settings-mobile-detail-active'));

// Adapted from dashboard/static/js/lxmf.js contact detail sheet; native-only actions omitted.
function openContactDetail(contact) {
  const previousFocus = document.activeElement;
  const overlay = node('div', 'bottom-sheet-overlay'); overlay.id = 'contact-detail-overlay';
  const sheet = node('div', 'bottom-sheet'); sheet.id = 'contact-detail-sheet';
  sheet.setAttribute('role', 'dialog'); sheet.setAttribute('aria-modal', 'true'); sheet.setAttribute('aria-label', 'Contact details');
  const body = node('div', 'bottom-sheet-body');
  const close = node('button', 'bottom-sheet-close', '×'); close.type = 'button'; close.setAttribute('aria-label', 'Close contact details');
  const icon = node('div', 'contact-detail-avatar'); icon.append(avatar(contact.address, 64));
  const hashRow = node('div', 'contact-detail-hash-row'), copy = node('button', 'contact-detail-copy-btn'); copy.type = 'button'; copy.setAttribute('aria-label', 'Copy LXMF address');
  copy.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  hashRow.append(node('span', 'contact-detail-hash', contact.address), copy);
  const actions = node('div', 'contact-detail-actions contact-detail-primary-actions entity-action-grid');
  const message = node('button', 'nr-btn entity-action-btn'); message.type = 'button';
  message.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><span>Message</span>';
  const feedback = node('p', 'notice'); feedback.setAttribute('role', 'status');
  actions.append(message); body.append(close, icon, node('div', 'contact-detail-name', contact.name || contact.handle || contact.address.slice(0, 12)), hashRow, actions, feedback);
  sheet.append(node('div', 'bottom-sheet-handle'), body); document.body.append(overlay, sheet);
  function dismiss() { overlay.remove(); sheet.remove(); previousFocus?.focus(); }
  close.addEventListener('click', dismiss); overlay.addEventListener('click', dismiss);
  message.addEventListener('click', () => { dismiss(); selectContact(contact.address); });
  copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(contact.address); feedback.textContent = 'Public LXMF address copied.'; } catch { feedback.textContent = 'Clipboard unavailable. Select and copy the address above.'; } });
  sheet.addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); dismiss(); }
    if (event.key === 'Tab') { const buttons = [close, copy, message]; const index = buttons.indexOf(document.activeElement); if ((!event.shiftKey && index === 2) || (event.shiftKey && index === 0)) { event.preventDefault(); buttons[event.shiftKey ? 2 : 0].focus(); } }
  });
  void sheet.offsetHeight; overlay.classList.add('active'); sheet.classList.add('open'); close.focus();
}
