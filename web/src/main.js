import { Identity, Reticulum, toHex } from '@reticulum/core';
import { LXMRouter } from '@reticulum/lxmf';
import './style.css';

const $ = (id) => document.getElementById(id);
const STORAGE_KEY = 'ratspeak-web-experiment-contacts-v1';
let identity = null;
let address = '';
const normalizeFid = (value) => /^\d{1,12}$/.test(value.trim()) ? value.trim() : null;
function updateContacts() {
  let contacts = [];
  try { contacts = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch {}
  $('contacts').replaceChildren();
  for (const contact of contacts) {
    const li = document.createElement('li');
    const strong = document.createElement('strong');
    strong.textContent = contact.handle ? '@' + contact.handle : 'FID ' + contact.fid;
    const small = document.createElement('small');
    small.textContent = 'FID ' + contact.fid + ' · ' + contact.address;
    li.append(strong, small);
    $('contacts').append(li);
  }
}
function parseCard(value) {
  let card;
  if (value.startsWith('http:') || value.startsWith('https:')) {
    const url = new URL(value);
    if (!url.searchParams.has('contact')) throw new Error('No contact in this link');
    card = JSON.parse(atob(url.searchParams.get('contact').replace(/-/g, '+').replace(/_/g, '/')));
  } else card = JSON.parse(value);
  if (card.type !== 'ratspeak-web-contact-v1' || !normalizeFid(String(card.fid)) || !/^[0-9a-f]{32}$/i.test(card.address))
    throw new Error('Invalid contact card: expected FID and 16-byte LXMF destination');
  if (card.handle && !/^[a-zA-Z0-9_.-]{1,64}$/.test(card.handle)) throw new Error('Invalid handle');
  return { fid: String(card.fid), handle: card.handle || '', address: card.address.toLowerCase() };
}
$('create').addEventListener('click', async () => {
  $('create').disabled = true;
  $('status').textContent = 'Generating locally…';
  try {
    identity = await Identity.generate();
    const router = new LXMRouter(identity, new Reticulum());
    await router.init();
    address = toHex(router.deliveryDest.destinationHash);
    $('address').textContent = address;
    $('status').textContent = 'Reticulum identity created locally. Keep this tab open.';
    $('share').disabled = false;
  } catch (error) {
    $('status').textContent = 'Identity initialization failed: ' + error.message;
    $('create').disabled = false;
  }
});
$('share').addEventListener('click', async () => {
  const fid = normalizeFid($('fid').value);
  const handle = $('handle').value.trim().replace(/^@/, '');
  if (!address || !fid || (handle && !/^[a-zA-Z0-9_.-]{1,64}$/.test(handle))) {
    $('feedback').textContent = 'Generate an identity, then enter a valid numeric FID and optional handle.';
    return;
  }
  const card = { type: 'ratspeak-web-contact-v1', fid, handle, address };
  const payload = btoa(JSON.stringify(card)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const link = new URL(window.location.href);
  link.search = '';
  link.hash = '';
  link.searchParams.set('contact', payload);
  try { await navigator.clipboard.writeText(link.href); $('feedback').textContent = 'Public invitation copied!'; }
  catch { $('feedback').textContent = 'Copy this public invitation: ' + link.href; }
});
$('add').addEventListener('click', () => {
  try {
    const contact = parseCard($('invite').value.trim());
    let contacts = [];
    try { contacts = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch {}
    contacts = contacts.filter((item) => item.fid !== contact.fid);
    contacts.push(contact);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts));
    $('feedback').textContent = 'Public contact saved locally (identity unverified).';
    updateContacts();
  } catch (error) { $('feedback').textContent = error.message; }
});
const incoming = new URL(window.location.href).searchParams.get('contact');
if (incoming) {
  $('invite').value = window.location.href;
  $('feedback').textContent = 'Incoming public contact card. Review before adding.';
}
updateContacts();
