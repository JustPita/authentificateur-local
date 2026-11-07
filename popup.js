import { totp, normalize, parseOtpauth, parseMigration } from './lib.js';

const $ = s => document.querySelector(s);
import { b64, open, seal } from './vault.js';
const enc = new TextEncoder();
const ITER = 600000;

let key = null;      // CryptoKey AES-GCM (en mémoire seulement + storage.session)
let vault = null;    // { v, iter, salt, iv, data }
let entries = [];
let timer = null;

// ---------- Chiffrement ----------
async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function persist() {
  vault = { ...vault, ...(await seal(key, entries)) };
  await chrome.storage.local.set({ vault });
}

// ---------- Session (déverrouillage temporaire) ----------
async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { autolock: 5, ...(settings || {}) };
}
async function saveSession() {
  const { autolock } = await getSettings();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  await chrome.storage.session.set({
    sess: { k: b64.to(raw), exp: autolock ? Date.now() + autolock * 60000 : 0 },
  });
}
async function clearSession() { await chrome.storage.session.remove('sess'); }

// ---------- Vues ----------
const views = ['lock', 'main', 'add', 'settings'];
function show(v) {
  views.forEach(n => ($('#v-' + n).hidden = n !== v));
  clearInterval(timer);
  if (v === 'main') { render(); timer = setInterval(tick, 1000); }
}
function toast(msg) { $('#toast').textContent = msg; setTimeout(() => ($('#toast').textContent = ''), 1500); }

function showLock() {
  key = null; entries = [];
  const first = !vault;
  $('#lock-msg').textContent = first
    ? 'Créez un mot de passe maître. Il chiffre vos clés ; il n\'est pas récupérable si vous l\'oubliez.'
    : 'Entrez votre mot de passe maître.';
  $('#pw2').hidden = !first;
  $('#btn-unlock').textContent = first ? 'Créer le coffre' : 'Déverrouiller';
  $('#pw').value = $('#pw2').value = ''; $('#lock-err').textContent = '';
  show('lock'); $('#pw').focus();
}

async function unlock() {
  const pw = $('#pw').value, err = $('#lock-err');
  err.textContent = '';
  try {
    if (!vault) {
      if (pw.length < 8) return (err.textContent = '8 caractères minimum.');
      if (pw !== $('#pw2').value) return (err.textContent = 'Les mots de passe diffèrent.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKey(pw, salt, ITER);
      entries = [];
      vault = { v: 1, iter: ITER, salt: b64.to(salt) };
      await persist();
    } else {
      $('#btn-unlock').disabled = true;
      const k = await deriveKey(pw, b64.from(vault.salt), vault.iter);
      try { entries = await open(k, vault); } catch { return (err.textContent = 'Mot de passe incorrect.'); }
      key = k;
    }
    await saveSession();
    show('main');
  } finally { $('#btn-unlock').disabled = false; }
}

async function lock() { await clearSession(); showLock(); }

// ---------- Liste ----------
function fmt(code) { const h = code.length / 2; return code.slice(0, h) + ' ' + code.slice(h); }

function render() {
  const q = $('#search').value.trim().toLowerCase();
  const list = $('#list');
  list.replaceChildren();
  const shown = entries.filter(e => (e.issuer + ' ' + e.name).toLowerCase().includes(q));
  $('#empty').hidden = entries.length > 0;
  for (const e of shown) {
    const d = document.createElement('div'); d.className = 'item'; d.dataset.id = e.id;
    const iss = document.createElement('div'); iss.className = 'iss'; iss.textContent = e.issuer || e.name || '(sans nom)';
    const nm = document.createElement('div'); nm.className = 'nm'; nm.textContent = e.issuer ? e.name : '';
    const code = document.createElement('div'); code.className = 'code'; code.textContent = '… … …';
    const bar = document.createElement('div'); bar.className = 'bar';
    const tools = document.createElement('div'); tools.className = 'tools';
    const ren = document.createElement('button'); ren.textContent = '✎'; ren.title = 'Renommer';
    const del = document.createElement('button'); del.textContent = '🗑'; del.title = 'Supprimer';
    ren.onclick = async ev => {
      ev.stopPropagation();
      const n = prompt('Service :', e.issuer); if (n === null) return;
      const a = prompt('Compte :', e.name); if (a === null) return;
      e.issuer = n.trim(); e.name = a.trim(); await persist(); render();
    };
    del.onclick = async ev => {
      ev.stopPropagation();
      if (!confirm(`Supprimer « ${e.issuer || e.name} » ?\nAssurez-vous d'avoir désactivé la 2FA ou d'avoir une autre copie de la clé.`)) return;
      entries = entries.filter(x => x.id !== e.id); await persist(); render();
    };
    tools.append(ren, del);
    d.append(iss, nm, code, bar, tools);
    d.onclick = async () => {
      const { code: c } = await totp(e);
      await navigator.clipboard.writeText(c); toast('Code copié');
    };
    list.append(d);
  }
  tick();
}

async function tick() {
  const now = Date.now();
  for (const d of document.querySelectorAll('.item')) {
    const e = entries.find(x => x.id === d.dataset.id); if (!e) continue;
    const { code, remaining } = await totp(e, now);
    d.querySelector('.code').textContent = fmt(code);
    d.querySelector('.bar').style.width = (remaining / e.period) * 100 + '%';
    d.classList.toggle('low', remaining <= 5);
  }
}

// ---------- Ajout ----------
function isDup(a) { return entries.some(b => b.secret === a.secret && b.issuer === a.issuer && b.name === a.name); }

async function addEntries(list) {
  let added = 0;
  for (const e of list) if (!isDup(e)) { entries.push(e); added++; }
  await persist();
  return added;
}

async function addFromUri() {
  const err = $('#add-err'); err.textContent = '';
  try {
    const raw = $('#uri').value.trim();
    let list, skipped = [];
    if (raw.startsWith('otpauth-migration:')) ({ entries: list, skipped } = parseMigration(raw));
    else list = raw.split(/\s+/).filter(Boolean).map(parseOtpauth);
    if (!list.length) throw new Error('Aucun compte TOTP trouvé.');
    const n = await addEntries(list);
    $('#uri').value = '';
    show('main');
    toast(`${n} compte(s) ajouté(s)` + (skipped.length ? `, ${skipped.length} ignoré(s)` : ''));
  } catch (e) { err.textContent = e.message; }
}

// Décode un QR depuis une image (jsQR, local). Essaie plusieurs échelles.
async function decodeQr(blob) {
  const bmp = await createImageBitmap(blob);
  for (const max of [bmp.width, 1600, 1000, 600]) {
    const s = Math.min(1, max / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * s)), h = Math.max(1, Math.round(bmp.height * s));
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(bmp, 0, 0, w, h);
    const r = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
    if (r && r.data) return r.data;
  }
  return null;
}

async function importImages(files) {
  const err = $('#add-err'); err.textContent = '';
  let added = 0, skipped = 0, failed = 0;
  for (const f of files) {
    try {
      const text = await decodeQr(f);
      if (!text) { failed++; continue; }
      let list;
      if (text.startsWith('otpauth-migration:')) { const m = parseMigration(text); list = m.entries; skipped += m.skipped.length; }
      else if (text.startsWith('otpauth:')) list = [parseOtpauth(text)];
      else { failed++; continue; }
      added += await addEntries(list);
    } catch (e) { failed++; }
  }
  if (!added && !skipped) { err.textContent = failed ? 'Aucun QR code TOTP lisible dans cette image.' : 'Rien à ajouter.'; return; }
  show('main');
  toast(`${added} compte(s) ajouté(s)` + (skipped ? `, ${skipped} ignoré(s)` : '') + (failed ? `, ${failed} image(s) illisible(s)` : ''));
}

async function addManual() {
  const err = $('#add-err'); err.textContent = '';
  try {
    const e = normalize({
      issuer: $('#m-issuer').value, name: $('#m-name').value, secret: $('#m-secret').value,
      algorithm: $('#m-alg').value, digits: $('#m-digits').value, period: $('#m-period').value,
    });
    await totp(e); // vérifie que le calcul fonctionne
    await addEntries([e]);
    ['#m-issuer', '#m-name', '#m-secret'].forEach(s => ($(s).value = ''));
    show('main'); toast('Compte ajouté');
  } catch (e) { err.textContent = e.message; }
}

// ---------- Paramètres ----------
async function openSettings() {
  $('#autolock').value = String((await getSettings()).autolock);
  $('#set-msg').textContent = '';
  show('settings');
}

function download(name, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

async function importBackup(file) {
  const msg = $('#set-msg');
  try {
    const v = JSON.parse(await file.text());
    if (v.v !== 1 || !v.salt || !v.data) throw new Error('Fichier non reconnu.');
    const pw = prompt('Mot de passe maître de cette sauvegarde :'); if (pw === null) return;
    const k = await deriveKey(pw, b64.from(v.salt), v.iter);
    let list;
    try { list = await open(k, v); } catch { throw new Error('Mot de passe incorrect pour cette sauvegarde.'); }
    const n = await addEntries(list.map(e => ({ ...e, id: crypto.randomUUID() })));
    msg.textContent = `${n} compte(s) importé(s).`;
  } catch (e) { msg.textContent = e.message; }
}

// ---------- Événements ----------
$('#btn-unlock').onclick = unlock;
$('#pw').onkeydown = $('#pw2').onkeydown = e => { if (e.key === 'Enter') unlock(); };
$('#btn-lock').onclick = lock;
$('#btn-add').onclick = () => { $('#add-err').textContent = ''; show('add'); };
$('#add-back').onclick = () => show('main');
$('#btn-add-uri').onclick = addFromUri;
$('#btn-cam').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('cam.html') });
$('#btn-qr').onclick =() => $('#file-qr').click();
$('#file-qr').onchange = e => { const f = [...e.target.files]; e.target.value = ''; if (f.length) importImages(f); };
document.addEventListener('paste', e => {
  if ($('#v-add').hidden) return;
  const f = [...(e.clipboardData?.files || [])].filter(x => x.type.startsWith('image/'));
  if (f.length) { e.preventDefault(); importImages(f); }
});
$('#btn-add-manual').onclick = addManual;
$('#btn-settings').onclick = openSettings;
$('#set-back').onclick = () => show('main');
$('#search').oninput = render;
$('#autolock').onchange = async e => {
  await chrome.storage.local.set({ settings: { autolock: Number(e.target.value) } });
  await saveSession();
};
$('#btn-export').onclick = () => download(`authentificateur-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(vault, null, 2));
$('#btn-import').onclick = () => $('#file-import').click();
$('#file-import').onchange = e => { if (e.target.files[0]) importBackup(e.target.files[0]); e.target.value = ''; };
$('#btn-wipe').onclick = async () => {
  if (!confirm('Effacer TOUT le coffre ? Cette action est irréversible.')) return;
  if (!confirm('Dernière confirmation : toutes les clés seront perdues.')) return;
  await chrome.storage.local.remove('vault'); await clearSession(); vault = null; showLock();
};

// ---------- Démarrage ----------
(async () => {
  ({ vault = null } = await chrome.storage.local.get('vault'));
  if (vault) {
    const { sess } = await chrome.storage.session.get('sess');
    if (sess && (!sess.exp || sess.exp > Date.now())) {
      try {
        const k = await crypto.subtle.importKey('raw', b64.from(sess.k), 'AES-GCM', true, ['encrypt', 'decrypt']);
        entries = await open(k, vault); key = k;
        await saveSession(); // prolonge l'inactivité
        return show('main');
      } catch { await clearSession(); }
    } else if (sess) await clearSession();
  }
  showLock();
})();
