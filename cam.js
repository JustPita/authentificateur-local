import { parseOtpauth, parseMigration } from './lib.js';
import { b64, open, seal } from './vault.js';

const $ = s => document.querySelector(s);
const status = (t, c = '') => { const s = $('#status'); s.textContent = t; s.className = 'status ' + c; };
const seen = new Set();
let stream = null, key = null, stopped = false;

async function loadKey() {
  const { sess } = await chrome.storage.session.get('sess');
  if (!sess || (sess.exp && sess.exp < Date.now())) return null;
  return crypto.subtle.importKey('raw', b64.from(sess.k), 'AES-GCM', true, ['encrypt', 'decrypt']);
}

async function add(list) {
  const { vault } = await chrome.storage.local.get('vault'); // relu à chaque fois
  const entries = await open(key, vault);
  let n = 0;
  for (const e of list) {
    if (!entries.some(b => b.secret === e.secret && b.issuer === e.issuer && b.name === e.name)) { entries.push(e); n++; }
  }
  await chrome.storage.local.set({ vault: { ...vault, ...(await seal(key, entries)) } });
  return n;
}

async function handle(text) {
  let list, skipped = 0;
  if (text.startsWith('otpauth-migration:')) { const m = parseMigration(text); list = m.entries; skipped = m.skipped.length; }
  else if (text.startsWith('otpauth:')) list = [parseOtpauth(text)];
  else return;
  const n = await add(list);
  const li = document.createElement('li');
  li.textContent = `${n} compte(s) ajouté(s)` + (skipped ? `, ${skipped} ignoré(s)` : '') +
    (n < list.length ? `, ${list.length - n} déjà présent(s)` : '') + ' : ' +
    list.map(e => e.issuer || e.name).join(', ');
  $('#log').append(li);
  status('QR lu ✔ — passez le suivant, ou cliquez sur « Terminer ».', 'ok');
}

function stop() {
  stopped = true;
  stream?.getTracks().forEach(t => t.stop());
  window.close();
}

async function loop() {
  const video = $('#video'), canvas = $('#canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  while (!stopped) {
    if (video.readyState >= 2 && video.videoWidth) {
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const r = jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height,
        { inversionAttempts: 'attemptBoth' });
      if (r && r.data && !seen.has(r.data)) {
        seen.add(r.data);
        try { await handle(r.data); } catch (e) { status('Erreur : ' + e.message, 'err'); }
      }
    }
    await new Promise(r => setTimeout(r, 200));
  }
}

(async () => {
  $('#stop').onclick = stop;
  const { vault } = await chrome.storage.local.get('vault');
  key = vault ? await loadKey() : null;
  if (!key) return status('Coffre verrouillé : cliquez sur l\'icône de l\'extension, déverrouillez-le, puis rouvrez cette page.', 'err');
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 } } });
  } catch (e) {
    return status('Caméra inaccessible : ' + e.message + '. Autorisez la caméra pour cette page.', 'err');
  }
  $('#video').srcObject = stream;
  await $('#video').play();
  status('Caméra active. Présentez le QR code…');
  loop();
})();
