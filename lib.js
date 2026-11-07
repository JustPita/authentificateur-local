// Logique TOTP + imports. Aucune dépendance, aucun accès réseau.
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(s) {
  s = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, val = 0;
  const out = [];
  for (const c of s) {
    const i = A.indexOf(c);
    if (i < 0) throw new Error('Clé invalide (base32 attendu : A-Z et 2-7)');
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  if (!out.length) throw new Error('Clé vide');
  return new Uint8Array(out);
}

export function base32Encode(u8) {
  let bits = 0, val = 0, out = '';
  for (const b of u8) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
}

export async function totp(e, now = Date.now()) {
  const period = e.period || 30, digits = e.digits || 6;
  const alg = (e.algorithm || 'SHA1').toUpperCase();
  const counter = Math.floor(now / 1000 / period);
  const dv = new DataView(new ArrayBuffer(8));
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  dv.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey(
    'raw', base32Decode(e.secret), { name: 'HMAC', hash: 'SHA-' + alg.slice(3) }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, dv.buffer));
  const o = h[h.length - 1] & 15;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits;
  return { code: String(n).padStart(digits, '0'), remaining: period - ((now / 1000) % period) };
}

function normalize(e) {
  const algorithm = (e.algorithm || 'SHA1').toUpperCase().replace('-', '');
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error('Algorithme non supporté : ' + algorithm);
  base32Decode(e.secret); // valide la clé
  return {
    id: crypto.randomUUID(),
    issuer: (e.issuer || '').trim(),
    name: (e.name || '').trim(),
    secret: e.secret.toUpperCase().replace(/[\s=-]/g, ''),
    algorithm,
    digits: Number(e.digits) === 8 ? 8 : 6,
    period: Number(e.period) > 0 ? Number(e.period) : 30,
  };
}
export { normalize };

// otpauth://totp/Issuer:compte?secret=...&issuer=...
export function parseOtpauth(uri) {
  const u = new URL(uri.trim());
  if (u.protocol !== 'otpauth:') throw new Error('Pas un lien otpauth://');
  if (u.host !== 'totp') throw new Error('Seul le type TOTP est supporté (pas HOTP)');
  let label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  let issuer = u.searchParams.get('issuer') || '';
  let name = label;
  const i = label.indexOf(':');
  if (i >= 0) { if (!issuer) issuer = label.slice(0, i); name = label.slice(i + 1); }
  return normalize({
    issuer, name,
    secret: u.searchParams.get('secret') || '',
    algorithm: u.searchParams.get('algorithm'),
    digits: u.searchParams.get('digits'),
    period: u.searchParams.get('period'),
  });
}

// --- Import Google Authenticator : otpauth-migration://offline?data=... (protobuf) ---
function readVarint(b, p) {
  let r = 0, s = 0, x;
  do { x = b[p.i++]; r += (x & 127) * 2 ** s; s += 7; } while (x & 128);
  return r;
}
function readMsg(b, onField) {
  const p = { i: 0 };
  while (p.i < b.length) {
    const tag = readVarint(b, p), f = tag >>> 3, w = tag & 7;
    if (w === 0) onField(f, readVarint(b, p));
    else if (w === 2) { const l = readVarint(b, p); onField(f, b.subarray(p.i, p.i + l)); p.i += l; }
    else if (w === 1) p.i += 8;
    else if (w === 5) p.i += 4;
    else throw new Error('Données de migration corrompues');
  }
}

export function parseMigration(uri) {
  const u = new URL(uri.trim());
  if (u.protocol !== 'otpauth-migration:') throw new Error('Pas un lien otpauth-migration://');
  const raw = (u.searchParams.get('data') || '').replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(raw);
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
  const dec = new TextDecoder();
  const out = [], skipped = [];
  readMsg(bytes, (f, v) => {
    if (f !== 1) return;
    const o = { algorithm: 'SHA1', digits: 6, type: 2 };
    readMsg(v, (g, x) => {
      if (g === 1) o.secret = base32Encode(x);
      else if (g === 2) o.name = dec.decode(x);
      else if (g === 3) o.issuer = dec.decode(x);
      else if (g === 4) o.algorithm = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' }[x] || 'MD5';
      else if (g === 5) o.digits = x === 2 ? 8 : 6;
      else if (g === 6) o.type = x;
    });
    if (o.type !== 2) { skipped.push(o.issuer || o.name || '?'); return; } // HOTP ignoré
    try { out.push(normalize(o)); } catch { skipped.push(o.issuer || o.name || '?'); }
  });
  return { entries: out, skipped };
}
