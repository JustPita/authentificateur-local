// Chiffrement partagé entre le popup et la page webcam.
const enc = new TextEncoder(), dec = new TextDecoder();
export const b64 = {
  to: u8 => btoa(String.fromCharCode(...u8)),
  from: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
};
export async function seal(k, list) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify(list)));
  return { iv: b64.to(iv), data: b64.to(new Uint8Array(ct)) };
}
export async function open(k, v) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.from(v.iv) }, k, b64.from(v.data));
  return JSON.parse(dec.decode(pt));
}
