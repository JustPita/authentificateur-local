// Génère icons/*.png sans dépendance : node scripts/make-icons.mjs
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
const crcT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = b => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (t, d) => { const b = Buffer.alloc(12 + d.length); b.writeUInt32BE(d.length, 0); b.write(t, 4); d.copy(b, 8); b.writeUInt32BE(crc(b.subarray(4, 8 + d.length)), 8 + d.length); return b; };
function png(s) {
  const SS = 4, raw = Buffer.alloc((s * 4 + 1) * s);
  const inRR = (x, y) => { const r = 0.22 * s, cx = Math.min(Math.max(x, r), s - r), cy = Math.min(Math.max(y, r), s - r); return (x - cx) ** 2 + (y - cy) ** 2 <= r * r; };
  const white = (x, y) => {
    const c = s / 2, d = Math.hypot(x - c, y - c);
    if (Math.abs(d - 0.28 * s) <= 0.035 * s) return true;                       // anneau
    const t = 0.03 * s;
    if (Math.abs(x - c) <= t && y >= c - 0.2 * s && y <= c + t) return true;    // aiguille haute
    if (Math.abs(y - c) <= t && x >= c - t && x <= c + 0.14 * s) return true;   // aiguille droite
    return false;
  };
  for (let y = 0; y < s; y++) {
    raw[y * (s * 4 + 1)] = 0;
    for (let x = 0; x < s; x++) {
      let a = 0, w = 0;
      for (let i = 0; i < SS; i++) for (let j = 0; j < SS; j++) {
        const px = x + (i + 0.5) / SS, py = y + (j + 0.5) / SS;
        if (inRR(px, py)) { a++; if (white(px, py)) w++; }
      }
      const o = y * (s * 4 + 1) + 1 + x * 4, n = SS * SS;
      const f = a ? w / a : 0;
      raw[o] = Math.round(0xfa * (1 - f) + 255 * f); raw[o + 1] = Math.round(0x1e * (1 - f) + 255 * f);
      raw[o + 2] = Math.round(0x4e * (1 - f) + 255 * f); raw[o + 3] = Math.round(255 * a / n);
    }
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(s, 0); ihdr.writeUInt32BE(s, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
mkdirSync('icons', { recursive: true });
for (const s of [16, 32, 48, 128]) writeFileSync(`icons/icon${s}.png`, png(s));
