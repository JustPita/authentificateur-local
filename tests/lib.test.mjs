import test from 'node:test';
import assert from 'node:assert/strict';
import { totp, base32Encode, base32Decode, parseOtpauth, parseMigration } from '../lib.js';

const enc = s => base32Encode(new TextEncoder().encode(s));
const S1 = enc('12345678901234567890');
const S256 = enc('12345678901234567890123456789012');
const S512 = enc('1234567890123456789012345678901234567890123456789012345678901234');
const code = async (algorithm, secret, t) => (await totp({ secret, algorithm, digits: 8 }, t * 1000)).code;

// Vecteurs de test de la RFC 6238 (annexe B)
test('RFC 6238 SHA1', async () => {
  assert.equal(await code('SHA1', S1, 59), '94287082');
  assert.equal(await code('SHA1', S1, 1111111109), '07081804');
  assert.equal(await code('SHA1', S1, 20000000000), '65353130');
});
test('RFC 6238 SHA256', async () => assert.equal(await code('SHA256', S256, 59), '46119246'));
test('RFC 6238 SHA512', async () => assert.equal(await code('SHA512', S512, 59), '90693936'));

test('base32 aller-retour', () => {
  const b = new Uint8Array([0, 1, 2, 250, 251, 255, 7]);
  assert.deepEqual(base32Decode(base32Encode(b)), b);
  assert.throws(() => base32Decode('1!?'));
});

test('otpauth://', () => {
  const e = parseOtpauth('otpauth://totp/GitHub:moi@x.fr?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60');
  assert.equal(e.issuer, 'GitHub'); assert.equal(e.name, 'moi@x.fr');
  assert.equal(e.digits, 8); assert.equal(e.period, 60);
  assert.throws(() => parseOtpauth('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP'));
});

test('otpauth-migration://', () => {
  const sb = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef];
  const nm = [...'a@b'].map(c => c.charCodeAt(0)), is = [...'Svc'].map(c => c.charCodeAt(0));
  const inner = [0x0a, sb.length, ...sb, 0x12, nm.length, ...nm, 0x1a, is.length, ...is, 0x20, 1, 0x28, 1, 0x30, 2];
  const data = encodeURIComponent(Buffer.from([0x0a, inner.length, ...inner]).toString('base64'));
  const m = parseMigration('otpauth-migration://offline?data=' + data);
  assert.deepEqual(m.entries.map(x => [x.issuer, x.name, x.secret]), [['Svc', 'a@b', 'JBSWY3DPEHPK3PXP']]);
});
