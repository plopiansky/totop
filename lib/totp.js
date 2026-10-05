import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function normalizeSecret(input) {
  return String(input || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
}

export function isValidSecret(input) {
  const s = normalizeSecret(input);
  return s.length >= 16 && /^[A-Z2-7]+$/.test(s);
}

export function base32Decode(input) {
  const s = normalizeSecret(input);
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('מפתח לא תקין');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totp(secret, { time = Date.now(), step = 30, digits = 6, algorithm = 'sha1' } = {}) {
  const counter = Math.floor(time / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac(algorithm, base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function secondsLeft(time = Date.now(), step = 30) {
  return step - (Math.floor(time / 1000) % step);
}

// מקבל גם מפתח גולמי וגם קישור otpauth://
export function parseKeyInput(input) {
  const raw = String(input || '').trim();
  if (raw.startsWith('otpauth://')) {
    const url = new URL(raw);
    const secret = url.searchParams.get('secret');
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, '').replace(/^totp\//i, ''));
    return { secret: normalizeSecret(secret), label };
  }
  return { secret: normalizeSecret(raw), label: '' };
}
