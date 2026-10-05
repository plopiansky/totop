const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function normalizeSecret(input) {
  return String(input || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
}

export function isValidSecret(input) {
  const s = normalizeSecret(input);
  return s.length >= 16 && /^[A-Z2-7]+$/.test(s);
}

export function base32Decode(input) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of normalizeSecret(input)) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('מפתח לא תקין');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function totp(secret, { time = Date.now(), step = 30, digits = 6, algorithm = 'SHA-1' } = {}) {
  const counter = Math.floor(time / 1000 / step);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[h.length - 1] & 0xf;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const secondsLeft = (time = Date.now(), step = 30) => step - (Math.floor(time / 1000) % step);

// מקבל מפתח גולמי או קישור otpauth://
export function parseKeyInput(input) {
  const raw = String(input || '').trim();
  if (raw.startsWith('otpauth://')) {
    const url = new URL(raw);
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, '').replace(/^totp\//i, ''));
    return { secret: normalizeSecret(url.searchParams.get('secret')), label };
  }
  return { secret: normalizeSecret(raw), label: '' };
}
