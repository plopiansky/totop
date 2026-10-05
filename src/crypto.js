// כל המפתחות נגזרים מסוד אחד, ENC_KEY (64 תווי hex), שמוגדר כ-secret ב-Cloudflare.
const te = new TextEncoder();

const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g) || [], b => parseInt(b, 16));
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export function checkEncKey(env) {
  if (!/^[0-9a-fA-F]{64}$/.test(env.ENC_KEY || '')) throw new Error('ENC_KEY חסר או לא תקין (נדרשים 64 תווי hex)');
}

async function derive(env, label) {
  checkEncKey(env);
  const k = await crypto.subtle.importKey('raw', fromHex(env.ENC_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, te.encode(label)));
}

export async function encrypt(env, text) {
  const key = await crypto.subtle.importKey('raw', await derive(env, 'aes'), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
  return `${b64(iv)}.${b64(ct)}`;
}

export async function decrypt(env, packed) {
  const [iv, ct] = packed.split('.').map(unb64);
  const key = await crypto.subtle.importKey('raw', await derive(env, 'aes'), 'AES-GCM', false, ['decrypt']);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

// סיסמה בת 4 ספרות חלשה מטבעה, לכן מוסיפים לה "פלפל" סודי שלא נמצא במסד הנתונים.
// מי שגונב את ה-DB בלבד לא יכול לנחש סיסמאות.
export async function hashPin(env, pin, saltHex = toHex(crypto.getRandomValues(new Uint8Array(16)))) {
  const pepper = await derive(env, 'pin');
  const salt = new Uint8Array([...fromHex(saltHex), ...pepper]);
  const base = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 }, base, 256);
  return { salt: saltHex, hash: toHex(bits) };
}

export async function verifyPin(env, pin, saltHex, hashHex) {
  const { hash } = await hashPin(env, pin, saltHex);
  let diff = hash.length ^ hashHex.length;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ (hashHex.charCodeAt(i) || 0);
  return diff === 0;
}

// הנתיב הסודי של ה-api_link בימות המשיח (היא לא יכולה לחתום בקשות)
export async function yemotPathSecret(env) {
  return toHex(await derive(env, 'yemot-path')).slice(0, 40);
}

export const randomToken = () => toHex(crypto.getRandomValues(new Uint8Array(32)));
export async function sha256Hex(text) { return toHex(await crypto.subtle.digest('SHA-256', te.encode(text))); }
export function safeEqual(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
