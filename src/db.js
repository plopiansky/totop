import { hashPin, verifyPin, encrypt, decrypt, randomToken, sha256Hex } from './crypto.js';

export const MAX_FAILS = 5;
export const LOCK_MS = 15 * 60 * 1000;
const SESSION_MS = 7 * 24 * 3600 * 1000;

// 0501234567 / +972501234567 / 972-50-1234567 -> 0501234567
export function normalizePhone(input) {
  let d = String(input || '').replace(/\D/g, '');
  if (d.startsWith('972')) d = '0' + d.slice(3);
  return /^0\d{8,9}$/.test(d) ? d : '';
}

export const getSetting = async (db, key) => (await db.prepare('SELECT value FROM settings WHERE key=?').bind(key).first())?.value ?? null;
export const setSetting = (db, key, value) =>
  db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(key, String(value)).run();

export const findUserByPhone = (db, phone) => db.prepare('SELECT * FROM users WHERE phone=?').bind(phone).first();
export const countUsers = async db => (await db.prepare('SELECT COUNT(*) AS n FROM users').first()).n;

// המשתמש הראשון הוא המנהל. מחזיר null אם המספר כבר רשום.
export async function createUser(env, { phone, name, pin }) {
  const { salt, hash } = await hashPin(env, pin);
  try {
    await env.DB.prepare(
      'INSERT INTO users(phone,name,pin_salt,pin_hash,is_admin,created_at) VALUES(?,?,?,?,(SELECT COUNT(*)=0 FROM users),?)'
    ).bind(phone, name, salt, hash, Date.now()).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) return null;
    throw e;
  }
  return findUserByPhone(env.DB, phone);
}

// בדיקת סיסמה עם נעילה אחרי 5 כשלונות. תוצאות: ok | wrong | locked | unknown
export async function checkPin(env, phone, pin, now = Date.now()) {
  const u = await findUserByPhone(env.DB, phone);
  if (!u) { await hashPin(env, pin); return { status: 'unknown' }; } // שומר על זמן תגובה דומה
  if (u.locked_until > now) return { status: 'locked', user: u };
  if (await verifyPin(env, pin, u.pin_salt, u.pin_hash)) {
    if (u.failed) await env.DB.prepare('UPDATE users SET failed=0, locked_until=0 WHERE id=?').bind(u.id).run();
    return { status: 'ok', user: u };
  }
  const failed = u.failed + 1;
  const lock = failed >= MAX_FAILS ? now + LOCK_MS : 0;
  await env.DB.prepare('UPDATE users SET failed=?, locked_until=? WHERE id=?').bind(lock ? 0 : failed, lock, u.id).run();
  return { status: lock ? 'locked' : 'wrong', user: u };
}

export async function createSession(db, userId, now = Date.now()) {
  const token = randomToken();
  await db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await sha256Hex(token), userId, now + SESSION_MS).run();
  return token;
}
export async function sessionUser(db, token, now = Date.now()) {
  if (!token) return null;
  return db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?')
    .bind(await sha256Hex(token), now).first();
}
export async function deleteSession(db, token) {
  await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256Hex(token)).run();
}

export async function addKey(env, userId, name, secret) {
  const r = await env.DB.prepare('INSERT INTO totp_keys(user_id,name,secret_enc) VALUES(?,?,?)').bind(userId, name, await encrypt(env, secret)).run();
  return r.meta?.last_row_id;
}
export async function listKeys(db, userId) {
  return (await db.prepare('SELECT id,name FROM totp_keys WHERE user_id=? ORDER BY id').bind(userId).all()).results;
}
export async function getSecret(env, userId, keyId) {
  const k = await env.DB.prepare('SELECT secret_enc FROM totp_keys WHERE id=? AND user_id=?').bind(keyId, userId).first();
  return k ? decrypt(env, k.secret_enc) : null;
}
export async function deleteKey(db, userId, keyId) {
  const r = await db.prepare('DELETE FROM totp_keys WHERE id=? AND user_id=?').bind(keyId, userId).run();
  return (r.meta?.changes ?? 0) > 0;
}
