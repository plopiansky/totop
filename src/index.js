import { PAGE } from './page.js';
import { handleCall } from './call.js';
import { installExtension } from './ymapi.js';
import { parseKeyInput, isValidSecret } from './totp.js';
import { yemotPathSecret, safeEqual, checkEncKey } from './crypto.js';
import {
  getSetting, setSetting, normalizePhone, countUsers, createUser, checkPin,
  createSession, sessionUser, deleteSession, addKey, listKeys, deleteKey,
} from './db.js';

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
const text = (status, body, type = 'text/plain; charset=utf-8') =>
  new Response(body, { status, headers: { 'Content-Type': type, 'Cache-Control': 'no-store' } });

const cookie = (token, maxAge = 604800) =>
  `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const sidOf = req => /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.get('Cookie') || '')?.[1];

const validPin = p => /^\d{4}$/.test(p);
const cleanName = n => String(n || '').trim().replace(/\s+/g, ' ').slice(0, 40);

async function readBody(req) {
  // דורשים JSON כדי שטופס מאתר אחר לא יוכל לשלוח בקשה בשם המשתמש
  if (!(req.headers.get('Content-Type') || '').includes('application/json')) throw new Error('bad type');
  return req.json();
}

async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === 'GET' && path === '/') return text(200, PAGE, 'text/html; charset=utf-8');
  checkEncKey(env);

  // ימות המשיח: /yemot/<סוד שנגזר מ-ENC_KEY>
  if (path.startsWith('/yemot/')) {
    if (!safeEqual(path.slice(7), await yemotPathSecret(env))) return text(404, 'not found');
    return text(200, await handleCall(env, Object.fromEntries(url.searchParams)));
  }

  const me = await sessionUser(env.DB, sidOf(req));
  const configured = (await getSetting(env.DB, 'configured')) === '1';

  if (req.method === 'GET' && path === '/api/state') {
    return json(200, {
      configured,
      hasUsers: (await countUsers(env.DB)) > 0,
      openRegistration: (await getSetting(env.DB, 'open_registration')) === '1',
      user: me && { name: me.name, phone: me.phone, isAdmin: !!me.is_admin },
    });
  }

  if (req.method !== 'POST' && req.method !== 'DELETE' && req.method !== 'GET') return json(405, { error: 'method' });
  const body = req.method === 'POST' ? await readBody(req) : {};

  // הקמת המערכת בימות המשיח. בפעם הראשונה דורשת קוד הקמה, אחר כך מנהל מחובר.
  if (req.method === 'POST' && path === '/api/setup') {
    if (configured) {
      if (!me?.is_admin) return json(403, { error: 'רק מנהל יכול להקים מחדש' });
    } else {
      if (!env.SETUP_CODE) return json(500, { error: 'SETUP_CODE לא הוגדר ב-Cloudflare' });
      if (!safeEqual(String(body.setupCode || ''), env.SETUP_CODE)) return json(403, { error: 'קוד הקמה שגוי' });
    }
    const folder = body.folder === '/' || /^\/\d{1,3}$/.test(body.folder || '') ? body.folder : null;
    if (!folder) return json(400, { error: 'נתיב לא תקין. למשל / או /9' });
    if (!body.token || String(body.token).length > 200) return json(400, { error: 'חסר טוקן' });
    if (!body.confirm) return json(400, { error: 'יש לאשר את הדריסה של השלוחה' });
    const apiLink = `${url.origin}/yemot/${await yemotPathSecret(env)}`;
    try {
      const notes = await installExtension(String(body.token).trim(), folder, apiLink);
      await setSetting(env.DB, 'configured', '1');
      return json(200, { ok: true, notes });
    } catch (e) {
      return json(502, { error: e.message });
    }
  }

  if (req.method === 'POST' && (path === '/api/login' || path === '/api/register')) {
    const phone = normalizePhone(body.phone);
    const pin = String(body.pin || '');
    if (!phone || !validPin(pin)) return json(400, { error: 'יש להזין מספר טלפון תקין וסיסמה בת 4 ספרות' });

    if (path === '/api/register') {
      if (!configured) return json(400, { error: 'המערכת עדיין לא הוקמה' });
      const first = (await countUsers(env.DB)) === 0;
      if (!first && (await getSetting(env.DB, 'open_registration')) !== '1') {
        return json(403, { error: 'ההרשמה סגורה. בקשו ממנהל להוסיף אתכם' });
      }
      const name = cleanName(body.name);
      if (!name) return json(400, { error: 'יש להזין שם' });
      const u = await createUser(env, { phone, name, pin });
      if (!u) return json(409, { error: 'המספר כבר רשום' });
      return json(200, { ok: true }, { 'Set-Cookie': cookie(await createSession(env.DB, u.id)) });
    }

    const r = await checkPin(env, phone, pin);
    if (r.status === 'locked') return json(429, { error: 'החשבון ננעל ל-15 דקות עקב ניסיונות שגויים' });
    if (r.status !== 'ok') return json(401, { error: 'מספר טלפון או סיסמה שגויים' });
    return json(200, { ok: true }, { 'Set-Cookie': cookie(await createSession(env.DB, r.user.id)) });
  }

  if (!path.startsWith('/api/')) return json(404, { error: 'not found' });
  if (!me) return json(401, { error: 'לא מחובר' });

  if (req.method === 'POST' && path === '/api/logout') {
    await deleteSession(env.DB, sidOf(req));
    return json(200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
  }
  if (req.method === 'GET' && path === '/api/keys') return json(200, { keys: await listKeys(env.DB, me.id) });

  if (req.method === 'POST' && path === '/api/keys') {
    const parsed = parseKeyInput(body.key);
    const name = cleanName(body.name) || cleanName(parsed.label);
    if (!name) return json(400, { error: 'יש להזין שם (יוקרא בטלפון)' });
    if (!isValidSecret(parsed.secret)) return json(400, { error: 'מפתח לא תקין. צריך מפתח Base32 או קישור otpauth' });
    return json(200, { ok: true, id: await addKey(env, me.id, name, parsed.secret) });
  }
  const del = /^\/api\/keys\/(\d+)$/.exec(path);
  if (req.method === 'DELETE' && del) {
    return (await deleteKey(env.DB, me.id, Number(del[1]))) ? json(200, { ok: true }) : json(404, { error: 'לא נמצא' });
  }

  if (path.startsWith('/api/admin/')) {
    if (!me.is_admin) return json(403, { error: 'למנהל בלבד' });
    if (req.method === 'POST' && path === '/api/admin/registration') {
      await setSetting(env.DB, 'open_registration', body.open ? '1' : '0');
      return json(200, { ok: true });
    }
    if (req.method === 'POST' && path === '/api/admin/users') {
      const phone = normalizePhone(body.phone), name = cleanName(body.name), pin = String(body.pin || '');
      if (!phone || !name || !validPin(pin)) return json(400, { error: 'שם, טלפון וסיסמה בת 4 ספרות הם חובה' });
      return (await createUser(env, { phone, name, pin })) ? json(200, { ok: true }) : json(409, { error: 'המספר כבר רשום' });
    }
  }
  return json(404, { error: 'not found' });
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (e) {
      console.error(e);
      return json(e.message?.startsWith('ENC_KEY') ? 500 : 400, { error: e.message?.startsWith('ENC_KEY') ? e.message : 'בקשה לא תקינה' });
    }
  },
};
