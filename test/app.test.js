import test from 'node:test';
import assert from 'node:assert/strict';
import { totp, parseKeyInput } from '../src/totp.js';
import { handleCall } from '../src/call.js';
import { createUser, addKey, checkPin, normalizePhone } from '../src/db.js';
import { yemotPathSecret } from '../src/crypto.js';
import worker from '../src/index.js';
import { makeEnv } from './helpers.js';

// וקטורי בדיקה מ-RFC 6238 (SHA1, מפתח "12345678901234567890")
const RFC = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('TOTP לפי RFC 6238', async () => {
  assert.equal(await totp(RFC, { time: 59_000, digits: 8 }), '94287082');
  assert.equal(await totp(RFC, { time: 1111111109_000, digits: 8 }), '07081804');
});

test('פענוח קישור otpauth ונרמול טלפון', () => {
  assert.equal(parseKeyInput(`otpauth://totp/Google:me%40x.com?secret=${RFC.toLowerCase()}`).secret, RFC);
  assert.equal(normalizePhone('+972-50-123-4567'), '0501234567');
  assert.equal(normalizePhone('abc'), '');
});

test('שיחה: זיהוי אוטומטי, ברכה, בחירת מפתח וקוד', async () => {
  const env = makeEnv();
  const u = await createUser(env, { phone: '0501234567', name: 'פנחס', pin: '1234' });
  const T = 1_000_000_000_000;
  const call = (q) => handleCall(env, { ApiPhone: '0501234567', ...q }, T);

  assert.match(await call({}), /שלום פנחס.*=p,no,4,4/);
  assert.match(await call({ p: '0000' }), /שגויה/);
  assert.match(await call({ p: '1234' }), /לא הוגדרו/);

  await addKey(env, u.id, 'גוגל פינקי', RFC);
  await addKey(env, u.id, 'גוגל גד', RFC);
  const menu = await call({ p: '1234' });
  assert.match(menu, /לסיסמה של גוגל פינקי הקש 1\. לסיסמה של גוגל גד הקש 2=k,/);

  const out = await call({ p: '1234', k: '2' });
  const code = await totp(RFC, { time: T });
  assert.ok(out.includes('גוגל גד'));
  assert.ok(out.includes([...code].map(d => `n-${d}`).join('.')), out);
  assert.match(await call({ p: '1234', k: '2', r: '2' }), /להתראות/);
});

test('מספר לא רשום, ומספר חסוי מתבקש להקיש', async () => {
  const env = makeEnv();
  assert.match(await handleCall(env, { ApiPhone: '0509999999' }), /אינו רשום/);
  assert.match(await handleCall(env, { ApiPhone: '' }), /=ph,/);
});

test('נעילה אחרי 5 ניסיונות שגויים', async () => {
  const env = makeEnv();
  await createUser(env, { phone: '0501234567', name: 'א', pin: '1234' });
  for (let i = 0; i < 5; i++) await checkPin(env, '0501234567', '0000');
  assert.equal((await checkPin(env, '0501234567', '1234')).status, 'locked');
  assert.equal((await checkPin(env, '0501234567', '1234', Date.now() + 16 * 60_000)).status, 'ok');
});

test('המפתח מוצפן ב-DB, והמשתמש הראשון הוא מנהל', async () => {
  const env = makeEnv();
  const a = await createUser(env, { phone: '0501111111', name: 'א', pin: '1111' });
  const b = await createUser(env, { phone: '0502222222', name: 'ב', pin: '2222' });
  assert.equal(a.is_admin, 1);
  assert.equal(b.is_admin, 0);
  assert.equal(await createUser(env, { phone: '0501111111', name: 'ג', pin: '3333' }), null);
  await addKey(env, a.id, 'x', RFC);
  const row = await env.DB.prepare('SELECT secret_enc FROM totp_keys').first();
  assert.ok(!row.secret_enc.includes(RFC));
});

test('Worker: הרשמה, כניסה, הוספת מפתח ונתיב ימות המשיח', async () => {
  const env = makeEnv();
  const req = (method, path, body, cookie) => worker.fetch(new Request('https://t.example' + path, {
    method, body: body && JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', ...(cookie && { Cookie: cookie }) },
  }), env);

  // לפני הקמה אי אפשר להירשם
  assert.equal((await req('POST', '/api/register', { phone: '0501234567', pin: '1234', name: 'פנחס' })).status, 400);
  // קוד הקמה שגוי
  assert.equal((await req('POST', '/api/setup', { setupCode: 'x', token: 't', folder: '/', confirm: true })).status, 403);

  await env.DB.prepare("INSERT INTO settings(key,value) VALUES('configured','1')").run();
  const reg = await req('POST', '/api/register', { phone: '050-123-4567', pin: '1234', name: 'פנחס' });
  assert.equal(reg.status, 200);
  const sid = reg.headers.get('Set-Cookie').split(';')[0];

  assert.equal((await req('POST', '/api/keys', { name: 'גוגל', key: RFC }, sid)).status, 200);
  assert.equal((await req('POST', '/api/keys', { name: 'x', key: 'bad' }, sid)).status, 400);
  const keys = await (await req('GET', '/api/keys', null, sid)).json();
  assert.equal(keys.keys[0].name, 'גוגל');

  // הרשמה של אחרים סגורה כברירת מחדל
  assert.equal((await req('POST', '/api/register', { phone: '0502222222', pin: '1234', name: 'ב' })).status, 403);
  assert.equal((await req('POST', '/api/login', { phone: '0501234567', pin: '9999' })).status, 401);
  assert.equal((await req('GET', '/api/keys')).status, 401);

  const secret = await yemotPathSecret(env);
  const r = await worker.fetch(new Request(`https://t.example/yemot/${secret}?ApiPhone=0501234567`), env);
  assert.match(await r.text(), /שלום פנחס/);
  assert.equal((await worker.fetch(new Request('https://t.example/yemot/wrong'), env)).status, 404);
});

test('הקמת שלוחה בימות המשיח (עם fetch מדומה): גיבוי ודריסה', async () => {
  const { installExtension } = await import('../src/ymapi.js');
  const calls = [];
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const p = Object.fromEntries(init.body);
    const method = url.split('/').pop();
    calls.push({ method, ...p });
    if (method === 'DownloadFile') return new Response('type=menu\n');
    return new Response(JSON.stringify({ responseStatus: 'OK' }));
  };
  try {
    const notes = await installExtension('0771234567:pw', '/', 'https://t.example/yemot/abc');
    assert.deepEqual(calls.map(c => c.method), ['GetSession', 'DownloadFile', 'UploadTextFile', 'UploadTextFile']);
    assert.equal(calls[2].what, 'ivr2:/ext.ini.totop-backup');
    assert.equal(calls[3].what, 'ivr2:/ext.ini');
    assert.equal(calls[3].contents, 'type=api\napi_link=https://t.example/yemot/abc\n');
    assert.equal(notes.length, 1);

    globalThis.fetch = async () => new Response(JSON.stringify({ responseStatus: 'FAILED', message: 'bad token' }));
    await assert.rejects(installExtension('x', '/', 'l'), /bad token/);
  } finally { globalThis.fetch = orig; }
});

test('בלי ENC_KEY ובלי SETUP_CODE: המפתח נוצר אוטומטית וההקמה לא דורשת קוד', async () => {
  const env = { DB: makeEnv().DB };
  const req = (method, path, body) => worker.fetch(new Request('https://t.example' + path, {
    method, body: body && JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
  }), env);
  // בלי קוד הקמה אנחנו מגיעים לשלב הטוקן (ונכשלים שם), לא נחסמים על הקוד
  const r = await req('POST', '/api/setup', { token: '', folder: '/', confirm: true });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /טוקן/);
  assert.ok(await env.DB.prepare("SELECT value FROM settings WHERE key='enc_key'").first());
});
