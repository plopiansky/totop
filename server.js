import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Store } from './lib/store.js';
import { Throttle, handleCall } from './lib/yemot.js';
import { isValidSecret, parseKeyInput } from './lib/totp.js';

const root = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || join(root, 'data');
// סוד בנתיב ה-API של ימות המשיח, כי היא לא יכולה לחתום בקשות
const YEMOT_SECRET = process.env.YEMOT_SECRET;
const SECURE_COOKIE = process.env.SECURE_COOKIE === '1';

if (!YEMOT_SECRET || YEMOT_SECRET.length < 16) {
  console.error('חובה להגדיר YEMOT_SECRET באורך 16 תווים לפחות (למשל: openssl rand -hex 16)');
  process.exit(1);
}

const store = new Store(DATA_DIR);
const phoneThrottle = new Throttle();
const webThrottle = new Throttle({ max: 10 });
const sessions = new Map(); // token -> username
const page = readFileSync(join(root, 'public', 'index.html'));

const send = (res, status, body, type = 'application/json; charset=utf-8') => {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'",
  });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};

const readJson = req => new Promise((resolve, reject) => {
  let data = '';
  req.on('data', c => { data += c; if (data.length > 10_000) { reject(new Error('too big')); req.destroy(); } });
  req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { reject(new Error('bad json')); } });
});

const sessionUser = req => {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  return m ? sessions.get(m[1]) : undefined;
};

const startSession = (res, username) => {
  const token = randomBytes(32).toString('hex');
  sessions.set(token, username);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${SECURE_COOKIE ? '; Secure' : ''}`);
};

const validCreds = (u, p) => /^\d{4,12}$/.test(u) && /^\d{6,12}$/.test(p);

const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;
  try {
    if (req.method === 'GET' && path === '/') return send(res, 200, page, 'text/html; charset=utf-8');

    // ימות המשיח: /yemot/<סוד>
    if (path.startsWith('/yemot/')) {
      if (!safeEqual(path.slice(7), YEMOT_SECRET)) return send(res, 404, 'not found', 'text/plain');
      const q = Object.fromEntries(url.searchParams);
      return send(res, 200, handleCall(store, phoneThrottle, q), 'text/plain; charset=utf-8');
    }

    if (req.method === 'POST' && (path === '/api/register' || path === '/api/login')) {
      const { username = '', password = '' } = await readJson(req);
      const ip = req.socket.remoteAddress;
      if (webThrottle.blocked(ip)) return send(res, 429, { error: 'יותר מדי ניסיונות, נסו מאוחר יותר' });
      if (path === '/api/register') {
        if (!validCreds(username, password)) {
          return send(res, 400, { error: 'שם משתמש: 4 עד 12 ספרות. סיסמה: 6 עד 12 ספרות (כדי שאפשר יהיה להקיש בטלפון)' });
        }
        if (!store.createUser(username, password)) return send(res, 409, { error: 'שם המשתמש תפוס' });
        startSession(res, username);
        return send(res, 200, { ok: true });
      }
      if (!store.authenticate(username, password)) {
        webThrottle.fail(ip);
        return send(res, 401, { error: 'שם משתמש או סיסמה שגויים' });
      }
      webThrottle.reset(ip);
      startSession(res, username);
      return send(res, 200, { ok: true });
    }

    if (path.startsWith('/api/')) {
      const user = sessionUser(req);
      if (!user) return send(res, 401, { error: 'לא מחובר' });

      if (req.method === 'POST' && path === '/api/logout') {
        const m = /sid=([a-f0-9]+)/.exec(req.headers.cookie);
        sessions.delete(m[1]);
        res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/');
        return send(res, 200, { ok: true });
      }
      if (req.method === 'GET' && path === '/api/keys') {
        return send(res, 200, { username: user, keys: store.listKeys(user) });
      }
      if (req.method === 'POST' && path === '/api/keys') {
        const { name = '', key = '' } = await readJson(req);
        const parsed = parseKeyInput(key);
        const label = String(name).trim() || parsed.label;
        if (!label || label.length > 40) return send(res, 400, { error: 'יש להזין שם (עד 40 תווים)' });
        if (!isValidSecret(parsed.secret)) return send(res, 400, { error: 'מפתח לא תקין. צריך מפתח Base32 או קישור otpauth' });
        const id = store.addKey(user, label, parsed.secret);
        return send(res, 200, { ok: true, id });
      }
      const del = /^\/api\/keys\/(\d+)$/.exec(path);
      if (req.method === 'DELETE' && del) {
        return store.deleteKey(user, Number(del[1])) ? send(res, 200, { ok: true }) : send(res, 404, { error: 'לא נמצא' });
      }
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 400, { error: 'בקשה לא תקינה' });
  }
});

server.listen(PORT, () => console.log(`http://localhost:${PORT}`));
