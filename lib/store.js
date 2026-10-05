import { randomBytes, createCipheriv, createDecipheriv, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { join } from 'node:path';

export function loadEncKey(dataDir) {
  if (process.env.TOTP_ENC_KEY) {
    const k = Buffer.from(process.env.TOTP_ENC_KEY, 'hex');
    if (k.length !== 32) throw new Error('TOTP_ENC_KEY חייב להיות 64 תווי hex');
    return k;
  }
  mkdirSync(dataDir, { recursive: true });
  const file = join(dataDir, '.enckey');
  if (!existsSync(file)) writeFileSync(file, randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(readFileSync(file, 'utf8').trim(), 'hex');
}

export function encrypt(key, text) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), data].map(b => b.toString('base64')).join('.');
}

export function decrypt(key, packed) {
  const [iv, tag, data] = packed.split('.').map(s => Buffer.from(s, 'base64'));
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const hash = scryptSync(password, Buffer.from(saltHex, 'hex'), 32);
  return timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

export class Store {
  constructor(dataDir) {
    this.dir = dataDir;
    this.file = join(dataDir, 'db.json');
    this.key = loadEncKey(dataDir);
    mkdirSync(dataDir, { recursive: true });
    this.db = existsSync(this.file) ? JSON.parse(readFileSync(this.file, 'utf8')) : { users: {} };
  }

  save() {
    const tmp = this.file + '.tmp';
    writeFileSync(tmp, JSON.stringify(this.db), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  createUser(username, password) {
    if (this.db.users[username]) return null;
    this.db.users[username] = { passwordHash: hashPassword(password), keys: [], nextId: 1 };
    this.save();
    return this.db.users[username];
  }

  authenticate(username, password) {
    const u = this.db.users[username];
    // מריצים scrypt גם כשהמשתמש לא קיים כדי לא לחשוף את קיומו בזמן התגובה
    if (!u) { hashPassword(password); return null; }
    return verifyPassword(password, u.passwordHash) ? u : null;
  }

  addKey(username, name, secret) {
    const u = this.db.users[username];
    const entry = { id: u.nextId++, name, secret: encrypt(this.key, secret) };
    u.keys.push(entry);
    this.save();
    return entry.id;
  }

  listKeys(username) {
    return this.db.users[username].keys.map(k => ({ id: k.id, name: k.name }));
  }

  getSecret(username, id) {
    const k = this.db.users[username]?.keys.find(k => k.id === id);
    return k ? { id: k.id, name: k.name, secret: decrypt(this.key, k.secret) } : null;
  }

  deleteKey(username, id) {
    const u = this.db.users[username];
    const before = u.keys.length;
    u.keys = u.keys.filter(k => k.id !== id);
    if (u.keys.length !== before) this.save();
    return u.keys.length !== before;
  }
}
