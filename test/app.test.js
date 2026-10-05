import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { totp, parseKeyInput } from '../lib/totp.js';
import { Store } from '../lib/store.js';
import { Throttle, handleCall } from '../lib/yemot.js';

// וקטורי בדיקה מ-RFC 6238 (SHA1, מפתח "12345678901234567890")
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('TOTP לפי RFC 6238', () => {
  assert.equal(totp(RFC_SECRET, { time: 59_000, digits: 8 }), '94287082');
  assert.equal(totp(RFC_SECRET, { time: 1111111109_000, digits: 8 }), '07081804');
});

test('פענוח קישור otpauth', () => {
  const r = parseKeyInput(`otpauth://totp/Google:me%40x.com?secret=${RFC_SECRET.toLowerCase()}&issuer=Google`);
  assert.equal(r.secret, RFC_SECRET);
});

function setup() {
  const store = new Store(mkdtempSync(join(tmpdir(), 'totop-')));
  store.createUser('1234', '654321');
  return { store, throttle: new Throttle() };
}

test('תהליך שיחה מלא', () => {
  const { store, throttle } = setup();
  const T = 1_000_000_000_000; // תחילת חלון של 30 שניות
  assert.match(handleCall(store, throttle, {}), /=u,/);
  assert.match(handleCall(store, throttle, { u: '1234' }), /=p,/);
  assert.match(handleCall(store, throttle, { u: '1234', p: '1' }), /שגויים/);
  assert.match(handleCall(store, throttle, { u: '1234', p: '654321' }, T), /לא הוגדרו/);

  store.addKey('1234', 'גוגל', RFC_SECRET);
  const out = handleCall(store, throttle, { u: '1234', p: '654321' }, T);
  const code = totp(RFC_SECRET, { time: T });
  assert.ok(out.includes([...code].map(d => `n-${d}`).join('.')), out);

  store.addKey('1234', 'מיקרוסופט', RFC_SECRET);
  assert.match(handleCall(store, throttle, { u: '1234', p: '654321' }, T), /=k,/);
  assert.match(handleCall(store, throttle, { u: '1234', p: '654321', k: '2' }, T), /מיקרוסופט/);
});

test('חסימה אחרי ניסיונות שגויים', () => {
  const { store, throttle } = setup();
  for (let i = 0; i < 5; i++) handleCall(store, throttle, { u: '1234', p: '0', ApiPhone: '050' });
  assert.match(handleCall(store, throttle, { u: '1234', p: '654321' }), /יותר מדי/);
});

test('המפתח נשמר מוצפן', () => {
  const { store } = setup();
  store.addKey('1234', 'x', RFC_SECRET);
  assert.ok(!JSON.stringify(store.db).includes(RFC_SECRET));
});
