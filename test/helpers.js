import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

// מדמה את ה-API של D1 מעל sqlite מקומי
export function fakeD1() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => {
      const r = db.prepare(sql).run(...args);
      return { meta: { last_row_id: Number(r.lastInsertRowid), changes: r.changes } };
    },
  });
  return { prepare: sql => stmt(sql) };
}

export const makeEnv = () => ({ DB: fakeD1(), ENC_KEY: 'ab'.repeat(32), SETUP_CODE: 'setup-code-123' });
