import { totp, secondsLeft } from './totp.js';

// ימות המשיח שולחת בקשת GET עם כל הפרמטרים שנאספו עד כה, ומצפה
// לתשובת טקסט של פקודות מופרדות ב-& (read=..., id_list_message=..., go_to_folder=...).

const HANGUP = 'go_to_folder=hangup';

// תווים שמשבשים את תחביר הפקודות
const clean = s => String(s).replace(/[=,&.\-:;|"'<>\\/]/g, ' ').replace(/\s+/g, ' ').trim();

const say = text => `id_list_message=t-${clean(text)}&${HANGUP}`;

// read=<הודעה>=<משתנה>,<שימוש חוזר>,<מקס>,<מינ>,<זמן>,<סוג>,<חסימת *>,<חסימת 0>
const ask = (prompt, name, max, min, type = 'Digits') =>
  `read=${prompt}=${name},no,${max},${min},10,${type},no,no`;

const digitsToSpeech = code => [...code].map(d => `n-${d}`).join('.');

export class Throttle {
  constructor({ max = 5, windowMs = 15 * 60 * 1000 } = {}) {
    this.max = max; this.windowMs = windowMs; this.hits = new Map();
  }
  _recent(key) {
    const now = Date.now();
    const list = (this.hits.get(key) || []).filter(t => now - t < this.windowMs);
    this.hits.set(key, list);
    return list;
  }
  blocked(key) { return this._recent(key).length >= this.max; }
  fail(key) { this._recent(key).push(Date.now()); }
  reset(key) { this.hits.delete(key); }
}

export function handleCall(store, throttle, q, now = Date.now()) {
  const u = (q.u || '').trim();
  const p = (q.p || '').trim();
  const phone = q.ApiPhone || 'unknown';

  if (!u) return ask('t-ברוכים הבאים. אנא הקש את שם המשתמש ובסיומו סולמית', 'u', 12, 4);
  if (!p) return ask('t-אנא הקש את הסיסמה ובסיומה סולמית', 'p', 12, 4);

  const keyU = `u:${u}`, keyP = `p:${phone}`;
  if (throttle.blocked(keyU) || throttle.blocked(keyP)) {
    return say('יותר מדי ניסיונות שגויים. נסו שוב מאוחר יותר');
  }
  const user = /^\d+$/.test(u) && /^\d+$/.test(p) ? store.authenticate(u, p) : null;
  if (!user) {
    throttle.fail(keyU); throttle.fail(keyP);
    return say('שם משתמש או סיסמה שגויים');
  }
  throttle.reset(keyU);

  const keys = store.listKeys(u);
  if (keys.length === 0) return say('לא הוגדרו מפתחות. היכנסו לאתר להוספת מפתח');

  let chosen;
  if (keys.length === 1) {
    chosen = keys[0];
  } else {
    const id = parseInt(q.k, 10);
    chosen = keys.find(k => k.id === id);
    if (!chosen) {
      const menu = keys.map(k => `לקוד של ${clean(k.name)} הקש ${k.id}`).join(' ');
      return ask(`t-${menu}`, 'k', 4, 1);
    }
  }

  const { secret } = store.getSecret(u, chosen.id);
  let code = totp(secret, { time: now });
  // אם נשארו פחות מ-6 שניות, הקוד עלול לפוג באמצע ההקראה, אז מקריאים את הבא
  if (secondsLeft(now) < 6) code = totp(secret, { time: now + 6000 });

  if (q.r === '1') {
    // נשלחה בקשה לשמיעה חוזרת: נשאל שוב עם קוד עדכני
  } else if (q.r !== undefined && q.r !== '') {
    return say('להתראות');
  }
  return ask(`t-הקוד של ${clean(chosen.name)} הוא.${digitsToSpeech(code)}.t-לשמיעה חוזרת הקש 1 לסיום הקש 2`, 'r', 1, 1);
}
