import { checkPin, findUserByPhone, listKeys, getSecret, normalizePhone } from './db.js';
import { totp, secondsLeft } from './totp.js';

// ימות המשיח שולחת GET עם כל הפרמטרים שנאספו עד כה ומצפה לפקודות מופרדות ב-&.
const HANGUP = 'go_to_folder=hangup';

// תווים שמשבשים את תחביר הפקודות
const clean = s => String(s).replace(/[=,&.\-:;|"'<>\\/]/g, ' ').replace(/\s+/g, ' ').trim();
const say = text => `id_list_message=t-${clean(text)}&${HANGUP}`;
// read=<הודעה>=<משתנה>,<שימוש חוזר>,<מקס>,<מינ>,<זמן>,<סוג>,<חסימת *>,<חסימת 0>
const ask = (prompt, name, max, min) => `read=${prompt}=${name},no,${max},${min},10,Digits,no,no`;
const spoken = code => [...code].map(d => `n-${d}`).join('.');

export async function handleCall(env, q, now = Date.now()) {
  // זיהוי אוטומטי לפי מספר המתקשר. אם הוא חסוי, מבקשים להקיש אותו.
  let phone = normalizePhone(q.ApiPhone);
  if (!phone) {
    if (!q.ph) return ask('t-מספר הטלפון שלך חסוי. אנא הקש את מספר הטלפון שלך', 'ph', 10, 9);
    phone = normalizePhone(q.ph);
  }
  const user = phone && await findUserByPhone(env.DB, phone);
  if (!user) return say('מספר הטלפון אינו רשום במערכת');

  if (!q.p) return ask(`t-שלום ${clean(user.name)}. אנא הזן את הסיסמה`, 'p', 4, 4);

  const auth = await checkPin(env, phone, String(q.p), now);
  if (auth.status === 'locked') return say('החשבון ננעל זמנית עקב ניסיונות שגויים. נסו שוב מאוחר יותר');
  if (auth.status !== 'ok') return say('הסיסמה שגויה');

  const keys = await listKeys(env.DB, user.id);
  if (!keys.length) return say('לא הוגדרו מפתחות. היכנסו לאתר להוספת מפתח');

  const pos = parseInt(q.k, 10);
  const chosen = keys.length === 1 ? keys[0] : keys[pos - 1];
  if (!chosen) {
    const menu = keys.map((k, i) => `לסיסמה של ${clean(k.name)} הקש ${i + 1}`).join('. ');
    return ask(`t-${menu}`, 'k', String(keys.length).length, 1);
  }

  if (q.r !== undefined && q.r !== '' && q.r !== '1') return say('להתראות');

  const secret = await getSecret(env, user.id, chosen.id);
  // אם נשארו פחות מ-6 שניות הקוד עלול לפוג באמצע ההקראה, אז מקריאים את הבא
  const code = await totp(secret, { time: secondsLeft(now) < 6 ? now + 6000 : now });
  return ask(`t-הקוד של ${clean(chosen.name)} הוא.${spoken(code)}.t-לשמיעה חוזרת הקש 1 לסיום הקש 2`, 'r', 1, 1);
}
