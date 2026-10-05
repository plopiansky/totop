// לקוח ל-API של ימות המשיח והקמת המערכת.
// token הוא "מספר_מערכת:סיסמה" או טוקן שהתקבל מ-Login.
const BASE = 'https://www.call2all.co.il/ym/api/';

async function call(method, token, params = {}) {
  const res = await fetch(BASE + method, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, ...params }),
  });
  const text = await res.text();
  try { return { json: JSON.parse(text), text }; } catch { return { json: null, text }; }
}

const failure = r => r.json?.message || r.json?.responseStatus || r.text.slice(0, 200) || 'שגיאה לא ידועה';
const ok = r => r.json?.responseStatus === 'OK';

export function extIni(apiLink) {
  return `type=api\napi_link=${apiLink}\n`;
}

// folder: "/" לשלוחה הראשית של המערכת, או למשל "/9"
export async function installExtension(token, folder, apiLink) {
  const session = await call('GetSession', token);
  if (!ok(session)) throw new Error('הטוקן נדחה על ידי ימות המשיח: ' + failure(session));

  const dir = folder === '/' ? '' : folder;
  const file = `ivr2:${dir}/ext.ini`;
  const notes = [];

  // אם כבר קיימת שם הגדרה אחרת, שומרים לה גיבוי לפני שדורסים
  const existing = await call('DownloadFile', token, { path: file });
  const hadFile = existing.json === null && existing.text.trim() !== '';
  if (hadFile && !existing.text.includes(apiLink)) {
    const bak = await call('UploadTextFile', token, { what: `ivr2:${dir}/ext.ini.totop-backup`, contents: existing.text });
    if (!ok(bak)) throw new Error('לא הצלחתי לגבות את ההגדרה הקיימת, לא שיניתי כלום: ' + failure(bak));
    notes.push(`ההגדרה הקודמת נשמרה בגיבוי: ${dir}/ext.ini.totop-backup`);
  }

  let up = await call('UploadTextFile', token, { what: file, contents: extIni(apiLink) });
  if (!ok(up) && dir) {
    await call('UpdateExtension', token, { path: `ivr2:${dir}` });
    up = await call('UploadTextFile', token, { what: file, contents: extIni(apiLink) });
  }
  if (!ok(up)) throw new Error('הקמת השלוחה נכשלה: ' + failure(up));
  return notes;
}
