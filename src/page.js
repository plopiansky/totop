export const PAGE = `<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>קודי TOTP בטלפון</title>
<style>
  :root { --bg:#f5f6f8; --card:#fff; --text:#1c1e21; --muted:#6b7280; --accent:#2563eb; --danger:#dc2626; --ok:#16a34a; --border:#d9dce1; }
  @media (prefers-color-scheme: dark) { :root { --bg:#14161a; --card:#1e2127; --text:#e8e9eb; --muted:#9aa0a8; --border:#343942; } }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, sans-serif; }
  main { max-width:480px; margin:0 auto; padding:24px 16px; }
  h1 { font-size:22px; margin:0 0 16px; }
  h2 { font-size:17px; margin:0 0 8px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:16px; }
  label { display:block; margin:10px 0 4px; font-size:14px; color:var(--muted); }
  input[type=text], input[type=password], input[type=tel], input:not([type]) { width:100%; padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); font:inherit; }
  .check { display:flex; gap:8px; align-items:flex-start; margin-top:12px; font-size:14px; }
  button { padding:10px 16px; border:0; border-radius:8px; background:var(--accent); color:#fff; font:inherit; cursor:pointer; }
  button.secondary { background:transparent; color:var(--accent); border:1px solid var(--border); }
  button.danger { background:transparent; color:var(--danger); border:1px solid var(--border); padding:4px 10px; }
  .row { display:flex; gap:8px; margin-top:14px; }
  .err { color:var(--danger); min-height:1.4em; margin-top:8px; font-size:14px; }
  .good { color:var(--ok); margin-top:8px; font-size:14px; }
  .key { display:flex; align-items:center; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border); }
  .key:last-child { border:0; }
  .num { color:var(--muted); font-variant-numeric:tabular-nums; margin-inline-end:8px; }
  .hint { color:var(--muted); font-size:14px; }
  .top { display:flex; justify-content:space-between; align-items:center; }
  [hidden] { display:none !important; }
</style>
</head>
<body>
<main>
  <section id="setup" hidden>
    <h1>הקמת המערכת בימות המשיח</h1>
    <div class="card">
      <p class="hint">הטוקן משמש פעם אחת להקמת השלוחה ולא נשמר באתר.</p>
      <label for="scode">קוד הקמה (רק אם הגדרת SETUP_CODE ב-Cloudflare, אחרת להשאיר ריק)</label>
      <input id="scode" type="password" autocomplete="off">
      <label for="stoken">טוקן ימות המשיח (מספר מערכת:סיסמה)</label>
      <input id="stoken" type="password" dir="ltr" autocomplete="off">
      <label for="sfolder">שלוחה להקמה (/ היא השלוחה הראשית של המערכת)</label>
      <input id="sfolder" dir="ltr" value="/">
      <label class="check"><input type="checkbox" id="sconfirm"> אני מבין שהגדרת השלוחה הזו תוחלף. אם קיימת הגדרה אחרת היא תגובה אוטומטית לפני כן.</label>
      <div class="row"><button id="dosetup">הקמה</button></div>
      <div class="err" id="setuperr"></div><div class="good" id="setupok"></div>
    </div>
  </section>

  <section id="auth" hidden>
    <h1>קודי TOTP בטלפון</h1>
    <div class="card">
      <label for="phone">מספר טלפון</label>
      <input id="phone" type="tel" inputmode="numeric" autocomplete="username" dir="ltr" placeholder="0501234567">
      <label for="pin">סיסמה (4 ספרות)</label>
      <input id="pin" type="password" inputmode="numeric" maxlength="4" autocomplete="current-password">
      <div id="namebox" hidden>
        <label for="name">שם (יוקרא בטלפון: "שלום ...")</label>
        <input id="name" maxlength="40">
      </div>
      <div class="row">
        <button id="login">כניסה</button>
        <button id="register" class="secondary">הרשמה</button>
      </div>
      <div class="err" id="autherr"></div>
    </div>
  </section>

  <section id="app" hidden>
    <div class="top"><h1 id="hello"></h1><button class="secondary" id="logout">יציאה</button></div>
    <div class="card"><h2>המפתחות שלי</h2><div id="keys"></div></div>
    <div class="card">
      <h2>הוספת מפתח</h2>
      <label for="kname">שם (יוקרא בטלפון, למשל: גוגל פינקי)</label>
      <input id="kname" maxlength="40">
      <label for="kkey">מפתח TOTP או קישור otpauth</label>
      <input id="kkey" dir="ltr" autocomplete="off" spellcheck="false">
      <div class="row"><button id="add">הוספה</button></div>
      <div class="err" id="apperr"></div>
    </div>
    <div class="card" id="admin" hidden>
      <h2>ניהול</h2>
      <label class="check"><input type="checkbox" id="openreg"> לאפשר הרשמה חופשית (כל מי שמכיר את האתר יוכל להירשם, והשיחות על חשבון המערכת שלך)</label>
      <label for="anm">הוספת משתמש: שם</label><input id="anm" maxlength="40">
      <label for="aph">טלפון</label><input id="aph" type="tel" dir="ltr">
      <label for="apin">סיסמה (4 ספרות)</label><input id="apin" type="password" inputmode="numeric" maxlength="4">
      <div class="row"><button id="adduser">הוספת משתמש</button><button id="resetup" class="secondary">הקמה מחדש בימות המשיח</button></div>
      <div class="err" id="adminerr"></div>
    </div>
    <p class="hint">להשמעת קוד: התקשרו למספר של ימות המשיח מהטלפון הרשום, הזינו את הסיסמה ובחרו מפתח.</p>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'שגיאה');
  return j;
}
function view(name) { for (const s of ['setup', 'auth', 'app']) $(s).hidden = s !== name; }
async function refresh() {
  const st = await api('GET', '/api/state');
  if (!st.user) {
    view(st.configured ? 'auth' : 'setup');
    $('namebox').hidden = false;
    $('register').hidden = st.hasUsers && !st.openRegistration;
    $('namebox').hidden = $('register').hidden;
    return;
  }
  view('app');
  $('hello').textContent = 'שלום ' + st.user.name;
  $('admin').hidden = !st.user.isAdmin;
  $('openreg').checked = st.openRegistration;
  const { keys } = await api('GET', '/api/keys');
  const box = $('keys');
  box.replaceChildren();
  if (!keys.length) box.textContent = 'עדיין לא הוספת מפתחות.';
  keys.forEach((k, i) => {
    const row = document.createElement('div'); row.className = 'key';
    const label = document.createElement('span');
    const num = document.createElement('span'); num.className = 'num'; num.textContent = (i + 1) + '.';
    label.append(num, k.name);
    const del = document.createElement('button'); del.className = 'danger'; del.textContent = 'מחיקה';
    del.onclick = async () => { if (confirm('למחוק את ' + k.name + '?')) { await api('DELETE', '/api/keys/' + k.id); refresh(); } };
    row.append(label, del); box.append(row);
  });
}
function guarded(errId, fn) {
  return async () => { $(errId).textContent = ''; try { await fn(); } catch (e) { $(errId).textContent = e.message; } };
}
const creds = () => ({ phone: $('phone').value, pin: $('pin').value, name: $('name').value });
$('login').onclick = guarded('autherr', async () => { await api('POST', '/api/login', creds()); $('pin').value = ''; refresh(); });
$('register').onclick = guarded('autherr', async () => { await api('POST', '/api/register', creds()); $('pin').value = ''; refresh(); });
$('logout').onclick = async () => { await api('POST', '/api/logout', {}); refresh(); };
$('add').onclick = guarded('apperr', async () => {
  await api('POST', '/api/keys', { name: $('kname').value, key: $('kkey').value });
  $('kname').value = $('kkey').value = ''; refresh();
});
const setup = guarded('setuperr', async () => {
  $('setupok').textContent = '';
  const r = await api('POST', '/api/setup', { setupCode: $('scode').value, token: $('stoken').value, folder: $('sfolder').value, confirm: $('sconfirm').checked });
  $('stoken').value = '';
  $('setupok').textContent = 'המערכת הוקמה. ' + (r.notes || []).join(' ');
  setTimeout(refresh, 1500);
});
$('dosetup').onclick = setup;
$('resetup').onclick = () => { view('setup'); };
$('openreg').onchange = guarded('adminerr', () => api('POST', '/api/admin/registration', { open: $('openreg').checked }));
$('adduser').onclick = guarded('adminerr', async () => {
  await api('POST', '/api/admin/users', { name: $('anm').value, phone: $('aph').value, pin: $('apin').value });
  $('anm').value = $('aph').value = $('apin').value = '';
});
refresh();
</script>
</body>
</html>`;
