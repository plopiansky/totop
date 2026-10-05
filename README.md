# totop

קודי TOTP שמוקראים בטלפון דרך ימות המשיח. רץ על Cloudflare Workers עם מסד נתונים D1.

## איך זה עובד
1. נכנסים לאתר ומזינים טוקן של ימות המשיח (`מספר_מערכת:סיסמה`). האתר בונה את השלוחה (`type=api`) שמחוברת אליו. הטוקן לא נשמר.
2. כל משתמש נרשם עם מספר טלפון, שם וסיסמה בת 4 ספרות, ומוסיף מפתחות TOTP עם שם.
3. מתקשרים מהטלפון הרשום: "שלום פנחס, אנא הזן את הסיסמה", ואז "לסיסמה של גוגל פינקי הקש 1, לסיסמה של גוגל גד הקש 2", והקוד מוקרא.

## פריסה ב-Cloudflare
```
npm install
npx wrangler login
npx wrangler d1 create totop            # מדביקים את ה-database_id ב-wrangler.toml
npx wrangler d1 migrations apply totop --remote
npx wrangler secret put ENC_KEY         # הדביקו פלט של: openssl rand -hex 32
npx wrangler secret put SETUP_CODE      # קוד שרק אתם מכירים, להגנה על שלב ההקמה
npx wrangler deploy
```
חשוב: ב-`ENC_KEY` מוצפנים המפתחות ונגזר הנתיב הסודי של ימות המשיח. אם תאבדו או תחליפו אותו, המפתחות השמורים לא יפוענחו.

אחרי הפריסה נכנסים לכתובת האתר, ממלאים את מסך ההקמה (קוד הקמה + טוקן ימות המשיח), ואז נרשמים. המשתמש הראשון הוא המנהל.
את ההקמה עושים דרך הדומיין הסופי, כי כתובת ה-`api_link` נקבעת לפי הכתובת שבה פתחתם את האתר.

## פיתוח
```
npm test                                  # בדיקות (Node 22.5+)
printf 'ENC_KEY=%s\nSETUP_CODE=dev\n' $(openssl rand -hex 32) > .dev.vars
npx wrangler d1 migrations apply totop --local
npx wrangler dev
```

## אבטחה
- סיסמה בת 4 ספרות חלשה, ולכן: נעילה ל-15 דקות אחרי 5 ניסיונות שגויים, ו"פלפל" סודי מ-`ENC_KEY` בגיבוב, כך שגניבת מסד הנתונים לבדו לא מאפשרת לנחש סיסמאות.
- זיהוי לפי מספר המתקשר (caller ID) ניתן לזיוף, והסיסמה היא הגנה שנייה. מי שמכיר את הסיסמה ויכול לזייף את המספר יקבל קודים.
- הקוד מוקרא בקול, כדאי להתקשר ממקום פרטי.
- הרשמה חופשית כבויה כברירת מחדל, כי כל שיחה היא על חשבון יחידות המערכת שלכם. המנהל מוסיף משתמשים ידנית.

## פריסה אוטומטית (GitHub Actions)
דחיפה ל-`main` מריצה בדיקות, מחילה מיגרציות על D1 ופורסת. נדרשים שני Secrets בריפו
(Settings, Secrets and variables, Actions):
- `CLOUDFLARE_API_TOKEN`: טוקן מ-Cloudflare עם הרשאות Workers Scripts:Edit ו-D1:Edit (תבנית "Edit Cloudflare Workers" מספיקה, והוסיפו לה D1).
- `CLOUDFLARE_ACCOUNT_ID`

את `ENC_KEY` ו-`SETUP_CODE` מגדירים פעם אחת עם `wrangler secret put`, והם נשארים בין פריסות.
צריך גם `npm install` מקומי פעם אחת כדי ש-`package-lock.json` ייכנס לריפו (`npm ci` דורש אותו).
