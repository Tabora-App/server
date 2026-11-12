// Язык ответов и писем сервера: ошибка — на языке запроса, письмо — на языке аккаунта.
// Сервер на временной базе, письма складываются файлами:
//   node tests/i18n.mjs <адрес сервера> <домен> <каталог писем>
import crypto from "node:crypto";
import fs from "node:fs";

const [base, DOMAIN = "tabora.app", OUTBOX] = process.argv.slice(2);
let passed = 0;
let failed = 0;
const check = (name, ok, detail = "") => {
  if (ok) {
    passed++;
    console.log(`OK   ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}${detail ? `\n     ${String(detail).slice(0, 600)}` : ""}`);
  }
};
const hash = s => crypto.createHash("sha256").update(s).digest("hex");
const stamp = Date.now().toString(36);
const device = n => hash(`i18n-device-${stamp}-${n}`).slice(0, 24);
const CYR = /[А-Яа-яЁёІіЇїЄєҐґ]/;
const RU_ONLY = /[ыэъё]/i;
async function call(method, path, { token, body, lang, ip = "203.0.113.120" } = {}) {
  const headers = { "X-Forwarded-For": ip };
  if (lang) headers["Accept-Language"] = lang;
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {}
  return { status: res.status, json, text: text.slice(0, 500) };
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function letters(to) {
  for (let i = 0; i < 25; i++) {
    const hits = fs.readdirSync(OUTBOX).filter(f => f.endsWith(".json")).map(f => JSON.parse(fs.readFileSync(`${OUTBOX}/${f}`, "utf8"))).filter(m => m.to === to);
    if (hits.length || i === 24) {
      return hits;
    }
    await sleep(150);
  }
  return [];
}
// у каждого запроса свой несуществующий адрес: после пяти неудач вход в один аккаунт закрывается
const wrong = lang => call("POST", "/v1/account/login", { lang, body: { email: `nobody${(lang || "none").replace(/[^a-z]/gi, "").slice(0, 6).toLowerCase()}${stamp}@${DOMAIN}`, loginHash: hash("x"), deviceId: device(`w-${lang}`), deviceName: "x" }, ip: `198.18.50.${10 + ["", "en", "uk", "es", "de", "ru"].indexOf(lang || "")}` });

// ---- ошибки на языке запроса ----
const ru = await wrong("");
check("без заголовка языка ответ русский, как у прежних версий", ru.status === 401 && ru.json.message === "Неверный адрес или пароль", ru.text);
const en = await wrong("en-US,en;q=0.9");
check("английский запрос — английский ответ, код ошибки прежний", en.status === 401 && en.json.code === "bad-credentials" && !CYR.test(en.json.message) && /password/i.test(en.json.message), en.text);
const uk = await wrong("uk-UA,uk;q=0.9");
check("украинский запрос — украинский ответ", uk.status === 401 && CYR.test(uk.json.message) && uk.json.message !== ru.json.message && !RU_ONLY.test(uk.json.message), uk.text);
const es = await wrong("es");
check("испанский запрос — испанский ответ", es.status === 401 && !CYR.test(es.json.message) && /contraseña/i.test(es.json.message), es.text);
const de = await wrong("de-DE,de;q=0.9");
check("язык не из наших — английский ответ", de.json.message === en.json.message, de.text);
check("явный русский — русский ответ", (await wrong("ru-RU,ru")).json.message === ru.json.message);

// ---- письмо на языке аккаунта ----
async function account(name, lang) {
  const A = { email: `${name}${stamp}@${DOMAIN}`, pw: hash(`${name}-password`) };
  const r = await call("POST", "/v1/account/register", { lang, body: { email: A.email, loginHash: A.pw, kdf: 2, deviceId: device(`${name}-1`), deviceName: "Phone" }, ip: "198.18.51.1" });
  A.ok = r.status === 200;
  // вход с нового устройства: владельцу уходит письмо
  await call("POST", "/v1/account/login", { lang, body: { email: A.email, loginHash: A.pw, deviceId: device(`${name}-2`), deviceName: "Laptop-77" }, ip: "198.18.51.2" });
  A.mail = (await letters(A.email))[0] || null;
  return A;
}
const S = await account("ies", "es-MX,es;q=0.9");
check("аккаунт с испанским приложением получает письмо о новом устройстве по-испански", S.ok && !!S.mail && S.mail.subject.startsWith("Tabora: ") && !CYR.test(S.mail.subject) && !CYR.test(S.mail.text) && S.mail.text.includes("Laptop-77") && S.mail.text.includes(S.email), JSON.stringify(S.mail));
const E = await account("ien", "en-GB");
check("с английским — по-английски", E.ok && !!E.mail && !CYR.test(E.mail.subject + E.mail.text) && /device/i.test(E.mail.text) && E.mail.text.includes("Laptop-77"), JSON.stringify(E.mail));
const U = await account("iuk", "uk");
check("с украинским — по-украински", U.ok && !!U.mail && CYR.test(U.mail.text) && !RU_ONLY.test(U.mail.subject + U.mail.text) && U.mail.text.includes("Laptop-77"), JSON.stringify(U.mail));
const R = await account("iru", "");
check("приложение без заголовка языка — письмо по-русски", R.ok && !!R.mail && R.mail.subject === "Tabora: вход с нового устройства" && /В аккаунт вошли с устройства/.test(R.mail.text), JSON.stringify(R.mail));
check("абзацы письма сохранены в переводе", !!S.mail && !!R.mail && S.mail.text.split("\n\n").length === R.mail.text.split("\n\n").length, `${S.mail?.text.split("\n\n").length} и ${R.mail?.text.split("\n\n").length}`);

console.log(`\nитог: ${passed} из ${passed + failed}`);
process.exit(failed ? 1 : 0);
