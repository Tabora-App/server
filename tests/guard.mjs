// Защита входа от подбора пароля: предел на аккаунт для незнакомых устройств (общий со всех
// адресов), предел неудач с одного адреса, повторная проверка пароля, уведомления владельцу.
// Сервер запущен без почтового сервера, письма складываются файлами:
//   node tests/guard.mjs <адрес сервера> <домен> <каталог писем>
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
    console.log(`FAIL ${name}${detail ? `\n     ${String(detail).slice(0, 500)}` : ""}`);
  }
};
const hash = s => crypto.createHash("sha256").update(s).digest("hex");
const stamp = Date.now().toString(36);
const device = n => crypto.createHash("sha256").update(`guard-device-${stamp}-${n}`).digest("hex").slice(0, 24);
const ipOf = n => `198.18.${(n >> 8) & 255}.${n & 255}`;
let ipSeq = 1;
const freshIp = () => ipOf(ipSeq++);
async function call(method, path, { token, body, ip } = {}) {
  const headers = { "X-Forwarded-For": ip || "203.0.113.77" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {}
  return { status: res.status, json, text: text.slice(0, 400) };
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function letters(to, subject) {
  for (let i = 0; i < 20; i++) {
    const hits = fs.readdirSync(OUTBOX).filter(f => f.endsWith(".json")).map(f => JSON.parse(fs.readFileSync(`${OUTBOX}/${f}`, "utf8"))).filter(m => m.to === to && m.subject === subject);
    if (hits.length || i === 19) {
      return hits;
    }
    await sleep(150);
  }
  return [];
}
function totp(secretB32, shift = 0) {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretB32.replace(/=+$/, "")) bits += abc.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + shift));
  const h = crypto.createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}
const mail = name => `${name}${stamp}@${DOMAIN}`;
const login = (email, pw, dev, ip, extra = {}) => call("POST", "/v1/account/login", { body: { email, loginHash: pw, deviceId: dev, deviceName: "Чужой компьютер", ...extra }, ip });

// ---- аккаунт владельца ----
const A = { email: mail("ga"), pw: hash("a-good"), bad: hash("a-bad") };
let r = await call("POST", "/v1/account/register", { body: { email: A.email, loginHash: A.pw, kdf: 2, deviceId: device("a-own"), deviceName: "Мак владельца" } });
check("аккаунт создан", r.status === 200, r.text);

// ---- подбор пароля с множества адресов и устройств ----
const first = [];
for (let i = 0; i < 5; i++) {
  first.push((await login(A.email, hash(`guess-${i}`), device(`att-${i}`), freshIp())).status);
}
check("первые пять неверных паролей с разных адресов получают обычный отказ", first.join() === "401,401,401,401,401", first.join());
const shutRight = await login(A.email, A.pw, device("att-x"), freshIp());
const shutWrong = await login(A.email, A.bad, device("att-y"), freshIp());
check("дальше вход с новых устройств закрыт — даже с верным паролем и с нового адреса", shutRight.status === 429 && shutRight.json.code === "rate-limited" && /новых устройств/.test(shutRight.json.message), shutRight.text);
check("ответ на верный и на неверный пароль одинаков: по нему пароль не проверить", shutWrong.status === 429 && shutWrong.text === shutRight.text, `${shutWrong.text} | ${shutRight.text}`);
r = await login(A.email, A.pw, device("a-own"), freshIp());
check("владелец со своего устройства входит как обычно, с любого адреса", r.status === 200 && !!r.json.session?.token, r.text);
r = await login(A.email, A.bad, device("a-own"), freshIp());
check("неверный пароль со знакомого устройства — обычный отказ, без закрытия", r.status === 401 && r.json.code === "bad-credentials", r.text);
let notes = await letters(A.email, "Tabora: к аккаунту подбирают пароль");
check("владельцу ушло одно письмо о подборе пароля", notes.length === 1 && notes[0].text.includes(A.email) && /Вход с новых устройств временно закрыт/.test(notes[0].text), JSON.stringify(notes).slice(0, 300));
for (let i = 0; i < 3; i++) {
  await login(A.email, hash(`more-${i}`), device(`att2-${i}`), freshIp());
}
notes = await letters(A.email, "Tabora: к аккаунту подбирают пароль");
check("новые попытки во время закрытия счёт не сбрасывают и писем не плодят", notes.length === 1 && (await login(A.email, A.pw, device("att-z"), freshIp())).status === 429, String(notes.length));

// ---- несуществующий аккаунт ведёт себя так же ----
const ghost = mail("ghost");
const g = [];
for (let i = 0; i < 5; i++) {
  g.push((await login(ghost, hash(`g-${i}`), device(`gh-${i}`), freshIp())).status);
}
r = await login(ghost, hash("g-x"), device("gh-x"), freshIp());
check("по закрытию входа не узнать, есть ли такой аккаунт", g.join() === "401,401,401,401,401" && r.status === 429 && r.json.message === shutRight.json.message, `${g.join()} ${r.text}`);

// ---- вход с нового устройства: письмо владельцу ----
const B = { email: mail("gb"), pw: hash("b-good") };
r = await call("POST", "/v1/account/register", { body: { email: B.email, loginHash: B.pw, kdf: 2, deviceId: device("b-own"), deviceName: "Мак" } });
B.s1 = r.json?.session?.token;
check("регистрация писем о входе не шлёт", (await letters(B.email, "Tabora: вход с нового устройства")).length === 0);
r = await call("POST", "/v1/account/login", { body: { email: B.email, loginHash: B.pw, deviceId: device("b-phone"), deviceName: "Веб-версия: Safari, iPhone" }, ip: freshIp() });
let entered = await letters(B.email, "Tabora: вход с нового устройства");
check("вход с нового устройства: владельцу письмо с названием устройства", r.status === 200 && entered.length === 1 && entered[0].text.includes("Веб-версия: Safari, iPhone"), JSON.stringify(entered).slice(0, 300));
await call("POST", "/v1/account/login", { body: { email: B.email, loginHash: B.pw, deviceId: device("b-phone"), deviceName: "Веб-версия: Safari, iPhone" }, ip: freshIp() });
await sleep(400);
check("повторный вход с того же устройства нового письма не даёт", (await letters(B.email, "Tabora: вход с нового устройства")).length === 1);

// ---- повторная проверка пароля в настройках: счёт на аккаунт, а не на адрес ----
const re = [];
for (let i = 0; i < 5; i++) {
  re.push((await call("POST", "/v1/account/2fa/setup", { token: B.s1, body: { loginHash: hash(`re-${i}`) }, ip: freshIp() })).status);
}
r = await call("POST", "/v1/account/2fa/setup", { token: B.s1, body: { loginHash: B.pw }, ip: freshIp() });
check("в настройках пароль не перебрать, меняя адреса: после пяти ошибок пауза и для верного пароля", re.join() === "401,401,401,401,401" && r.status === 429, `${re.join()} ${r.text}`);

// ---- двухфакторная защита: владелец входит с нового устройства и во время подбора ----
const C = { email: mail("gc"), pw: hash("c-good") };
r = await call("POST", "/v1/account/register", { body: { email: C.email, loginHash: C.pw, kdf: 2, deviceId: device("c-own"), deviceName: "Мак" } });
C.s1 = r.json?.session?.token;
r = await call("POST", "/v1/account/2fa/setup", { token: C.s1, body: { loginHash: C.pw } });
C.secret = r.json?.secret;
r = await call("POST", "/v1/account/2fa/enable", { token: C.s1, body: { code: totp(C.secret) } });
check("двухфакторная защита включена", r.status === 200 && r.json.backupCodes?.length === 10, r.text);
for (let i = 0; i < 5; i++) {
  await login(C.email, hash(`c-${i}`), device(`catt-${i}`), freshIp());
}
r = await login(C.email, C.pw, device("c-new"), freshIp());
const shutC = r.text;
check("во время подбора верный пароль без кода с нового устройства не входит", r.status === 429, r.text);
r = await login(C.email, C.pw, device("c-new"), freshIp(), { totp: "000000" });
check("верный пароль с неверным кодом — тот же ответ, что и закрытие", r.status === 429 && r.text === shutC, r.text);
r = await login(C.email, hash("c-wrong"), device("c-new"), freshIp(), { totp: totp(C.secret, 1) });
check("неверный пароль с верным кодом — тот же ответ", r.status === 429 && r.text === shutC, r.text);
r = await login(C.email, C.pw, device("c-new"), freshIp(), { totp: totp(C.secret, 1) });
check("верный пароль и верный код: владелец входит с нового устройства, несмотря на подбор", r.status === 200 && !!r.json.session?.token, r.text);
r = await login(C.email, C.pw, device("c-new2"), freshIp(), { totp: C.secret ? "111111" : "" });
check("после входа владельца закрытие снято: дальше обычные ответы", r.status === 401 && r.json.code === "bad-2fa", r.text);

// ---- много неудач с одного адреса ----
const X = "198.19.0.9";
const xs = [];
for (let i = 0; i < 20; i++) {
  xs.push((await login(mail(`nobody${i}`), hash("x"), device(`x-${i}`), X)).status);
}
r = await login(B.email, B.pw, device("b-own"), X);
const other = await login(B.email, B.pw, device("b-own"), freshIp());
check("двадцать неудач с одного адреса закрывают вход с него на час, с других адресов вход открыт", xs.every(s => s === 401) && r.status === 429 && /С вашего адреса/.test(r.json.message) && other.status === 200, `${xs.join()} ${r.text} ${other.status}`);

console.log(`\nИТОГ: ${passed} из ${passed + failed}`);
process.exit(failed ? 1 : 0);
