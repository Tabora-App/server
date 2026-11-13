// Проверка HTTP-контракта tabora-server на запущенном экземпляре без почтового сервера:
//   node tests/contract.mjs http://127.0.0.1:7711 tabora.app /путь/к/каталогу-писем [сотрудник] [адрес-поддержки]
// Сервер должен быть запущен с пустой базой, TABORA_SIGNUP_PER_IP=6 (тест проверяет и этот
// предел) и TABORA_MAIL_OUTBOX=<тот же каталог>: письма сервера складываются туда файлами.
// Для обращений в поддержку проверка сама регистрирует аккаунт сотрудника: его адрес (четвёртый
// аргумент, по умолчанию kot.test@<домен>) должен стоять в TABORA_SUPPORT_STAFF сервера, а
// адрес для писем поддержке (пятый аргумент, по умолчанию postmaster@<домен>) — в
// TABORA_SUPPORT_NOTIFY.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const BASE = (process.argv[2] || "http://127.0.0.1:7711").replace(/\/+$/, "");
const DOMAIN = process.argv[3] || "tabora.app";
const OUTBOX = process.argv[4] || "";
const STAFF = (process.argv[5] || `kot.test@${DOMAIN}`).toLowerCase();
const NOTIFY = (process.argv[6] || `postmaster@${DOMAIN}`).toLowerCase();
let passed = 0;
let failed = 0;

function check(name, ok, detail = "") {
  if (ok) {
    passed++;
    console.log("OK  ", name);
  } else {
    failed++;
    console.log("FAIL", name, detail);
  }
}

async function call(method, path, { body, token, ip = "198.51.100.1", raw } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch (e) {}
  return { status: res.status, json, text, headers: res.headers };
}

const hash = seed => crypto.createHash("sha256").update(seed).digest("hex");
const device = n => crypto.createHash("sha256").update("device" + n).digest("hex").slice(0, 24);
const tag = crypto.randomBytes(3).toString("hex");
const name = n => `t${tag}${n}`;
const mail = n => `${name(n)}@${DOMAIN}`;

function b32decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const ch of text) {
    acc = (acc << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 255);
      acc &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

/** Код приложения (RFC 6238) для секрета в Base32; shift — сдвиг в шагах по 30 секунд. */
function totp(secret, shift = 0) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + shift));
  const h = crypto.createHmac("sha1", b32decode(secret)).update(buf).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1e6).padStart(6, "0");
}

const otherCode = code => String((Number(code) + 1) % 1e6).padStart(6, "0");

/** Последнее письмо сервера на адрес: { subject, text, code }. Письма уходят в фоне, поэтому ждём. */
// subject — ждать письмо именно с этой темой: письмо уходит в фоне и может появиться чуть позже ответа
async function lastMail(to, { wait = 2500, after = 0, subject = null } = {}) {
  const until = Date.now() + wait;
  for (;;) {
    const found = fs
      .readdirSync(OUTBOX)
      .filter(f => f.endsWith(".json") && Number(f.split("-")[0]) >= after)
      .sort()
      .map(f => JSON.parse(fs.readFileSync(path.join(OUTBOX, f), "utf8")))
      .filter(m => m.to === to && (subject === null || m.subject === subject))
      .pop();
    if (found || Date.now() > until) {
      const m = found && /(\d{3,4}) (\d{3,4})/.exec(found.text);
      return found ? { ...found, code: m ? m[1] + m[2] : null } : null;
    }
    await new Promise(r => setTimeout(r, 100));
  }
}

const mailsTo = to => fs.readdirSync(OUTBOX).filter(f => f.endsWith(".json")).map(f => JSON.parse(fs.readFileSync(path.join(OUTBOX, f), "utf8"))).filter(m => m.to === to);

function recoveryKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  return { verifier: `ed25519:${pub}`, sign: msg => crypto.sign(null, Buffer.from(msg), privateKey).toString("hex") };
}

const r0 = await call("GET", "/v1/health");
check("сервер отвечает", r0.status === 200 && r0.json.ok === true, r0.text);
check("ответы не кешируются", r0.headers.get("cache-control") === "no-store");

// имена
check("свободное имя доступно", (await call("GET", `/v1/account/available?email=${encodeURIComponent(mail("a"))}`)).json.available === true);
for (const bad of ["ab", "postmaster", "hello", "tabora-team", "A..b", `x@other.example`, "", "a".repeat(40)]) {
  const r = await call("GET", `/v1/account/available?email=${encodeURIComponent(bad.includes("@") ? bad : bad + "@" + DOMAIN)}`);
  check(`имя «${bad.slice(0, 14)}» недоступно`, r.status === 200 && r.json.available === false, r.text);
}
check("версия хеша для неизвестного адреса — текущая", (await call("GET", `/v1/account/prelogin?email=${encodeURIComponent(mail("nobody"))}`)).json.kdf === 2);

// регистрация
const A = { email: mail("a"), pw1: hash("a-pass-1"), pw2: hash("a-pass-2"), pw3: hash("a-pass-3") };
let r = await call("POST", "/v1/account/register", { body: { email: A.email, loginHash: A.pw1, kdf: 2, deviceId: device(1), deviceName: "Мак Анны" } });
check("регистрация", r.status === 200 && /^u[0-9a-f]{20}$/.test(r.json.userId) && /^tbs_/.test(r.json.session.token) && r.json.session.expiresAt === null, r.text);
A.userId = r.json?.userId;
A.s1 = r.json?.session?.token;
check("без почтового сервера ящик не выдаётся", r.json.mail === null);
check("занятое имя недоступно", (await call("GET", `/v1/account/available?email=${encodeURIComponent(A.email)}`)).json.available === false);
r = await call("POST", "/v1/account/register", { body: { email: A.email, loginHash: A.pw2, kdf: 2, deviceId: device(9), deviceName: "x" } });
check("повторная регистрация отклонена", r.status === 409 && r.json.code === "taken" && r.json.message === "Такой адрес уже занят", r.text);
for (const [what, body] of [
  ["плохое имя", { email: "ab@" + DOMAIN, loginHash: A.pw1, kdf: 2, deviceId: device(1) }],
  ["чужой домен", { email: "anna@other.example", loginHash: A.pw1, kdf: 2, deviceId: device(1) }],
  ["плохой хеш", { email: mail("z"), loginHash: "123", kdf: 2, deviceId: device(1) }],
  ["старая версия хеша", { email: mail("z"), loginHash: A.pw1, kdf: 1, deviceId: device(1) }],
  ["плохое устройство", { email: mail("z"), loginHash: A.pw1, kdf: 2, deviceId: "x" }],
]) {
  r = await call("POST", "/v1/account/register", { body });
  check(`регистрация: ${what} → 400`, r.status === 400 && !!r.json?.code && !!r.json?.message, r.text);
}
r = await call("POST", "/v1/account/register", { raw: "{не json" });
check("не JSON → 400 с понятным ответом", r.status === 400 && r.json?.code === "bad-request", r.text);
r = await call("POST", "/v1/account/register", { raw: JSON.stringify({ email: A.email, pad: "x".repeat(70_000) }) });
check("слишком большой запрос отклонён", r.status === 413, String(r.status));

// вход
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw1, deviceId: device(2), deviceName: "Второй\u0007 компьютер" } });
check("вход со второго устройства", r.status === 200 && r.json.userId === A.userId && r.json.kdf === 2 && !!r.json.session.token, r.text);
A.s2 = r.json?.session?.token;
r = await call("POST", "/v1/account/login", { body: { email: name("a"), loginHash: A.pw1, deviceId: device(2), deviceName: "Второй компьютер" } });
check("вход по имени без домена", r.status === 200, r.text);
A.s2b = r.json?.session?.token;
const wrong = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw2, deviceId: device(2) }, ip: "198.51.100.7" });
const unknown = await call("POST", "/v1/account/login", { body: { email: mail("ghost"), loginHash: A.pw2, deviceId: device(2) }, ip: "198.51.100.7" });
check("неверный пароль → 401", wrong.status === 401 && wrong.json.code === "bad-credentials", wrong.text);
check("неизвестный адрес отвечает так же, как неверный пароль", unknown.status === 401 && unknown.text === wrong.text, unknown.text);

// устройства и сессии
r = await call("GET", "/v1/account/devices", { token: A.s1 });
check("список устройств", r.status === 200 && r.json.length === 2 && r.json.some(d => d.name === "Мак Анны" && d.current) && r.json.some(d => d.name === "Второй компьютер" && !d.current) && r.json.every(d => typeof d.at === "number"), r.text);
r = await call("GET", "/v1/account/devices", { token: "tbs_" + "x".repeat(43) });
check("чужой токен → 401 «сессия истекла»", r.status === 401 && r.json.code === "session-expired", r.text);
r = await call("GET", "/v1/account/devices");
check("без токена → 401", r.status === 401 && r.json.code === "session-expired", r.text);

// завершение сеанса другого устройства
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw1, deviceId: device(3), deviceName: "Потерянный телефон" } });
const s3 = r.json?.session?.token;
r = await call("GET", "/v1/account/devices", { token: A.s1 });
check("в списке устройств видно, у каких есть действующая сессия", r.status === 200 && r.json.length === 3 && r.json.every(d => d.active === true), r.text);
r = await call("POST", `/v1/account/devices/${device(3)}/revoke`, { body: { loginHash: A.pw1 } });
check("завершение сеанса без токена → 401", r.status === 401 && r.json.code === "session-expired", r.text);
r = await call("POST", `/v1/account/devices/${device(3)}/revoke`, { token: A.s1, body: { loginHash: A.pw2 } });
check("завершение сеанса с неверным паролем → 401", r.status === 401 && r.json.code === "bad-credentials" && (await call("GET", "/v1/account/devices", { token: s3 })).status === 200, r.text);
r = await call("POST", `/v1/account/devices/${device(1)}/revoke`, { token: A.s1, body: { loginHash: A.pw1 } });
check("своё устройство так не завершить → 400", r.status === 400 && r.json.code === "bad-request", r.text);
r = await call("POST", `/v1/account/devices/${device(7)}/revoke`, { token: A.s1, body: { loginHash: A.pw1 } });
check("неизвестное устройство → 404", r.status === 404 && r.json.code === "not-found", r.text);
r = await call("POST", "/v1/account/devices/x/revoke", { token: A.s1, body: { loginHash: A.pw1 } });
check("кривой номер устройства → 400", r.status === 400, r.text);
r = await call("POST", `/v1/account/devices/${device(3)}/revoke`, { token: A.s1, body: { loginHash: A.pw1 } });
check("завершение сеанса другого устройства", r.status === 200, r.text);
check("его сессия больше не действует", (await call("GET", "/v1/account/devices", { token: s3 })).status === 401);
r = await call("GET", "/v1/account/devices", { token: A.s1 });
check("устройство пропало из списка, остальные на месте", r.status === 200 && r.json.length === 2 && !r.json.some(d => d.id === device(3)) && (await call("GET", "/v1/account/devices", { token: A.s2 })).status === 200, r.text);

// блокировка перебора (отдельный аккаунт и адрес)
const B = { email: mail("b"), pw: hash("b-pass") };
r = await call("POST", "/v1/account/register", { body: { email: B.email, loginHash: B.pw, kdf: 2, deviceId: device(3), deviceName: "B" } });
B.s = r.json?.session?.token;
let codes = [];
for (let i = 0; i < 6; i++) {
  codes.push((await call("POST", "/v1/account/login", { body: { email: B.email, loginHash: hash("guess" + i), deviceId: device(3) }, ip: "203.0.113.5" })).status);
}
check("пять неверных паролей подряд, шестая попытка заблокирована", codes.join() === "401,401,401,401,401,429", codes.join());
r = await call("POST", "/v1/account/login", { body: { email: B.email, loginHash: B.pw, deviceId: device(3) }, ip: "203.0.113.5" });
check("во время паузы не проходит и верный пароль", r.status === 429 && r.json.code === "rate-limited" && /минуту|мин/.test(r.json.message), r.text);
r = await call("POST", "/v1/account/login", { body: { email: B.email, loginHash: B.pw, deviceId: device(3) }, ip: "203.0.113.99" });
check("с другого адреса владелец входит (блокировкой его не отрезать)", r.status === 200, r.text);

// смена пароля
r = await call("POST", "/v1/account/password", { token: A.s1, body: { oldLoginHash: A.pw2, newLoginHash: A.pw2, kdf: 2 } });
check("смена пароля: неверный текущий → 401", r.status === 401 && r.json.code === "bad-credentials" && r.json.message === "Неверный текущий пароль", r.text);
r = await call("POST", "/v1/account/password", { token: A.s1, body: { oldLoginHash: A.pw1, newLoginHash: A.pw2, kdf: 2 } });
check("смена пароля", r.status === 200, r.text);
check("текущая сессия после смены пароля жива", (await call("GET", "/v1/account/devices", { token: A.s1 })).status === 200);
check("сессии других устройств завершены", (await call("GET", "/v1/account/devices", { token: A.s2 })).status === 401 && (await call("GET", "/v1/account/devices", { token: A.s2b })).status === 401);
check("старый пароль больше не подходит", (await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw1, deviceId: device(2) }, ip: "198.51.100.8" })).status === 401);
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw2, deviceId: device(2), deviceName: "Второй компьютер" } });
check("новый пароль подходит", r.status === 200, r.text);
A.s2 = r.json?.session?.token;

// ключ восстановления и сброс
const key = recoveryKey();
r = await call("POST", "/v1/account/recovery", { token: A.s1, body: { recoveryVerifier: "abcdef" } });
check("ключ проверки прежней схемы не принимается", r.status === 400, r.text);
let ch = await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.20" });
r = await call("POST", "/v1/account/reset", { body: { email: A.email, nonce: ch.json.nonce, recoveryProof: key.sign(`tabora-reset-v2|${A.email}|${A.pw3}|${ch.json.nonce}`), newLoginHash: A.pw3, kdf: 2 }, ip: "198.51.100.20" });
check("сброс без зарегистрированного ключа → 409", r.status === 409 && r.json.code === "no-recovery", r.text);
r = await call("POST", "/v1/account/recovery", { token: A.s1, body: { recoveryVerifier: key.verifier } });
check("ключ проверки зарегистрирован", r.status === 200, r.text);
ch = await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.20" });
check("nonce выдан", ch.status === 200 && /^[0-9a-f]{32}$/.test(ch.json.nonce), ch.text);
const other = recoveryKey();
r = await call("POST", "/v1/account/reset", { body: { email: A.email, nonce: ch.json.nonce, recoveryProof: other.sign(`tabora-reset-v2|${A.email}|${A.pw3}|${ch.json.nonce}`), newLoginHash: A.pw3, kdf: 2 }, ip: "198.51.100.20" });
check("сброс чужим ключом → отказ", r.status === 400 && r.json.code === "bad-proof", r.text);
r = await call("POST", "/v1/account/reset", { body: { email: A.email, nonce: ch.json.nonce, recoveryProof: key.sign(`tabora-reset-v2|${A.email}|${A.pw3}|${ch.json.nonce}`), newLoginHash: A.pw3, kdf: 2 }, ip: "198.51.100.20" });
check("nonce одноразовый: после неудачи тот же не годится", r.status === 400 && r.json.code === "bad-nonce", r.text);
ch = await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.20" });
r = await call("POST", "/v1/account/reset", { body: { email: A.email, nonce: ch.json.nonce, recoveryProof: key.sign(`tabora-reset-v2|${A.email}|${A.pw2}|${ch.json.nonce}`), newLoginHash: A.pw3, kdf: 2 }, ip: "198.51.100.20" });
check("подпись под другим паролем не подходит", r.status === 400 && r.json.code === "bad-proof", r.text);
ch = await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.20" });
r = await call("POST", "/v1/account/reset", {
  body: { email: A.email, nonce: ch.json.nonce, recoveryProof: key.sign(`tabora-reset-v2|${A.email}|${A.pw3}|${ch.json.nonce}`), newLoginHash: A.pw3, kdf: 2, legacyRecoveryProof: "00", newRecoveryVerifier: other.verifier },
  ip: "198.51.100.20",
});
check("сброс верным ключом", r.status === 200, r.text);
check("после сброса все сессии завершены", (await call("GET", "/v1/account/devices", { token: A.s1 })).status === 401 && (await call("GET", "/v1/account/devices", { token: A.s2 })).status === 401);
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw3, deviceId: device(1), deviceName: "Мак Анны" }, ip: "198.51.100.21" });
check("вход новым паролем после сброса", r.status === 200, r.text);
A.s1 = r.json?.session?.token;
// с другого адреса: у сброса свой предел (десять обращений в час с адреса), первый уже почти выбран
ch = await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.23" });
r = await call("POST", "/v1/account/reset", { body: { email: A.email, nonce: ch.json.nonce, recoveryProof: other.sign(`tabora-reset-v2|${A.email}|${A.pw1}|${ch.json.nonce}`), newLoginHash: A.pw1, kdf: 2 }, ip: "198.51.100.23" });
check("присланный при сбросе новый ключ проверки не подменил прежний", r.status === 400 && r.json.code === "bad-proof", r.text);
codes = [];
for (let i = 0; i < 3; i++) {
  codes.push((await call("POST", "/v1/account/reset/challenge", { body: { email: A.email }, ip: "198.51.100.20" })).status);
}
check("сброс: не больше десяти обращений в час с одного адреса", codes.includes(429), codes.join());
const ghost = await call("POST", "/v1/account/reset/challenge", { body: { email: mail("ghost") }, ip: "198.51.100.22" });
check("nonce выдаётся и для неизвестного адреса", ghost.status === 200 && /^[0-9a-f]{32}$/.test(ghost.json.nonce), ghost.text);

// замена хеша входа и выход
r = await call("POST", "/v1/account/upgrade", { token: A.s1, body: { oldLoginHash: A.pw3, newLoginHash: A.pw1, kdf: 2 } });
check("замена хеша входа", r.status === 200 && (await call("GET", "/v1/account/devices", { token: A.s1 })).status === 200, r.text);
r = await call("GET", "/v1/mail/aliases", { token: A.s1 });
check("список алиасов пуст", r.status === 200 && Array.isArray(r.json) && r.json.length === 0, r.text);
r = await call("POST", "/v1/mail/aliases", { token: A.s1, body: { site: "booking.com" } });
check("без почтового сервера алиас не создаётся", r.status === 503 && r.json.code === "mail-unavailable", r.text);
r = await call("POST", "/v1/account/logout", { token: A.s1 });
check("выход", r.status === 200 && (await call("GET", "/v1/account/devices", { token: A.s1 })).status === 401, r.text);

// ---- двухфакторная защита входа ----
const C = { email: mail("c"), pw: hash("c-pass"), pw2: hash("c-pass-2"), pw3: hash("c-pass-3"), ip: "198.51.100.50" };
r = await call("POST", "/v1/account/register", { body: { email: C.email, loginHash: C.pw, kdf: 2, deviceId: device(40), deviceName: "C" }, ip: C.ip });
C.s = r.json?.session?.token;
r = await call("GET", "/v1/account/security", { token: C.s });
check("настройки входа нового аккаунта: всё выключено", r.status === 200 && r.json.twoFactor.enabled === false && r.json.twoFactor.backupCodes === 0 && r.json.backupEmail === null && r.json.backupEmailPending === null && r.json.recoveryKey === false && r.json.mail === true, r.text);
check("настройки входа без сессии → 401", (await call("GET", "/v1/account/security")).status === 401);
r = await call("POST", "/v1/account/2fa/setup", { token: C.s, body: { loginHash: C.pw2 }, ip: C.ip });
check("настройка 2FA требует верный пароль", r.status === 401 && r.json.code === "bad-credentials", r.text);
r = await call("POST", "/v1/account/2fa/enable", { token: C.s, body: { code: "123456" }, ip: C.ip });
check("включить 2FA без начатой настройки нельзя", r.status === 400 && r.json.code === "2fa-setup-expired", r.text);
r = await call("POST", "/v1/account/2fa/setup", { token: C.s, body: { loginHash: C.pw }, ip: C.ip });
check("настройка 2FA выдаёт секрет и ссылку для приложения", r.status === 200 && /^[A-Z2-7]{32}$/.test(r.json.secret) && r.json.uri === `otpauth://totp/Tabora:${C.email.replace("@", "%40")}?secret=${r.json.secret}&issuer=Tabora&algorithm=SHA1&digits=6&period=30`, r.text);
C.secret = r.json?.secret;
check("до подтверждения кодом защита выключена", (await call("GET", "/v1/account/security", { token: C.s })).json.twoFactor.enabled === false && (await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(40) }, ip: C.ip })).status === 200);
r = await call("POST", "/v1/account/2fa/enable", { token: C.s, body: { code: otherCode(totp(C.secret)) }, ip: C.ip });
check("неверный первый код не включает защиту", r.status === 401 && r.json.code === "bad-2fa", r.text);
const firstCode = totp(C.secret);
r = await call("POST", "/v1/account/2fa/enable", { token: C.s, body: { code: ` ${firstCode.slice(0, 3)} ${firstCode.slice(3)} ` }, ip: C.ip });
check("верный код включает защиту и выдаёт десять резервных кодов", r.status === 200 && r.json.backupCodes.length === 10 && new Set(r.json.backupCodes).size === 10 && r.json.backupCodes.every(c => /^[a-z2-9]{4}-[a-z2-9]{4}$/.test(c)), r.text);
C.codes = r.json?.backupCodes || [];
r = await call("GET", "/v1/account/security", { token: C.s });
check("защита включена, резервных кодов десять", r.json.twoFactor.enabled === true && r.json.twoFactor.backupCodes === 10 && /^\d{4}-/.test(r.json.twoFactor.since), r.text);
r = await call("POST", "/v1/account/2fa/setup", { token: C.s, body: { loginHash: C.pw }, ip: C.ip });
check("повторная настройка при включённой защите → 409", r.status === 409 && r.json.code === "2fa-on", r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), deviceName: "C2" }, ip: C.ip });
check("вход без кода → 401 «нужен код»", r.status === 401 && r.json.code === "2fa-required", r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw2, deviceId: device(41), totp: totp(C.secret, 1) }, ip: C.ip });
check("неверный пароль с верным кодом → обычный отказ, код не тратится", r.status === 401 && r.json.code === "bad-credentials", r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), totp: firstCode }, ip: C.ip });
check("код, которым включали защиту, второй раз не принимается", r.status === 401 && r.json.code === "bad-2fa" && /уже использован/.test(r.json.message), r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), totp: otherCode(totp(C.secret, 1)) }, ip: C.ip });
check("неверный код → 401", r.status === 401 && r.json.code === "bad-2fa", r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), deviceName: "C2", totp: totp(C.secret, 1) }, ip: C.ip });
check("вход с паролем и свежим кодом", r.status === 200 && !!r.json.session.token, r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), totp: C.codes[0].toUpperCase().replace("-", " ") }, ip: C.ip });
check("вход с резервным кодом (в любом написании)", r.status === 200, r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), totp: C.codes[0] }, ip: C.ip });
check("резервный код одноразовый", r.status === 401 && r.json.code === "bad-2fa", r.text);
check("резервных кодов осталось девять", (await call("GET", "/v1/account/security", { token: C.s })).json.twoFactor.backupCodes === 9);
r = await call("POST", "/v1/account/2fa/codes", { token: C.s, body: { loginHash: C.pw }, ip: C.ip });
check("новые резервные коды без второго фактора не выдаются", r.status === 401 && r.json.code === "2fa-required", r.text);
r = await call("POST", "/v1/account/2fa/codes", { token: C.s, body: { loginHash: C.pw, code: C.codes[1] }, ip: C.ip });
check("новые резервные коды", r.status === 200 && r.json.backupCodes.length === 10 && !r.json.backupCodes.includes(C.codes[2]), r.text);
const oldCode = C.codes[2];
C.codes = r.json?.backupCodes || [];
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw, deviceId: device(41), totp: oldCode }, ip: C.ip });
check("прежние резервные коды перестали действовать", r.status === 401 && r.json.code === "bad-2fa", r.text);

// ---- резервный адрес ----
const BOX = "anna.backup@example.org";
r = await call("POST", "/v1/account/backup-email", { token: C.s, body: { loginHash: C.pw, address: BOX }, ip: C.ip });
check("резервный адрес при включённой защите требует код", r.status === 401 && r.json.code === "2fa-required", r.text);
for (const [what, address] of [["не адрес", "anna"], ["свой адрес", C.email], ["перевод строки", "a@example.org\r\nBcc: x@example.org"], ["кириллица", "анна@example.org"]]) {
  r = await call("POST", "/v1/account/backup-email", { token: C.s, body: { loginHash: C.pw, code: C.codes[0], address }, ip: C.ip });
  check(`резервный адрес: ${what} → 400`, r.status === 400 && r.json.code === "bad-address", r.text);
}
check("отказы по адресу второй фактор не тратят: резервных кодов по-прежнему десять", (await call("GET", "/v1/account/security", { token: C.s })).json.twoFactor.backupCodes === 10);
let t0 = Date.now();
r = await call("POST", "/v1/account/backup-email", { token: C.s, body: { loginHash: C.pw, code: C.codes[0], address: " Anna.Backup@Example.ORG " }, ip: C.ip });
check("резервный адрес принят и ждёт подтверждения", r.status === 200 && r.json.pending.address === BOX && /^\d{4}-/.test(r.json.pending.expiresAt), r.text);
let letter = await lastMail(BOX, { after: t0 - 5 });
check("на адрес ушло письмо с кодом из шести цифр", !!letter && /^\d{6}$/.test(letter.code || "") && letter.subject === "Tabora: подтверждение резервного адреса" && letter.text.includes(C.email), JSON.stringify(letter));
r = await call("GET", "/v1/account/security", { token: C.s });
check("до подтверждения адрес не резервный", r.json.backupEmail === null && r.json.backupEmailPending.address === BOX, r.text);
r = await call("POST", "/v1/account/backup-email/verify", { token: C.s, body: { code: otherCode(letter.code) }, ip: C.ip });
check("неверный код подтверждения → 400", r.status === 400 && r.json.code === "bad-code", r.text);
r = await call("POST", "/v1/account/backup-email/verify", { token: C.s, body: { code: `${letter.code.slice(0, 3)} ${letter.code.slice(3)}` }, ip: C.ip });
check("код из письма подтверждает адрес", r.status === 200 && r.json.address === BOX, r.text);
r = await call("POST", "/v1/account/backup-email/verify", { token: C.s, body: { code: letter.code }, ip: C.ip });
check("код подтверждения одноразовый", r.status === 400 && r.json.code === "no-code", r.text);
r = await call("GET", "/v1/account/security", { token: C.s });
check("адрес записан как резервный", r.json.backupEmail.address === BOX && r.json.backupEmailPending === null, r.text);
r = await call("POST", "/v1/account/backup-email", { token: C.s, body: { loginHash: C.pw, code: C.codes[1], address: BOX }, ip: C.ip });
check("тот же адрес повторно → 409", r.status === 409 && r.json.code === "same-address", r.text);

// ---- сброс пароля по коду из письма ----
t0 = Date.now();
r = await call("POST", "/v1/account/reset/email", { body: { email: mail("ghost") }, ip: "198.51.100.60" });
const ghostReset = r.text;
r = await call("POST", "/v1/account/reset/email", { body: { email: B.email }, ip: "198.51.100.60" });
check("запрос сброса для неизвестного адреса и для аккаунта без резервной почты отвечает одинаково", r.status === 200 && r.text === ghostReset && r.text === "{}", r.text);
r = await call("POST", "/v1/account/reset/email", { body: { email: C.email }, ip: "198.51.100.60" });
check("запрос сброса для аккаунта с резервной почтой отвечает так же", r.status === 200 && r.text === ghostReset, r.text);
letter = await lastMail(BOX, { after: t0 - 5, subject: "Tabora: сброс пароля" });
check("на резервный адрес ушёл код сброса из восьми цифр", !!letter && /^\d{8}$/.test(letter.code || "") && letter.subject === "Tabora: сброс пароля", JSON.stringify(letter));
check("другим адресам писем о сбросе нет", mailsTo(B.email).length === 0 && mailsTo(mail("ghost")).length === 0);
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code.replace(/.$/, d => (Number(d) + 1) % 10), newLoginHash: C.pw2, kdf: 2 }, ip: "198.51.100.60" });
check("неверный код сброса → 400", r.status === 400 && r.json.code === "bad-code", r.text);
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code, newLoginHash: C.pw2, kdf: 2 }, ip: "198.51.100.60" });
check("сброс по письму не обходит двухфакторную защиту", r.status === 401 && r.json.code === "2fa-required", r.text);
check("пароль без второго фактора не сменился", (await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw2, deviceId: device(41), totp: C.codes[2] }, ip: C.ip })).status === 401);
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code, newLoginHash: C.pw2, kdf: 2, totp: C.codes[3], deviceId: "x" }, ip: "198.51.100.60" });
check("сброс: плохое устройство → 400, код из письма не тратится", r.status === 400 && r.json.code === "bad-request", r.text);
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code, newLoginHash: C.pw2, kdf: 2, totp: C.codes[3], deviceId: device(42), deviceName: "После сброса" }, ip: "198.51.100.60" });
check("сброс по коду из письма и второму фактору сразу выдаёт сессию устройству", r.status === 200 && /^tbs_/.test(r.json.session?.token || "") && r.json.userId && r.json.kdf === 2 && r.json.mail === null, r.text);
check("выданная при сбросе сессия действует, прежние завершены", (await call("GET", "/v1/account/security", { token: r.json.session.token })).status === 200 && (await call("GET", "/v1/account/security", { token: C.s })).status === 401);
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code, newLoginHash: C.pw3, kdf: 2, totp: C.codes[4] }, ip: "198.51.100.60" });
check("код сброса одноразовый", r.status === 400 && r.json.code === "bad-code", r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw2, deviceId: device(40), deviceName: "C", totp: C.codes[4] }, ip: C.ip });
check("вход новым паролем (код по-прежнему нужен)", r.status === 200, r.text);
C.s = r.json?.session?.token;
const notice = mailsTo(BOX).filter(m => m.subject === "Tabora: пароль аккаунта сброшен").pop();
check("о сбросе пришло уведомление", !!notice && notice.text.includes(C.email), JSON.stringify(notice));
// пять неверных кодов гасят код сброса
t0 = Date.now();
await call("POST", "/v1/account/reset/email", { body: { email: C.email }, ip: "198.51.100.61" });
letter = await lastMail(BOX, { after: t0 - 5 });
codes = [];
for (let i = 0; i < 5; i++) {
  codes.push((await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: "0000000" + i, newLoginHash: C.pw3, kdf: 2, totp: C.codes[5] }, ip: "198.51.100.61" })).json.code);
}
r = await call("POST", "/v1/account/reset/email/confirm", { body: { email: C.email, code: letter.code, newLoginHash: C.pw3, kdf: 2, totp: C.codes[5] }, ip: "198.51.100.61" });
check("после пяти неверных попыток верный код сброса уже не действует", codes.every(c => c === "bad-code") && r.status === 400 && r.json.code === "bad-code", r.text);
t0 = Date.now();
await call("POST", "/v1/account/reset/email", { body: { email: C.email }, ip: "198.51.100.62" });
const third = await lastMail(BOX, { after: t0 - 5 });
const resetMails = () => mailsTo(BOX).filter(m => m.subject === "Tabora: сброс пароля").length;
const before = resetMails();
r = await call("POST", "/v1/account/reset/email", { body: { email: C.email }, ip: "198.51.100.63" });
await new Promise(done => setTimeout(done, 700));
check("на аккаунт не больше трёх писем сброса в сутки (четвёртый запрос отвечает так же, письма нет)", !!third && before === 3 && resetMails() === 3 && r.status === 200 && r.text === "{}", `${before} → ${resetMails()}`);

// ---- ключ восстановления снимает двухфакторную защиту; выключение и удаление адреса ----
const ckey = recoveryKey();
await call("POST", "/v1/account/recovery", { token: C.s, body: { recoveryVerifier: ckey.verifier } });
ch = await call("POST", "/v1/account/reset/challenge", { body: { email: C.email }, ip: "198.51.100.70" });
r = await call("POST", "/v1/account/reset", { body: { email: C.email, nonce: ch.json.nonce, recoveryProof: ckey.sign(`tabora-reset-v2|${C.email}|${C.pw3}|${ch.json.nonce}`), newLoginHash: C.pw3, kdf: 2 }, ip: "198.51.100.70" });
check("сброс ключом восстановления выключает двухфакторную защиту", r.status === 200 && r.json.twoFactorDisabled === true, r.text);
r = await call("POST", "/v1/account/login", { body: { email: C.email, loginHash: C.pw3, deviceId: device(40), deviceName: "C" }, ip: C.ip });
check("после него вход только по паролю", r.status === 200, r.text);
C.s = r.json?.session?.token;
r = await call("GET", "/v1/account/security", { token: C.s });
check("защита выключена, резервный адрес остался, ключ восстановления отмечен", r.json.twoFactor.enabled === false && r.json.twoFactor.backupCodes === 0 && r.json.backupEmail.address === BOX && r.json.recoveryKey === true, r.text);
r = await call("POST", "/v1/account/backup-email/remove", { token: C.s, body: { loginHash: C.pw }, ip: C.ip });
check("удаление резервного адреса требует верный пароль", r.status === 401 && r.json.code === "bad-credentials", r.text);
r = await call("POST", "/v1/account/backup-email/remove", { token: C.s, body: { loginHash: C.pw3 }, ip: C.ip });
check("резервный адрес удалён", r.status === 200 && (await call("GET", "/v1/account/security", { token: C.s })).json.backupEmail === null, r.text);
check("об удалении пришло уведомление на прежний адрес", mailsTo(BOX).some(m => m.subject === "Tabora: резервный адрес удалён"));

// пауза после неверных кодов (отдельный аккаунт: она длится четверть часа)
const D = { email: mail("d"), pw: hash("d-pass"), ip: "198.51.100.51" };
r = await call("POST", "/v1/account/register", { body: { email: D.email, loginHash: D.pw, kdf: 2, deviceId: device(50), deviceName: "D" }, ip: D.ip });
D.s = r.json?.session?.token;
r = await call("POST", "/v1/account/2fa/setup", { token: D.s, body: { loginHash: D.pw }, ip: D.ip });
D.secret = r.json?.secret;
r = await call("POST", "/v1/account/2fa/enable", { token: D.s, body: { code: totp(D.secret) }, ip: D.ip });
D.codes = r.json?.backupCodes || [];
codes = [];
for (let i = 0; i < 6; i++) {
  codes.push((await call("POST", "/v1/account/login", { body: { email: D.email, loginHash: D.pw, deviceId: device(50), totp: "aaaa-aaa" + "23456789"[i] }, ip: `203.0.113.${40 + i}` })).status);
}
check("пять неверных кодов подряд (с разных адресов), шестая попытка заблокирована", codes.join() === "401,401,401,401,401,429", codes.join());
r = await call("POST", "/v1/account/login", { body: { email: D.email, loginHash: D.pw, deviceId: device(50), totp: D.codes[0] }, ip: "203.0.113.90" });
check("во время паузы не проходит и верный резервный код", r.status === 429 && r.json.code === "rate-limited" && /неверных кодов/.test(r.json.message), r.text);
r = await call("POST", "/v1/account/2fa/disable", { token: D.s, body: { loginHash: D.pw, code: D.codes[0] }, ip: D.ip });
check("выключить защиту во время паузы тоже нельзя", r.status === 429, r.text);

// ---- ключи шифрования почты: копия закрытого ключа и каталог открытых ключей ----
/** Открытый ключ OpenPGP версии 4 (пакет ключа и пакет имени) и его отпечаток: seed делает ключи разными. */
function pgpKey(seed) {
  const body = Buffer.concat([Buffer.from([4, 0x5f, 0, 0, 0, 22, 9, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x01, 0x07, 0x40]), crypto.createHash("sha256").update(seed).digest()]);
  const fingerprint = crypto.createHash("sha1").update(Buffer.concat([Buffer.from([0x99, 0, body.length]), body])).digest("hex");
  return { fingerprint, bin: Buffer.concat([Buffer.from([0x98, body.length]), body, Buffer.from([0xb4, 3, 0x61, 0x40, 0x62])]) };
}
const zb32 = buf => {
  const abc = "ybndrfg8ejkmcpqxot1uwisza345h769";
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of buf) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += abc[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return bits ? out + abc[(acc << (5 - bits)) & 31] : out;
};
const wkd = local => zb32(crypto.createHash("sha1").update(local.toLowerCase()).digest());
const b64 = n => crypto.randomBytes(n).toString("base64");
const K = { email: mail("k"), pw: hash("k-pass"), ip: "198.51.100.61", local: name("k") };
r = await call("POST", "/v1/account/register", { body: { email: K.email, loginHash: K.pw, kdf: 2, deviceId: device(60), deviceName: "Мак" }, ip: K.ip });
K.s = r.json?.session?.token;
r = await call("GET", "/v1/mail/pgp", { ip: K.ip });
check("ключи почты без сессии не отдаются", r.status === 401 && r.json.code === "session-expired", r.text);
r = await call("GET", "/v1/mail/pgp", { token: K.s, ip: K.ip });
check("у нового аккаунта ключей нет", r.status === 200 && r.json.rev === 0 && r.json.fingerprint === null && r.json.publicKey === null && r.json.blob === null && r.json.wrapPassword === null && r.json.wrapRecovery === null, r.text);
const key1 = pgpKey("k1");
const key2 = pgpKey("k2");
const wrap1 = b64(60);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 0, wrapPassword: wrap1 } });
check("обёртка паролем без хеша входа отклоняется", r.status === 401 && r.json.code === "bad-credentials", r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 0, wrapPassword: wrap1, loginHash: hash("не тот пароль") } });
check("обёртка паролем с неверным хешем входа отклоняется", r.status === 401 && r.json.code === "bad-credentials" && r.json.message === "Неверный пароль", r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 0, wrapPassword: wrap1, loginHash: K.pw } });
check("обёртка ключа данных сохраняется отдельно от ключа", r.status === 200 && r.json.rev === 1 && r.json.wrapPassword === wrap1 && r.json.fingerprint === null, r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 0, wrapPassword: b64(60), loginHash: K.pw } });
check("запись с устаревшим номером версии отклоняется", r.status === 409 && r.json.code === "pgp-conflict", r.text);
const blob1 = b64(700);
for (const [what, body] of [
  ["ключ без копии", { rev: 1, fingerprint: key1.fingerprint, publicKey: key1.bin.toString("base64") }],
  ["чужой отпечаток", { rev: 1, fingerprint: key2.fingerprint, publicKey: key1.bin.toString("base64"), blob: blob1 }],
  ["не ключ", { rev: 1, fingerprint: key1.fingerprint, publicKey: Buffer.from("-----BEGIN PGP PUBLIC KEY BLOCK-----").toString("base64"), blob: blob1 }],
  ["закрытый ключ вместо открытого", { rev: 1, fingerprint: key1.fingerprint, publicKey: Buffer.concat([Buffer.from([0x94]), key1.bin.subarray(1)]).toString("base64"), blob: blob1 }],
  ["не Base64", { rev: 1, fingerprint: key1.fingerprint, publicKey: "@@@", blob: blob1 }],
  ["слишком короткая обёртка", { rev: 1, wrapPassword: b64(8), loginHash: K.pw }],
  ["слишком большая копия", { rev: 1, fingerprint: key1.fingerprint, publicKey: key1.bin.toString("base64"), blob: b64(30000) }],
]) {
  r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body });
  check(`ключи почты: ${what} → отказ`, r.status === 400 && r.json.code === "pgp-invalid", r.text);
}
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 1, fingerprint: key1.fingerprint.toUpperCase(), publicKey: key1.bin.toString("base64"), blob: blob1 } });
check("ключ и его зашифрованная копия сохранены", r.status === 200 && r.json.rev === 2 && r.json.fingerprint === key1.fingerprint && r.json.publicKey === key1.bin.toString("base64") && r.json.blob === blob1 && r.json.wrapPassword === wrap1 && /^\d{4}-/.test(r.json.updatedAt), r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 2, fingerprint: key2.fingerprint, publicKey: key2.bin.toString("base64"), blob: b64(700) } });
check("другой ключ поверх существующего без явной замены отклоняется", r.status === 409 && r.json.code === "pgp-conflict", r.text);
const wrapR = b64(60);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 2, wrapRecovery: wrapR } });
check("обёртка ключом восстановления добавляется, остальное не меняется", r.status === 200 && r.json.rev === 3 && r.json.wrapRecovery === wrapR && r.json.wrapPassword === wrap1 && r.json.blob === blob1, r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 3, wrapRecovery: "" } });
check("пустая обёртка ключом восстановления убирает её", r.status === 200 && r.json.wrapRecovery === null && r.json.wrapPassword === wrap1, r.text);
const blob2 = b64(700);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 4, fingerprint: key2.fingerprint, publicKey: key2.bin.toString("base64"), blob: blob2, replace: true } });
check("замена ключа по одной лишь сессии отклоняется", r.status === 401 && r.json.code === "bad-credentials", r.text);
r = await call("PUT", "/v1/mail/pgp", { token: K.s, ip: K.ip, body: { rev: 4, fingerprint: key2.fingerprint, publicKey: key2.bin.toString("base64"), blob: blob2, wrapPassword: b64(60), replace: true, loginHash: K.pw } });
check("явная замена ключа с паролем проходит", r.status === 200 && r.json.rev === 5 && r.json.fingerprint === key2.fingerprint && r.json.blob === blob2, r.text);
r = await call("POST", "/v1/account/login", { body: { email: K.email, loginHash: K.pw, deviceId: device(61), deviceName: "Второй" }, ip: K.ip });
r = await call("GET", "/v1/mail/pgp", { token: r.json?.session?.token, ip: K.ip });
check("второе устройство после входа получает ту же копию", r.status === 200 && r.json.rev === 5 && r.json.blob === blob2 && r.json.fingerprint === key2.fingerprint, r.text);
r = await call("GET", "/v1/mail/pgp", { token: A.s1, ip: K.ip });
check("чужая сессия чужих ключей не видит", r.status !== 200 || r.json.fingerprint !== key2.fingerprint, r.text);
// каталог открытых ключей (WKD)
let res = await fetch(`${BASE}/.well-known/openpgpkey/hu/${wkd(K.local)}?l=${K.local}`, { headers: { "X-Forwarded-For": "198.51.100.62" } });
let got = Buffer.from(await res.arrayBuffer());
check("каталог отдаёт открытый ключ двоичным", res.status === 200 && res.headers.get("content-type") === "application/octet-stream" && got.equals(key2.bin), `${res.status} ${got.length}`);
res = await fetch(`${BASE}/.well-known/openpgpkey/hu/${wkd(K.local)}`, { headers: { "X-Forwarded-For": "198.51.100.62" } });
check("каталог отвечает и без имени в запросе", res.status === 200 && Buffer.from(await res.arrayBuffer()).equals(key2.bin));
res = await fetch(`${BASE}/.well-known/openpgpkey/hu/${wkd(K.local).toUpperCase()}?l=${K.local.toUpperCase()}`, { headers: { "X-Forwarded-For": "198.51.100.62" } });
check("регистр имени и хеша не важен", res.status === 200);
for (const [what, url] of [
  ["имя не соответствует хешу", `/.well-known/openpgpkey/hu/${wkd(K.local)}?l=${name("a")}`],
  ["аккаунт без ключа", `/.well-known/openpgpkey/hu/${wkd(name("a"))}?l=${name("a")}`],
  ["несуществующий адрес", `/.well-known/openpgpkey/hu/${wkd("nobody-here")}?l=nobody-here`],
  ["мусор вместо хеша", "/.well-known/openpgpkey/hu/..%2F..%2Fetc"],
]) {
  res = await fetch(BASE + url, { headers: { "X-Forwarded-For": "198.51.100.62" } });
  check(`каталог: ${what} → 404`, res.status === 404, String(res.status));
}
res = await fetch(`${BASE}/.well-known/openpgpkey/policy`);
check("файл политики каталога есть", res.status === 200 && (await res.text()) === "");

// ---- синхронизация: непрозрачные записи, зашифрованные браузером ----
const kid = seed => crypto.createHash("sha256").update(seed).digest("hex").slice(0, 16);
const S = { email: mail("sy"), pw: hash("sy-pass"), ip: "198.51.100.80" };
r = await call("POST", "/v1/account/register", { body: { email: S.email, loginHash: S.pw, kdf: 2, deviceId: device(70), deviceName: "Мак" }, ip: S.ip });
S.s = r.json?.session?.token;
const T = { email: mail("sz"), pw: hash("sz-pass"), ip: "198.51.100.81" };
r = await call("POST", "/v1/account/register", { body: { email: T.email, loginHash: T.pw, kdf: 2, deviceId: device(71), deviceName: "Мак" }, ip: T.ip });
T.s = r.json?.session?.token;
const sync = (who, method, tail = "", body) => call(method, "/v1/sync" + tail, { token: who.s, ip: who.ip, body });
const [K1, K2, K3] = [kid("k1"), kid("k2"), kid("k3")];
const savedList = j => (j?.saved || []).map(x => `${x.c}/${x.id}:${x.rev}`).join();
const itemList = j => (j?.items || []).map(x => `${x.c}/${x.id}:${x.rev}:${x.deleted}`).join();
const put = (who, gen, keyId, items) => sync(who, "POST", "", { gen, keyId, items });
const bm = (id, base, blob) => ({ c: "bookmarks", id, base, blob });

r = await call("GET", "/v1/sync", { ip: S.ip });
check("синхронизация без сессии → 401", r.status === 401 && r.json.code === "session-expired", r.text);
check("запись и сброс синхронизации без сессии → 401", (await call("POST", "/v1/sync", { ip: S.ip, body: { gen: 1, keyId: K1, items: [] } })).status === 401 && (await call("POST", "/v1/sync/reset", { ip: S.ip, body: { keyId: K1 } })).status === 401 && (await call("DELETE", "/v1/sync", { ip: S.ip })).status === 401);
r = await sync(S, "GET");
check("у нового аккаунта данных синхронизации нет", r.status === 200 && r.json.rev === 0 && r.json.gen === 1 && r.json.keyId === null && Array.isArray(r.json.items) && r.json.items.length === 0 && r.json.more === false, r.text);
const [b1, b2, b3] = [b64(100), b64(2000), b64(1)];
r = await put(S, 1, K1, [bm("a1", 0, b1), bm("a2", 0, b2), { c: "history", id: "h_1-X", base: 0, blob: b3 }]);
check("первые записи сохранены, каждая получила следующий номер", r.status === 200 && r.json.rev === 3 && r.json.gen === 1 && r.json.keyId === K1 && savedList(r.json) === "bookmarks/a1:1,bookmarks/a2:2,history/h_1-X:3" && Array.isArray(r.json.conflicts) && r.json.conflicts.length === 0, r.text);
r = await sync(S, "GET", "?since=0");
check("записи читаются по возрастанию номера, блоки те же", r.status === 200 && r.json.rev === 3 && r.json.keyId === K1 && r.json.more === false && itemList(r.json) === "bookmarks/a1:1:false,bookmarks/a2:2:false,history/h_1-X:3:false" && r.json.items[0].blob === b1 && r.json.items[1].blob === b2 && r.json.items[2].blob === b3, r.text);
r = await sync(S, "GET", "?since=1&limit=1");
check("limit ограничивает ответ, more сообщает об остатке", r.status === 200 && itemList(r.json) === "bookmarks/a2:2:false" && r.json.more === true && r.json.rev === 3, r.text);
r = await sync(S, "GET", "?since=2&limit=1");
check("последняя страница: more = false", itemList(r.json) === "history/h_1-X:3:false" && r.json.more === false, r.text);
r = await sync(S, "GET", "?since=3");
check("новее последнего номера записей нет", r.status === 200 && r.json.items.length === 0 && r.json.more === false && r.json.rev === 3, r.text);
r = await sync(S, "GET", "?limit=5000");
check("limit больше тысячи не ошибка", r.status === 200 && r.json.items.length === 3, r.text);
for (const q of ["?since=-1", "?since=abc", "?limit=0", "?limit=x"]) {
  r = await sync(S, "GET", q);
  check(`чтение синхронизации: ${q} → 400`, r.status === 400 && r.json.code === "sync-invalid" && !!r.json.message, r.text);
}
const b1b = b64(300);
r = await put(S, 1, K1, [bm("a1", 1, b1b)]);
check("обновление виденной версии сохраняется", r.status === 200 && savedList(r.json) === "bookmarks/a1:4" && r.json.rev === 4 && r.json.conflicts.length === 0, r.text);
r = await sync(S, "GET", "?since=3");
check("обновлённая запись приходит с новым номером и блоком", itemList(r.json) === "bookmarks/a1:4:false" && r.json.items[0].blob === b1b, r.text);
const b4 = b64(50);
r = await put(S, 1, K1, [bm("a1", 1, b64(10)), bm("a3", 0, b4), bm("a2", 0, b64(10)), bm("zz", 9, b64(10))]);
let cf = Object.fromEntries((r.json?.conflicts || []).map(x => [x.id, x]));
check(
  "устаревшая версия попадает в conflicts с состоянием сервера, остальные записи сохраняются",
  r.status === 200 && savedList(r.json) === "bookmarks/a3:5" && r.json.rev === 5 && r.json.conflicts.length === 3 && cf.a1?.c === "bookmarks" && cf.a1.rev === 4 && cf.a1.deleted === false && cf.a1.blob === b1b && cf.a2?.rev === 2 && cf.a2.blob === b2,
  r.text
);
check("запись, которой на сервере нет, а устройство её «видело» → conflict как удалённая", cf.zz?.rev === 0 && cf.zz.deleted === true && cf.zz.blob === null, r.text);
r = await sync(S, "GET", "?since=4");
check("расхождения на сервере ничего не изменили", itemList(r.json) === "bookmarks/a3:5:false" && r.json.items[0].blob === b4, r.text);
r = await put(S, 1, K1, [{ c: "bookmarks", id: "a2", base: 2, deleted: true }]);
check("удаление сохраняется надгробием", r.status === 200 && savedList(r.json) === "bookmarks/a2:6" && r.json.rev === 6, r.text);
r = await sync(S, "GET", "?since=5");
check("надгробие приходит без блока", itemList(r.json) === "bookmarks/a2:6:true" && r.json.items[0].blob === null, r.text);
r = await put(S, 1, K1, [bm("a2", 2, b64(10))]);
check("запись поверх надгробия по старой версии → conflict с надгробием", r.status === 200 && savedList(r.json) === "" && r.json.rev === 6 && r.json.conflicts.length === 1 && r.json.conflicts[0].rev === 6 && r.json.conflicts[0].deleted === true && r.json.conflicts[0].blob === null, r.text);
const b5 = b64(20);
r = await put(S, 1, K1, [bm("a2", 6, b5)]);
check("запись поверх надгробия по его версии восстанавливает её", r.status === 200 && savedList(r.json) === "bookmarks/a2:7", r.text);
const b6 = b64(30);
r = await put(S, 1, K1, [bm("d1", 0, b6), bm("d1", 0, b64(30))]);
check("повтор ключа в одном запросе: первая сохраняется, вторая расходится с ней", r.status === 200 && savedList(r.json) === "bookmarks/d1:8" && r.json.conflicts.length === 1 && r.json.conflicts[0].rev === 8 && r.json.conflicts[0].blob === b6, r.text);
r = await put(S, 1, K2, [bm("k", 0, b64(10))]);
check("другой ключ шифрования → 409 sync-key, в ответе текущие поколение и ключ", r.status === 409 && r.json.code === "sync-key" && r.json.message === "Данные синхронизации зашифрованы другим ключом" && r.json.gen === 1 && r.json.keyId === K1, r.text);
r = await put(S, 2, K1, [bm("k", 0, b64(10))]);
check("чужое поколение → 409 sync-reset", r.status === 409 && r.json.code === "sync-reset" && r.json.gen === 1 && r.json.keyId === K1, r.text);
for (const [what, body] of [
  ["неверный ключ записи", { gen: 1, keyId: K1, items: [bm("a/b", 0, b3)] }],
  ["слишком длинный ключ записи", { gen: 1, keyId: K1, items: [bm("x".repeat(65), 0, b3)] }],
  ["неверный раздел", { gen: 1, keyId: K1, items: [{ c: "Bookmarks", id: "n1", base: 0, blob: b3 }] }],
  ["отрицательная версия", { gen: 1, keyId: K1, items: [bm("n1", -1, b3)] }],
  ["дробная версия", { gen: 1, keyId: K1, items: [bm("n1", 1.5, b3)] }],
  ["запись без содержимого", { gen: 1, keyId: K1, items: [{ c: "bookmarks", id: "n1", base: 0 }] }],
  ["пустое содержимое", { gen: 1, keyId: K1, items: [bm("n1", 0, "")] }],
  ["содержимое не в Base64", { gen: 1, keyId: K1, items: [bm("n1", 0, "@@@")] }],
  ["неверный отпечаток ключа", { gen: 1, keyId: "XYZ", items: [bm("n1", 0, b3)] }],
  ["нет поколения", { keyId: K1, items: [bm("n1", 0, b3)] }],
  ["нулевое поколение", { gen: 0, keyId: K1, items: [bm("n1", 0, b3)] }],
  ["записи не списком", { gen: 1, keyId: K1, items: { n1: b3 } }],
]) {
  r = await sync(S, "POST", "", body);
  check(`запись синхронизации: ${what} → 400`, r.status === 400 && r.json.code === "sync-invalid" && !!r.json.message, r.text);
}
r = await call("POST", "/v1/sync", { token: S.s, ip: S.ip, raw: "{не json" });
check("запись синхронизации: не JSON → 400", r.status === 400 && r.json?.code === "sync-invalid", r.text);
// одна неверная запись отклоняет запрос целиком
r = await put(S, 1, K1, [bm("n1", 0, b3), bm("n2", 0, b64(96 * 1024 + 1))]);
check("блок больше 96 КиБ → 413 sync-limit", r.status === 413 && r.json.code === "sync-limit" && !!r.json.message, r.text);
r = await put(S, 1, K1, Array.from({ length: 201 }, (_, i) => bm("m" + i, 0, b3)));
check("больше 200 записей в запросе → 413 sync-limit", r.status === 413 && r.json.code === "sync-limit", r.text);
r = await sync(S, "GET", "?since=8");
check("отклонённые запросы ничего не сохранили", r.status === 200 && r.json.rev === 8 && r.json.items.length === 0 && r.json.keyId === K1, r.text);
const bMax = b64(96 * 1024);
r = await put(S, 1, K1, [bm("max", 0, bMax)]);
check("блок ровно 96 КиБ принимается", r.status === 200 && savedList(r.json) === "bookmarks/max:9", r.text);
// 120 записей по 72 КиБ тремя запросами около 3,8 МиБ: больше общего предела тела, меньше предела синхронизации
const heavy = Array.from({ length: 120 }, (_, i) => bm("w" + i, 0, b64(72 * 1024)));
codes = [];
for (let i = 0; i < 3; i++) {
  r = await put(S, 1, K1, heavy.slice(i * 40, i * 40 + 40));
  codes.push(r.status);
}
check("запросы на несколько мегабайт принимаются, номера идут подряд", codes.join() === "200,200,200" && r.json.saved.length === 40 && r.json.saved[0].rev === 90 && r.json.saved[39].rev === 129 && r.json.rev === 129, codes.join() + " " + r.text.slice(0, 200));
r = await sync(S, "GET", "?since=9&limit=1000");
const page1 = r.json?.items || [];
check("ответ ограничен и по объёму: блоков не больше 8 МиБ за раз, об остатке говорит more", r.status === 200 && page1.length === 113 && r.json.more === true && r.json.rev === 129 && page1.every((x, i) => x.rev === 10 + i && x.blob === heavy[i].blob), `${r.status} ${page1.length} ${r.json?.more}`);
r = await sync(S, "GET", `?since=${page1[page1.length - 1]?.rev}&limit=1000`);
check("остаток дочитывается от номера последней полученной записи", r.status === 200 && r.json.items.length === 7 && r.json.more === false && r.json.items.every((x, i) => x.rev === 123 + i && x.blob === heavy[113 + i].blob), `${r.status} ${r.json?.items?.length} ${r.json?.more}`);
// тело больше 4 МиБ: сервер отвечает 413, не дочитав запрос, поэтому клиент может увидеть и обрыв соединения
let tooBig = "";
try {
  r = await put(S, 1, K1, Array.from({ length: 50 }, (_, i) => bm("v" + i, 0, b64(72 * 1024))));
  tooBig = `${r.status} ${r.json?.code}`;
} catch (e) {
  tooBig = "обрыв";
}
r = await sync(S, "GET", "?since=129");
check(`запрос синхронизации больше 4 МиБ не принимается (${tooBig})`, (tooBig === "413 sync-limit" || tooBig === "обрыв") && r.status === 200 && r.json.rev === 129 && r.json.items.length === 0, tooBig);
// изоляция аккаунтов
r = await sync(T, "GET");
check("второй аккаунт чужих записей не видит", r.status === 200 && r.json.rev === 0 && r.json.gen === 1 && r.json.keyId === null && r.json.items.length === 0, r.text.slice(0, 300));
const tb = b64(64);
r = await put(T, 1, K2, [bm("a1", 0, tb)]);
check("у каждого аккаунта свой счётчик и свой ключ", r.status === 200 && savedList(r.json) === "bookmarks/a1:1" && r.json.rev === 1 && r.json.keyId === K2, r.text);
r = await sync(S, "GET", "?since=0&limit=3");
check("запись второго аккаунта не затронула первый", r.json.rev === 129 && r.json.items.every(x => x.blob !== tb) && itemList(r.json) === "history/h_1-X:3:false,bookmarks/a1:4:false,bookmarks/a3:5:false" && r.json.more === true, r.text.slice(0, 300));
// сброс
r = await sync(S, "POST", "/reset", { keyId: "не ключ" });
check("сброс с неверным отпечатком ключа → 400", r.status === 400 && r.json.code === "sync-invalid", r.text);
r = await sync(S, "POST", "/reset", { keyId: K1 });
check("сброс: записи удалены, поколение выросло, счётчик не обнулился", r.status === 200 && r.json.rev === 130 && r.json.gen === 2 && r.json.keyId === K1 && Object.keys(r.json).length === 3, r.text);
r = await sync(S, "GET", "?since=0");
check("после сброса записей нет", r.status === 200 && r.json.items.length === 0 && r.json.rev === 130 && r.json.gen === 2 && r.json.keyId === K1 && r.json.more === false, r.text);
r = await put(S, 1, K1, [bm("a1", 0, b1)]);
check("запись со старым поколением после сброса → 409 sync-reset", r.status === 409 && r.json.code === "sync-reset" && r.json.message === "Данные синхронизации были сброшены: нужно начать заново" && r.json.gen === 2 && r.json.keyId === K1, r.text);
r = await put(S, 2, K1, [bm("a1", 0, b1)]);
check("с новым поколением записи создаются заново, номера продолжаются", r.status === 200 && savedList(r.json) === "bookmarks/a1:131" && r.json.gen === 2, r.text);
r = await sync(S, "POST", "/reset", { keyId: K2 });
check("сброс с новым ключом", r.status === 200 && r.json.rev === 132 && r.json.gen === 3 && r.json.keyId === K2, r.text);
r = await put(S, 3, K1, [bm("a1", 0, b1)]);
check("прежний ключ после сброса с новым → 409 sync-key", r.status === 409 && r.json.code === "sync-key" && r.json.gen === 3 && r.json.keyId === K2, r.text);
r = await put(S, 3, K2, [bm("a1", 0, b1)]);
check("новый ключ и новое поколение принимаются", r.status === 200 && savedList(r.json) === "bookmarks/a1:133", r.text);
// выключение синхронизации
r = await sync(S, "DELETE");
check("DELETE стирает записи и ключ, поколение растёт", r.status === 200 && r.json.gen === 4 && r.json.keyId === null && r.json.rev === 133 && Object.keys(r.json).length === 3, r.text);
r = await sync(S, "GET", "?since=0");
check("после DELETE записей и ключа нет", r.status === 200 && r.json.items.length === 0 && r.json.keyId === null && r.json.gen === 4 && r.json.rev === 133, r.text);
r = await put(S, 3, K2, [bm("a1", 0, b1)]);
check("запись со старым поколением после DELETE → 409 sync-reset", r.status === 409 && r.json.code === "sync-reset" && r.json.gen === 4 && r.json.keyId === null, r.text);
r = await sync(S, "GET");
check("отклонённая запись ключ не запомнила", r.json.keyId === null && r.json.rev === 133, r.text);
r = await put(S, 4, K3, [bm("a1", 0, b1)]);
check("после DELETE синхронизация начинается заново с любым ключом", r.status === 200 && savedList(r.json) === "bookmarks/a1:134" && r.json.keyId === K3 && r.json.gen === 4, r.text);
// одновременные запросы одного аккаунта идут по очереди
let batches = await Promise.all(Array.from({ length: 8 }, (_, i) => put(S, 4, K3, Array.from({ length: 25 }, (_, j) => bm(`c${i}_${j}`, 0, "eA==")))));
let revs = batches.flatMap(x => (x.json?.saved || []).map(v => v.rev)).sort((x, y) => x - y);
check(
  "одновременные записи получают номера подряд, без повторов и пропусков",
  batches.every(x => x.status === 200 && x.json.saved.length === 25 && x.json.saved.every((v, i, all) => i === 0 || v.rev === all[i - 1].rev + 1)) && revs.length === 200 && revs.every((v, i) => v === 135 + i),
  batches.map(x => x.status).join() + " " + revs.slice(0, 5).join()
);
batches = await Promise.all(Array.from({ length: 6 }, () => put(S, 4, K3, [bm("race", 0, b64(8))])));
const won = batches.filter(x => x.json?.saved?.length === 1);
check(
  "одну и ту же новую запись из одновременных запросов сохраняет только один, остальным приходит его версия",
  batches.every(x => x.status === 200) && won.length === 1 && won[0].json.saved[0].rev === 335 && batches.filter(x => x !== won[0]).every(x => x.json.saved.length === 0 && x.json.conflicts.length === 1 && x.json.conflicts[0].rev === 335),
  batches.map(x => `${x.status}:${x.json?.saved?.length}:${x.json?.conflicts?.length}`).join()
);
r = await sync(S, "GET", "?since=334");
check("после одновременных записей счётчик равен числу сохранённых", r.json.rev === 335 && itemList(r.json) === "bookmarks/race:335:false", r.text);
r = await sync(T, "GET");
check("сбросы первого аккаунта второй не затронули", r.json.rev === 1 && r.json.gen === 1 && r.json.keyId === K2 && itemList(r.json) === "bookmarks/a1:1:false" && r.json.items[0].blob === tb, r.text);
// предел числа записей: 30 000 на аккаунт (у второго аккаунта одна уже есть)
const tiny = (prefix, n) => Array.from({ length: n }, (_, j) => bm(prefix + j, 0, "eA=="));
let seen = new Set();
for (let i = 0; i < 149; i++) {
  seen.add((await put(T, 1, K2, tiny(`n${i}_`, 200))).status);
}
r = await put(T, 1, K2, tiny("q", 200));
check("запрос, с которым записей стало бы больше 30 000, отклоняется целиком", [...seen].join() === "200" && r.status === 413 && r.json.code === "sync-limit" && /30000/.test(r.json.message), [...seen].join() + " " + r.text);
r = await put(T, 1, K2, tiny("q", 199));
check("ровно 30 000 записей помещаются", r.status === 200 && r.json.saved.length === 199 && r.json.rev === 30000, r.text.slice(0, 200));
const q0 = r.json?.saved?.[0]?.rev;
r = await put(T, 1, K2, [bm("one-more", 0, "eA==")]);
check("ещё одна запись сверх предела → 413 sync-limit", r.status === 413 && r.json.code === "sync-limit", r.text);
r = await put(T, 1, K2, [bm("a1", 1, b64(10)), { c: "bookmarks", id: "q0", base: q0, deleted: true }]);
check("при заполненном хранилище записи можно обновлять и удалять", r.status === 200 && r.json.saved.length === 2 && r.json.rev === 30002, r.text);
r = await put(T, 1, K2, [bm("one-more", 0, "eA==")]);
check("надгробие остаётся записью и места под новую не освобождает", r.status === 413 && r.json.code === "sync-limit", r.text);
// предел объёма: 64 МиБ на аккаунт; 682 записи по 96 КиБ — это 65 472 КиБ из 65 536
r = await sync(T, "POST", "/reset", { keyId: K2 });
check("сброс освобождает хранилище", r.status === 200 && r.json.gen === 2 && r.json.rev === 30003, r.text);
seen = new Set();
let g0 = 0;
for (let i = 0; i < 22; i++) {
  r = await put(T, 2, K2, Array.from({ length: 31 }, (_, j) => bm(`g${i}_${j}`, 0, b64(96 * 1024))));
  seen.add(r.status);
  if (i === 0) {
    g0 = r.json?.saved?.[0]?.rev;
  }
}
r = await put(T, 2, K2, [bm("over", 0, b64(64 * 1024 + 1))]);
check("запись, с которой данных стало бы больше 64 МиБ, отклоняется", [...seen].join() === "200" && r.status === 413 && r.json.code === "sync-limit" && /64 МБ/.test(r.json.message), [...seen].join() + " " + r.text);
r = await put(T, 2, K2, [bm("fit", 0, b64(64 * 1024))]);
check("ровно 64 МиБ помещаются", r.status === 200 && r.json.saved.length === 1, r.text);
r = await put(T, 2, K2, [bm("byte", 0, "eA==")]);
check("ещё один байт сверх предела → 413 sync-limit", r.status === 413 && r.json.code === "sync-limit", r.text);
r = await put(T, 2, K2, [{ c: "bookmarks", id: "g0_0", base: g0, deleted: true }]);
const freed = r.status;
r = await put(T, 2, K2, [bm("after", 0, b64(96 * 1024))]);
check("надгробие в объём не входит: место удалённой записи можно занять", freed === 200 && r.status === 200 && r.json.saved.length === 1, `${freed} ${r.text.slice(0, 200)}`);
codes = [];
for (let i = 0; i < 6; i++) {
  codes.push((await sync(T, "POST", "/reset", { keyId: K2 })).status);
}
check("сброс синхронизации — не больше шести в час", codes.join() === "200,200,200,200,200,429", codes.join());

// ---- обращения в поддержку ----
const U = { email: mail("u"), pw: hash("u-pass"), ip: "198.51.100.90" };
const V = { email: mail("v"), pw: hash("v-pass"), ip: "198.51.100.91" };
const H = { email: STAFF, pw: hash("staff-pass"), ip: "198.51.100.92" };
for (const [who, n] of [[U, 80], [V, 81], [H, 82]]) {
  r = await call("POST", "/v1/account/register", { body: { email: who.email, loginHash: who.pw, kdf: 2, deviceId: device(n), deviceName: "Мак" }, ip: who.ip });
  if (r.status === 409) {
    // база не пустая: аккаунт сотрудника остался от прошлого запуска
    r = await call("POST", "/v1/account/login", { body: { email: who.email, loginHash: who.pw, deviceId: device(n), deviceName: "Мак" }, ip: who.ip });
  }
  who.s = r.json?.session?.token;
}
check(`аккаунт сотрудника поддержки ${STAFF} готов`, !!H.s && !!U.s && !!V.s, r.text);
const sup = (who, method, tail, body) => call(method, "/v1/support" + tail, { token: who.s, ip: who.ip, body });
const download = async (who, id) => {
  const res = await fetch(`${BASE}/v1/support/files/${id}`, { headers: { "X-Forwarded-For": who.ip, ...(who.s ? { Authorization: `Bearer ${who.s}` } : {}) } });
  return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
};
const isoTime = v => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v || "");
const byId = (j, id) => (j?.tickets || []).find(t => t.id === id);

check(
  "обращения без сессии → 401",
  (await call("GET", "/v1/support/tickets")).status === 401 && (await call("GET", "/v1/support/unread")).status === 401 && (await call("POST", "/v1/support/tickets", { body: { subject: "Тема", text: "Текст" } })).status === 401 && (await call("GET", "/v1/support/tickets/1")).status === 401 && (await download({ ip: U.ip }, 1)).status === 401
);
r = await sup(U, "GET", "/tickets");
check("у нового аккаунта обращений нет", r.status === 200 && r.json.staff === false && Array.isArray(r.json.tickets) && r.json.tickets.length === 0 && r.headers.get("cache-control") === "no-store", r.text);
r = await sup(U, "GET", "/unread");
check("непрочитанных ответов нет, очереди у пользователя нет", r.status === 200 && r.json.count === 0 && r.json.staff === false && !("queue" in r.json), r.text);
const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), crypto.randomBytes(5000)]);
const note = Buffer.from("журнал: строка 1\nстрока 2\n");
const shot = { name: "shot.png", type: "image/png", data: png.toString("base64") };
for (const [what, body] of [
  ["короткая тема", { subject: " ab ", text: "Текст" }],
  ["слишком длинная тема", { subject: "я".repeat(141), text: "Текст" }],
  ["нет темы", { text: "Текст" }],
  ["пустой текст", { subject: "Тема", text: "  \n " }],
  ["слишком длинный текст", { subject: "Тема", text: "я".repeat(8001) }],
  ["сведения о браузере не объектом", { subject: "Тема", text: "Текст", meta: ["x"] }],
  ["слишком большие сведения о браузере", { subject: "Тема", text: "Текст", meta: { pad: "x".repeat(2100) } }],
  ["пять вложений", { subject: "Тема", text: "Текст", files: Array(5).fill(shot) }],
  ["вложение неверного типа", { subject: "Тема", text: "Текст", files: [{ name: "a.svg", type: "image/svg+xml", data: png.toString("base64") }] }],
  ["вложение без типа", { subject: "Тема", text: "Текст", files: [{ name: "a.png", data: png.toString("base64") }] }],
  ["вложение больше 2 МиБ", { subject: "Тема", text: "Текст", files: [{ name: "big.png", type: "image/png", data: b64(2 * 1024 * 1024 + 1) }] }],
  ["пустое вложение", { subject: "Тема", text: "Текст", files: [{ name: "a.png", type: "image/png", data: "" }] }],
  ["вложение не в Base64", { subject: "Тема", text: "Текст", files: [{ name: "a.png", type: "image/png", data: "@@@" }] }],
]) {
  r = await sup(U, "POST", "/tickets", body);
  check(`обращение: ${what} → 400`, r.status === 400 && r.json.code === "support-invalid" && !!r.json.message, r.text);
}
check("отклонённые обращения не созданы", (await sup(U, "GET", "/tickets")).json.tickets.length === 0 && mailsTo(NOTIFY).length === 0);
t0 = Date.now();
r = await sup(U, "POST", "/tickets", {
  subject: "  Не открывается почта  ",
  text: "Здравствуйте!\r\nПочта не открывается после обновления.",
  meta: { version: "1.4.2", os: "macOS 15" },
  files: [{ name: "../снимок\\экрана\u0007.png", type: "image/png", data: png.toString("base64") }, { name: "журнал.txt", type: "text/plain", data: note.toString("base64") }],
});
const created = r;
U.t = r.json?.id;
let m0 = r.json?.messages?.[0];
check(
  "обращение создано",
  r.status === 200 && Number.isInteger(U.t) && r.json.subject === "Не открывается почта" && r.json.status === "open" && isoTime(r.json.createdAt) && isoTime(r.json.updatedAt) && r.json.staff === false && !("author" in r.json) && !("meta" in r.json) && r.json.messages.length === 1 && Number.isInteger(m0.id) && m0.from === "user" && m0.text === "Здравствуйте!\nПочта не открывается после обновления." && isoTime(m0.at),
  r.text
);
const att = m0?.files || [];
check(
  "вложения приняты, имя очищено от путей и управляющих знаков",
  att.length === 2 && Number.isInteger(att[0].id) && att[0].name === "снимокэкрана.png" && att[0].type === "image/png" && att[0].size === png.length && att[1].name === "журнал.txt" && att[1].type === "text/plain" && att[1].size === note.length && !("data" in att[0]),
  JSON.stringify(att)
);
letter = await lastMail(NOTIFY, { after: t0 - 5 });
check("поддержке ушло письмо о новом обращении", !!letter && letter.subject === `Новое обращение № ${U.t}: Не открывается почта` && letter.text.includes(U.email) && letter.text.includes("Почта не открывается после обновления."), JSON.stringify(letter));
r = await sup(U, "GET", "/tickets");
let row = byId(r.json, U.t);
check("обращение в списке автора", r.status === 200 && r.json.tickets.length === 1 && row?.subject === "Не открывается почта" && row.status === "open" && row.messages === 1 && row.unread === false && isoTime(row.createdAt) && isoTime(row.updatedAt) && !("author" in row), r.text);
r = await sup(U, "GET", `/tickets/${U.t}`);
check("чтение отдаёт обращение в том же виде, что и создание", r.status === 200 && r.text === created.text, r.text);
// посторонний
let codes4 = [
  (await sup(V, "GET", `/tickets/${U.t}`)).json?.code,
  (await sup(V, "POST", `/tickets/${U.t}/messages`, { text: "Чужой" })).json?.code,
  (await sup(V, "POST", `/tickets/${U.t}/status`, { status: "closed" })).json?.code,
];
let f = await download(V, att[0].id);
check("чужое обращение для постороннего не существует: чтение, ответ, статус, вложение → 404", codes4.join() === "not-found,not-found,not-found" && f.status === 404 && (await sup(V, "GET", `/tickets/${U.t}`)).status === 404, codes4.join() + " " + f.status);
r = await sup(V, "GET", "/tickets?scope=all");
check("scope=all для обычного пользователя — только свои обращения", r.status === 200 && r.json.staff === false && r.json.tickets.length === 0, r.text);
codes4 = [];
for (const tail of ["/tickets/abc", "/tickets/0", "/tickets/-1", "/tickets/99999999", "/files/abc", "/files/99999999"]) {
  r = await sup(U, "GET", tail);
  codes4.push(`${r.status}:${r.json?.code}`);
}
check("несуществующие обращение и вложение → 404", codes4.every(c => c === "404:not-found"), codes4.join());
r = await sup(U, "GET", `/tickets/${U.t}`);
check("посторонний ничего не изменил", r.json.status === "open" && r.json.messages.length === 1, r.text);
// вложения
f = await download(U, att[0].id);
check(
  "автор скачивает вложение байт в байт, с типом и запретом его угадывать",
  f.status === 200 && f.body.equals(png) && f.headers.get("content-type") === "image/png" && f.headers.get("content-disposition") === `attachment; filename*=UTF-8''${encodeURIComponent("снимокэкрана.png")}` && f.headers.get("x-content-type-options") === "nosniff" && f.headers.get("cache-control") === "private, max-age=3600",
  `${f.status} ${f.body.length} ${f.headers.get("content-type")} ${f.headers.get("content-disposition")} ${f.headers.get("cache-control")}`
);
f = await download(U, att[1].id);
check("текстовое вложение отдаётся как text/plain", f.status === 200 && f.body.equals(note) && f.headers.get("content-type") === "text/plain", `${f.status} ${f.headers.get("content-type")}`);
// сотрудник
r = await sup(H, "GET", "/tickets");
check("сотрудник: свой список пуст, признак staff", r.status === 200 && r.json.staff === true && r.json.tickets.length === 0, r.text);
r = await sup(H, "GET", "/tickets?scope=all");
row = byId(r.json, U.t);
check("сотрудник: scope=all показывает обращения всех с адресом автора", r.status === 200 && r.json.staff === true && row?.author === U.email && row.unread === true && row.messages === 1 && row.status === "open", r.text);
r = await sup(H, "GET", "/unread");
H.queue = r.json?.queue;
check("сотрудник: очередь открытых обращений", r.status === 200 && r.json.staff === true && r.json.count === 0 && Number.isInteger(H.queue) && H.queue >= 1, r.text);
r = await sup(H, "GET", `/tickets/${U.t}`);
check("сотрудник видит автора и сведения о браузере", r.status === 200 && r.json.staff === true && r.json.author === U.email && r.json.meta?.version === "1.4.2" && r.json.meta.os === "macOS 15" && r.json.messages.length === 1 && r.json.messages[0].files.length === 2, r.text);
check("прочитанное сотрудником обращение не отмечено непрочитанным", byId((await sup(H, "GET", "/tickets?scope=all")).json, U.t)?.unread === false);
f = await download(H, att[0].id);
check("сотрудник скачивает вложение", f.status === 200 && f.body.equals(png), String(f.status));
t0 = Date.now();
r = await sup(H, "POST", `/tickets/${U.t}/messages`, { text: "Здравствуйте! Очистите кеш и перезапустите браузер." });
check(
  "ответ сотрудника: статус answered, сообщение от поддержки",
  r.status === 200 && r.json.status === "answered" && r.json.staff === true && r.json.messages.length === 2 && r.json.messages[1].from === "staff" && r.json.messages[1].text === "Здравствуйте! Очистите кеш и перезапустите браузер." && r.json.messages[1].files.length === 0 && r.json.updatedAt > created.json.updatedAt,
  r.text
);
letter = await lastMail(U.email, { after: t0 - 5 });
check("пользователю ушло письмо с ответом поддержки", !!letter && letter.subject === "Ответ поддержки Tabora: Не открывается почта" && letter.text.includes("Очистите кеш и перезапустите браузер.") && letter.text.includes("Ответить можно в браузере (Настройки → Поддержка) или на сайте https://support."), JSON.stringify(letter));
r = await sup(U, "GET", "/unread");
check("у пользователя один непрочитанный ответ", r.status === 200 && r.json.count === 1 && r.json.staff === false, r.text);
row = byId((await sup(U, "GET", "/tickets")).json, U.t);
check("в списке пользователя обращение отвечено и не прочитано", row?.status === "answered" && row.unread === true && row.messages === 2, JSON.stringify(row));
check("отвеченное обращение ушло из очереди поддержки", (await sup(H, "GET", "/unread")).json.queue === H.queue - 1);
r = await sup(U, "GET", `/tickets/${U.t}`);
check("пользователь читает ответ: автора и сведений о браузере в ответе нет", r.status === 200 && r.json.messages.length === 2 && r.json.messages[1].from === "staff" && r.json.staff === false && !("author" in r.json) && !("meta" in r.json), r.text);
check("чтение снимает отметку непрочитанного", (await sup(U, "GET", "/unread")).json.count === 0 && byId((await sup(U, "GET", "/tickets")).json, U.t)?.unread === false);
// ответ пользователя
const webp = Buffer.concat([Buffer.from("RIFF"), crypto.randomBytes(300)]);
t0 = Date.now();
r = await sup(U, "POST", `/tickets/${U.t}/messages`, { text: "Не помогло, всё по-прежнему.", files: [{ name: "после.webp", type: "image/webp", data: webp.toString("base64") }] });
m0 = r.json?.messages?.[2];
check("ответ пользователя возвращает обращение в open", r.status === 200 && r.json.status === "open" && r.json.messages.length === 3 && m0?.from === "user" && m0.files.length === 1 && m0.files[0].name === "после.webp" && m0.files[0].type === "image/webp" && m0.files[0].size === webp.length, r.text);
letter = await lastMail(NOTIFY, { after: t0 - 5 });
check("поддержке ушло письмо об ответе пользователя", !!letter && letter.subject === `Ответ в обращении № ${U.t}: Не открывается почта` && letter.text.includes(U.email) && letter.text.includes("Не помогло, всё по-прежнему."), JSON.stringify(letter));
r = await sup(H, "GET", "/tickets?scope=all&status=open");
row = byId(r.json, U.t);
check("сотрудник видит новый ответ: обращение открыто и не прочитано", row?.status === "open" && row.unread === true && row.messages === 3 && (await sup(H, "GET", "/unread")).json.queue === H.queue, r.text);
check("свой ответ пользователю непрочитанным не считается", (await sup(U, "GET", "/unread")).json.count === 0);
f = await download(H, m0?.files?.[0]?.id);
check("вложение из ответа скачивается", f.status === 200 && f.body.equals(webp) && f.headers.get("content-type") === "image/webp", String(f.status));
// закрытие и повторное открытие
r = await sup(U, "POST", `/tickets/${U.t}/status`, { status: "closed" });
check("автор закрывает обращение", r.status === 200 && r.json.status === "closed" && r.json.messages.length === 3 && r.json.staff === false, r.text);
check("фильтр по статусу", (await sup(U, "GET", "/tickets?status=closed")).json.tickets.length === 1 && (await sup(U, "GET", "/tickets?status=open")).json.tickets.length === 0 && (await sup(H, "GET", "/unread")).json.queue === H.queue - 1);
r = await sup(U, "POST", `/tickets/${U.t}/status`, { status: "open" });
check("автор открывает обращение снова", r.status === 200 && r.json.status === "open", r.text);
r = await sup(H, "POST", `/tickets/${U.t}/status`, { status: "closed" });
check("сотрудник закрывает обращение", r.status === 200 && r.json.status === "closed" && r.json.staff === true && r.json.author === U.email, r.text);
r = await sup(U, "POST", `/tickets/${U.t}/messages`, { text: "Снова не работает." });
check("сообщение автора открывает закрытое обращение", r.status === 200 && r.json.status === "open" && r.json.messages.length === 4, r.text);
for (const [what, body] of [["статус answered", { status: "answered" }], ["пустой статус", { status: "" }], ["без статуса", {}]]) {
  r = await sup(U, "POST", `/tickets/${U.t}/status`, body);
  check(`смена статуса: ${what} → 400`, r.status === 400 && r.json.code === "support-invalid", r.text);
}
for (const [what, body] of [["пустой текст", { text: " " }], ["нет текста", {}], ["вложение неверного типа", { text: "Текст", files: [{ name: "a.html", type: "text/html", data: "eA==" }] }]]) {
  r = await sup(U, "POST", `/tickets/${U.t}/messages`, body);
  check(`сообщение: ${what} → 400`, r.status === 400 && r.json.code === "support-invalid", r.text);
}
check("неизвестные фильтры списка → 400", (await sup(U, "GET", "/tickets?status=nope")).json.code === "support-invalid" && (await sup(U, "GET", "/tickets?scope=nope")).json.code === "support-invalid");
// сотрудник в собственном обращении — обычный пользователь
r = await sup(H, "POST", "/tickets", { subject: "Проверка от сотрудника", text: "Пишу как пользователь" });
H.t = r.json?.id;
check("сотрудник создаёт своё обращение как пользователь", r.status === 200 && r.json.staff === false && !("author" in r.json) && r.json.messages[0].from === "user", r.text);
r = await sup(H, "POST", `/tickets/${H.t}/messages`, { text: "Дополнение" });
check("сообщение сотрудника в своём обращении — от пользователя, статус open", r.status === 200 && r.json.status === "open" && r.json.messages.length === 2 && r.json.messages[1].from === "user" && r.json.staff === false, r.text);
r = await sup(H, "GET", "/tickets");
check("своё обращение сотрудника в списке «мои», без адреса автора", r.json.tickets.length === 1 && r.json.tickets[0].id === H.t && !("author" in r.json.tickets[0]) && r.json.tickets[0].unread === false, r.text);
r = await sup(H, "GET", "/tickets?scope=all");
check(
  "общий список: обращения всех, недавно изменённые сверху",
  byId(r.json, H.t)?.author === H.email && byId(r.json, U.t)?.author === U.email && r.json.tickets.every((t, i, all) => i === 0 || all[i - 1].updatedAt >= t.updatedAt) && r.json.tickets[0].id === H.t,
  r.text
);
check("обращение сотрудника пользователю не видно", (await sup(U, "GET", `/tickets/${H.t}`)).status === 404);
// четыре вложения по 2 МиБ: запрос около 11 МиБ
const big = crypto.randomBytes(2 * 1024 * 1024);
r = await sup(V, "POST", "/tickets", { subject: "Большие вложения", text: "Четыре файла по 2 МиБ", files: [0, 1, 2, 3].map(i => ({ name: `f${i}.jpg`, type: "image/jpeg", data: big.toString("base64") })) });
V.t = r.json?.id;
check("четыре вложения по 2 МиБ принимаются", r.status === 200 && r.json.messages[0].files.length === 4 && r.json.messages[0].files.every(x => x.size === big.length && x.type === "image/jpeg"), r.text.slice(0, 300));
f = await download(V, r.json?.messages?.[0]?.files?.[3]?.id);
check("большое вложение скачивается байт в байт", f.status === 200 && f.body.equals(big), `${f.status} ${f.body.length}`);
// пределы: сообщений в час от пользователя и сообщений в обращении
codes = [];
for (let i = 0; i < 61; i++) {
  codes.push((await sup(V, "POST", `/tickets/${V.t}/messages`, { text: `Сообщение ${i + 1}` })).status);
}
r = await sup(V, "POST", `/tickets/${V.t}/messages`, { text: "Ещё одно" });
check("от пользователя не больше 60 сообщений в час", codes.slice(0, 60).every(c => c === 200) && codes[60] === 429 && r.status === 429 && r.json.code === "support-limit" && !!r.json.message, codes.slice(55).join() + " " + r.text);
codes = [];
for (let i = 0; i < 139; i++) {
  codes.push((await sup(H, "POST", `/tickets/${V.t}/messages`, { text: `Ответ ${i + 1}` })).status);
}
r = await sup(H, "POST", `/tickets/${V.t}/messages`, { text: "Двести первое" });
check("в обращении не больше 200 сообщений", codes.every(c => c === 200) && r.status === 429 && r.json.code === "support-limit" && /слишком много сообщений/.test(r.json.message), codes.filter(c => c !== 200).join() + " " + r.text);
r = await sup(V, "GET", `/tickets/${V.t}`);
check("переписка из 200 сообщений читается целиком и по порядку", r.status === 200 && r.json.messages.length === 200 && r.json.status === "answered" && r.json.messages[199].from === "staff" && r.json.messages.every((x, i, all) => i === 0 || all[i - 1].id < x.id), `${r.status} ${r.json?.messages?.length}`);
// одновременные создания не обходят предел незакрытых обращений (у V одно уже есть)
batches = await Promise.all(Array.from({ length: 8 }, (_, i) => sup(V, "POST", "/tickets", { subject: `Одновременное ${i + 1}`, text: "Текст" })));
check(
  "одновременные создания: незакрытых обращений всё равно не больше пяти",
  batches.filter(x => x.status === 200).length === 4 && batches.filter(x => x.status === 429 && x.json.code === "support-limit").length === 4 && (await sup(V, "GET", "/tickets")).json.tickets.length === 5,
  batches.map(x => x.status).join()
);
// пределы: незакрытые обращения и новые обращения за сутки (у U одно уже есть)
codes = [];
const mine = [U.t];
for (let i = 0; i < 4; i++) {
  r = await sup(U, "POST", "/tickets", { subject: `Обращение ${i + 2}`, text: "Текст" });
  codes.push(r.status);
  mine.push(r.json?.id);
}
r = await sup(U, "POST", "/tickets", { subject: "Шестое обращение", text: "Текст" });
check("не больше пяти незакрытых обращений", codes.join() === "200,200,200,200" && r.status === 429 && r.json.code === "support-limit" && /незакрытых/.test(r.json.message), codes.join() + " " + r.text);
for (const id of mine) {
  await sup(U, "POST", `/tickets/${id}/status`, { status: "closed" });
}
codes = [];
for (let i = 0; i < 5; i++) {
  r = await sup(U, "POST", "/tickets", { subject: `Обращение ${i + 6}`, text: "Текст" });
  codes.push(r.status);
  mine.push(r.json?.id);
}
await sup(U, "POST", `/tickets/${mine[mine.length - 1]}/status`, { status: "closed" });
r = await sup(U, "POST", "/tickets", { subject: "Одиннадцатое обращение", text: "Текст" });
check("не больше десяти новых обращений в сутки", codes.join() === "200,200,200,200,200" && r.status === 429 && r.json.code === "support-limit" && /сутки/.test(r.json.message), codes.join() + " " + r.text);
r = await sup(U, "GET", "/tickets");
check("в списке пользователя десять обращений, чужих нет", r.json.tickets.length === 10 && r.json.tickets.every(t => mine.includes(t.id)), String(r.json.tickets.length));
// тело больше 12 МиБ: как и у синхронизации, отказ может выглядеть обрывом соединения
tooBig = "";
try {
  r = await sup(H, "POST", "/tickets", { subject: "Слишком большой запрос", text: "x".repeat(13 * 1024 * 1024) });
  tooBig = `${r.status} ${r.json?.code}`;
} catch (e) {
  tooBig = "обрыв";
}
check(`запрос обращения больше 12 МиБ не принимается (${tooBig})`, (tooBig === "400 support-invalid" || tooBig === "обрыв") && (await sup(H, "GET", "/tickets")).json.tickets.length === 1, tooBig);

// ---- сайт поддержки: вход «только поддержка» ----
const W = { email: mail("w"), pw: hash("w-pass"), ip: "198.51.100.93" };
r = await call("POST", "/v1/account/register", { body: { email: W.email, loginHash: W.pw, kdf: 2, deviceId: device(83), deviceName: "Мак" }, ip: W.ip });
W.s = r.json?.session?.token;
r = await sup(W, "POST", "/tickets", { subject: "Вопрос с компьютера", text: "Написано в браузере" });
const wTicket = r.json?.id;
r = await call("POST", "/v1/account/login", { body: { email: W.email, loginHash: W.pw, deviceId: device(84), deviceName: "Сайт поддержки: Chrome, Mac", scope: "support" }, ip: W.ip });
const SD = { s: r.json?.session?.token, ip: W.ip };
check("вход с сайта поддержки: сессия выдана, доступа к почте в ответе нет", r.status === 200 && !!SD.s && r.json.mail === null && !!wTicket, r.text);
r = await call("POST", "/v1/account/login", { body: { email: W.email, loginHash: W.pw, deviceId: device(85), deviceName: "x", scope: "everything" }, ip: W.ip });
check("неизвестное назначение входа → 400", r.status === 400 && r.json.code === "bad-request", r.text);
r = await sup(SD, "GET", "/tickets");
let r2 = await sup(SD, "GET", `/tickets/${wTicket}`);
check("сессия сайта поддержки видит обращения своего аккаунта", r.status === 200 && r.json.tickets.length === 1 && r.json.tickets[0].id === wTicket && r2.status === 200 && r2.json.messages[0].text === "Написано в браузере", r.text);
r = await sup(SD, "POST", `/tickets/${wTicket}/messages`, { text: "Дополнение с сайта", files: [shot] });
r2 = await sup(SD, "POST", "/tickets", { subject: "Второе обращение с сайта", text: "Создано на сайте поддержки" });
const dTicket = r2.json?.id;
check("…пишет в них, прикладывает файлы и создаёт новые", r.status === 200 && r.json.messages.length === 2 && r.json.messages[1].files.length === 1 && r2.status === 200 && !!dTicket, r.text + r2.text);
r = await download(SD, (await sup(SD, "GET", `/tickets/${wTicket}`)).json.messages[1].files[0].id);
r2 = await sup(SD, "POST", `/tickets/${dTicket}/status`, { status: "closed" });
check("…скачивает вложения, закрывает обращения и читает счётчик", r.status === 200 && r.body.equals(png) && r2.status === 200 && r2.json.status === "closed" && (await sup(SD, "GET", "/unread")).status === 200, `${r.status} ${r2.text}`);
codes = [];
for (const [method, path, body] of [
  ["GET", "/v1/account/devices"], ["GET", "/v1/account/security"], ["GET", "/v1/mail/aliases"], ["GET", "/v1/mail/pgp"], ["POST", "/v1/mail/password", {}], ["GET", "/v1/sync?since=0"], ["GET", "/v1/mail/jmap/session"],
  ["POST", "/v1/mail/aliases", {}], ["POST", "/v1/account/password", { oldLoginHash: W.pw, newLoginHash: hash("w-other"), kdf: 2 }], ["POST", "/v1/pair/start", {}],
  ["POST", "/v1/sync", { gen: 1, keyId: "k", items: [] }], ["POST", "/v1/account/2fa/setup", { loginHash: W.pw }],
]) {
  r = await call(method, path, { token: SD.s, ip: SD.ip, body });
  codes.push(`${r.status} ${r.json?.code}`);
}
check("…а к устройствам, настройкам входа, почте, ключам и синхронизации не допускается: 403", codes.every(c => c === "403 session-scope"), codes.join(" | "));
r = await call("POST", "/v1/account/login", { body: { email: W.email, loginHash: W.pw, deviceId: device(83), deviceName: "Мак" }, ip: W.ip });
check("пароль аккаунта такой сессией не сменить: обычный вход по-прежнему проходит", r.status === 200 && !!r.json.session?.token, r.text);
r = await call("GET", "/v1/account/devices", { token: W.s, ip: W.ip });
check("вход сайта поддержки виден в списке устройств аккаунта", r.status === 200 && r.json.some(d => d.name === "Сайт поддержки: Chrome, Mac" && d.active), r.text);
r = await call("POST", "/v1/account/logout", { token: SD.s, ip: SD.ip });
r2 = await sup(SD, "GET", "/tickets");
check("сессия сайта поддержки завершается выходом", r.status === 200 && r2.status === 401 && r2.json.code === "session-expired", `${r.status} ${r2.text}`);

// ---- обращения без аккаунта ----
const G = { ip: "203.0.113.200", email: "guest.person@example.org" };
const guest = (tail, body, ip = G.ip) => call("POST", "/v1/support/guest" + tail, { body, ip });
const guestDownload = async (key, id) => {
  const res = await fetch(`${BASE}/v1/support/guest/file`, { method: "POST", headers: { "Content-Type": "application/json", "X-Forwarded-For": G.ip }, body: JSON.stringify({ key, id }) });
  return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
};
const queueBefore = (await sup(H, "GET", "/unread")).json.queue;
const notifyBefore = mailsTo(NOTIFY).length;
for (const [what, body] of [
  ["без адреса", { subject: "Тема обращения", text: "Текст" }],
  ["негодный адрес", { email: "not-an-address", subject: "Тема обращения", text: "Текст" }],
  ["адрес в домене Tabora", { email: mail("u"), subject: "Тема обращения", text: "Текст" }],
  ["короткая тема", { email: G.email, subject: "ab", text: "Текст" }],
  ["пустой текст", { email: G.email, subject: "Тема обращения", text: "   " }],
  ["слишком длинный текст", { email: G.email, subject: "Тема обращения", text: "я".repeat(8001) }],
]) {
  r = await guest("", body, "203.0.113.201");
  check(`обращение без аккаунта: ${what} → 400`, r.status === 400 && r.json.code === "support-invalid" && !!r.json.message, r.text);
}
check("отклонённые обращения без аккаунта писем не вызвали", mailsTo(G.email).length === 0 && mailsTo(mail("u")).every(m => !/подтвердите/.test(m.subject)));
r = await guest("", { email: " Guest.Person@Example.org ", subject: "Не могу войти в аккаунт", text: "СЕКРЕТНЫЙ ТЕКСТ АВТОРА: забыл пароль", lang: "en" });
let letters = mailsTo(G.email);
const link = (letters[0]?.text.match(/https:\/\/support\.[a-z.]+\/#t=(\d+\.[A-Za-z0-9_-]{32})/) || [])[1] || "";
const gId = Number(link.split(".")[0]);
check("обращение без аккаунта принято: ответ ничего не раскрывает, на адрес ушло одно письмо со ссылкой", r.status === 200 && JSON.stringify(r.json) === '{"sent":true}' && letters.length === 1 && gId > 0, r.text + JSON.stringify(letters).slice(0, 300));
check("письмо — на языке обращения и без текста автора", /^Tabora: confirm support request #\d+$/.test(letters[0]?.subject || "") && !/[а-яё]/i.test(letters[0]?.text || "x") && !/СЕКРЕТНЫЙ|Не могу войти/.test(JSON.stringify(letters[0] || {})), JSON.stringify(letters[0] || {}).slice(0, 400));
r = await sup(H, "GET", "/tickets?scope=all");
r2 = await sup(H, "GET", `/tickets/${gId}`);
check("до подтверждения адреса поддержка обращения не видит и письма о нём не получает", !byId(r.json, gId) && r2.status === 404 && (await sup(H, "GET", "/unread")).json.queue === queueBefore && mailsTo(NOTIFY).length === notifyBefore, r2.text);
codes = [];
for (const key of [`${gId}.${"A".repeat(32)}`, `${gId + 999}.${link.split(".")[1]}`, `${wTicket}.${link.split(".")[1]}`, "nope", `${gId}.short`, ""]) {
  codes.push((await guest("/open", { key })).status);
}
check("чужой, неверный и негодный ключ ссылки → 404, обращение аккаунта ключом не открыть", codes.every(c => c === 404), codes.join());
r = await guest("/messages", { key: link, text: "до подтверждения" });
check("до открытия ссылки в обращение не написать", r.status === 404, r.text);
r = await guest("/open", { key: link });
check("ссылка открывает обращение автору", r.status === 200 && r.json.id === gId && r.json.guest === true && r.json.email === G.email && r.json.staff === false && r.json.status === "open" && r.json.messages.length === 1 && r.json.messages[0].from === "user" && /СЕКРЕТНЫЙ ТЕКСТ/.test(r.json.messages[0].text) && !("author" in r.json) && !("meta" in r.json), r.text);
await new Promise(done => setTimeout(done, 400));
r = await sup(H, "GET", "/tickets?scope=all");
r2 = await sup(H, "GET", `/tickets/${gId}`);
let notes = mailsTo(NOTIFY).slice(notifyBefore);
check("после открытия ссылки обращение видно поддержке с пометкой «без аккаунта», ей ушло письмо", byId(r.json, gId)?.author === G.email && byId(r.json, gId)?.guest === true && byId(r.json, gId)?.unread === true && r2.status === 200 && r2.json.guest === true && r2.json.author === G.email && (await sup(H, "GET", "/unread")).json.queue === queueBefore + 1 && notes.length === 1 && /без аккаунта/.test(notes[0].text) && notes[0].subject === `Новое обращение № ${gId}: Не могу войти в аккаунт`, JSON.stringify(notes).slice(0, 300));
await guest("/open", { key: link });
check("повторное открытие ссылки второго письма поддержке не шлёт", mailsTo(NOTIFY).length === notifyBefore + 1);
check("посторонний аккаунт обращения без аккаунта не видит", (await sup(U, "GET", `/tickets/${gId}`)).status === 404 && !byId((await sup(U, "GET", "/tickets")).json, gId));
r = await sup(H, "POST", `/tickets/${gId}/messages`, { text: "Здравствуйте! Сбросьте пароль ключом восстановления.", files: [{ name: "how.txt", type: "text/plain", data: note.toString("base64") }] });
await new Promise(done => setTimeout(done, 400));
letters = mailsTo(G.email);
check("ответ поддержки уходит автору письмом на его языке, с текстом ответа и той же ссылкой", r.status === 200 && r.json.status === "answered" && letters.length === 2 && /^Reply from Tabora support: /.test(letters[1].subject) && letters[1].text.includes("Сбросьте пароль ключом восстановления") && letters[1].text.includes(`/#t=${link}`) && !/Настройки → Поддержка|Settings/.test(letters[1].text), JSON.stringify(letters[1] || {}).slice(0, 400));
r = await guest("/open", { key: link });
const gFile = r.json?.messages?.[1]?.files?.[0];
r2 = await guestDownload(link, gFile?.id);
const foreignFile = (await sup(W, "GET", `/tickets/${wTicket}`)).json.messages[1].files[0].id;
check("автор видит ответ и скачивает его вложение; чужое вложение по своей ссылке не получить", r.json.status === "answered" && r.json.messages[1].from === "staff" && gFile?.name === "how.txt" && r2.status === 200 && r2.body.equals(note) && /^attachment;/.test(r2.headers.get("content-disposition") || "") && (await guestDownload(link, foreignFile)).status === 404 && (await guestDownload(`${gId}.${"B".repeat(32)}`, gFile.id)).status === 404, `${r2.status}`);
r = await guest("/messages", { key: link, text: "Спасибо, получилось" });
await new Promise(done => setTimeout(done, 400)); // the letter to support goes out in the background
notes = mailsTo(NOTIFY).slice(notifyBefore);
check("ответ автора возвращает обращение в очередь, поддержке уходит письмо", r.status === 200 && r.json.status === "open" && r.json.messages.length === 3 && r.json.messages[2].from === "user" && notes.length === 2 && notes[1].subject === `Ответ в обращении № ${gId}: Не могу войти в аккаунт`, r.text);
r = await guest("/status", { key: link, status: "closed" });
r2 = await guest("/status", { key: link, status: "deleted" });
check("автор закрывает обращение; иной статус → 400", r.status === 200 && r.json.status === "closed" && r2.status === 400 && r2.json.code === "support-invalid", r.text + r2.text);
// пределы
codes = [];
for (let i = 0; i < 3; i++) {
  codes.push((await guest("", { email: `limit${i}@example.org`, subject: "Проверка предела", text: "Текст" })).status);
}
check("с одного сетевого адреса — не больше трёх обращений без аккаунта в час", codes.join() === "200,200,429", codes.join());
codes = [];
for (let i = 0; i < 3; i++) {
  codes.push((await guest("", { email: "flood@example.org", subject: "Проверка предела", text: "Текст" }, `203.0.113.${210 + i}`)).status);
}
check("на один адрес почты — не больше двух неподтверждённых обращений, с каких бы адресов их ни слали", codes.join() === "200,200,429" && mailsTo("flood@example.org").length === 2, codes.join());

// ---- удаление аккаунта ----
const X = { email: mail("x"), pw: hash("x-pass"), ip: "198.51.100.95" };
r = await call("POST", "/v1/account/register", { body: { email: X.email, loginHash: X.pw, kdf: 2, deviceId: device(87), deviceName: "Мак" }, ip: X.ip });
X.s = r.json?.session?.token;
r = await sup(X, "POST", "/tickets", { subject: "Обращение удаляемого аккаунта", text: "Будет удалено вместе с аккаунтом" });
const xTicket = r.json?.id;
r = await call("POST", "/v1/account/login", { body: { email: X.email, loginHash: X.pw, deviceId: device(88), deviceName: "Сайт поддержки", scope: "support" }, ip: X.ip });
const xDesk = r.json?.session?.token;
r = await call("POST", "/v1/account/login", { body: { email: X.email, loginHash: X.pw, deviceId: device(89), deviceName: "Второй" }, ip: X.ip });
const xOther = r.json?.session?.token;
check("аккаунт для удаления готов: две сессии, сессия сайта поддержки, обращение", !!X.s && !!xDesk && !!xOther && !!xTicket && (await sup(H, "GET", `/tickets/${xTicket}`)).status === 200);
r = await call("POST", "/v1/account/delete", { body: { loginHash: X.pw }, ip: X.ip });
r2 = await call("POST", "/v1/account/delete", { token: xDesk, body: { loginHash: X.pw }, ip: X.ip });
check("удаление без сессии → 401, сессией сайта поддержки → 403", r.status === 401 && r2.status === 403 && r2.json.code === "session-scope", `${r.status} ${r2.text}`);
r = await call("POST", "/v1/account/delete", { token: X.s, body: { loginHash: hash("not-the-password") }, ip: X.ip });
r2 = await call("POST", "/v1/account/delete", { token: X.s, body: {}, ip: X.ip });
check("удаление с неверным паролем и без пароля не проходит, аккаунт цел", r.status === 401 && r.json.code === "bad-credentials" && r2.status === 400 && (await call("GET", "/v1/account/devices", { token: X.s, ip: X.ip })).status === 200, `${r.text} ${r2.text}`);
r = await call("POST", "/v1/account/delete", { token: X.s, body: { loginHash: X.pw }, ip: X.ip });
check("удаление с верным паролем проходит сразу", r.status === 200 && JSON.stringify(r.json) === "{}", r.text);
codes = [];
for (const token of [X.s, xOther, xDesk]) {
  codes.push((await call("GET", "/v1/support/tickets", { token, ip: X.ip })).status);
}
r = await call("POST", "/v1/account/login", { body: { email: X.email, loginHash: X.pw, deviceId: device(87), deviceName: "Мак" }, ip: X.ip });
check("после удаления все сессии завершены и войти нельзя", codes.join() === "401,401,401" && r.status === 401 && r.json.code === "bad-credentials", codes.join() + " " + r.text);
r = await call("GET", `/v1/account/available?email=${encodeURIComponent(X.email)}`);
r2 = await call("POST", "/v1/account/register", { body: { email: X.email, loginHash: hash("someone-else"), kdf: 2, deviceId: device(90), deviceName: "Чужой" }, ip: "198.51.100.96" });
check("имя удалённого аккаунта больше не выдаётся", r.json.available === false && r2.status === 409, r.text + " " + r2.text);
r = await sup(H, "GET", `/tickets/${xTicket}`);
check("обращения удалённого аккаунта удалены вместе с ним", r.status === 404 && !byId((await sup(H, "GET", "/tickets?scope=all")).json, xTicket), r.text);

// со вторым шагом: нужен ещё и код
const Y = { email: mail("y"), pw: hash("y-pass"), ip: "198.51.100.97" };
r = await call("POST", "/v1/account/register", { body: { email: Y.email, loginHash: Y.pw, kdf: 2, deviceId: device(91), deviceName: "Мак" }, ip: Y.ip });
Y.s = r.json?.session?.token;
r = await call("POST", "/v1/account/2fa/setup", { token: Y.s, body: { loginHash: Y.pw }, ip: Y.ip });
Y.secret = r.json?.secret;
r = await call("POST", "/v1/account/2fa/enable", { token: Y.s, body: { code: totp(Y.secret) }, ip: Y.ip });
check("у второго аккаунта включён второй шаг", r.status === 200 && !!Y.secret, r.text);
r = await call("POST", "/v1/account/delete", { token: Y.s, body: { loginHash: Y.pw }, ip: Y.ip });
r2 = await call("POST", "/v1/account/delete", { token: Y.s, body: { loginHash: Y.pw, code: otherCode(totp(Y.secret, 1)) }, ip: Y.ip });
check("со вторым шагом удаление без кода и с неверным кодом не проходит", r.status === 401 && r.json.code === "2fa-required" && r2.status === 401 && r2.json.code === "bad-2fa" && (await call("GET", "/v1/account/devices", { token: Y.s, ip: Y.ip })).status === 200, r.text + " " + r2.text);
r = await call("POST", "/v1/account/delete", { token: Y.s, body: { loginHash: Y.pw, code: totp(Y.secret, 1) }, ip: Y.ip });
check("с паролем и верным кодом аккаунт удаляется", r.status === 200 && (await call("GET", "/v1/account/devices", { token: Y.s, ip: Y.ip })).status === 401, r.text);

// пределы регистрации с одного адреса и прочее
codes = [];
for (let i = 0; i < 7; i++) {
  codes.push((await call("POST", "/v1/account/register", { body: { email: mail("s" + i), loginHash: hash("s" + i), kdf: 2, deviceId: device(20 + i), deviceName: "s" }, ip: "192.0.2.77" })).status);
}
check("с одного адреса не больше шести аккаунтов в сутки", codes.join() === "200,200,200,200,200,200,429", codes.join());
r = await call("GET", "/v1/nope");
check("неизвестный адрес → 404 в общем формате", r.status === 404 && r.json?.code === "not-found", r.text);

console.log(`ИТОГ: ${passed} из ${passed + failed}`);
process.exit(failed ? 1 : 0);
