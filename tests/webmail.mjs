// Почта веб-версии: доступ к ящику по сессии аккаунта (src/webmail.rs). Сервер аккаунтов запущен с
// имитацией почтового сервера (tests/fake-jmap.mjs):
//   node tests/webmail.mjs <адрес сервера аккаунтов> <адрес имитации> <домен>
import crypto from "node:crypto";

const [base, fake, DOMAIN = "tabora.app"] = process.argv.slice(2);
let passed = 0;
let failed = 0;
const check = (name, ok, detail = "") => {
  if (ok) {
    passed++;
    console.log(`OK   ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}${detail ? `\n     ${String(detail).slice(0, 400)}` : ""}`);
  }
};
const hash = s => crypto.createHash("sha256").update(s).digest("hex");
const device = n => crypto.createHash("sha256").update("webmail-device" + n).digest("hex").slice(0, 24);
async function call(method, path, { token, body, raw, type, ip = "203.0.113.50" } = {}) {
  const headers = { "X-Forwarded-For": ip };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined && !raw) headers["Content-Type"] = "application/json";
  if (type) headers["Content-Type"] = type;
  const res = await fetch(base + path, { method, headers, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined) });
  const buf = Buffer.from(await res.arrayBuffer());
  let json = null;
  try {
    json = JSON.parse(buf.toString());
  } catch (e) {}
  return { status: res.status, json, text: buf.toString().slice(0, 300), buf, headers: res.headers };
}
const fakeLog = async () => (await fetch(`${fake}/__log`)).json();
const stamp = Date.now().toString(36);
const A = { email: `wm${stamp}a@${DOMAIN}`, pw: hash("a") };
const B = { email: `wm${stamp}b@${DOMAIN}`, pw: hash("b") };
const MAIL = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"];

// вход веб-версии: доступ по сессии, пароль приложения не выдаётся
let r = await call("POST", "/v1/account/register", { body: { email: A.email, loginHash: A.pw, kdf: 2, deviceId: device(1), deviceName: "Веб-версия: Chrome", mailAccess: "session" } });
A.web = r.json?.session?.token;
check("регистрация из веб-версии: почта по сессии, пароля приложения в ответе нет", r.status === 200 && r.json.mail?.session === true && r.json.mail.address === A.email && !("password" in r.json.mail), r.text);
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw, deviceId: device(2), deviceName: "Мак" } });
A.desk = r.json?.session?.token;
check("вход браузера по-прежнему получает пароль приложения", r.status === 200 && typeof r.json.mail?.password === "string" && r.json.mail.login === A.email, r.text);
let st = await fakeLog();
check("на почтовом сервере у ящика один пароль приложения (у браузера), веб-сессия своего не заняла", st.accounts.find(a => a.name === A.email.split("@")[0])?.appPasswords === 1, JSON.stringify(st.accounts));
// то же устройство переходит с пароля приложения на сессию: пароль приложения отзывается
r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw, deviceId: device(2), deviceName: "Мак", mailAccess: "session" } });
st = await fakeLog();
check("устройство, перешедшее на доступ по сессии, свой пароль приложения теряет", r.status === 200 && r.json.mail?.session === true && st.accounts.find(a => a.name === A.email.split("@")[0])?.appPasswords === 0, JSON.stringify(st.accounts));
r = await call("POST", "/v1/account/register", { body: { email: B.email, loginHash: B.pw, kdf: 2, deviceId: device(3), deviceName: "Веб-версия", mailAccess: "session" } });
B.web = r.json?.session?.token;

// описание ящика
r = await call("GET", "/v1/mail/jmap/session");
check("почта без сессии → 401", r.status === 401 && r.json.code === "session-expired", r.text);
r = await call("GET", "/v1/mail/jmap/session", { token: A.web });
const accA = r.json?.primaryAccounts?.["urn:ietf:params:jmap:mail"];
check("описание ящика отдаётся владельцу", r.status === 200 && r.json.username === A.email && !!accA && r.headers.get("cache-control") === "private, no-store", r.text);
r = await call("GET", "/v1/mail/jmap/session", { token: B.web });
const accB = r.json?.primaryAccounts?.["urn:ietf:params:jmap:mail"];
check("у другого аккаунта — свой ящик", r.status === 200 && r.json.username === B.email && accB !== accA, r.text);

// почтовые вызовы
r = await call("POST", "/v1/mail/jmap", { token: A.web, body: { using: MAIL, methodCalls: [["Mailbox/get", { accountId: accA, ids: null }, "c0"], ["Email/query", { accountId: accA }, "c1"], ["Email/get", { accountId: accA, ids: ["e1"] }, "c2"]] } });
check("почтовые методы пересылаются и возвращают ответ почтового сервера", r.status === 200 && r.json.methodResponses.length === 3 && r.json.methodResponses[0][0] === "Mailbox/get" && r.json.methodResponses[2][1].list[0].subject === `письмо для ${A.email.split("@")[0]}` && r.json.methodResponses[1][2] === "c1", r.text);
st = await fakeLog();
const last = st.log[st.log.length - 1];
check("почтовый сервер видит запрос от владельца ящика с основным паролем, а не от службы", last.as === `primary:${A.email.split("@")[0]}` && JSON.stringify(last.calls) === JSON.stringify(["Mailbox/get", "Email/query", "Email/get"]), JSON.stringify(last));
const before = st.log.length;
for (const [name, body] of [
  ["управление паролями приложений", { using: MAIL, methodCalls: [["x:AppPassword/set", { create: { p: {} } }, "c0"]] }],
  ["управление учётками", { using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], methodCalls: [["x:Account/get", {}, "c0"]] }],
  ["чужая возможность рядом с почтовой", { using: [...MAIL, "urn:ietf:params:jmap:sieve"], methodCalls: [["Email/get", {}, "c0"]] }],
  ["запрещённый метод после разрешённого", { using: MAIL, methodCalls: [["Email/get", {}, "c0"], ["SieveScript/set", {}, "c1"]] }],
  ["фильтры почты", { using: MAIL, methodCalls: [["VacationResponse/set", {}, "c0"]] }],
]) {
  r = await call("POST", "/v1/mail/jmap", { token: A.web, body });
  check(`отказ: ${name} → 403`, r.status === 403 && r.json.code === "mail-forbidden", r.text);
}
r = await call("POST", "/v1/mail/jmap", { token: A.web, raw: "не json", type: "application/json" });
check("не JSON → 400", r.status === 400, r.text);
r = await call("POST", "/v1/mail/jmap", { body: { using: MAIL, methodCalls: [["Email/get", {}, "c0"]] } });
check("почтовый вызов без сессии → 401", r.status === 401, r.text);
st = await fakeLog();
check("ни один отклонённый запрос до почтового сервера не дошёл", st.log.length === before, `было ${before}, стало ${st.log.length}`);

// блоки: загрузка и скачивание
const data = crypto.randomBytes(300_000);
r = await call("POST", `/v1/mail/jmap/upload/${accA}`, { token: A.web, raw: data, type: "application/pdf" });
const blobId = r.json?.blobId;
check("файл загружается: номер блока, тип и размер от почтового сервера", r.status === 200 && !!blobId && r.json.size === data.length && r.json.type === "application/pdf", r.text);
r = await call("GET", `/v1/mail/jmap/download/${accA}/${blobId}/${encodeURIComponent("отчёт 1.pdf")}?accept=application/pdf`, { token: A.web });
check("файл скачивается целым, как вложение и без угадывания типа", r.status === 200 && r.buf.equals(data) && r.headers.get("content-type") === "application/pdf" && r.headers.get("content-disposition") === "attachment" && r.headers.get("x-content-type-options") === "nosniff", `${r.status} ${r.buf.length}`);
r = await call("GET", `/v1/mail/jmap/download/${accB}/${blobId}/x.pdf`, { token: B.web });
check("чужой блок другому аккаунту не отдаётся", r.status === 404, r.text);
r = await call("GET", `/v1/mail/jmap/download/${accA}/${blobId}/x.pdf`);
check("скачивание без сессии → 401", r.status === 401, r.text);
r = await call("GET", `/v1/mail/jmap/download/${accA}/${encodeURIComponent("../session")}/x`, { token: A.web });
check("путь с выходом из каталога отклоняется", r.status === 400, r.text);
const big = Buffer.alloc(53 * 1024 * 1024);
r = await call("POST", `/v1/mail/jmap/upload/${accA}`, { token: A.web, raw: big, type: "application/octet-stream" }).catch(e => ({ status: 0, text: String(e) }));
check("файл больше предела не принимается", r.status === 413 || r.status === 400 || r.status === 0, `${r.status} ${r.text}`);

// выход и отзыв сессии закрывают почту
r = await call("POST", "/v1/account/logout", { token: B.web, body: {} });
r = await call("GET", "/v1/mail/jmap/session", { token: B.web });
check("после выхода сессия почту не открывает", r.status === 401, r.text);
r = await call("POST", `/v1/account/devices/${device(1)}/revoke`, { token: A.desk, body: { loginHash: A.pw } });
r = await call("POST", "/v1/mail/jmap", { token: A.web, body: { using: MAIL, methodCalls: [["Mailbox/get", {}, "c0"]] } });
check("завершённый с другого устройства сеанс теряет почту сразу", r.status === 401 && r.json.code === "session-expired", r.text);

console.log(`\nИТОГ: ${passed} из ${passed + failed}`);
process.exit(failed ? 1 : 0);
