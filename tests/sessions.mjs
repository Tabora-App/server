// Сессия не завершается сама: войдя один раз, человек остаётся в аккаунте, пока не выйдет.
// Сервер на временной базе; вторая часть запускается после перезапуска сервера (при старте он
// заново применяет схему и делает уборку просроченного — сессии это пережить должны).
//   node tests/sessions.mjs <адрес сервера> <домен> <порт базы> <файл состояния> [after]
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const [base, DOMAIN = "tabora.app", PGPORT, STATE, PHASE = "before"] = process.argv.slice(2);
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
const sql = q => execFileSync("psql", ["-h", "127.0.0.1", "-p", PGPORT, "-U", "tabora", "-d", "tabora", "-At", "-c", q], { encoding: "utf8" }).trim();
async function call(method, path, { token, body } = {}) {
  const headers = { "X-Forwarded-For": "203.0.113.90" };
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
const alive = async token => (await call("GET", "/v1/account/devices", { token })).status;

if (PHASE === "before") {
  const stamp = Date.now().toString(36);
  const device = n => hash(`session-device-${stamp}-${n}`).slice(0, 24);
  const A = { email: `sess${stamp}@${DOMAIN}`, pw: hash("a-password"), pw2: hash("a-new-password") };
  let r = await call("POST", "/v1/account/register", { body: { email: A.email, loginHash: A.pw, kdf: 2, deviceId: device(1), deviceName: "Телефон" } });
  check("при входе сервер не называет срок сессии", r.status === 200 && r.json.session.expiresAt === null, r.text);
  A.t1 = r.json.session.token;
  r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw, deviceId: device(2), deviceName: "Ноутбук" } });
  A.t2 = r.json.session.token;
  r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw, deviceId: device(3), deviceName: "Планшет" } });
  A.t3 = r.json.session.token;
  r = await call("POST", "/v1/account/login", { body: { email: A.email, loginHash: A.pw, deviceId: device(4), deviceName: "Рабочий компьютер" } });
  A.t4 = r.json.session.token;
  check("четыре устройства вошли", [A.t1, A.t2, A.t3, A.t4].every(t => /^tbs_/.test(t || "")), r.text);

  // сессии как будто выданы 400 дней назад по прежнему правилу (на 180 дней) и с тех пор не использовались
  const old = 400 * 86_400_000;
  sql(`update sessions set created_at = created_at - ${old}, last_seen = last_seen - ${old}, expires_at = created_at - ${old} + ${180 * 86_400_000}`);
  check("сессия, выданная 400 дней назад и «просроченная» по прежнему правилу, действует", (await alive(A.t1)) === 200 && (await alive(A.t2)) === 200);
  r = await call("GET", "/v1/account/devices", { token: A.t1 });
  check("в списке устройств все четыре числятся вошедшими", r.status === 200 && r.json.length === 4 && r.json.every(d => d.active), r.text);

  // завершают сессию только действия человека
  r = await call("POST", "/v1/account/logout", { token: A.t2, body: {} });
  check("выход завершает сессию этого устройства", r.status === 200 && (await alive(A.t2)) === 401, r.text);
  check("выход на одном устройстве не трогает остальные", (await alive(A.t1)) === 200 && (await alive(A.t3)) === 200 && (await alive(A.t4)) === 200);
  r = await call("POST", `/v1/account/devices/${device(3)}/revoke`, { token: A.t1, body: { loginHash: A.pw } });
  check("отзыв устройства из списка завершает его сессию", r.status === 200 && (await alive(A.t3)) === 401, r.text);
  check("отзыв одного устройства не трогает остальные", (await alive(A.t1)) === 200 && (await alive(A.t4)) === 200);
  fs.writeFileSync(STATE, JSON.stringify(A));
} else {
  const A = JSON.parse(fs.readFileSync(STATE, "utf8"));
  check("после перезапуска сервера (схема и уборка просроченного) обе сессии действуют", (await alive(A.t1)) === 200 && (await alive(A.t4)) === 200);
  check("завершённые выходом и отзывом сессии после перезапуска не ожили", (await alive(A.t2)) === 401 && (await alive(A.t3)) === 401);
  const left = sql(`select count(*) from sessions s join users u on u.id = s.user_id where u.email = '${A.email}'`);
  check("в базе у аккаунта остались ровно две сессии", left === "2", left);
  fs.unlinkSync(STATE);
}
console.log(`\nитог: ${passed} из ${passed + failed}`);
process.exit(failed ? 1 : 0);
