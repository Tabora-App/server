// Имитация почтового сервера для проверок почты веб-версии (tests/webmail.mjs): отвечает на служебные
// вызовы сервера аккаунтов (домены, учётки, пароли приложений) и на почтовые вызовы владельца ящика,
// хранит загруженные блоки и записывает, что и от чьего имени у неё спросили.
//   node tests/fake-jmap.mjs <порт> <домен> <служебный ключ>
import { createServer } from "node:http";

const [port, domain, apiKey] = process.argv.slice(2);
const accounts = new Map(); // id → { name, password, appPasswords: Map(id → secret) }
const blobs = new Map();
const log = [];
let seq = 0;

function who(req) {
  const auth = req.headers.authorization || "";
  if (auth === `Bearer ${apiKey}`) {
    return { service: true };
  }
  if (auth.startsWith("Basic ")) {
    const [login, password] = Buffer.from(auth.slice(6), "base64").toString().split(/:(.*)/s);
    for (const [id, a] of accounts) {
      if (`${a.name}@${domain}` === login && (a.password === password || [...a.appPasswords.values()].includes(password))) {
        return { id, primary: a.password === password };
      }
    }
  }
  return null;
}

function method(name, args, user) {
  if (name.startsWith("x:") && !user.service && !name.startsWith("x:AppPassword/")) {
    return ["error", { type: "forbidden" }];
  }
  if (name === "x:Domain/query") return [name, { ids: ["d1"] }];
  if (name === "x:Domain/get") return [name, { list: [{ id: "d1", name: domain }] }];
  if (name === "x:Account/set") {
    const created = {};
    for (const [k, v] of Object.entries(args.create || {})) {
      const id = `acc${++seq}`;
      accounts.set(id, { name: v.name, password: v.credentials?.["0"]?.secret || "", appPasswords: new Map() });
      created[k] = { id };
    }
    for (const [id, patch] of Object.entries(args.update || {})) {
      const a = accounts.get(id);
      if (a && patch["credentials/0"]) a.password = patch["credentials/0"].secret;
    }
    for (const id of args.destroy || []) accounts.delete(id);
    return [name, { created, updated: Object.fromEntries(Object.keys(args.update || {}).map(k => [k, null])), destroyed: args.destroy || [] }];
  }
  if (name === "x:AppPassword/set") {
    const a = accounts.get(user.id);
    const created = {};
    for (const k of Object.keys(args.create || {})) {
      const id = `ap${++seq}`;
      a.appPasswords.set(id, `app_${id}_secret`);
      created[k] = { id, secret: `app_${id}_secret` };
    }
    for (const id of args.destroy || []) a.appPasswords.delete(id);
    return [name, { created, destroyed: args.destroy || [] }];
  }
  if (name === "x:AppPassword/get") return [name, { list: [...accounts.get(user.id).appPasswords.keys()].map(id => ({ id })) }];
  if (name === "Mailbox/get") return [name, { accountId: user.id, state: "s1", list: [{ id: "mb1", name: "Inbox", role: "inbox", totalEmails: 1, unreadEmails: 1 }] }];
  if (name === "Email/query") return [name, { accountId: user.id, ids: ["e1"], total: 1, position: 0 }];
  if (name === "Email/get") return [name, { accountId: user.id, state: "s1", list: [{ id: "e1", subject: `письмо для ${accounts.get(user.id).name}` }] }];
  return [name, { accountId: user.id }];
}

createServer((req, res) => {
  const chunks = [];
  req.on("data", c => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/__log") {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ log, accounts: [...accounts].map(([id, a]) => ({ id, name: a.name, appPasswords: a.appPasswords.size })) }));
      return;
    }
    const user = who(req);
    const entry = { method: req.method, path: url.pathname + url.search, as: user ? (user.service ? "service" : user.primary ? `primary:${accounts.get(user.id).name}` : `app:${accounts.get(user.id).name}`) : "nobody", type: req.headers["content-type"] || "", size: body.length };
    log.push(entry);
    if (!user) {
      res.writeHead(401, { "WWW-Authenticate": 'Basic realm="fake"' }).end();
      return;
    }
    if (req.method === "GET" && url.pathname === "/jmap/session") {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ username: `${accounts.get(user.id)?.name}@${domain}`, primaryAccounts: { "urn:ietf:params:jmap:mail": user.id }, accounts: { [user.id]: {} }, capabilities: { "urn:ietf:params:jmap:core": { maxSizeUpload: 50000000 } }, apiUrl: `https://mx.${domain}/jmap/` }));
      return;
    }
    if (req.method === "POST" && (url.pathname === "/jmap" || url.pathname === "/jmap/")) {
      const json = JSON.parse(body.toString());
      entry.calls = json.methodCalls.map(c => c[0]);
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ methodResponses: json.methodCalls.map(([name, args, tag]) => [...method(name, args, user), tag]) }));
      return;
    }
    let m = /^\/jmap\/upload\/([^/]+)\/$/.exec(url.pathname);
    if (req.method === "POST" && m) {
      const id = `blob${++seq}`;
      blobs.set(id, { body, type: req.headers["content-type"], owner: user.id });
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ accountId: decodeURIComponent(m[1]), blobId: id, type: req.headers["content-type"], size: body.length }));
      return;
    }
    m = /^\/jmap\/download\/([^/]+)\/([^/]+)\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      const blob = blobs.get(decodeURIComponent(m[2]));
      if (!blob || blob.owner !== user.id) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": url.searchParams.get("accept") || "application/octet-stream", "X-Name": encodeURIComponent(decodeURIComponent(m[3])) }).end(blob.body);
      return;
    }
    res.writeHead(404).end();
  });
}).listen(Number(port), "127.0.0.1", () => console.log(`имитация почтового сервера: 127.0.0.1:${port}`));
