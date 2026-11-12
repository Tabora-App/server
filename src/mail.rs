/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Почтовый сервер Stalwart: ящики, пароли приложений и алиасы через его объекты JMAP.
//!
//! Ящик создаётся служебным ключом (право только на учётки пользователей). Основной пароль
//! ящика выводится из секрета сервера и номера пользователя, нигде не хранится и клиентам не
//! отдаётся: им сервер входит в ящик с 127.0.0.1, чтобы выдать или отозвать пароль приложения.
//! Каждое устройство получает свой пароль приложения: он подходит к IMAP и SMTP, отзывается
//! при выходе с устройства и ничего не говорит о пароле аккаунта.
//!
//! Письма от сервера (код подтверждения резервного адреса, код сброса пароля, уведомления о
//! смене настроек входа) уходят от служебного ящика `no-reply@домен` обычными вызовами JMAP
//! по локальному адресу: почтовому серверу не нужны ни открытая пересылка, ни особые правила.

use crate::util::{hmac256, now_ms, random};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::OnceCell;

const ADMIN_USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];
const MAIL_USING: [&str; 3] = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"];
/// Имя служебного ящика (в списке запрещённых для регистрации) и метка, из которой выводится его пароль.
const SYSTEM_LOCAL: &str = "no-reply";
const SYSTEM_ID: &str = "system/no-reply";
const SYSTEM_QUOTA: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum MailError {
    /// адрес уже занят ящиком или алиасом
    Taken,
    /// почтовый сервер не принял учётные данные
    Unauthorized,
    /// почтовый сервер не отвечает
    Unavailable(String),
    /// почтовый сервер отклонил запрос
    Rejected(String),
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailError::Taken => write!(f, "адрес занят"),
            MailError::Unauthorized => write!(f, "вход отклонён"),
            MailError::Unavailable(e) => write!(f, "недоступен: {e}"),
            MailError::Rejected(e) => write!(f, "отклонено: {e}"),
        }
    }
}

enum Auth<'a> {
    Service,
    User { login: &'a str, password: &'a str },
}

/// Служебный ящик глазами JMAP: номер учётки, личность отправителя и папка черновиков.
struct Sender {
    account: String,
    identity: String,
    drafts: String,
}

pub struct Stalwart {
    base: String,
    api_key: String,
    domain: String,
    mail_key: [u8; 32],
    quota_bytes: u64,
    http: reqwest::Client,
    domain_id: OnceCell<String>,
    sender: OnceCell<Sender>,
    /// Только для проверок: письма не отправляются, а складываются файлами в этот каталог.
    outbox: Option<PathBuf>,
}

pub struct AppPassword {
    pub id: String,
    pub secret: String,
}

impl Stalwart {
    pub fn new(base: &str, api_key: &str, domain: &str, mail_key: [u8; 32], quota_bytes: u64, outbox: Option<PathBuf>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("клиент HTTP");
        Self { base: base.trim_end_matches('/').to_string(), api_key: api_key.to_string(), domain: domain.to_string(), mail_key, quota_bytes, http, domain_id: OnceCell::new(), sender: OnceCell::new(), outbox }
    }

    /// Без адреса или ключа почтовая часть выключена: аккаунты работают, ящики не создаются.
    pub fn enabled(&self) -> bool {
        !self.base.is_empty() && !self.api_key.is_empty()
    }

    fn primary_password(&self, public_id: &str) -> String {
        hex::encode(hmac256(&self.mail_key, &[public_id.as_bytes()]))
    }

    fn loopback() -> Value {
        json!({ "127.0.0.1": true, "::1": true })
    }

    /// Несколько вызовов одним запросом; ответы — по порядку вызовов. Отказ любого вызова
    /// (ошибка метода, notCreated, notUpdated, notDestroyed) — ошибка всего запроса.
    async fn calls(&self, auth: Auth<'_>, using: &[&str], calls: Value) -> Result<Vec<Value>, MailError> {
        let expected = calls.as_array().map(Vec::len).unwrap_or(0);
        let body = json!({ "using": using, "methodCalls": calls });
        let req = self.http.post(format!("{}/jmap", self.base)).json(&body);
        let req = match auth {
            Auth::Service => req.bearer_auth(&self.api_key),
            Auth::User { login, password } => req.basic_auth(login, Some(password)),
        };
        let res = req.send().await.map_err(|e| MailError::Unavailable(e.to_string()))?;
        let status = res.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(MailError::Unauthorized);
        }
        if !status.is_success() {
            return Err(MailError::Unavailable(format!("HTTP {}", status.as_u16())));
        }
        let v: Value = res.json().await.map_err(|e| MailError::Unavailable(e.to_string()))?;
        let list = v.get("methodResponses").and_then(Value::as_array).ok_or_else(|| MailError::Rejected("пустой ответ".into()))?;
        let mut out = Vec::with_capacity(expected);
        for item in list {
            let name = item.get(0).and_then(Value::as_str).unwrap_or("");
            let resp = item.get(1).cloned().unwrap_or(Value::Null);
            if name == "error" {
                return Err(MailError::Rejected(resp.to_string()));
            }
            for key in ["notCreated", "notUpdated", "notDestroyed"] {
                if let Some(obj) = resp.get(key).and_then(Value::as_object) {
                    if let Some(err) = obj.values().next() {
                        if err.get("type").and_then(Value::as_str) == Some("primaryKeyViolation") {
                            return Err(MailError::Taken);
                        }
                        return Err(MailError::Rejected(err.to_string()));
                    }
                }
            }
            out.push(resp);
        }
        if out.len() < expected {
            return Err(MailError::Rejected("почтовый сервер ответил не на все вызовы".into()));
        }
        Ok(out)
    }

    async fn jmap(&self, auth: Auth<'_>, method: &str, args: Value) -> Result<Value, MailError> {
        Ok(self.calls(auth, &ADMIN_USING, json!([[method, args, "c0"]])).await?.remove(0))
    }

    async fn domain_id(&self) -> Result<&str, MailError> {
        self.domain_id
            .get_or_try_init(|| async {
                let ids = self.jmap(Auth::Service, "x:Domain/query", json!({})).await?;
                let list = self.jmap(Auth::Service, "x:Domain/get", json!({ "ids": ids.get("ids").cloned().unwrap_or(Value::Null) })).await?;
                list.get("list")
                    .and_then(Value::as_array)
                    .and_then(|l| l.iter().find(|d| d.get("name").and_then(Value::as_str) == Some(self.domain.as_str())))
                    .and_then(|d| d.get("id").and_then(Value::as_str))
                    .map(str::to_string)
                    .ok_or_else(|| MailError::Rejected(format!("домена {} нет на почтовом сервере", self.domain)))
            })
            .await
            .map(String::as_str)
    }

    /// Новый ящик `local@домен`. Возвращает его номер на почтовом сервере.
    pub async fn create_account(&self, local: &str, public_id: &str) -> Result<String, MailError> {
        let domain_id = self.domain_id().await?;
        let args = json!({ "create": { "u": {
            "@type": "User",
            "name": local,
            "domainId": domain_id,
            "roles": { "@type": "User" },
            "description": "Tabora: ящик пользователя",
            "credentials": { "0": { "@type": "Password", "secret": self.primary_password(public_id), "allowedIps": Self::loopback() } },
            "quotas": { "maxDiskQuota": self.quota_bytes },
        } } });
        let r = self.jmap(Auth::Service, "x:Account/set", args).await?;
        r.pointer("/created/u/id").and_then(Value::as_str).map(str::to_string).ok_or_else(|| MailError::Rejected("нет номера созданного ящика".into()))
    }

    pub async fn destroy_account(&self, mail_id: &str) -> Result<(), MailError> {
        self.jmap(Auth::Service, "x:Account/set", json!({ "destroy": [mail_id] })).await.map(|_| ())
    }

    /// Основной пароль выставляется заново (после смены секрета сервера прежний не подойдёт).
    async fn reset_primary(&self, mail_id: &str, public_id: &str) -> Result<(), MailError> {
        let patch = json!({ "update": { mail_id: {
            "credentials/0": { "@type": "Password", "secret": self.primary_password(public_id), "allowedIps": Self::loopback() },
        } } });
        self.jmap(Auth::Service, "x:Account/set", patch).await.map(|_| ())
    }

    /// Запрос от имени владельца ящика; если основной пароль не подошёл, он выставляется заново.
    async fn as_user(&self, local: &str, public_id: &str, mail_id: &str, method: &str, args: Value) -> Result<Value, MailError> {
        let login = format!("{}@{}", local, self.domain);
        let password = self.primary_password(public_id);
        match self.jmap(Auth::User { login: &login, password: &password }, method, args.clone()).await {
            Err(MailError::Unauthorized) => {
                self.reset_primary(mail_id, public_id).await?;
                self.jmap(Auth::User { login: &login, password: &password }, method, args).await
            }
            other => other,
        }
    }

    /// Произвольный запрос HTTP к почтовому серверу от имени владельца ящика (почта веб-версии,
    /// см. webmail.rs): path — путь с параметрами. Если основной пароль не подошёл, он
    /// выставляется заново и запрос повторяется.
    pub async fn user_http(&self, local: &str, public_id: &str, mail_id: &str, method: reqwest::Method, path: &str, content_type: Option<&str>, body: Option<axum::body::Bytes>) -> Result<reqwest::Response, MailError> {
        let login = format!("{}@{}", local, self.domain);
        let password = self.primary_password(public_id);
        for attempt in 0..2 {
            let mut req = self.http.request(method.clone(), format!("{}{}", self.base, path)).basic_auth(&login, Some(&password));
            if let Some(ct) = content_type {
                req = req.header(reqwest::header::CONTENT_TYPE, ct);
            }
            if let Some(b) = &body {
                req = req.body(b.clone());
            }
            let res = req.send().await.map_err(|e| MailError::Unavailable(e.to_string()))?;
            if res.status().as_u16() == 401 && attempt == 0 {
                self.reset_primary(mail_id, public_id).await?;
                continue;
            }
            return Ok(res);
        }
        Err(MailError::Unauthorized)
    }

    /// Пароль приложения для одного устройства. Секрет почтовый сервер показывает один раз.
    pub async fn create_app_password(&self, local: &str, public_id: &str, mail_id: &str, description: &str) -> Result<AppPassword, MailError> {
        let args = json!({ "create": { "p": { "description": description, "permissions": { "@type": "Inherit" } } } });
        let r = self.as_user(local, public_id, mail_id, "x:AppPassword/set", args).await?;
        let id = r.pointer("/created/p/id").and_then(Value::as_str);
        let secret = r.pointer("/created/p/secret").and_then(Value::as_str);
        match (id, secret) {
            (Some(id), Some(secret)) => Ok(AppPassword { id: id.to_string(), secret: secret.to_string() }),
            _ => Err(MailError::Rejected("почтовый сервер не вернул пароль приложения".into())),
        }
    }

    pub async fn destroy_app_password(&self, local: &str, public_id: &str, mail_id: &str, cred_id: &str) -> Result<(), MailError> {
        match self.as_user(local, public_id, mail_id, "x:AppPassword/set", json!({ "destroy": [cred_id] })).await {
            // уже отозван — это и требовалось
            Ok(_) | Err(MailError::Rejected(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Отзыв всех паролей приложений ящика (сброс пароля аккаунта: все устройства выходят).
    pub async fn destroy_all_app_passwords(&self, local: &str, public_id: &str, mail_id: &str) -> Result<usize, MailError> {
        let list = self.as_user(local, public_id, mail_id, "x:AppPassword/get", json!({ "ids": null })).await?;
        let ids: Vec<Value> = list.get("list").and_then(Value::as_array).map(|l| l.iter().filter_map(|x| x.get("id").cloned()).collect()).unwrap_or_default();
        if ids.is_empty() {
            return Ok(0);
        }
        let n = ids.len();
        self.as_user(local, public_id, mail_id, "x:AppPassword/set", json!({ "destroy": ids })).await?;
        Ok(n)
    }

    /// Алиасы ящика целиком: (имя до @, включён ли). Выключенный алиас письма не принимает.
    pub async fn set_aliases(&self, mail_id: &str, aliases: &[(String, bool)]) -> Result<(), MailError> {
        let domain_id = self.domain_id().await?;
        let mut map = serde_json::Map::new();
        for (i, (local, enabled)) in aliases.iter().enumerate() {
            map.insert(i.to_string(), json!({ "name": local, "domainId": domain_id, "enable": enabled }));
        }
        self.jmap(Auth::Service, "x:Account/set", json!({ "update": { mail_id: { "aliases": Value::Object(map) } } })).await.map(|_| ())
    }
}

/* ---- письма от сервера ---- */

impl Stalwart {
    /// Может ли сервер отправлять письма сам.
    pub fn can_send(&self) -> bool {
        self.outbox.is_some() || self.enabled()
    }

    /// Служебный ящик ещё не подготовлен (ensure_sender не вызывался или не удался).
    pub fn needs_sender(&self) -> bool {
        self.outbox.is_none() && self.sender.get().is_none()
    }

    fn system_login(&self) -> String {
        format!("{}@{}", SYSTEM_LOCAL, self.domain)
    }

    /// Номер учётки JMAP, под которой вошли: по нему идут вызовы почты.
    async fn session_account(&self, login: &str, password: &str) -> Result<String, MailError> {
        let res = self.http.get(format!("{}/jmap/session", self.base)).basic_auth(login, Some(password)).send().await.map_err(|e| MailError::Unavailable(e.to_string()))?;
        let status = res.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(MailError::Unauthorized);
        }
        if !status.is_success() {
            return Err(MailError::Unavailable(format!("HTTP {}", status.as_u16())));
        }
        let v: Value = res.json().await.map_err(|e| MailError::Unavailable(e.to_string()))?;
        v.pointer("/primaryAccounts/urn:ietf:params:jmap:mail").and_then(Value::as_str).map(str::to_string).ok_or_else(|| MailError::Rejected("почтовый сервер не назвал учётку".into()))
    }

    async fn create_system_account(&self) -> Result<String, MailError> {
        let domain_id = self.domain_id().await?;
        let args = json!({ "create": { "u": {
            "@type": "User",
            "name": SYSTEM_LOCAL,
            "domainId": domain_id,
            "roles": { "@type": "User" },
            "description": "Tabora",
            "credentials": { "0": { "@type": "Password", "secret": self.primary_password(SYSTEM_ID), "allowedIps": Self::loopback() } },
            "quotas": { "maxDiskQuota": SYSTEM_QUOTA },
        } } });
        match self.jmap(Auth::Service, "x:Account/set", args).await {
            Ok(r) => r.pointer("/created/u/id").and_then(Value::as_str).map(str::to_string).ok_or_else(|| MailError::Rejected("нет номера служебного ящика".into())),
            Err(MailError::Taken) => Err(MailError::Rejected(format!("ящик {} уже есть на почтовом сервере, но его номер неизвестен: запишите его в settings.system_mail_id", self.system_login()))),
            Err(e) => Err(e),
        }
    }

    /// Подготовить служебный ящик: войти в него, при необходимости создать его или заново
    /// выставить ему пароль (known — его номер, записанный при создании). Возвращает номер,
    /// который надо запомнить, если ящик создан этим вызовом.
    pub async fn ensure_sender(&self, known: Option<&str>) -> Result<Option<String>, MailError> {
        if !self.needs_sender() {
            return Ok(None);
        }
        if !self.enabled() {
            return Err(MailError::Unavailable("почта выключена".into()));
        }
        let login = self.system_login();
        let password = self.primary_password(SYSTEM_ID);
        let mut created = None;
        let account = match self.session_account(&login, &password).await {
            Ok(a) => a,
            Err(MailError::Unauthorized) => {
                match known {
                    Some(id) => self.reset_primary(id, SYSTEM_ID).await?,
                    None => created = Some(self.create_system_account().await?),
                }
                self.session_account(&login, &password).await?
            }
            Err(e) => return Err(e),
        };
        let auth = || Auth::User { login: &login, password: &password };
        let r = self
            .calls(auth(), &MAIL_USING, json!([["Identity/get", { "accountId": account }, "0"], ["Mailbox/get", { "accountId": account, "properties": ["role"] }, "1"]]))
            .await?;
        let find = |resp: &Value, key: &str, want: &str| -> Option<String> {
            resp.get("list")?.as_array()?.iter().find(|x| x.get(key).and_then(Value::as_str) == Some(want))?.get("id")?.as_str().map(str::to_string)
        };
        let identity = match find(&r[0], "email", &login) {
            Some(id) => id,
            None => {
                let made = self.calls(auth(), &MAIL_USING, json!([["Identity/set", { "accountId": account, "create": { "i": { "name": "Tabora", "email": login } } }, "0"]])).await?;
                made[0].pointer("/created/i/id").and_then(Value::as_str).map(str::to_string).ok_or_else(|| MailError::Rejected("личность отправителя не создана".into()))?
            }
        };
        let drafts = find(&r[1], "role", "drafts").or_else(|| find(&r[1], "role", "inbox")).ok_or_else(|| MailError::Rejected("в служебном ящике нет папок".into()))?;
        let _ = self.sender.set(Sender { account, identity, drafts });
        Ok(created)
    }

    /// Письмо от служебного ящика: черновик создаётся, отправляется и сразу удаляется.
    pub async fn send_system(&self, to: &str, subject: &str, text: &str) -> Result<(), MailError> {
        if let Some(dir) = &self.outbox {
            let name = format!("{}-{}.json", now_ms(), hex::encode(random::<4>()));
            let body = json!({ "to": to, "subject": subject, "text": text }).to_string();
            return std::fs::write(dir.join(name), body).map_err(|e| MailError::Unavailable(format!("каталог писем для проверок: {e}")));
        }
        let s = self.sender.get().ok_or_else(|| MailError::Unavailable("служебный ящик не подготовлен".into()))?;
        let login = self.system_login();
        let password = self.primary_password(SYSTEM_ID);
        let calls = json!([
            ["Email/set", { "accountId": s.account, "create": { "m": {
                "mailboxIds": { s.drafts.as_str(): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [{ "name": "Tabora", "email": login }],
                "to": [{ "email": to }],
                "subject": subject,
                "header:Auto-Submitted:asText": "auto-generated",
                "bodyValues": { "t": { "value": text } },
                "textBody": [{ "partId": "t", "type": "text/plain" }],
            } } }, "0"],
            ["EmailSubmission/set", { "accountId": s.account, "create": { "s": { "identityId": s.identity, "emailId": "#m" } }, "onSuccessDestroyEmail": ["#s"] }, "1"],
        ]);
        let r = self.calls(Auth::User { login: &login, password: &password }, &MAIL_USING, calls).await?;
        if r[0].pointer("/created/m").is_none() || r[1].pointer("/created/s").is_none() {
            return Err(MailError::Rejected("письмо не принято к отправке".into()));
        }
        Ok(())
    }
}
