//! Почта для веб-версии: доступ к ящику по сессии аккаунта.
//!
//! Браузеру Tabora каждое устройство получает пароль приложения и ходит с ним на почтовый сервер
//! само (IMAP, SMTP). Веб-странице такой путь не подходит: паролей приложений у ящика считаные
//! штуки, а закрытая вкладка оставляла бы свой занятым до истечения сессии. Поэтому веб-версия
//! работает с ящиком через этот сервер: запросы JMAP идут сюда с обычным токеном сессии, а сервер
//! пересылает их почтовому серверу от имени владельца ящика.
//!
//! Что это даёт: в браузере нет почтового пароля вовсе; выход или отзыв сессии сразу закрывает и
//! почту; странице доступны только почтовые методы (письма, папки, отправка) — настройки ящика,
//! пароли приложений и прочее управление через этот путь недоступны.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::Value;

use crate::api::{bad, err, local_of, mail_err, ApiError, App};
use crate::db::User;
use crate::mail::MailError;

/// Предел тела запроса с методами JMAP и загружаемого файла.
pub const MAX_CALL: usize = 4 * 1024 * 1024;
pub const MAX_UPLOAD: usize = 52 * 1024 * 1024;

const USING: [&str; 3] = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"];
const METHODS: [&str; 22] = [
    "Core/echo",
    "Mailbox/get", "Mailbox/changes", "Mailbox/query", "Mailbox/queryChanges", "Mailbox/set",
    "Thread/get", "Thread/changes",
    "Email/get", "Email/changes", "Email/query", "Email/queryChanges", "Email/set", "Email/copy", "Email/import", "Email/parse",
    "SearchSnippet/get",
    "Identity/get", "Identity/changes", "Identity/set",
    "EmailSubmission/get", "EmailSubmission/set",
];

/// Запрос JMAP веб-версии: только почтовые возможности и почтовые методы. Ошибка — что не так.
pub fn check_call(body: &Value) -> Result<(), &'static str> {
    let using = body.get("using").and_then(Value::as_array).ok_or("нет поля using")?;
    if using.is_empty() || !using.iter().all(|u| u.as_str().map(|s| USING.contains(&s)).unwrap_or(false)) {
        return Err("возможность вне почты");
    }
    let calls = body.get("methodCalls").and_then(Value::as_array).ok_or("нет поля methodCalls")?;
    if calls.is_empty() || calls.len() > 32 {
        return Err("число вызовов");
    }
    for call in calls {
        let name = call.get(0).and_then(Value::as_str).ok_or("вызов без имени метода")?;
        if !METHODS.contains(&name) {
            return Err("метод вне почты");
        }
        if !call.get(1).map(Value::is_object).unwrap_or(false) {
            return Err("вызов без аргументов");
        }
    }
    Ok(())
}

fn forbidden(why: &'static str) -> ApiError {
    eprintln!("почта веб-версии: запрос отклонён: {why}");
    err(StatusCode::FORBIDDEN, "mail-forbidden", "Этот запрос к почте веб-версии недоступен")
}

fn unavailable() -> ApiError {
    mail_err(MailError::Unavailable("у аккаунта нет ящика или почта выключена".into()))
}

/// Часть адреса (номер блока, имя файла): без разделителей пути и управляющих знаков.
fn segment(s: &str) -> Result<String, ApiError> {
    if s.is_empty() || s.len() > 400 || s.contains('/') || s.contains('\\') || s == "." || s == ".." || s.chars().any(char::is_control) {
        return Err(bad("bad-request", "Некорректный запрос: адрес файла"));
    }
    Ok(urlencode(s))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn owner(app: &App, headers: &HeaderMap) -> Result<(User, String), ApiError> {
    let (user, _, _) = app.auth(headers).await?;
    app.window(&format!("webmail:{}", user.id), 1500, 60_000)?;
    if !app.mail.enabled() {
        return Err(unavailable());
    }
    let mail_id = user.mail_id.clone().ok_or_else(unavailable)?;
    Ok((user, mail_id))
}

fn passthrough(status: u16, content_type: Option<&str>, body: Body) -> Response {
    let mut res = Response::new(body);
    *res.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = res.headers_mut();
    if let Some(ct) = content_type.and_then(|v| HeaderValue::from_str(v).ok()) {
        h.insert(CONTENT_TYPE, ct);
    }
    h.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    res
}

async fn relay(res: reqwest::Response) -> Result<Response, ApiError> {
    let status = res.status().as_u16();
    if status == 401 || status == 403 {
        // владельца ящика почтовый сервер обязан пускать: сбой на стороне почты, а не сессии
        return Err(unavailable());
    }
    let ct = res.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    Ok(passthrough(status, ct.as_deref(), Body::from_stream(res.bytes_stream())))
}

/// `GET /v1/mail/jmap/session` — описание ящика (номер учётки, пределы).
pub async fn session(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (user, mail_id) = owner(&app, &headers).await?;
    let res = app.mail.user_http(local_of(&user.email), &user.public_id, &mail_id, reqwest::Method::GET, "/jmap/session", None, None).await.map_err(mail_err)?;
    relay(res).await
}

/// `POST /v1/mail/jmap` — вызовы методов JMAP. Пропускаются только почтовые.
pub async fn call(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let (user, _, _) = app.auth(&headers).await?;
    let json: Value = serde_json::from_slice(&body).map_err(|_| bad("bad-request", "Некорректный запрос: не JSON"))?;
    check_call(&json).map_err(forbidden)?;
    app.window(&format!("webmail:{}", user.id), 1500, 60_000)?;
    if !app.mail.enabled() {
        return Err(unavailable());
    }
    let mail_id = user.mail_id.clone().ok_or_else(unavailable)?;
    let res = app.mail.user_http(local_of(&user.email), &user.public_id, &mail_id, reqwest::Method::POST, "/jmap/", Some("application/json"), Some(body)).await.map_err(mail_err)?;
    relay(res).await
}

#[derive(Deserialize)]
pub struct Accept {
    #[serde(default)]
    accept: String,
}

/// `GET /v1/mail/jmap/download/:account/:blob/:name?accept=тип` — содержимое вложения или письма.
pub async fn download(State(app): State<Arc<App>>, headers: HeaderMap, Path((account, blob, name)): Path<(String, String, String)>, Query(q): Query<Accept>) -> Result<Response, ApiError> {
    let (user, mail_id) = owner(&app, &headers).await?;
    let accept = if q.accept.is_empty() { "application/octet-stream".to_string() } else { q.accept };
    if accept.len() > 120 || accept.chars().any(|c| c.is_control() || c == ' ') {
        return Err(bad("bad-request", "Некорректный запрос: тип файла"));
    }
    let path = format!("/jmap/download/{}/{}/{}?accept={}", segment(&account)?, segment(&blob)?, segment(&name)?, urlencode(&accept));
    let res = app.mail.user_http(local_of(&user.email), &user.public_id, &mail_id, reqwest::Method::GET, &path, None, None).await.map_err(mail_err)?;
    // файл отдаётся только как данные для страницы: открыть его как документ на имени сервера нельзя
    let mut out = relay(res).await?;
    out.headers_mut().insert("content-disposition", HeaderValue::from_static("attachment"));
    Ok(out)
}

/// `POST /v1/mail/jmap/upload/:account` — загрузить вложение или исходник письма.
pub async fn upload(State(app): State<Arc<App>>, headers: HeaderMap, Path(account): Path<String>, body: Bytes) -> Result<Response, ApiError> {
    let (user, mail_id) = owner(&app, &headers).await?;
    let ct = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).filter(|v| v.len() <= 120 && !v.chars().any(char::is_control)).unwrap_or("application/octet-stream").to_string();
    let path = format!("/jmap/upload/{}/", segment(&account)?);
    let res = app.mail.user_http(local_of(&user.email), &user.public_id, &mail_id, reqwest::Method::POST, &path, Some(&ct), Some(body)).await.map_err(mail_err)?;
    relay(res).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mail_calls_pass() {
        let ok = json!({ "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"], "methodCalls": [["Mailbox/get", { "accountId": "a" }, "c0"], ["Email/query", {}, "c1"], ["EmailSubmission/set", {}, "c2"], ["Identity/set", {}, "c3"], ["Email/import", {}, "c4"]] });
        assert_eq!(check_call(&ok), Ok(()));
    }

    #[test]
    fn management_is_refused() {
        // управление ящиком и сервером: пароли приложений, учётки, ключи, фильтры
        for method in ["x:AppPassword/set", "x:AppPassword/get", "x:Account/set", "x:Account/get", "x:Domain/get", "SieveScript/set", "Principal/get", "VacationResponse/set", "Blob/copy", "PushSubscription/set", "email/get", "Email/Get", "Email/destroyAll"] {
            let body = json!({ "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"], "methodCalls": [[method, {}, "c0"]] });
            assert_eq!(check_call(&body), Err("метод вне почты"), "{method}");
        }
        // разрешённый метод рядом с запрещённым не спасает запрос
        let mixed = json!({ "using": ["urn:ietf:params:jmap:mail"], "methodCalls": [["Email/get", {}, "c0"], ["x:AppPassword/set", {}, "c1"]] });
        assert_eq!(check_call(&mixed), Err("метод вне почты"));
    }

    #[test]
    fn foreign_capabilities_are_refused() {
        for using in [json!(["urn:stalwart:jmap"]), json!(["urn:ietf:params:jmap:mail", "urn:stalwart:jmap"]), json!(["urn:ietf:params:jmap:sieve"]), json!([]), json!([1]), json!("urn:ietf:params:jmap:mail")] {
            let body = json!({ "using": using, "methodCalls": [["Email/get", {}, "c0"]] });
            assert!(check_call(&body).is_err(), "{using}");
        }
    }

    #[test]
    fn malformed_calls_are_refused() {
        let using = json!(["urn:ietf:params:jmap:mail"]);
        for calls in [json!([]), json!([["Email/get"]]), json!([["Email/get", "x", "c0"]]), json!([[1, {}, "c0"]]), json!("Email/get"), json!([{ "name": "Email/get" }])] {
            assert!(check_call(&json!({ "using": using, "methodCalls": calls })).is_err(), "{calls}");
        }
        let many: Vec<Value> = (0..33).map(|i| json!(["Email/get", {}, format!("c{i}")])).collect();
        assert!(check_call(&json!({ "using": using, "methodCalls": many })).is_err());
        assert!(check_call(&json!({ "methodCalls": [["Email/get", {}, "c0"]] })).is_err());
    }

    #[test]
    fn path_segments_cannot_escape() {
        assert!(segment("..").is_err());
        assert!(segment("a/b").is_err());
        assert!(segment("a\\b").is_err());
        assert!(segment("").is_err());
        assert!(segment("a\nb").is_err());
        assert_eq!(segment("отчёт 1.txt").unwrap(), "%D0%BE%D1%82%D1%87%D1%91%D1%82%201.txt");
        assert_eq!(segment("blob-Ab_1.~").unwrap(), "blob-Ab_1.~");
        assert_eq!(segment("a?b=c&d#e").unwrap(), "a%3Fb%3Dc%26d%23e");
    }
}
