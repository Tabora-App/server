/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Обращения в поддержку: пользователь пишет из браузера, поддержка отвечает там же.
//!
//! Переписку читает поддержка, поэтому она хранится открыто: это не сквозное шифрование, и
//! браузер говорит об этом пользователю. Обращение видят только его автор и сотрудники
//! поддержки; для всех остальных его нет (`404`).
//!
//! Сотрудники — аккаунты, чьи адреса перечислены в `TABORA_SUPPORT_STAFF`. В чужом обращении
//! сотрудник действует как поддержка: видит автора и сведения о браузере, его сообщения идут
//! от имени поддержки. В своём собственном обращении он обычный пользователь.
//!
//! Статусы: `open` — ждёт поддержку, `answered` — поддержка ответила, `closed` — закрыто.
//! Сообщение автора возвращает обращение в `open` (в том числе закрытое), ответ поддержки
//! переводит в `answered`. У каждой стороны своя отметка прочтения: непрочитанными считаются
//! сообщения другой стороны новее неё.
//!
//! Письма: о новом обращении и о каждом ответе пользователя — на `TABORA_SUPPORT_NOTIFY`, об
//! ответе поддержки — пользователю на адрес его аккаунта. Письма уходят в фоне: сбой почты не
//! отменяет ни обращение, ни сообщение.
//!
//! Where requests are written. In the browser (Settings -> Support) and on the support site
//! (`TABORA_SUPPORT_URL`). The site signs in with a session of the scope "support": it reaches
//! these requests and nothing else of the account (`App::auth_for`).
//!
//! Requests without an account (the support site, `/v1/support/guest…`). Someone who cannot sign
//! in, or has no account yet, leaves an e-mail address. The request is not shown to support
//! until the address is confirmed: a letter with a link goes to it, and opening the link confirms
//! the address. The letter has a fixed text and never carries what the author wrote, so the form
//! cannot be used to send someone a text of the sender's choosing. The link holds the request's
//! number and a secret; whoever has it reads the request and answers in it, and support's answers
//! come to the same address with the same link. A request whose link nobody opened in two days
//! is deleted. Attachments are not accepted from authors without an account.

use crate::api::{bad, client_ip, err, sized, wait_text, ApiError, ApiResult, App};
use crate::db::{self, Ticket, TicketSummary, User};
use crate::util::{clean_address, iso, now_ms, random, same};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use deadpool_postgres::GenericClient;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// Предел тела запроса с вложениями: четыре файла по 2 МиБ в Base64 и текст.
pub const MAX_BODY: usize = 12 * 1024 * 1024;
const SUBJECT_MIN: usize = 3;
const SUBJECT_MAX: usize = 140;
const TEXT_MAX: usize = 8000;
const META_MAX: usize = 2048;
const FILES_MAX: usize = 4;
const FILE_MAX: usize = 2 * 1024 * 1024;
const NAME_MAX: usize = 120;
/// Незакрытых обращений у пользователя, новых обращений в сутки, сообщений в обращении.
const OPEN_MAX: i64 = 5;
const DAILY_MAX: i64 = 10;
const MESSAGES_MAX: i64 = 200;
const USER_MESSAGES_PER_HOUR: u32 = 60;
const LIST_MAX: i64 = 200;
/// Писем поддержке из-за одного пользователя в час. Сами сообщения сохраняются и без письма.
const NOTIFY_PER_USER_HOUR: u32 = 12;
/// Допустимые вложения: тип и расширение для имени по умолчанию.
const TYPES: [(&str, &str); 4] = [("image/png", "png"), ("image/jpeg", "jpg"), ("image/webp", "webp"), ("text/plain", "txt")];
const STATUSES: [&str; 3] = ["open", "answered", "closed"];
/// Requests without an account. From one network address: new requests an hour and a day, and
/// any calls an hour. For one e-mail address: requests waiting for confirmation and new requests
/// a day (each one is a letter to that address). On the whole server: letters with links a day.
const GUEST_PER_IP_HOUR: u32 = 3;
const GUEST_PER_IP_DAY: u32 = 6;
const GUEST_CALLS_PER_IP_HOUR: u32 = 240;
const GUEST_PENDING_PER_ADDRESS: i64 = 2;
const GUEST_PER_ADDRESS_DAY: i64 = 3;
const GUEST_MESSAGES_PER_HOUR: u32 = 20;
const GUEST_KEY_BYTES: usize = 24;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn invalid(message: impl Into<String>) -> ApiError {
    bad("support-invalid", message)
}

fn limit(message: impl Into<String>) -> ApiError {
    err(StatusCode::TOO_MANY_REQUESTS, "support-limit", message)
}

fn no_ticket() -> ApiError {
    err(StatusCode::NOT_FOUND, "not-found", "Обращение не найдено")
}

fn too_large() -> ApiError {
    invalid(format!("Сообщение слишком большое: вместе с вложениями оно не должно превышать {} МБ", MAX_BODY / 1024 / 1024))
}

fn parse<'a, T: Deserialize<'a>>(body: &'a Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| invalid("Обращение не отправлено: некорректный запрос"))
}

/// Адреса сотрудников из `TABORA_SUPPORT_STAFF`: через запятую, регистр не важен.
pub fn staff_list(raw: &str) -> Vec<String> {
    raw.split(',').map(|a| a.trim().to_lowercase()).filter(|a| !a.is_empty()).collect()
}

fn is_staff(app: &App, user: &User) -> bool {
    let email = user.email.to_lowercase();
    app.support_staff.iter().any(|a| *a == email)
}

/// Кем смотрящий приходится обращению: Some(true) — поддержка, Some(false) — автор, None —
/// посторонний. Сотрудник в своём собственном обращении — автор.
fn role(app: &App, user: &User, t: &Ticket) -> Option<bool> {
    if t.user_id == Some(user.id) {
        Some(false)
    } else if is_staff(app, user) && (!t.is_guest() || t.guest_confirmed) {
        // a request without an account does not exist for support until its address is confirmed
        Some(true)
    } else {
        None
    }
}

/// Номер из адреса запроса: только положительное целое.
fn number(raw: &str) -> Option<i64> {
    if raw.is_empty() || raw.len() > 18 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<i64>().ok().filter(|n| *n > 0)
}

/* ---- проверка присланного ---- */

/// Тема: одна строка от 3 до 140 знаков.
fn clean_subject(raw: &str) -> Result<String, ApiError> {
    let s: String = raw.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let s = s.trim();
    if !(SUBJECT_MIN..=SUBJECT_MAX).contains(&s.chars().count()) {
        return Err(invalid(format!("Тема обращения: от {SUBJECT_MIN} до {SUBJECT_MAX} знаков")));
    }
    Ok(s.to_string())
}

/// Текст сообщения: от 1 до 8000 знаков; переводы строк и табуляция остаются, прочие
/// управляющие знаки убираются.
fn clean_text(raw: &str) -> Result<String, ApiError> {
    let s: String = raw.replace("\r\n", "\n").chars().map(|c| if c == '\r' { '\n' } else { c }).filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect();
    let s = s.trim();
    match s.chars().count() {
        0 => Err(invalid("Напишите текст сообщения")),
        n if n > TEXT_MAX => Err(invalid(format!("Сообщение длиннее {TEXT_MAX} знаков: сократите его или разделите на несколько"))),
        _ => Ok(s.to_string()),
    }
}

/// Сведения о браузере от клиента: объект JSON не больше 2 КиБ в записи. Хранится текстом.
fn clean_meta(meta: Option<Value>) -> Result<Option<String>, ApiError> {
    match meta {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) if map.is_empty() => Ok(None),
        Some(meta @ Value::Object(_)) => {
            let text = meta.to_string();
            if text.len() > META_MAX {
                return Err(invalid("Обращение не отправлено: сведения о браузере слишком большие"));
            }
            Ok(Some(text))
        }
        Some(_) => Err(invalid("Обращение не отправлено: сведения о браузере должны быть объектом")),
    }
}

/// Имя вложения: без разделителей пути, управляющих знаков и знаков смены направления письма
/// (ими расширение прячут в середине имени), не длиннее 120 знаков; расширение при обрезке
/// сохраняется. Пустое имя заменяется на «вложение» с расширением по типу.
fn clean_file_name(raw: &str, ext: &str) -> String {
    let hidden = |c: char| c.is_control() || matches!(c, '/' | '\\' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    let s: String = raw.chars().filter(|c| !hidden(*c)).collect();
    let s = s.trim().trim_start_matches('.').trim();
    if s.is_empty() {
        return format!("вложение.{ext}");
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= NAME_MAX {
        return s.to_string();
    }
    match chars.iter().rposition(|c| *c == '.') {
        Some(dot) if chars.len() - dot <= 12 && dot > 0 => {
            let tail: String = chars[dot..].iter().collect();
            let stem: String = chars[..NAME_MAX - (chars.len() - dot)].iter().collect();
            format!("{}{tail}", stem.trim_end())
        }
        _ => chars[..NAME_MAX].iter().collect::<String>().trim_end().to_string(),
    }
}

#[derive(Deserialize)]
pub struct FileBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    mime: String,
    data: String,
}

/// Проверенное вложение.
#[derive(Debug)]
struct Upload {
    name: String,
    mime: &'static str,
    data: Vec<u8>,
}

fn clean_files(files: Option<Vec<FileBody>>) -> Result<Vec<Upload>, ApiError> {
    let files = files.unwrap_or_default();
    if files.len() > FILES_MAX {
        return Err(invalid(format!("К сообщению можно приложить не больше {FILES_MAX} файлов")));
    }
    let too_big = || invalid(format!("Файл больше {} МБ: приложите файл поменьше", FILE_MAX / 1024 / 1024));
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let wanted = f.mime.trim().to_ascii_lowercase();
        let Some((mime, ext)) = TYPES.iter().find(|(m, _)| *m == wanted) else {
            return Err(invalid("Приложить можно только изображения PNG, JPEG, WebP и текстовые файлы"));
        };
        if f.data.len() > FILE_MAX * 4 / 3 + 8 {
            return Err(too_big());
        }
        let data = B64.decode(f.data.as_bytes()).map_err(|_| invalid("Вложение не отправлено: его содержимое повреждено"))?;
        if data.is_empty() {
            return Err(invalid("Вложение пустое: приложите другой файл"));
        }
        if data.len() > FILE_MAX {
            return Err(too_big());
        }
        out.push(Upload { name: clean_file_name(f.name.as_deref().unwrap_or(""), ext), mime, data });
    }
    Ok(out)
}

/// Имя файла для `filename*` заголовка Content-Disposition (RFC 5987): всё, кроме разрешённых
/// знаков ASCII, записывается байтами UTF-8 через процент.
fn encode_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() * 3);
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Начало текста для письма: не больше max знаков, обрезанное помечается многоточием.
fn excerpt(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

/* ---- письма ---- */

/// Письмо в фоне: ответ клиенту его не ждёт, сбой отправки ничего не отменяет.
fn mail_later(app: &Arc<App>, to: String, subject: String, text: String, ticket: i64) {
    let app = app.clone();
    tokio::spawn(async move {
        if let Err(e) = app.send_mail(&to, &subject, &text).await {
            eprintln!("поддержка: письмо об обращении № {ticket} не отправлено: {}", e.code);
        }
    });
}

/// Письмо поддержке о новом обращении или об ответе пользователя. У этих писем свои пределы:
/// они не должны выбрать суточный запас писем сервера, из которого уходят коды сброса пароля.
/// `author` names whose letters are counted together: an account or a request without an account.
fn notify_staff(app: &Arc<App>, author: &str, ticket: i64, subject: String, text: String) {
    let Some(to) = app.support_notify.clone() else { return };
    let now = now_ms();
    let per_user = app.limiter.hit(&format!("support-mail:{author}"), NOTIFY_PER_USER_HOUR, 3_600_000, now);
    if per_user.is_err() || app.limiter.hit("support-mail", (app.mail_daily_cap / 2).max(1), 86_400_000, now).is_err() {
        return;
    }
    mail_later(app, to, subject, text, ticket);
}

/* ---- ответы ---- */

fn summary_json(s: &TicketSummary, with_author: bool) -> Value {
    let t = &s.ticket;
    let mut v = json!({
        "id": t.id,
        "subject": t.subject,
        "status": t.status,
        "createdAt": iso(t.created_at),
        "updatedAt": iso(t.updated_at),
        "messages": s.messages,
        "unread": s.unread,
    });
    if with_author {
        v["author"] = json!(t.author);
        if t.is_guest() {
            v["guest"] = json!(true);
        }
    }
    v
}

/// Обращение целиком: сообщения по порядку и сведения о вложениях. Автора и сведения о
/// браузере видит только поддержка.
async fn ticket_json<C: GenericClient>(c: &C, t: &Ticket, as_staff: bool) -> Result<Value, ApiError> {
    let messages = db::ticket_messages(c, t.id).await?;
    let files = db::ticket_files(c, t.id).await?;
    let list: Vec<Value> = messages
        .iter()
        .map(|m| {
            let attached: Vec<Value> = files.iter().filter(|f| f.message_id == m.id).map(|f| json!({ "id": f.id, "name": f.name, "type": f.mime, "size": f.size })).collect();
            json!({ "id": m.id, "from": if m.staff { "staff" } else { "user" }, "text": m.body, "at": iso(m.created_at), "files": attached })
        })
        .collect();
    let mut v = json!({
        "id": t.id,
        "subject": t.subject,
        "status": t.status,
        "createdAt": iso(t.created_at),
        "updatedAt": iso(t.updated_at),
        "staff": as_staff,
        "messages": list,
    });
    if as_staff {
        v["author"] = json!(t.author);
        if t.is_guest() {
            v["guest"] = json!(true);
        }
        if let Some(meta) = t.meta.as_deref().and_then(|m| serde_json::from_str::<Value>(m).ok()) {
            v["meta"] = meta;
        }
    }
    Ok(v)
}

/// Обращение после изменения — в том же виде, что при чтении.
async fn fresh<C: GenericClient>(c: &C, id: i64, as_staff: bool) -> ApiResult {
    let t = db::ticket(c, id).await?.ok_or_else(no_ticket)?;
    Ok(Json(ticket_json(c, &t, as_staff).await?))
}

/* ---- запросы ---- */

#[derive(Deserialize)]
pub struct ListQuery {
    scope: Option<String>,
    status: Option<String>,
}

/// Список обращений: свои, а для сотрудника с `scope=all` — всех пользователей.
pub async fn list(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<ListQuery>) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support:{}", user.id), 1200, 3_600_000)?;
    let staff = is_staff(&app, &user);
    let all = match q.scope.as_deref().unwrap_or("mine") {
        "mine" | "" => false,
        "all" => staff,
        _ => return Err(invalid("Неизвестный список обращений")),
    };
    let status = match q.status.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) if STATUSES.contains(&s) => Some(s),
        Some(_) => return Err(invalid("Неизвестный статус обращения")),
    };
    let c = app.pool.get().await?;
    let found = db::tickets(&c, user.id, all, status, LIST_MAX).await?;
    Ok(Json(json!({ "staff": staff, "tickets": found.iter().map(|s| summary_json(s, all)).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
pub struct TicketBody {
    subject: String,
    text: String,
    #[serde(default)]
    meta: Option<Value>,
    #[serde(default)]
    files: Option<Vec<FileBody>>,
}

/// Новое обращение с первым сообщением.
pub async fn create(State(app): State<Arc<App>>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support-write:{}", user.id), 240, 3_600_000)?;
    let body = sized(body, too_large)?;
    let b: TicketBody = parse(&body)?;
    drop(body);
    let subject = clean_subject(&b.subject)?;
    let text = clean_text(&b.text)?;
    let meta = clean_meta(b.meta)?;
    let files = clean_files(b.files)?;
    let now = now_ms();
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let (open, recent) = db::ticket_counts_for_update(&tx, user.id, now - 86_400_000).await?;
    if open >= OPEN_MAX {
        return Err(limit("У вас уже пять незакрытых обращений. Дождитесь ответа или закройте те, что больше не нужны"));
    }
    if recent >= DAILY_MAX {
        return Err(limit("За сутки создано слишком много обращений. Напишите в одно из уже открытых или попробуйте завтра"));
    }
    let id = db::insert_ticket(&tx, user.id, &subject, meta.as_deref(), now).await?;
    let message = db::insert_ticket_message(&tx, id, false, Some(user.id), &text, now).await?;
    for f in &files {
        db::insert_ticket_file(&tx, message, id, &f.name, f.mime, &f.data).await?;
    }
    tx.commit().await?;
    let out = fresh(&c, id, false).await?;
    drop(c);
    let note = format!("Автор: {}\nТема: {subject}\nВложений: {}\n\n{}\n\nОтветить можно в браузере (Настройки → Поддержка) или на сайте {}", user.email, files.len(), excerpt(&text, 600), app.support_url);
    notify_staff(&app, &format!("u{}", user.id), id, format!("Новое обращение № {id}: {subject}"), note);
    Ok(out)
}

/// Обращение с перепиской. Чтение отмечает его прочитанным для смотрящей стороны.
pub async fn ticket(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support:{}", user.id), 1200, 3_600_000)?;
    let id = number(&id).ok_or_else(no_ticket)?;
    let c = app.pool.get().await?;
    let t = db::ticket(&c, id).await?.ok_or_else(no_ticket)?;
    let as_staff = role(&app, &user, &t).ok_or_else(no_ticket)?;
    db::mark_ticket_read(&c, id, as_staff, now_ms()).await?;
    Ok(Json(ticket_json(&c, &t, as_staff).await?))
}

#[derive(Deserialize)]
pub struct MessageBody {
    text: String,
    #[serde(default)]
    files: Option<Vec<FileBody>>,
}

/// Новое сообщение в обращении: от автора — обращение снова ждёт поддержку, от поддержки —
/// считается отвеченным, а автору уходит письмо.
pub async fn reply(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support-write:{}", user.id), 240, 3_600_000)?;
    let id = number(&id).ok_or_else(no_ticket)?;
    let body = sized(body, too_large)?;
    let b: MessageBody = parse(&body)?;
    drop(body);
    let text = clean_text(&b.text)?;
    let files = clean_files(b.files)?;
    let now = now_ms();
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let t = db::ticket_for_update(&tx, id).await?.ok_or_else(no_ticket)?;
    let as_staff = role(&app, &user, &t).ok_or_else(no_ticket)?;
    if db::ticket_message_count(&tx, id).await? >= MESSAGES_MAX {
        return Err(limit("В этом обращении слишком много сообщений: создайте новое"));
    }
    if !as_staff {
        app.limiter
            .hit(&format!("support-msg:{}", user.id), USER_MESSAGES_PER_HOUR, 3_600_000, now)
            .map_err(|ms| limit(format!("Слишком много сообщений подряд. Повторите через {}", wait_text(ms))))?;
    }
    // сообщение всегда новее отметок прочтения, поставленных до него: иначе ответ, пришедший
    // в ту же миллисекунду, что и чтение, остался бы «прочитанным»
    let at = now.max(t.updated_at + 1).max(t.user_read_at + 1).max(t.staff_read_at + 1);
    let message = db::insert_ticket_message(&tx, id, as_staff, Some(user.id), &text, at).await?;
    for f in &files {
        db::insert_ticket_file(&tx, message, id, &f.name, f.mime, &f.data).await?;
    }
    db::ticket_after_message(&tx, id, if as_staff { "answered" } else { "open" }, at, as_staff).await?;
    tx.commit().await?;
    let out = fresh(&c, id, as_staff).await?;
    drop(c);
    if as_staff {
        answer_letter(&app, &t, &text);
    } else {
        let note = format!("Автор: {}\nТема: {}\nВложений: {}\n\n{}\n\nОтветить можно в браузере (Настройки → Поддержка) или на сайте {}", user.email, t.subject, files.len(), excerpt(&text, 600), app.support_url);
        notify_staff(&app, &format!("u{}", user.id), id, format!("Ответ в обращении № {id}: {}", t.subject), note);
    }
    Ok(out)
}

/// The letter to the author about support's answer. An account gets it in its mailbox; an author
/// without an account gets it at the address of the request, with the request's link and in the
/// language the request was written in.
fn answer_letter(app: &Arc<App>, t: &Ticket, text: &str) {
    let id = t.id;
    let subject = format!("Ответ поддержки Tabora: {}", t.subject);
    match t.guest_key.as_deref().filter(|_| t.is_guest()) {
        None => {
            let letter = format!(
                "{}\n\n—\nОбращение № {id}: {}\nОтветить можно в браузере (Настройки → Поддержка) или на сайте {}\n\nПисьмо отправлено автоматически, отвечать на него не нужно.",
                excerpt(text, 4000),
                t.subject,
                app.support_url
            );
            mail_later(app, t.author.clone(), subject, letter, id);
        }
        Some(key) => {
            let letter = format!(
                "{}\n\n—\nОбращение № {id}: {}\nОтветить можно по ссылке: {}\n\nПисьмо отправлено автоматически, отвечать на него не нужно.",
                excerpt(text, 4000),
                t.subject,
                guest_link(app, id, key)
            );
            let (app, to, lang) = (app.clone(), t.author.clone(), t.guest_lang.clone());
            tokio::spawn(async move {
                if let Err(e) = app.send_mail_in(&to, &subject, &letter, lang.as_deref()).await {
                    eprintln!("поддержка: письмо об обращении № {id} не отправлено: {}", e.code);
                }
            });
        }
    }
}

#[derive(Deserialize)]
pub struct StatusBody {
    status: String,
}

/// Закрыть обращение или открыть его снова: может и автор, и поддержка.
pub async fn set_status(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support-write:{}", user.id), 240, 3_600_000)?;
    let id = number(&id).ok_or_else(no_ticket)?;
    let b: StatusBody = parse(&body)?;
    if b.status != "closed" && b.status != "open" {
        return Err(invalid("Обращение можно только закрыть или открыть снова"));
    }
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let t = db::ticket_for_update(&tx, id).await?.ok_or_else(no_ticket)?;
    let as_staff = role(&app, &user, &t).ok_or_else(no_ticket)?;
    if t.status != b.status {
        db::set_ticket_status(&tx, id, &b.status, now_ms().max(t.updated_at + 1)).await?;
    }
    tx.commit().await?;
    fresh(&c, id, as_staff).await
}

/// An attachment as a reply: its own type, offered only as a file to save, never to be guessed.
fn file_response(name: &str, mime: String, data: Vec<u8>) -> Response {
    let head = [
        (CONTENT_TYPE, mime),
        (CONTENT_DISPOSITION, format!("attachment; filename*=UTF-8''{}", encode_name(name))),
        (X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (CACHE_CONTROL, "private, max-age=3600".to_string()),
    ];
    (head, data).into_response()
}

/// Вложение: байты с исходным типом. Отдаётся только как файл для сохранения, тип браузеру
/// угадывать запрещено; доступ — как к самому обращению.
pub async fn file(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> Result<Response, ApiError> {
    let none = || err(StatusCode::NOT_FOUND, "not-found", "Вложение не найдено");
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support:{}", user.id), 1200, 3_600_000)?;
    let id = number(&id).ok_or_else(none)?;
    let c = app.pool.get().await?;
    let (name, mime, data) = db::ticket_file(&c, id, user.id, is_staff(&app, &user)).await?.ok_or_else(none)?;
    Ok(file_response(&name, mime, data))
}

/// Счётчик для значка в браузере: свои обращения с непрочитанным ответом поддержки, а для
/// сотрудника ещё и очередь — обращения всех пользователей, ждущие ответа.
pub async fn unread(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (user, _, _) = app.auth_for(&headers, "support").await?;
    app.window(&format!("support-unread:{}", user.id), 600, 3_600_000)?;
    let staff = is_staff(&app, &user);
    let c = app.pool.get().await?;
    let mut out = json!({ "count": db::tickets_unread(&c, user.id).await?, "staff": staff });
    if staff {
        out["queue"] = json!(db::tickets_open(&c).await?);
    }
    Ok(Json(out))
}

/* ---- requests without an account ---- */

/// The address of a request without an account on the support site. The key is after "#": a
/// browser does not send that part to a server, so it stays out of access logs.
fn guest_link(app: &App, id: i64, key: &str) -> String {
    format!("{}/#t={id}.{key}", app.support_url)
}

/// "<number>.<secret>" from a link.
fn guest_ref(raw: &str) -> Option<(i64, &str)> {
    let (id, key) = raw.trim().split_once('.')?;
    let ok = key.len() == GUEST_KEY_BYTES * 4 / 3 && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    Some((number(id)?, key)).filter(|_| ok)
}

/// The request a link leads to. A wrong number and a wrong secret are answered the same.
fn guest_match(t: Option<Ticket>, key: &str) -> Result<Ticket, ApiError> {
    let t = t.filter(|t| t.is_guest()).ok_or_else(no_ticket)?;
    let stored = t.guest_key.as_deref().unwrap_or("");
    if stored.is_empty() || !same(stored.as_bytes(), key.as_bytes()) {
        return Err(no_ticket());
    }
    Ok(t)
}

/// The request as its author sees it, with what the page needs to know about a guest's request.
async fn guest_json<C: GenericClient>(c: &C, id: i64) -> ApiResult {
    let t = db::ticket(c, id).await?.ok_or_else(no_ticket)?;
    let mut v = ticket_json(c, &t, false).await?;
    v["guest"] = json!(true);
    v["email"] = json!(t.author);
    Ok(Json(v))
}

fn guest_calls(app: &App, headers: &HeaderMap) -> Result<String, ApiError> {
    let ip = client_ip(headers);
    app.window(&format!("support-guest:{ip}"), GUEST_CALLS_PER_IP_HOUR, 3_600_000)?;
    Ok(ip)
}

#[derive(Deserialize)]
pub struct GuestBody {
    email: String,
    subject: String,
    text: String,
    #[serde(default)]
    lang: Option<String>,
}

/// `POST /v1/support/guest` — a request from someone without an account. Nothing reaches support
/// yet: a letter with a link goes to the address, and the request waits until the link is opened.
pub async fn guest_create(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let ip = guest_calls(&app, &headers)?;
    let b: GuestBody = parse(&body)?;
    let email = clean_address(&b.email).ok_or_else(|| invalid("Укажите адрес электронной почты, на который придёт ответ"))?;
    if email.ends_with(&format!("@{}", app.domain)) {
        // the letter would go to a mailbox that cannot be opened without the sign-in this person lacks
        return Err(invalid("Ответ придёт письмом, а ящик Tabora открывается только после входа. Укажите другой адрес или войдите в аккаунт"));
    }
    let subject = clean_subject(&b.subject)?;
    let text = clean_text(&b.text)?;
    let lang = b.lang.as_deref().filter(|l| crate::i18n::LANGS.contains(l)).unwrap_or("ru").to_string();
    if !app.mail.can_send() {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "mail-unavailable", "Сервер сейчас не отправляет письма: без письма обращение не подтвердить. Повторите позже"));
    }
    let now = now_ms();
    let busy = || limit("С вашего адреса уже отправлено несколько обращений. Откройте ссылку из письма или повторите позже");
    app.limiter.hit(&format!("support-guest-new:{ip}"), GUEST_PER_IP_HOUR, 3_600_000, now).map_err(|_| busy())?;
    app.limiter.hit(&format!("support-guest-day:{ip}"), GUEST_PER_IP_DAY, 86_400_000, now).map_err(|_| busy())?;
    // letters with links have their own share of the server's daily letters: the codes for
    // password resets go out of the rest
    app.limiter
        .hit("support-guest-mail", (app.mail_daily_cap / 4).max(1), 86_400_000, now)
        .map_err(|_| limit("Сегодня отправлено слишком много обращений. Повторите завтра"))?;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random::<GUEST_KEY_BYTES>());
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    // one at a time for an address: two requests sent together are counted one after another
    tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&format!("support-guest:{email}")]).await.map_err(db::DbError::from)?;
    let (pending, recent) = db::guest_ticket_counts(&tx, &email, now - 86_400_000).await?;
    if pending >= GUEST_PENDING_PER_ADDRESS || recent >= GUEST_PER_ADDRESS_DAY {
        return Err(limit("На этот адрес уже отправлены письма со ссылками. Откройте ссылку из письма или повторите завтра"));
    }
    let id = db::insert_guest_ticket(&tx, &email, &key, &lang, &subject, now).await?;
    db::insert_ticket_message(&tx, id, false, None, &text, now).await?;
    tx.commit().await?;
    let letter = format!(
        "Кто-то — возможно, вы — написал в поддержку Tabora и указал этот адрес для ответа.\n\nЧтобы обращение дошло до поддержки, откройте ссылку:\n{}\n\nПо этой же ссылке будет наш ответ. Ссылка действует как ключ к обращению: не пересылайте её.\n\nЕсли вы ничего не писали, ничего делать не нужно: без перехода по ссылке обращение удалится само.",
        guest_link(&app, id, &key)
    );
    if let Err(e) = app.send_mail_in(&email, &format!("Tabora: подтвердите обращение № {id}"), &letter, Some(&lang)).await {
        // without the letter the request can never be confirmed: it is not kept
        let _ = db::delete_ticket(&c, id).await;
        return Err(e);
    }
    Ok(Json(json!({ "sent": true })))
}

#[derive(Deserialize)]
pub struct GuestKeyBody {
    key: String,
}

/// `POST /v1/support/guest/open` — the request by its link. The first opening confirms the
/// author's address: from that moment support sees the request and is told about it.
pub async fn guest_open(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    guest_calls(&app, &headers)?;
    let b: GuestKeyBody = parse(&body)?;
    let (id, key) = guest_ref(&b.key).ok_or_else(no_ticket)?;
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let t = guest_match(db::ticket_for_update(&tx, id).await?, key)?;
    let now = now_ms();
    let first = db::confirm_guest_ticket(&tx, id, now.max(t.updated_at + 1)).await?;
    db::mark_ticket_read(&tx, id, false, now).await?;
    tx.commit().await?;
    let out = guest_json(&c, id).await?;
    if first {
        let text = db::ticket_messages(&c, id).await?.first().map(|m| m.body.clone()).unwrap_or_default();
        let note = format!("Автор: {} (без аккаунта)\nТема: {}\n\n{}\n\nОтветить можно в браузере (Настройки → Поддержка) или на сайте {}", t.author, t.subject, excerpt(&text, 600), app.support_url);
        notify_staff(&app, &format!("g{id}"), id, format!("Новое обращение № {id}: {}", t.subject), note);
    }
    Ok(out)
}

#[derive(Deserialize)]
pub struct GuestMessageBody {
    key: String,
    text: String,
}

/// `POST /v1/support/guest/messages` — the author's new message in a request without an account.
pub async fn guest_reply(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    guest_calls(&app, &headers)?;
    let b: GuestMessageBody = parse(&body)?;
    let (id, key) = guest_ref(&b.key).ok_or_else(no_ticket)?;
    let text = clean_text(&b.text)?;
    let now = now_ms();
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let t = guest_match(db::ticket_for_update(&tx, id).await?, key)?;
    if !t.guest_confirmed {
        return Err(no_ticket()); // the page opens the request first, and that confirms it
    }
    if db::ticket_message_count(&tx, id).await? >= MESSAGES_MAX {
        return Err(limit("В этом обращении слишком много сообщений: создайте новое"));
    }
    app.limiter
        .hit(&format!("support-msg:g{id}"), GUEST_MESSAGES_PER_HOUR, 3_600_000, now)
        .map_err(|ms| limit(format!("Слишком много сообщений подряд. Повторите через {}", wait_text(ms))))?;
    let at = now.max(t.updated_at + 1).max(t.user_read_at + 1).max(t.staff_read_at + 1);
    db::insert_ticket_message(&tx, id, false, None, &text, at).await?;
    db::ticket_after_message(&tx, id, "open", at, false).await?;
    tx.commit().await?;
    let out = guest_json(&c, id).await?;
    drop(c);
    let note = format!("Автор: {} (без аккаунта)\nТема: {}\n\n{}\n\nОтветить можно в браузере (Настройки → Поддержка) или на сайте {}", t.author, t.subject, excerpt(&text, 600), app.support_url);
    notify_staff(&app, &format!("g{id}"), id, format!("Ответ в обращении № {id}: {}", t.subject), note);
    Ok(out)
}

#[derive(Deserialize)]
pub struct GuestStatusBody {
    key: String,
    status: String,
}

/// `POST /v1/support/guest/status` — the author closes the request or opens it again.
pub async fn guest_status(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    guest_calls(&app, &headers)?;
    let b: GuestStatusBody = parse(&body)?;
    let (id, key) = guest_ref(&b.key).ok_or_else(no_ticket)?;
    if b.status != "closed" && b.status != "open" {
        return Err(invalid("Обращение можно только закрыть или открыть снова"));
    }
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let t = guest_match(db::ticket_for_update(&tx, id).await?, key)?;
    if !t.guest_confirmed {
        return Err(no_ticket());
    }
    if t.status != b.status {
        db::set_ticket_status(&tx, id, &b.status, now_ms().max(t.updated_at + 1)).await?;
    }
    tx.commit().await?;
    guest_json(&c, id).await
}

#[derive(Deserialize)]
pub struct GuestFileBody {
    key: String,
    id: i64,
}

/// `POST /v1/support/guest/file` — an attachment of support's answer in a request without an account.
pub async fn guest_file(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let none = || err(StatusCode::NOT_FOUND, "not-found", "Вложение не найдено");
    guest_calls(&app, &headers)?;
    let b: GuestFileBody = parse(&body)?;
    let (id, key) = guest_ref(&b.key).ok_or_else(none)?;
    let c = app.pool.get().await?;
    let t = guest_match(db::ticket(&c, id).await?, key).map_err(|_| none())?;
    if !t.guest_confirmed || b.id <= 0 {
        return Err(none());
    }
    let (name, mime, data) = db::ticket_file_of(&c, b.id, id).await?.ok_or_else(none)?;
    Ok(file_response(&name, mime, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused<T: std::fmt::Debug>(r: Result<T, ApiError>) -> (u16, &'static str) {
        let e = r.expect_err("должно быть отклонено");
        (e.status.as_u16(), e.code)
    }

    #[test]
    fn staff_addresses() {
        assert_eq!(staff_list(" Kot@Tabora.app, ,anna@tabora.app,"), vec!["kot@tabora.app", "anna@tabora.app"]);
        assert!(staff_list("").is_empty() && staff_list(" , ").is_empty());
    }

    #[test]
    fn path_numbers() {
        assert_eq!(number("17"), Some(17));
        for bad in ["", "0", "-1", "+1", "1.5", "a1", " 1", "99999999999999999999"] {
            assert_eq!(number(bad), None, "{bad}");
        }
    }

    #[test]
    fn subjects() {
        assert_eq!(clean_subject("  Не открывается почта \n").ok().as_deref(), Some("Не открывается почта"));
        assert_eq!(clean_subject("Тема\r\nBcc: x@example.org").ok().as_deref(), Some("Тема  Bcc: x@example.org"), "перевод строки не попадает в тему письма");
        assert_eq!(clean_subject(&"я".repeat(SUBJECT_MAX)).map(|s| s.chars().count()).ok(), Some(SUBJECT_MAX), "длина считается в знаках, а не в байтах");
        for bad in ["", "  ", "ab", " a \u{7} ", &"я".repeat(SUBJECT_MAX + 1)] {
            assert_eq!(refused(clean_subject(bad)), (400, "support-invalid"), "{bad}");
        }
    }

    #[test]
    fn texts() {
        assert_eq!(clean_text("  Привет.\r\nВторая\tстрока\u{0}\u{7}\rтретья  ").ok().as_deref(), Some("Привет.\nВторая\tстрока\nтретья"));
        assert_eq!(clean_text("я").ok().as_deref(), Some("я"));
        assert_eq!(clean_text(&"я".repeat(TEXT_MAX)).map(|s| s.chars().count()).ok(), Some(TEXT_MAX));
        for bad in ["", " \n\t ", "\u{0}", &"я".repeat(TEXT_MAX + 1)] {
            assert_eq!(refused(clean_text(bad)), (400, "support-invalid"));
        }
    }

    #[test]
    fn metas() {
        assert_eq!(clean_meta(None).ok(), Some(None));
        assert_eq!(clean_meta(Some(Value::Null)).ok(), Some(None));
        assert_eq!(clean_meta(Some(json!({}))).ok(), Some(None));
        assert_eq!(clean_meta(Some(json!({ "version": "1.4", "os": "macOS" }))).ok().flatten().as_deref(), Some(r#"{"os":"macOS","version":"1.4"}"#));
        assert_eq!(refused(clean_meta(Some(json!(["x"])))), (400, "support-invalid"));
        assert_eq!(refused(clean_meta(Some(json!("строка")))), (400, "support-invalid"));
        assert_eq!(refused(clean_meta(Some(json!({ "pad": "x".repeat(META_MAX) })))), (400, "support-invalid"));
        assert!(clean_meta(Some(json!({ "pad": "x".repeat(META_MAX - 10) }))).is_ok());
    }

    #[test]
    fn file_names() {
        assert_eq!(clean_file_name("снимок экрана.png", "png"), "снимок экрана.png");
        assert_eq!(clean_file_name("../..\\etc/pass\u{7}wd\n.png", "png"), "etcpasswd.png");
        assert_eq!(clean_file_name("C:\\Users\\anna\\shot.jpg", "jpg"), "C:Usersannashot.jpg");
        assert_eq!(clean_file_name("отчёт\u{202E}gnp.exe", "png"), "отчётgnp.exe", "знак смены направления убран");
        assert_eq!(clean_file_name("", "png"), "вложение.png");
        assert_eq!(clean_file_name(" /\\. ", "txt"), "вложение.txt");
        let long = clean_file_name(&format!("{}.webp", "я".repeat(300)), "webp");
        assert!(long.chars().count() == NAME_MAX && long.ends_with(".webp"), "{long}");
        assert_eq!(clean_file_name(&"x".repeat(300), "txt").chars().count(), NAME_MAX);
        let dotted = clean_file_name(&format!("a.{}", "y".repeat(200)), "txt");
        assert_eq!(dotted.chars().count(), NAME_MAX, "слишком длинное «расширение» не сохраняется");
    }

    fn upload(name: &str, mime: &str, data: &[u8]) -> FileBody {
        FileBody { name: Some(name.to_string()), mime: mime.to_string(), data: B64.encode(data) }
    }

    #[test]
    fn uploads() {
        assert!(clean_files(None).expect("без вложений").is_empty());
        let ok = clean_files(Some(vec![upload("a.png", "image/png", b"\x89PNG"), upload("b.jpg", " IMAGE/JPEG ", b"1"), upload("c.webp", "image/webp", &vec![7u8; FILE_MAX]), upload("", "text/plain", b"log")])).expect("четыре вложения");
        assert_eq!(ok.iter().map(|f| (f.name.as_str(), f.mime, f.data.len())).collect::<Vec<_>>(), vec![("a.png", "image/png", 4), ("b.jpg", "image/jpeg", 1), ("c.webp", "image/webp", FILE_MAX), ("вложение.txt", "text/plain", 3)]);
        for mime in ["image/svg+xml", "text/html", "application/pdf", "image/gif", "", "image/png; charset=x"] {
            assert_eq!(refused(clean_files(Some(vec![upload("a", mime, b"x")]))), (400, "support-invalid"), "{mime}");
        }
        assert_eq!(refused(clean_files(Some(vec![upload("a.png", "image/png", &vec![7u8; FILE_MAX + 1])]))), (400, "support-invalid"), "больше 2 МиБ");
        assert_eq!(refused(clean_files(Some(vec![FileBody { name: None, mime: "image/png".into(), data: "A".repeat(FILE_MAX * 2) }]))), (400, "support-invalid"));
        assert_eq!(refused(clean_files(Some(vec![upload("a.png", "image/png", b"")]))), (400, "support-invalid"), "пустое");
        assert_eq!(refused(clean_files(Some(vec![FileBody { name: None, mime: "image/png".into(), data: "@@@".into() }]))), (400, "support-invalid"), "не Base64");
        assert_eq!(refused(clean_files(Some((0..5).map(|_| upload("a.png", "image/png", b"x")).collect()))), (400, "support-invalid"), "пять вложений");
    }

    #[test]
    fn header_names_and_excerpts() {
        assert_eq!(encode_name("shot-1_v2.png"), "shot-1_v2.png");
        assert_eq!(encode_name("снимок 1.png"), "%D1%81%D0%BD%D0%B8%D0%BC%D0%BE%D0%BA%201.png");
        assert_eq!(encode_name("a\"b;c'd%e*f(g).txt"), "a%22b%3Bc%27d%25e%2Af%28g%29.txt");
        assert_eq!(excerpt("привет", 10), "привет");
        assert_eq!(excerpt("привет", 3), "при…");
    }

    #[test]
    fn body_shapes() {
        let t: TicketBody = parse(&Bytes::from_static(r#"{"subject":"Тема","text":"Текст","meta":{"os":"macOS"},"files":[{"name":"a.png","type":"image/png","data":"eA=="}]}"#.as_bytes())).expect("обращение");
        assert_eq!((t.subject.as_str(), t.text.as_str(), t.files.map(|f| f.len())), ("Тема", "Текст", Some(1)));
        let m: MessageBody = parse(&Bytes::from_static(r#"{"text":"Ответ"}"#.as_bytes())).expect("сообщение");
        assert!(m.text == "Ответ" && m.files.is_none());
        for raw in [r#"{"subject":"Тема"}"#, r#"{"subject":1,"text":"x"}"#, r#"{"subject":"Тема","text":"x","files":{}}"#, r#"{"subject":"Тема","text":"x","files":[{"name":"a"}]}"#, "[]", "{"] {
            assert_eq!(refused(parse::<TicketBody>(&Bytes::copy_from_slice(raw.as_bytes())).map(|_| ())), (400, "support-invalid"), "{raw}");
        }
    }
}
