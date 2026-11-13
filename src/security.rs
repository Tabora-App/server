/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Настройки входа: двухфакторная защита, резервный адрес и сброс пароля по коду из письма.
//!
//! Двухфакторная защита — коды приложения на телефоне (TOTP) и десять одноразовых резервных
//! кодов. Секрет в базе зашифрован ключом сервера, от резервных кодов и кодов из писем там
//! только HMAC. Включение, выключение и смена резервного адреса требуют пароль заново, а при
//! включённой защите — ещё и код.
//!
//! Сброс по письму доказывает только доступ к резервному ящику, поэтому второй фактор при нём
//! остаётся обязательным. Сервер меняет лишь пароль аккаунта: ключа сейфа у него нет, сейф на
//! компьютере пользователь открывает сам (проверкой системы или ключом восстановления).

use crate::api::{bad, check_device, client_ip, err, mail_err, parse, too_many, wait_text, ApiResult, App};
use crate::db;
use crate::mail::MailError;
use crate::util::{backup_code, base32, clean_address, clean_digits, clean_name, digits, is_hex, iso, mask_address, now_ms, open, random, same, seal};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

/// Сколько секрет ждёт подтверждения первым кодом.
const SETUP_TTL_MS: i64 = 15 * 60_000;
const MAIL_CODE_TTL_MS: i64 = 30 * 60_000;
const MAIL_CODE_ATTEMPTS: i32 = 5;
const BACKUP_CODES: usize = 10;

/// Текст уведомления на резервный адрес о перемене в настройках входа.
pub fn notice_text(email: &str, what: &str) -> String {
    format!("{what}\n\nАккаунт: {email}\n\nЕсли это сделали не вы, откройте браузер Tabora, сбросьте пароль ключом восстановления и проверьте настройки входа.\n\nПисьмо отправлено автоматически, отвечать на него не нужно.")
}

/// Код для письма: две половины через пробел, так его проще прочитать и набрать.
fn spaced(code: &str) -> String {
    let mid = code.len() / 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

fn new_backup_codes(app: &App, user_id: i64) -> (Vec<String>, Vec<[u8; 32]>) {
    let codes: Vec<String> = (0..BACKUP_CODES).map(|_| backup_code()).collect();
    let hashes = codes.iter().map(|c| app.code_hash(user_id, "backup", &c.replace('-', ""))).collect();
    (codes, hashes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reauth {
    login_hash: String,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

/// Состояние настроек входа для раздела «Безопасность».
pub async fn overview(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    let now = now_ms();
    let left = if sec.two_factor() { db::backup_codes_left(&c, user.id).await? } else { 0 };
    let pending = db::mail_code(&c, user.id, "backup-email").await?.filter(|m| m.expires_at > now && m.attempts < MAIL_CODE_ATTEMPTS);
    Ok(Json(json!({
        "mail": app.mail.can_send(),
        "twoFactor": { "enabled": sec.two_factor(), "since": sec.totp_at.map(iso), "backupCodes": left },
        "backupEmail": sec.backup_email.as_ref().map(|a| json!({ "address": a, "since": sec.backup_email_at.map(iso) })),
        "backupEmailPending": pending.map(|m| json!({ "address": m.address, "expiresAt": iso(m.expires_at) })),
        "recoveryKey": user.recovery.is_some(),
    })))
}

/* ---- двухфакторная защита ---- */

/// Начало настройки: новый секрет ждёт первого кода из приложения. До подтверждения защита выключена.
pub async fn two_factor_setup(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: Reauth = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let c = app.pool.get().await?;
    if db::security(&c, user.id).await?.two_factor() {
        return Err(err(StatusCode::CONFLICT, "2fa-on", "Двухфакторная защита уже включена"));
    }
    app.window(&format!("2fa-setup:{}", user.id), 10, 3_600_000)?;
    let secret = random::<20>();
    db::set_totp_pending(&c, user.id, &seal(&app.totp_key, user.public_id.as_bytes(), &secret), now_ms()).await?;
    let text = base32(&secret);
    let label = format!("Tabora:{}", user.email.replace('@', "%40"));
    Ok(Json(json!({ "secret": text, "uri": format!("otpauth://totp/{label}?secret={text}&issuer=Tabora&algorithm=SHA1&digits=6&period=30") })))
}

/// Первый верный код включает защиту; в ответе резервные коды, они показываются один раз.
pub async fn two_factor_enable(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: CodeBody = parse(&body)?;
    let now = now_ms();
    let key = format!("2fa-enable:{}", user.id);
    let locked = app.limiter.locked(&key, now);
    if locked > 0 {
        return Err(too_many(format!("Слишком много неверных кодов. Повторите через {}", wait_text(locked))));
    }
    let mut c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    if sec.two_factor() {
        return Err(err(StatusCode::CONFLICT, "2fa-on", "Двухфакторная защита уже включена"));
    }
    let expired = || bad("2fa-setup-expired", "Настройка устарела: начните её заново");
    let (Some(blob), Some(at)) = (sec.totp_pending.as_deref(), sec.totp_pending_at) else { return Err(expired()) };
    if now - at > SETUP_TTL_MS {
        return Err(expired());
    }
    let secret = open(&app.totp_key, user.public_id.as_bytes(), blob).ok_or_else(expired)?;
    let Some(step) = clean_digits(&b.code, 6).and_then(|d| app.totp_match(&secret, &d, now)) else {
        app.limiter.fail(&key, now);
        return Err(err(StatusCode::UNAUTHORIZED, "bad-2fa", "Код не подходит. Проверьте время на телефоне и введите свежий код"));
    };
    app.limiter.clear(&key);
    let (codes, hashes) = new_backup_codes(&app, user.id);
    let tx = c.transaction().await?;
    if !db::enable_totp(&tx, user.id, now, step).await? {
        return Err(expired());
    }
    db::replace_backup_codes(&tx, user.id, &hashes).await?;
    tx.commit().await?;
    eprintln!("двухфакторная защита включена: {}", user.public_id);
    app.notify(sec.backup_email, "Tabora: двухфакторная защита включена", notice_text(&user.email, "Для входа в аккаунт теперь нужен код из приложения на телефоне."));
    Ok(Json(json!({ "backupCodes": codes })))
}

pub async fn two_factor_disable(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: Reauth = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    if sec.two_factor() {
        app.second_factor(&c, &user, &sec, b.code.as_deref()).await?;
        db::disable_totp(&c, user.id).await?;
        eprintln!("двухфакторная защита выключена: {}", user.public_id);
        app.notify(sec.backup_email, "Tabora: двухфакторная защита выключена", notice_text(&user.email, "Для входа в аккаунт снова достаточно пароля."));
    }
    Ok(Json(json!({})))
}

/// `POST /v1/account/delete { loginHash, code? }` — the account is deleted at once and for good,
/// after the password is checked again and, with two-step protection on, the code as well. What
/// goes: the mailbox with all its mail and aliases, the encrypted sync data, the keys, the support
/// requests, the devices and every session. The name and the aliases' addresses are never given
/// out again. There is no way back and no waiting period: the owner asked for it this way.
///
/// The mailbox goes first: if the mail server cannot delete it now, nothing is deleted and the
/// request can be repeated. A session of the support site cannot delete the account.
pub async fn delete_account(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: Reauth = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let mut c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    app.second_factor(&c, &user, &sec, b.code.as_deref()).await?;
    // the farewell letter is written in the account's language, which is gone with the account
    let lang = db::lang_for_address(&c, &user.email).await.unwrap_or_else(|_| "ru".to_string());
    if let Some(mail_id) = user.mail_id.as_deref().filter(|_| app.mail.enabled()) {
        app.mail.destroy_account(mail_id).await.map_err(crate::api::mail_err)?;
    }
    let tx = c.transaction().await?;
    db::delete_user(&tx, user.id, crate::api::local_of(&user.email), now_ms()).await?;
    tx.commit().await?;
    drop(c);
    eprintln!("аккаунт удалён: {}", user.public_id);
    if let Some(to) = sec.backup_email {
        let text = format!(
            "Аккаунт {} удалён по запросу его владельца: почтовый ящик со всеми письмами, адреса для сайтов и данные синхронизации стёрты с сервера. Восстановить их нельзя, а адрес больше никому не выдаётся.\n\nПисьмо отправлено автоматически, отвечать на него не нужно.",
            user.email
        );
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = app.send_mail_in(&to, "Tabora: аккаунт удалён", &text, Some(&lang)).await {
                eprintln!("письмо об удалении аккаунта не отправлено: {}", e.code);
            }
        });
    }
    Ok(Json(json!({})))
}

/// Новые резервные коды; прежние перестают действовать.
pub async fn two_factor_codes(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: Reauth = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let mut c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    if !sec.two_factor() {
        return Err(err(StatusCode::CONFLICT, "2fa-off", "Двухфакторная защита выключена"));
    }
    app.second_factor(&c, &user, &sec, b.code.as_deref()).await?;
    let (codes, hashes) = new_backup_codes(&app, user.id);
    let tx = c.transaction().await?;
    db::replace_backup_codes(&tx, user.id, &hashes).await?;
    tx.commit().await?;
    Ok(Json(json!({ "backupCodes": codes })))
}

/* ---- резервный адрес ---- */

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupEmailBody {
    login_hash: String,
    #[serde(default)]
    code: Option<String>,
    address: String,
}

/// Новый резервный адрес: на него уходит код, адрес записывается только после подтверждения.
pub async fn backup_email_set(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: BackupEmailBody = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let address = clean_address(&b.address).ok_or_else(|| bad("bad-address", "Проверьте адрес: он должен выглядеть как имя@почта.зона"))?;
    let c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    // свой адрес и свои алиасы ведут в тот же ящик, в который без пароля не попасть
    let own = match address.split_once('@') {
        Some((local, domain)) if domain == app.domain => address == user.email || db::alias_owned(&c, user.id, local).await?,
        _ => false,
    };
    if own {
        return Err(bad("bad-address", "Резервный адрес должен вести в другой ящик: письма на этот адрес приходят в сам аккаунт"));
    }
    if sec.backup_email.as_deref() == Some(address.as_str()) {
        return Err(err(StatusCode::CONFLICT, "same-address", "Этот адрес уже подтверждён как резервный"));
    }
    if !app.mail.can_send() {
        return Err(mail_err(MailError::Unavailable("почта выключена".into())));
    }
    // второй фактор проверяется последним: одноразовый код не тратится на запрос с ошибкой в адресе
    app.second_factor(&c, &user, &sec, b.code.as_deref()).await?;
    app.window(&format!("bemail:{}", user.id), 3, 3_600_000)?;
    app.window(&format!("bemail-day:{}", user.id), 8, 86_400_000)?;
    let now = now_ms();
    let code = digits(6);
    db::put_mail_code(&c, user.id, "backup-email", &address, &app.code_hash(user.id, "backup-email", &code), now + MAIL_CODE_TTL_MS, now).await?;
    drop(c);
    let text = format!(
        "Код подтверждения: {}\n\nЕго запросили, чтобы сделать этот адрес резервным для аккаунта {}. На резервный адрес приходит код для сброса забытого пароля.\n\nКод действует 30 минут. Введите его в браузере Tabora: «Настройки → Аккаунт → Безопасность».\n\nЕсли вы этого не делали, ничего не нужно: без кода адрес не привяжется.\n\nПисьмо отправлено автоматически, отвечать на него не нужно.",
        spaced(&code),
        user.email
    );
    app.send_mail(&address, "Tabora: подтверждение резервного адреса", &text).await?;
    Ok(Json(json!({ "pending": { "address": address, "expiresAt": iso(now + MAIL_CODE_TTL_MS) } })))
}

pub async fn backup_email_verify(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: CodeBody = parse(&body)?;
    let now = now_ms();
    let c = app.pool.get().await?;
    let gone = || bad("no-code", "Код больше не действует: запросите новый");
    let Some(m) = db::mail_code(&c, user.id, "backup-email").await? else { return Err(gone()) };
    if m.expires_at <= now || m.attempts >= MAIL_CODE_ATTEMPTS {
        db::delete_mail_code(&c, user.id, "backup-email").await?;
        return Err(gone());
    }
    let ok = clean_digits(&b.code, 6).map(|d| same(&app.code_hash(user.id, "backup-email", &d), &m.code_hash)).unwrap_or(false);
    if !ok {
        let n = db::mail_code_attempt(&c, user.id, "backup-email").await?;
        return Err(bad("bad-code", if n >= MAIL_CODE_ATTEMPTS { "Код неверный, попытки закончились: запросите новый" } else { "Код неверный" }));
    }
    let old = db::security(&c, user.id).await?.backup_email;
    db::set_backup_email(&c, user.id, Some(&m.address), now).await?;
    db::delete_mail_code(&c, user.id, "backup-email").await?;
    // код сброса, отправленный на прежний адрес, больше не действует
    db::delete_mail_code(&c, user.id, "reset").await?;
    if let Some(old) = old.filter(|o| *o != m.address) {
        let what = format!("Резервным адресом аккаунта стал {}. На этот адрес код для сброса пароля больше не придёт.", mask_address(&m.address));
        app.notify(Some(old), "Tabora: резервный адрес изменён", notice_text(&user.email, &what));
    }
    Ok(Json(json!({ "address": m.address })))
}

pub async fn backup_email_remove(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: Reauth = parse(&body)?;
    app.reauth(&user, &b.login_hash, &client_ip(&headers))?;
    let c = app.pool.get().await?;
    let sec = db::security(&c, user.id).await?;
    app.second_factor(&c, &user, &sec, b.code.as_deref()).await?;
    db::set_backup_email(&c, user.id, None, now_ms()).await?;
    db::delete_mail_code(&c, user.id, "backup-email").await?;
    db::delete_mail_code(&c, user.id, "reset").await?;
    app.notify(sec.backup_email, "Tabora: резервный адрес удалён", notice_text(&user.email, "Этот адрес больше не резервный: код для сброса пароля сюда не придёт."));
    Ok(Json(json!({})))
}

/* ---- сброс пароля по коду из письма ---- */

#[derive(Deserialize)]
pub struct EmailBody {
    email: String,
}

/// Запрос кода сброса. Ответ одинаков для любого адреса: есть ли аккаунт и резервный адрес,
/// по нему не узнать. Письмо уходит в фоне, чтобы и время ответа об этом не говорило.
pub async fn reset_email_start(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let ip = client_ip(&headers);
    app.window(&format!("reset-mail-ip:{ip}"), 5, 3_600_000)?;
    let b: EmailBody = parse(&body)?;
    if let Some((_, email)) = app.parse_email(&b.email) {
        let c = app.pool.get().await?;
        if let Some(user) = db::user_by_email(&c, &email).await? {
            if let Some(address) = db::security(&c, user.id).await?.backup_email {
                let now = now_ms();
                // на аккаунт не больше трёх писем в сутки; о превышении не сообщаем
                if app.mail.can_send() && app.limiter.hit(&format!("reset-mail:{}", user.id), 3, 86_400_000, now).is_ok() {
                    let code = digits(8);
                    db::put_mail_code(&c, user.id, "reset", &address, &app.code_hash(user.id, "reset", &code), now + MAIL_CODE_TTL_MS, now).await?;
                    let text = format!(
                        "Код для сброса пароля аккаунта {}: {}\n\nКод действует 30 минут. Введите его в окне «Забыли пароль» браузера Tabora.\n\nЕсли вы не запрашивали сброс, ничего не делайте: пароль останется прежним. Никому не сообщайте этот код.\n\nПисьмо отправлено автоматически, отвечать на него не нужно.",
                        user.email,
                        spaced(&code)
                    );
                    let sender = app.clone();
                    tokio::spawn(async move {
                        if let Err(e) = sender.send_mail(&address, "Tabora: сброс пароля", &text).await {
                            eprintln!("письмо с кодом сброса не отправлено: {}", e.code);
                        }
                    });
                }
            }
        }
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetEmailBody {
    email: String,
    code: String,
    new_login_hash: String,
    #[serde(default)]
    kdf: i64,
    #[serde(default)]
    totp: Option<String>,
    /// устройство, с которого сбрасывают пароль: оно сразу входит в аккаунт
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_name: String,
    /// "session" — доступ к почте по сессии (веб-версия), без пароля приложения
    #[serde(default)]
    mail_access: Option<String>,
}

/// Новый пароль по коду из письма. При включённой двухфакторной защите нужен и её код: пока его
/// нет, код из письма не расходуется. Устройство, назвавшее себя, сразу получает сессию: второй
/// фактор уже предъявлен, а одноразовый код не должен тратиться дважды (на сброс и на вход).
pub async fn reset_email_confirm(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let ip = client_ip(&headers);
    app.window(&format!("reset-mail-confirm:{ip}"), 20, 3_600_000)?;
    let b: ResetEmailBody = parse(&body)?;
    if !is_hex(&b.new_login_hash, 64) || b.kdf != 2 {
        return Err(bad("bad-request", "Некорректный запрос: новый хеш входа"));
    }
    if let Some(id) = &b.device_id {
        check_device(id)?;
    }
    let wrong = || bad("bad-code", "Код не подходит или устарел: запросите новый");
    let Some((_, email)) = app.parse_email(&b.email) else { return Err(wrong()) };
    let now = now_ms();
    let c = app.pool.get().await?;
    let Some(user) = db::user_by_email(&c, &email).await? else { return Err(wrong()) };
    let Some(m) = db::mail_code(&c, user.id, "reset").await? else { return Err(wrong()) };
    if m.expires_at <= now || m.attempts >= MAIL_CODE_ATTEMPTS {
        db::delete_mail_code(&c, user.id, "reset").await?;
        return Err(wrong());
    }
    let ok = clean_digits(&b.code, 8).map(|d| same(&app.code_hash(user.id, "reset", &d), &m.code_hash)).unwrap_or(false);
    if !ok {
        db::mail_code_attempt(&c, user.id, "reset").await?;
        return Err(wrong());
    }
    let sec = db::security(&c, user.id).await?;
    app.second_factor(&c, &user, &sec, b.totp.as_deref()).await?;
    db::delete_mail_code(&c, user.id, "reset").await?;
    app.finish_reset(&c, &user, &b.new_login_hash, now).await?;
    eprintln!("пароль сброшен по коду из письма: {}", user.public_id);
    app.notify(sec.backup_email.clone(), "Tabora: пароль аккаунта сброшен", notice_text(&user.email, "Пароль аккаунта сброшен по коду из письма на этот адрес. Все устройства вышли из аккаунта."));
    let Some(device_id) = b.device_id else { return Ok(Json(json!({}))) };
    let device_name = clean_name(&b.device_name, "Устройство");
    db::upsert_device(&c, user.id, &device_id, &device_name, now).await?;
    let session = app.new_session(&c, user.id, &device_id, now).await?;
    crate::i18n::remember(&c, user.id, &headers).await;
    drop(c);
    // пароли приложений только что отозваны все: прежнего у устройства нет
    let mail = app.device_mail(&user, &device_id, &device_name, None, b.mail_access.as_deref()).await;
    Ok(Json(json!({ "userId": user.public_id, "session": session, "kdf": 2, "mail": mail })))
}
