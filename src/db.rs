/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! PostgreSQL: схема и запросы. Время везде — миллисекунды с 1970 года (BIGINT).
//! Пароль здесь не хранится: только HMAC от хеша входа, который браузер вывел из пароля.

use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::time::Duration;
use tokio_postgres::error::SqlState;
use tokio_postgres::{NoTls, Row};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
  id           BIGSERIAL PRIMARY KEY,
  public_id    TEXT NOT NULL UNIQUE,
  email        TEXT NOT NULL UNIQUE,
  salt         BYTEA NOT NULL,
  verifier     BYTEA NOT NULL,
  kdf          SMALLINT NOT NULL,
  recovery     TEXT,
  recovery_at  BIGINT,
  mail_id      TEXT,
  created_at   BIGINT NOT NULL,
  password_at  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id   TEXT NOT NULL,
  name        TEXT NOT NULL,
  first_seen  BIGINT NOT NULL,
  last_seen   BIGINT NOT NULL,
  mail_cred   TEXT,
  PRIMARY KEY (user_id, device_id)
);
-- Сессия не истекает по времени: человек остаётся в аккаунте, пока сам не выйдет. Завершают её
-- только выход, отзыв устройства из списка, смена и сброс пароля (удаление строки). Столбец
-- expires_at остался от прежней схемы (сессии на 180 дней) и нигде не читается.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  BYTEA PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id   TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  last_seen   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS reset_nonces (
  user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  nonce_hash  BYTEA NOT NULL,
  expires_at  BIGINT NOT NULL
);
-- Алиас не удаляется из таблицы никогда: освободившийся адрес мог бы занять другой человек
-- и получать письма, адресованные прежнему владельцу (в том числе ссылки сброса паролей).
CREATE TABLE IF NOT EXISTS aliases (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  local       TEXT NOT NULL UNIQUE,
  site        TEXT NOT NULL DEFAULT '',
  space       TEXT NOT NULL DEFAULT '',
  origin      TEXT NOT NULL DEFAULT 'manual',
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  BIGINT NOT NULL,
  deleted_at  BIGINT
);
CREATE INDEX IF NOT EXISTS aliases_user ON aliases(user_id);
-- Имена удалённых ящиков: по той же причине повторно не выдаются.
CREATE TABLE IF NOT EXISTS retired_names (
  local  TEXT PRIMARY KEY,
  at     BIGINT NOT NULL
);
-- Двухфакторная защита входа. Секрет TOTP зашифрован ключом сервера (util::seal), totp_at —
-- когда защита включена (NULL — выключена), totp_step — последний принятый шаг времени (код
-- нельзя использовать дважды). Счётчик неудач живёт в базе, а не в памяти: шесть цифр
-- перебираются дёшево, и перезапуск сервера не должен обнулять паузу.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_at BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_step BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_at BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_fails INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_locked_until BIGINT NOT NULL DEFAULT 0;
-- Резервный адрес: сюда приходит код сброса пароля. Записывается только после подтверждения.
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_email TEXT;
-- Язык писем аккаунта (ru, en, uk, es): его присылает приложение своими запросами.
ALTER TABLE users ADD COLUMN IF NOT EXISTS lang TEXT NOT NULL DEFAULT 'ru';
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_email_at BIGINT;
-- Одноразовые резервные коды входа: в базе только HMAC от кода.
CREATE TABLE IF NOT EXISTS backup_codes (
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  BYTEA NOT NULL,
  used_at    BIGINT,
  PRIMARY KEY (user_id, code_hash)
);
-- Коды из писем: подтверждение резервного адреса (backup-email) и сброс пароля (reset).
-- На назначение — один действующий код; в базе только HMAC от него.
CREATE TABLE IF NOT EXISTS mail_codes (
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL,
  address     TEXT NOT NULL,
  code_hash   BYTEA NOT NULL,
  expires_at  BIGINT NOT NULL,
  attempts    INT NOT NULL DEFAULT 0,
  created_at  BIGINT NOT NULL,
  PRIMARY KEY (user_id, purpose)
);
-- Защита от подбора пароля: неудачные входы в аккаунт с незнакомых устройств со всех адресов
-- сразу. Счёт в базе, а не в памяти: перезапуск сервера не даёт новых попыток.
CREATE TABLE IF NOT EXISTS login_guard (
  user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  fails        INT NOT NULL DEFAULT 0,
  last_fail    BIGINT NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  noticed_at   BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);
-- Ключи шифрования почты (OpenPGP). Открытый ключ публикуется в каталоге (wkd_hash — имя записи).
-- blob — закрытый ключ, зашифрованный браузером ключом данных; wrap_pw и wrap_rk — ключ данных,
-- зашифрованный ключом из пароля и из ключа восстановления. Все три блока сверху запечатаны
-- ключом сервера. rev растёт с каждым изменением: по нему отсекаются одновременные записи.
CREATE TABLE IF NOT EXISTS mail_keys (
  user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  rev          BIGINT NOT NULL DEFAULT 0,
  fingerprint  TEXT,
  public_key   BYTEA,
  wkd_hash     TEXT,
  blob         BYTEA,
  wrap_pw      BYTEA,
  wrap_rk      BYTEA,
  updated_at   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_keys_wkd ON mail_keys (wkd_hash);
-- Синхронизация. Записи зашифрованы браузером, ключа у сервера нет: blob для него непрозрачен.
-- rev в sync_state — счётчик изменений пользователя (не уменьшается никогда, в том числе после
-- сброса), gen — поколение данных (растёт при сбросе), key_id — отпечаток ключа шифрования.
-- У записи rev — номер изменения, которым она сохранена; удалённая запись остаётся надгробием
-- (deleted, blob пуст), чтобы об удалении узнали остальные устройства.
CREATE TABLE IF NOT EXISTS sync_state (
  user_id  BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  rev      BIGINT NOT NULL DEFAULT 0,
  gen      BIGINT NOT NULL DEFAULT 1,
  key_id   TEXT
);
CREATE TABLE IF NOT EXISTS sync_items (
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  coll        TEXT NOT NULL,
  id          TEXT NOT NULL,
  rev         BIGINT NOT NULL,
  deleted     BOOLEAN NOT NULL DEFAULT FALSE,
  blob        BYTEA,
  updated_at  BIGINT NOT NULL,
  PRIMARY KEY (user_id, coll, id)
);
CREATE INDEX IF NOT EXISTS sync_items_rev ON sync_items (user_id, rev);
-- Обращения в поддержку. Переписку читает поддержка, поэтому она хранится открыто. status:
-- open (ждёт поддержку), answered (поддержка ответила), closed. meta — сведения о браузере от
-- клиента (JSON текстом). user_read_at и staff_read_at — когда обращение последний раз читали
-- автор и поддержка: сообщения другой стороны новее отметки считаются непрочитанными.
CREATE TABLE IF NOT EXISTS tickets (
  id             BIGSERIAL PRIMARY KEY,
  user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject        TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'open',
  meta           TEXT,
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL,
  user_read_at   BIGINT NOT NULL DEFAULT 0,
  staff_read_at  BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tickets_user ON tickets (user_id);
CREATE INDEX IF NOT EXISTS tickets_updated ON tickets (updated_at);
-- staff — сообщение написано поддержкой; author_id — кто именно его написал.
CREATE TABLE IF NOT EXISTS ticket_messages (
  id          BIGSERIAL PRIMARY KEY,
  ticket_id   BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  staff       BOOLEAN NOT NULL,
  author_id   BIGINT,
  body        TEXT NOT NULL,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_messages_ticket ON ticket_messages (ticket_id);
CREATE TABLE IF NOT EXISTS ticket_files (
  id          BIGSERIAL PRIMARY KEY,
  message_id  BIGINT NOT NULL REFERENCES ticket_messages(id) ON DELETE CASCADE,
  ticket_id   BIGINT NOT NULL,
  name        TEXT NOT NULL,
  mime        TEXT NOT NULL,
  size        INT NOT NULL,
  data        BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_files_message ON ticket_files (message_id);
CREATE INDEX IF NOT EXISTS ticket_files_ticket ON ticket_files (ticket_id);
-- A sign-in for one purpose. '' is an ordinary session; 'support' is a session of the support
-- site: it reaches the support requests of its account and nothing else (api.rs: auth_for).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';
-- Requests from people without an account (the support site). Such a request has no user_id:
-- its author is known by an e-mail address. Support sees it only after the address is confirmed
-- with the link from the letter (guest_confirmed_at); guest_key is the secret of that link, and
-- whoever has the link reads the request and answers in it. guest_lang is the language of the
-- letters to the author.
ALTER TABLE tickets ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS guest_email TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS guest_key TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS guest_lang TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS guest_confirmed_at BIGINT;
CREATE INDEX IF NOT EXISTS tickets_guest ON tickets (guest_email) WHERE guest_email IS NOT NULL;
"#;

#[derive(Debug)]
pub enum DbError {
    Taken,
    Other(String),
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        if e.code() == Some(&SqlState::UNIQUE_VIOLATION) {
            DbError::Taken
        } else {
            DbError::Other(e.to_string())
        }
    }
}

impl From<deadpool_postgres::PoolError> for DbError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        DbError::Other(e.to_string())
    }
}

pub fn pool(url: &str) -> Result<Pool, String> {
    let cfg: tokio_postgres::Config = url.parse().map_err(|e| format!("строка подключения к базе: {e}"))?;
    let mgr = Manager::from_config(cfg, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Fast });
    Pool::builder(mgr)
        .max_size(8)
        .runtime(Runtime::Tokio1)
        .wait_timeout(Some(Duration::from_secs(5)))
        .create_timeout(Some(Duration::from_secs(5)))
        .build()
        .map_err(|e| format!("пул подключений: {e}"))
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub public_id: String,
    pub email: String,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub kdf: i16,
    pub recovery: Option<String>,
    pub mail_id: Option<String>,
}

const USER_COLS: &str = "id, public_id, email, salt, verifier, kdf, recovery, mail_id";

fn user(row: &Row) -> User {
    User {
        id: row.get(0),
        public_id: row.get(1),
        email: row.get(2),
        salt: row.get(3),
        verifier: row.get(4),
        kdf: row.get(5),
        recovery: row.get(6),
        mail_id: row.get(7),
    }
}

pub async fn user_by_email<C: GenericClient>(c: &C, email: &str) -> Result<Option<User>, DbError> {
    Ok(c.query_opt(&format!("SELECT {USER_COLS} FROM users WHERE email = $1"), &[&email]).await?.as_ref().map(user))
}

pub async fn user_by_id<C: GenericClient>(c: &C, id: i64) -> Result<Option<User>, DbError> {
    Ok(c.query_opt(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"), &[&id]).await?.as_ref().map(user))
}

/// Занято ли имя: ящиком, алиасом (в том числе удалённым) или именем удалённого ящика.
pub async fn name_taken<C: GenericClient>(c: &C, local: &str, email: &str) -> Result<bool, DbError> {
    let row = c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) OR EXISTS(SELECT 1 FROM aliases WHERE local = $2) OR EXISTS(SELECT 1 FROM retired_names WHERE local = $2)",
            &[&email, &local],
        )
        .await?;
    Ok(row.get(0))
}

pub async fn insert_user<C: GenericClient>(c: &C, public_id: &str, email: &str, salt: &[u8], verifier: &[u8], kdf: i16, now: i64) -> Result<i64, DbError> {
    let row = c
        .query_one(
            "INSERT INTO users (public_id, email, salt, verifier, kdf, created_at, password_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id",
            &[&public_id, &email, &salt, &verifier, &kdf, &now],
        )
        .await?;
    Ok(row.get(0))
}

pub async fn set_mail_id<C: GenericClient>(c: &C, user_id: i64, mail_id: &str) -> Result<(), DbError> {
    c.execute("UPDATE users SET mail_id = $2 WHERE id = $1", &[&user_id, &mail_id]).await?;
    Ok(())
}

pub async fn set_password<C: GenericClient>(c: &C, user_id: i64, salt: &[u8], verifier: &[u8], kdf: i16, now: i64) -> Result<(), DbError> {
    c.execute("UPDATE users SET salt = $2, verifier = $3, kdf = $4, password_at = $5 WHERE id = $1", &[&user_id, &salt, &verifier, &kdf, &now]).await?;
    Ok(())
}

pub async fn set_recovery<C: GenericClient>(c: &C, user_id: i64, verifier: Option<&str>, now: i64) -> Result<(), DbError> {
    c.execute("UPDATE users SET recovery = $2, recovery_at = $3 WHERE id = $1", &[&user_id, &verifier, &now]).await?;
    Ok(())
}

pub async fn signups_since<C: GenericClient>(c: &C, since: i64) -> Result<i64, DbError> {
    Ok(c.query_one("SELECT count(*) FROM users WHERE created_at > $1", &[&since]).await?.get(0))
}

/// Устройство входит: запись создаётся или обновляется. Возвращает прежний пароль приложения,
/// если он был (его надо отозвать на почтовом сервере).
pub async fn upsert_device<C: GenericClient>(c: &C, user_id: i64, device_id: &str, name: &str, now: i64) -> Result<Option<String>, DbError> {
    let old: Option<String> = c
        .query_opt("SELECT mail_cred FROM devices WHERE user_id = $1 AND device_id = $2", &[&user_id, &device_id])
        .await?
        .and_then(|r| r.get(0));
    c.execute(
        "INSERT INTO devices (user_id, device_id, name, first_seen, last_seen) VALUES ($1, $2, $3, $4, $4)
         ON CONFLICT (user_id, device_id) DO UPDATE SET name = EXCLUDED.name, last_seen = EXCLUDED.last_seen",
        &[&user_id, &device_id, &name, &now],
    )
    .await?;
    Ok(old)
}

pub async fn set_device_cred<C: GenericClient>(c: &C, user_id: i64, device_id: &str, cred: Option<&str>) -> Result<(), DbError> {
    c.execute("UPDATE devices SET mail_cred = $3 WHERE user_id = $1 AND device_id = $2", &[&user_id, &device_id, &cred]).await?;
    Ok(())
}

pub async fn clear_device_creds<C: GenericClient>(c: &C, user_id: i64) -> Result<(), DbError> {
    c.execute("UPDATE devices SET mail_cred = NULL WHERE user_id = $1", &[&user_id]).await?;
    Ok(())
}

pub async fn device_cred<C: GenericClient>(c: &C, user_id: i64, device_id: &str) -> Result<Option<String>, DbError> {
    Ok(c.query_opt("SELECT mail_cred FROM devices WHERE user_id = $1 AND device_id = $2", &[&user_id, &device_id]).await?.and_then(|r| r.get(0)))
}

/// Входило ли это устройство в аккаунт раньше (и не было ли с тех пор завершено).
pub async fn device_known<C: GenericClient>(c: &C, user_id: i64, device_id: &str) -> Result<bool, DbError> {
    Ok(c.query_one("SELECT EXISTS(SELECT 1 FROM devices WHERE user_id = $1 AND device_id = $2)", &[&user_id, &device_id]).await?.get(0))
}

/// Сколько ещё закрыт вход в аккаунт с незнакомых устройств (0 — открыт).
pub async fn guard_locked<C: GenericClient>(c: &C, user_id: i64, now: i64) -> Result<i64, DbError> {
    let until: Option<i64> = c.query_opt("SELECT locked_until FROM login_guard WHERE user_id = $1", &[&user_id]).await?.map(|r| r.get(0));
    Ok((until.unwrap_or(0) - now).max(0))
}

/// Неверный пароль с незнакомого устройства. Счёт обнуляется, если сутки было тихо. Возвращает
/// назначенную паузу и признак «пора написать владельцу» (не чаще раза в сутки).
pub async fn guard_fail<C: GenericClient>(c: &C, user_id: i64, now: i64, pause: fn(i32) -> i64) -> Result<(i64, bool), DbError> {
    let r = c
        .query_one(
            "INSERT INTO login_guard (user_id, fails, last_fail) VALUES ($1, 1, $2)
             ON CONFLICT (user_id) DO UPDATE SET fails = CASE WHEN login_guard.last_fail < $2 - 86400000 THEN 1 ELSE login_guard.fails + 1 END, last_fail = $2
             RETURNING fails, noticed_at",
            &[&user_id, &now],
        )
        .await?;
    let fails: i32 = r.get(0);
    let noticed: i64 = r.get(1);
    let wait = pause(fails);
    let notice = wait > 0 && noticed < now - 86_400_000;
    c.execute(
        "UPDATE login_guard SET locked_until = $2, noticed_at = CASE WHEN $3 THEN $4 ELSE noticed_at END WHERE user_id = $1",
        &[&user_id, &(now + wait), &notice, &now],
    )
    .await?;
    Ok((wait, notice))
}

pub async fn guard_clear<C: GenericClient>(c: &C, user_id: i64) -> Result<(), DbError> {
    c.execute("DELETE FROM login_guard WHERE user_id = $1", &[&user_id]).await?;
    Ok(())
}

pub struct Device {
    pub id: String,
    pub name: String,
    pub at: i64,
    /// у устройства есть действующая сессия (иначе оно вышло и осталось только в списке)
    pub active: bool,
}

pub async fn devices<C: GenericClient>(c: &C, user_id: i64) -> Result<Vec<Device>, DbError> {
    let rows = c
        .query(
            "SELECT d.device_id, d.name, d.last_seen, EXISTS(SELECT 1 FROM sessions s WHERE s.user_id = d.user_id AND s.device_id = d.device_id)
             FROM devices d WHERE d.user_id = $1 ORDER BY d.last_seen DESC",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(|r| Device { id: r.get(0), name: r.get(1), at: r.get(2), active: r.get(3) }).collect())
}

/// Завершить все сессии одного устройства. Возвращает, сколько их было.
pub async fn delete_device_sessions<C: GenericClient>(c: &C, user_id: i64, device_id: &str) -> Result<u64, DbError> {
    Ok(c.execute("DELETE FROM sessions WHERE user_id = $1 AND device_id = $2", &[&user_id, &device_id]).await?)
}

/// Убрать устройство из списка: только когда у него не осталось ни сессий, ни доступа к почте.
pub async fn forget_device<C: GenericClient>(c: &C, user_id: i64, device_id: &str) -> Result<u64, DbError> {
    Ok(c
        .execute(
            "DELETE FROM devices d WHERE d.user_id = $1 AND d.device_id = $2 AND d.mail_cred IS NULL
             AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = d.user_id AND s.device_id = d.device_id)",
            &[&user_id, &device_id],
        )
        .await?)
}

pub async fn create_session<C: GenericClient>(c: &C, token_hash: &[u8], user_id: i64, device_id: &str, now: i64, scope: &str) -> Result<(), DbError> {
    // expires_at не читается (сессия бессрочна); столбец обязателен в прежней схеме — пишем 0
    c.execute(
        "INSERT INTO sessions (token_hash, user_id, device_id, created_at, expires_at, last_seen, scope) VALUES ($1, $2, $3, $4, 0, $4, $5)",
        &[&token_hash, &user_id, &device_id, &now, &scope],
    )
    .await?;
    Ok(())
}

/// Действующая сессия: пользователь и устройство. Срока у сессии нет: она действует, пока строка
/// не удалена (выход, отзыв устройства, смена или сброс пароля). Отметка «был в сети» обновляется
/// не чаще раза в час.
/// The session of a token: its account, its device and its scope ('' is an ordinary session).
pub async fn session<C: GenericClient>(c: &C, token_hash: &[u8], now: i64) -> Result<Option<(User, String, String)>, DbError> {
    let row = c
        .query_opt(
            "SELECT u.id, u.public_id, u.email, u.salt, u.verifier, u.kdf, u.recovery, u.mail_id, s.device_id, s.last_seen, s.scope
             FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1",
            &[&token_hash],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let u = user(&row);
    let device_id: String = row.get(8);
    let last_seen: i64 = row.get(9);
    if now - last_seen > 3_600_000 {
        c.execute("UPDATE sessions SET last_seen = $2 WHERE token_hash = $1", &[&token_hash, &now]).await?;
        c.execute("UPDATE devices SET last_seen = $3 WHERE user_id = $1 AND device_id = $2", &[&u.id, &device_id, &now]).await?;
    }
    Ok(Some((u, device_id, row.get(10))))
}

/// Язык писем для адреса: свой ящик аккаунта, его резервный адрес или адрес, ждущий
/// подтверждения кодом. Чужой адрес — русский.
pub async fn lang_for_address<C: GenericClient>(c: &C, address: &str) -> Result<String, DbError> {
    let row = c
        .query_opt(
            "SELECT lang FROM users WHERE email = $1 OR backup_email = $1
             UNION ALL SELECT u.lang FROM mail_codes m JOIN users u ON u.id = m.user_id WHERE m.address = $1
             LIMIT 1",
            &[&address],
        )
        .await?;
    Ok(row.map(|r| r.get(0)).unwrap_or_else(|| "ru".to_string()))
}

pub async fn delete_session<C: GenericClient>(c: &C, token_hash: &[u8]) -> Result<(), DbError> {
    c.execute("DELETE FROM sessions WHERE token_hash = $1", &[&token_hash]).await?;
    Ok(())
}

/// Завершить сессии пользователя, кроме одной (None — все). Возвращает устройства, у которых
/// не осталось ни одной сессии: их пароли приложений надо отозвать.
pub async fn delete_sessions<C: GenericClient>(c: &C, user_id: i64, keep: Option<&[u8]>) -> Result<Vec<(String, Option<String>)>, DbError> {
    match keep {
        Some(k) => c.execute("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", &[&user_id, &k]).await?,
        None => c.execute("DELETE FROM sessions WHERE user_id = $1", &[&user_id]).await?,
    };
    let rows = c
        .query(
            "SELECT d.device_id, d.mail_cred FROM devices d WHERE d.user_id = $1
             AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = d.user_id AND s.device_id = d.device_id)",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

pub async fn has_session<C: GenericClient>(c: &C, user_id: i64, device_id: &str) -> Result<bool, DbError> {
    Ok(c.query_one("SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id = $1 AND device_id = $2)", &[&user_id, &device_id]).await?.get(0))
}

/// Уборка просроченного: одноразовые коды и незавершённая настройка. Сессии сюда не входят —
/// по времени они не истекают.
pub async fn purge_expired<C: GenericClient>(c: &C, now: i64) -> Result<u64, DbError> {
    let n = c.execute("DELETE FROM reset_nonces WHERE expires_at <= $1", &[&now]).await?;
    c.execute("DELETE FROM mail_codes WHERE expires_at <= $1", &[&now]).await?;
    c.execute("UPDATE users SET totp_pending = NULL, totp_pending_at = NULL WHERE totp_pending_at IS NOT NULL AND totp_pending_at <= $1", &[&(now - 3_600_000)]).await?;
    // a request without an account whose address was not confirmed in two days: nobody opened the link
    c.execute("DELETE FROM tickets WHERE guest_email IS NOT NULL AND guest_confirmed_at IS NULL AND created_at <= $1", &[&(now - GUEST_UNCONFIRMED_MS)]).await?;
    Ok(n)
}

/// How long a request without an account waits for its address to be confirmed.
pub const GUEST_UNCONFIRMED_MS: i64 = 2 * 86_400_000;

pub async fn put_nonce<C: GenericClient>(c: &C, user_id: i64, hash: &[u8], expires: i64) -> Result<(), DbError> {
    c.execute(
        "INSERT INTO reset_nonces (user_id, nonce_hash, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET nonce_hash = EXCLUDED.nonce_hash, expires_at = EXCLUDED.expires_at",
        &[&user_id, &hash, &expires],
    )
    .await?;
    Ok(())
}

/// Одноразовый nonce: забирается из базы при любой попытке, даже неудачной.
pub async fn take_nonce<C: GenericClient>(c: &C, user_id: i64) -> Result<Option<(Vec<u8>, i64)>, DbError> {
    Ok(c.query_opt("DELETE FROM reset_nonces WHERE user_id = $1 RETURNING nonce_hash, expires_at", &[&user_id]).await?.map(|r| (r.get(0), r.get(1))))
}

#[derive(Clone, Debug)]
pub struct Alias {
    pub id: i64,
    pub local: String,
    pub site: String,
    pub space: String,
    pub origin: String,
    pub enabled: bool,
    pub created_at: i64,
}

fn alias(row: &Row) -> Alias {
    Alias { id: row.get(0), local: row.get(1), site: row.get(2), space: row.get(3), origin: row.get(4), enabled: row.get(5), created_at: row.get(6) }
}

/// Действующие алиасы пользователя (без удалённых), новые сверху.
pub async fn aliases<C: GenericClient>(c: &C, user_id: i64) -> Result<Vec<Alias>, DbError> {
    let rows = c
        .query("SELECT id, local, site, space, origin, enabled, created_at FROM aliases WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC, id DESC", &[&user_id])
        .await?;
    Ok(rows.iter().map(alias).collect())
}

pub async fn insert_alias<C: GenericClient>(c: &C, user_id: i64, local: &str, site: &str, space: &str, origin: &str, now: i64) -> Result<Alias, DbError> {
    let row = c
        .query_one(
            "INSERT INTO aliases (user_id, local, site, space, origin, created_at) VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, local, site, space, origin, enabled, created_at",
            &[&user_id, &local, &site, &space, &origin, &now],
        )
        .await?;
    Ok(alias(&row))
}

pub async fn update_alias<C: GenericClient>(c: &C, user_id: i64, id: i64, enabled: Option<bool>, site: Option<&str>, space: Option<&str>) -> Result<Option<Alias>, DbError> {
    let row = c
        .query_opt(
            "UPDATE aliases SET enabled = COALESCE($3, enabled), site = COALESCE($4, site), space = COALESCE($5, space)
             WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL RETURNING id, local, site, space, origin, enabled, created_at",
            &[&user_id, &id, &enabled, &site, &space],
        )
        .await?;
    Ok(row.as_ref().map(alias))
}

pub async fn delete_alias<C: GenericClient>(c: &C, user_id: i64, id: i64, now: i64) -> Result<bool, DbError> {
    Ok(c.execute("UPDATE aliases SET deleted_at = $3, enabled = FALSE WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL", &[&user_id, &id, &now]).await? > 0)
}

/* ---- двухфакторная защита, резервный адрес, коды из писем ---- */

#[derive(Clone, Debug, Default)]
pub struct Security {
    pub totp_secret: Option<Vec<u8>>,
    pub totp_at: Option<i64>,
    pub totp_pending: Option<Vec<u8>>,
    pub totp_pending_at: Option<i64>,
    pub totp_locked_until: i64,
    pub backup_email: Option<String>,
    pub backup_email_at: Option<i64>,
}

impl Security {
    pub fn two_factor(&self) -> bool {
        self.totp_at.is_some() && self.totp_secret.is_some()
    }
}

pub async fn security<C: GenericClient>(c: &C, user_id: i64) -> Result<Security, DbError> {
    let r = c
        .query_one(
            "SELECT totp_secret, totp_at, totp_pending, totp_pending_at, totp_locked_until, backup_email, backup_email_at FROM users WHERE id = $1",
            &[&user_id],
        )
        .await?;
    Ok(Security {
        totp_secret: r.get(0),
        totp_at: r.get(1),
        totp_pending: r.get(2),
        totp_pending_at: r.get(3),
        totp_locked_until: r.get(4),
        backup_email: r.get(5),
        backup_email_at: r.get(6),
    })
}

pub async fn set_totp_pending<C: GenericClient>(c: &C, user_id: i64, blob: &[u8], now: i64) -> Result<(), DbError> {
    c.execute("UPDATE users SET totp_pending = $2, totp_pending_at = $3 WHERE id = $1", &[&user_id, &blob, &now]).await?;
    Ok(())
}

/// Секрет, ждавший подтверждения, становится действующим; step — шаг времени принятого кода.
pub async fn enable_totp<C: GenericClient>(c: &C, user_id: i64, now: i64, step: i64) -> Result<bool, DbError> {
    let n = c
        .execute(
            "UPDATE users SET totp_secret = totp_pending, totp_at = $2, totp_step = $3, totp_pending = NULL, totp_pending_at = NULL, totp_fails = 0, totp_locked_until = 0
             WHERE id = $1 AND totp_pending IS NOT NULL AND totp_at IS NULL",
            &[&user_id, &now, &step],
        )
        .await?;
    Ok(n > 0)
}

pub async fn disable_totp<C: GenericClient>(c: &C, user_id: i64) -> Result<bool, DbError> {
    let n = c
        .execute(
            "UPDATE users SET totp_secret = NULL, totp_at = NULL, totp_step = 0, totp_pending = NULL, totp_pending_at = NULL, totp_fails = 0, totp_locked_until = 0 WHERE id = $1 AND totp_at IS NOT NULL",
            &[&user_id],
        )
        .await?;
    c.execute("DELETE FROM backup_codes WHERE user_id = $1", &[&user_id]).await?;
    Ok(n > 0)
}

/// Код принят, если его шаг времени новее последнего принятого: второй раз тот же код не пройдёт.
pub async fn totp_accept<C: GenericClient>(c: &C, user_id: i64, step: i64) -> Result<bool, DbError> {
    Ok(c.execute("UPDATE users SET totp_step = $2, totp_fails = 0, totp_locked_until = 0 WHERE id = $1 AND totp_step < $2", &[&user_id, &step]).await? > 0)
}

/// Неудачная проверка второго фактора: счётчик растёт, пауза считается от него.
pub async fn totp_fail<C: GenericClient>(c: &C, user_id: i64, now: i64, pause: fn(i32) -> i64) -> Result<i64, DbError> {
    let fails: i32 = c.query_one("UPDATE users SET totp_fails = totp_fails + 1 WHERE id = $1 RETURNING totp_fails", &[&user_id]).await?.get(0);
    let until = now + pause(fails);
    c.execute("UPDATE users SET totp_locked_until = $2 WHERE id = $1", &[&user_id, &until]).await?;
    Ok(until - now)
}

pub async fn totp_clear_fails<C: GenericClient>(c: &C, user_id: i64) -> Result<(), DbError> {
    c.execute("UPDATE users SET totp_fails = 0, totp_locked_until = 0 WHERE id = $1", &[&user_id]).await?;
    Ok(())
}

pub async fn replace_backup_codes<C: GenericClient>(c: &C, user_id: i64, hashes: &[[u8; 32]]) -> Result<(), DbError> {
    c.execute("DELETE FROM backup_codes WHERE user_id = $1", &[&user_id]).await?;
    for h in hashes {
        c.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)", &[&user_id, &&h[..]]).await?;
    }
    Ok(())
}

/// Резервный код одноразовый: отметка «использован» ставится тем же запросом, что и проверка.
pub async fn use_backup_code<C: GenericClient>(c: &C, user_id: i64, hash: &[u8], now: i64) -> Result<bool, DbError> {
    Ok(c.execute("UPDATE backup_codes SET used_at = $3 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL", &[&user_id, &hash, &now]).await? > 0)
}

pub async fn backup_codes_left<C: GenericClient>(c: &C, user_id: i64) -> Result<i64, DbError> {
    Ok(c.query_one("SELECT count(*) FROM backup_codes WHERE user_id = $1 AND used_at IS NULL", &[&user_id]).await?.get(0))
}

pub async fn set_backup_email<C: GenericClient>(c: &C, user_id: i64, address: Option<&str>, now: i64) -> Result<(), DbError> {
    let at = address.map(|_| now);
    c.execute("UPDATE users SET backup_email = $2, backup_email_at = $3 WHERE id = $1", &[&user_id, &address, &at]).await?;
    Ok(())
}

/// Имя принадлежит действующему алиасу этого пользователя.
pub async fn alias_owned<C: GenericClient>(c: &C, user_id: i64, local: &str) -> Result<bool, DbError> {
    Ok(c.query_one("SELECT EXISTS(SELECT 1 FROM aliases WHERE user_id = $1 AND local = $2 AND deleted_at IS NULL)", &[&user_id, &local]).await?.get(0))
}

pub struct MailCode {
    pub address: String,
    pub code_hash: Vec<u8>,
    pub expires_at: i64,
    pub attempts: i32,
}

/// Новый код заменяет прежний того же назначения.
pub async fn put_mail_code<C: GenericClient>(c: &C, user_id: i64, purpose: &str, address: &str, hash: &[u8], expires: i64, now: i64) -> Result<(), DbError> {
    c.execute(
        "INSERT INTO mail_codes (user_id, purpose, address, code_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, purpose) DO UPDATE SET address = EXCLUDED.address, code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = 0, created_at = EXCLUDED.created_at",
        &[&user_id, &purpose, &address, &hash, &expires, &now],
    )
    .await?;
    Ok(())
}

pub async fn mail_code<C: GenericClient>(c: &C, user_id: i64, purpose: &str) -> Result<Option<MailCode>, DbError> {
    Ok(c
        .query_opt("SELECT address, code_hash, expires_at, attempts FROM mail_codes WHERE user_id = $1 AND purpose = $2", &[&user_id, &purpose])
        .await?
        .map(|r| MailCode { address: r.get(0), code_hash: r.get(1), expires_at: r.get(2), attempts: r.get(3) }))
}

pub async fn mail_code_attempt<C: GenericClient>(c: &C, user_id: i64, purpose: &str) -> Result<i32, DbError> {
    Ok(c.query_opt("UPDATE mail_codes SET attempts = attempts + 1 WHERE user_id = $1 AND purpose = $2 RETURNING attempts", &[&user_id, &purpose]).await?.map(|r| r.get(0)).unwrap_or(i32::MAX))
}

pub async fn delete_mail_code<C: GenericClient>(c: &C, user_id: i64, purpose: &str) -> Result<(), DbError> {
    c.execute("DELETE FROM mail_codes WHERE user_id = $1 AND purpose = $2", &[&user_id, &purpose]).await?;
    Ok(())
}

/* ---- ключи шифрования почты ---- */

#[derive(Clone, Debug, Default)]
pub struct MailKeys {
    pub rev: i64,
    pub fingerprint: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub wkd_hash: Option<String>,
    pub blob: Option<Vec<u8>>,
    pub wrap_pw: Option<Vec<u8>>,
    pub wrap_rk: Option<Vec<u8>>,
    pub updated_at: i64,
}

pub async fn mail_keys<C: GenericClient>(c: &C, user_id: i64) -> Result<Option<MailKeys>, DbError> {
    let row = c.query_opt("SELECT rev, fingerprint, public_key, wkd_hash, blob, wrap_pw, wrap_rk, updated_at FROM mail_keys WHERE user_id = $1", &[&user_id]).await?;
    Ok(row.map(|r| MailKeys { rev: r.get(0), fingerprint: r.get(1), public_key: r.get(2), wkd_hash: r.get(3), blob: r.get(4), wrap_pw: r.get(5), wrap_rk: r.get(6), updated_at: r.get(7) }))
}

/// Запись ключей для изменения: строка пользователя блокируется до конца транзакции, поэтому
/// два одновременных сохранения идут по очереди (в том числе самое первое, когда записи ещё нет).
pub async fn mail_keys_for_update<C: GenericClient>(c: &C, user_id: i64) -> Result<Option<MailKeys>, DbError> {
    c.query_opt("SELECT id FROM users WHERE id = $1 FOR UPDATE", &[&user_id]).await?;
    mail_keys(c, user_id).await
}

pub async fn save_mail_keys<C: GenericClient>(c: &C, user_id: i64, k: &MailKeys) -> Result<(), DbError> {
    c.execute(
        "INSERT INTO mail_keys (user_id, rev, fingerprint, public_key, wkd_hash, blob, wrap_pw, wrap_rk, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (user_id) DO UPDATE SET rev = EXCLUDED.rev, fingerprint = EXCLUDED.fingerprint, public_key = EXCLUDED.public_key, wkd_hash = EXCLUDED.wkd_hash, \
         blob = EXCLUDED.blob, wrap_pw = EXCLUDED.wrap_pw, wrap_rk = EXCLUDED.wrap_rk, updated_at = EXCLUDED.updated_at",
        &[&user_id, &k.rev, &k.fingerprint, &k.public_key, &k.wkd_hash, &k.blob, &k.wrap_pw, &k.wrap_rk, &k.updated_at],
    )
    .await?;
    Ok(())
}

pub async fn public_key_by_wkd<C: GenericClient>(c: &C, hash: &str) -> Result<Option<Vec<u8>>, DbError> {
    Ok(c.query_opt("SELECT public_key FROM mail_keys WHERE wkd_hash = $1 AND public_key IS NOT NULL", &[&hash]).await?.map(|r| r.get(0)))
}

/* ---- синхронизация ---- */

#[derive(Clone, Debug, PartialEq)]
pub struct SyncState {
    pub rev: i64,
    pub gen: i64,
    pub key_id: Option<String>,
}

impl Default for SyncState {
    /// Состояние пользователя, который ещё ничего не синхронизировал.
    fn default() -> Self {
        Self { rev: 0, gen: 1, key_id: None }
    }
}

fn sync_state_row(r: &Row) -> SyncState {
    SyncState { rev: r.get(0), gen: r.get(1), key_id: r.get(2) }
}

pub async fn sync_state<C: GenericClient>(c: &C, user_id: i64) -> Result<SyncState, DbError> {
    Ok(c.query_opt("SELECT rev, gen, key_id FROM sync_state WHERE user_id = $1", &[&user_id]).await?.as_ref().map(sync_state_row).unwrap_or_default())
}

/// Состояние для изменения: строка создаётся при первом обращении и блокируется до конца
/// транзакции, поэтому номера rev раздаются по очереди и без пропусков.
pub async fn sync_state_for_update<C: GenericClient>(c: &C, user_id: i64) -> Result<SyncState, DbError> {
    c.execute("INSERT INTO sync_state (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", &[&user_id]).await?;
    Ok(sync_state_row(&c.query_one("SELECT rev, gen, key_id FROM sync_state WHERE user_id = $1 FOR UPDATE", &[&user_id]).await?))
}

pub async fn save_sync_state<C: GenericClient>(c: &C, user_id: i64, s: &SyncState) -> Result<(), DbError> {
    c.execute("UPDATE sync_state SET rev = $2, gen = $3, key_id = $4 WHERE user_id = $1", &[&user_id, &s.rev, &s.gen, &s.key_id]).await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SyncItem {
    pub coll: String,
    pub id: String,
    pub rev: i64,
    pub deleted: bool,
    pub blob: Option<Vec<u8>>,
}

fn sync_item(r: &Row) -> SyncItem {
    SyncItem { coll: r.get(0), id: r.get(1), rev: r.get(2), deleted: r.get(3), blob: r.get(4) }
}

/// Номера и размеры записей новее since, по возрастанию rev: по ним выбирается страница ответа.
pub async fn sync_sizes<C: GenericClient>(c: &C, user_id: i64, since: i64, limit: i64) -> Result<Vec<(i64, i64)>, DbError> {
    let rows = c
        .query("SELECT rev, COALESCE(octet_length(blob), 0)::bigint FROM sync_items WHERE user_id = $1 AND rev > $2 ORDER BY rev LIMIT $3", &[&user_id, &since, &limit])
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// Записи с rev в промежутке (since, upto], по возрастанию rev.
pub async fn sync_items<C: GenericClient>(c: &C, user_id: i64, since: i64, upto: i64) -> Result<Vec<SyncItem>, DbError> {
    let rows = c
        .query("SELECT coll, id, rev, deleted, blob FROM sync_items WHERE user_id = $1 AND rev > $2 AND rev <= $3 ORDER BY rev", &[&user_id, &since, &upto])
        .await?;
    Ok(rows.iter().map(sync_item).collect())
}

/// Что сервер знает о записях с этими ключами: (раздел, ключ, rev, размер блока).
pub async fn sync_known<C: GenericClient>(c: &C, user_id: i64, colls: &[&str], ids: &[&str]) -> Result<Vec<(String, String, i64, i64)>, DbError> {
    let rows = c
        .query(
            "SELECT i.coll, i.id, i.rev, COALESCE(octet_length(i.blob), 0)::bigint FROM sync_items i
             JOIN unnest($2::text[], $3::text[]) AS k(coll, id) ON i.coll = k.coll AND i.id = k.id WHERE i.user_id = $1",
            &[&user_id, &colls, &ids],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3))).collect())
}

/// Записи с этими ключами целиком: текущее состояние сервера для ответа о расхождениях.
/// Ключи в наборе не повторяются.
pub async fn sync_lookup<C: GenericClient>(c: &C, user_id: i64, colls: &[&str], ids: &[&str]) -> Result<Vec<SyncItem>, DbError> {
    let rows = c
        .query(
            "SELECT i.coll, i.id, i.rev, i.deleted, i.blob FROM sync_items i
             JOIN unnest($2::text[], $3::text[]) AS k(coll, id) ON i.coll = k.coll AND i.id = k.id WHERE i.user_id = $1",
            &[&user_id, &colls, &ids],
        )
        .await?;
    Ok(rows.iter().map(sync_item).collect())
}

/// Сколько у пользователя записей (вместе с надгробиями) и сколько байт в их блоках.
pub async fn sync_usage<C: GenericClient>(c: &C, user_id: i64) -> Result<(i64, i64), DbError> {
    let r = c.query_one("SELECT count(*), COALESCE(sum(octet_length(blob)), 0)::bigint FROM sync_items WHERE user_id = $1", &[&user_id]).await?;
    Ok((r.get(0), r.get(1)))
}

/// Записи сохраняются одним запросом; ключи в наборе не повторяются (иначе запрос не выполнится).
pub async fn sync_write<C: GenericClient>(c: &C, user_id: i64, colls: &[&str], ids: &[&str], revs: &[i64], deleted: &[bool], blobs: &[Option<&[u8]>], now: i64) -> Result<(), DbError> {
    c.execute(
        "INSERT INTO sync_items (user_id, coll, id, rev, deleted, blob, updated_at)
         SELECT $1::bigint, k.coll, k.id, k.rev, k.deleted, k.blob, $7::bigint
         FROM unnest($2::text[], $3::text[], $4::bigint[], $5::boolean[], $6::bytea[]) AS k(coll, id, rev, deleted, blob)
         ON CONFLICT (user_id, coll, id) DO UPDATE SET rev = EXCLUDED.rev, deleted = EXCLUDED.deleted, blob = EXCLUDED.blob, updated_at = EXCLUDED.updated_at",
        &[&user_id, &colls, &ids, &revs, &deleted, &blobs, &now],
    )
    .await?;
    Ok(())
}

pub async fn sync_clear<C: GenericClient>(c: &C, user_id: i64) -> Result<(), DbError> {
    c.execute("DELETE FROM sync_items WHERE user_id = $1", &[&user_id]).await?;
    Ok(())
}

/* ---- обращения в поддержку ---- */

#[derive(Clone, Debug)]
pub struct Ticket {
    pub id: i64,
    /// the author's account; None for a request without an account
    pub user_id: Option<i64>,
    pub subject: String,
    pub status: String,
    pub meta: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub user_read_at: i64,
    pub staff_read_at: i64,
    /// адрес аккаунта автора; у обращения без аккаунта — адрес, который указал автор
    pub author: String,
    /// a request without an account: the secret of its link, the language of letters to the
    /// author, and whether the author's address is confirmed
    pub guest_key: Option<String>,
    pub guest_lang: Option<String>,
    pub guest_confirmed: bool,
}

impl Ticket {
    pub fn is_guest(&self) -> bool {
        self.user_id.is_none()
    }
}

const TICKET_SELECT: &str = "SELECT t.id, t.user_id, t.subject, t.status, t.meta, t.created_at, t.updated_at, t.user_read_at, t.staff_read_at, COALESCE(u.email, t.guest_email, ''), t.guest_key, t.guest_lang, t.guest_confirmed_at IS NOT NULL FROM tickets t LEFT JOIN users u ON u.id = t.user_id";
/// What support sees: requests of accounts and confirmed requests without an account.
const TICKET_VISIBLE: &str = "(t.user_id IS NOT NULL OR t.guest_confirmed_at IS NOT NULL)";

fn ticket_row(r: &Row) -> Ticket {
    Ticket {
        id: r.get(0),
        user_id: r.get(1),
        subject: r.get(2),
        status: r.get(3),
        meta: r.get(4),
        created_at: r.get(5),
        updated_at: r.get(6),
        user_read_at: r.get(7),
        staff_read_at: r.get(8),
        author: r.get(9),
        guest_key: r.get(10),
        guest_lang: r.get(11),
        guest_confirmed: r.get(12),
    }
}

pub async fn ticket<C: GenericClient>(c: &C, id: i64) -> Result<Option<Ticket>, DbError> {
    Ok(c.query_opt(&format!("{TICKET_SELECT} WHERE t.id = $1"), &[&id]).await?.as_ref().map(ticket_row))
}

/// Обращение для изменения: его строка блокируется до конца транзакции.
pub async fn ticket_for_update<C: GenericClient>(c: &C, id: i64) -> Result<Option<Ticket>, DbError> {
    Ok(c.query_opt(&format!("{TICKET_SELECT} WHERE t.id = $1 FOR UPDATE OF t"), &[&id]).await?.as_ref().map(ticket_row))
}

pub struct TicketSummary {
    pub ticket: Ticket,
    pub messages: i64,
    pub unread: bool,
}

/// Список обращений, недавно изменённые сверху. all — обращения всех пользователей (для
/// поддержки), иначе только свои. В своём обращении непрочитанными считаются ответы поддержки,
/// в чужом — сообщения автора.
pub async fn tickets<C: GenericClient>(c: &C, viewer: i64, all: bool, status: Option<&str>, limit: i64) -> Result<Vec<TicketSummary>, DbError> {
    let rows = c
        .query(
            &format!(
                "SELECT s.*, (SELECT count(*) FROM ticket_messages m WHERE m.ticket_id = s.id),
                   EXISTS (SELECT 1 FROM ticket_messages m WHERE m.ticket_id = s.id AND
                     CASE WHEN s.user_id = $1 THEN m.staff AND m.created_at > s.user_read_at ELSE NOT m.staff AND m.created_at > s.staff_read_at END)
                 FROM ({TICKET_SELECT} WHERE (($2::boolean AND {TICKET_VISIBLE}) OR t.user_id = $1) AND ($3::text IS NULL OR t.status = $3::text) ORDER BY t.updated_at DESC, t.id DESC LIMIT $4) s
                 ORDER BY s.updated_at DESC, s.id DESC"
            ),
            &[&viewer, &all, &status, &limit],
        )
        .await?;
    Ok(rows.iter().map(|r| TicketSummary { ticket: ticket_row(r), messages: r.get(13), unread: r.get(14) }).collect())
}

/// Сколько у пользователя незакрытых обращений и сколько создано после since. Строка
/// пользователя блокируется до конца транзакции: два одновременных создания идут по очереди.
pub async fn ticket_counts_for_update<C: GenericClient>(c: &C, user_id: i64, since: i64) -> Result<(i64, i64), DbError> {
    c.query_opt("SELECT id FROM users WHERE id = $1 FOR UPDATE", &[&user_id]).await?;
    let r = c
        .query_one("SELECT count(*) FILTER (WHERE status <> 'closed'), count(*) FILTER (WHERE created_at > $2) FROM tickets WHERE user_id = $1", &[&user_id, &since])
        .await?;
    Ok((r.get(0), r.get(1)))
}

/// Новое обращение: автор его уже «прочитал».
pub async fn insert_ticket<C: GenericClient>(c: &C, user_id: i64, subject: &str, meta: Option<&str>, now: i64) -> Result<i64, DbError> {
    Ok(c.query_one("INSERT INTO tickets (user_id, subject, meta, created_at, updated_at, user_read_at) VALUES ($1, $2, $3, $4, $4, $4) RETURNING id", &[&user_id, &subject, &meta, &now]).await?.get(0))
}

/// A request without an account, not yet seen by support: the address is to be confirmed first.
pub async fn insert_guest_ticket<C: GenericClient>(c: &C, email: &str, key: &str, lang: &str, subject: &str, now: i64) -> Result<i64, DbError> {
    Ok(c
        .query_one(
            "INSERT INTO tickets (user_id, guest_email, guest_key, guest_lang, subject, created_at, updated_at, user_read_at) VALUES (NULL, $1, $2, $3, $4, $5, $5, $5) RETURNING id",
            &[&email, &key, &lang, &subject, &now],
        )
        .await?
        .get(0))
}

/// Requests without an account from one address: (waiting for confirmation, made after `since`).
pub async fn guest_ticket_counts<C: GenericClient>(c: &C, email: &str, since: i64) -> Result<(i64, i64), DbError> {
    let r = c
        .query_one("SELECT count(*) FILTER (WHERE guest_confirmed_at IS NULL), count(*) FILTER (WHERE created_at > $2) FROM tickets WHERE guest_email = $1", &[&email, &since])
        .await?;
    Ok((r.get(0), r.get(1)))
}

/// The author's address is confirmed: from now on support sees the request. true if it was not confirmed before.
pub async fn confirm_guest_ticket<C: GenericClient>(c: &C, id: i64, now: i64) -> Result<bool, DbError> {
    Ok(c.execute("UPDATE tickets SET guest_confirmed_at = $2, updated_at = $2 WHERE id = $1 AND guest_confirmed_at IS NULL", &[&id, &now]).await? > 0)
}

pub async fn delete_ticket<C: GenericClient>(c: &C, id: i64) -> Result<(), DbError> {
    c.execute("DELETE FROM tickets WHERE id = $1", &[&id]).await?;
    Ok(())
}

/// An attachment of the given request (for the author of a request without an account).
pub async fn ticket_file_of<C: GenericClient>(c: &C, id: i64, ticket_id: i64) -> Result<Option<(String, String, Vec<u8>)>, DbError> {
    let row = c.query_opt("SELECT name, mime, data FROM ticket_files WHERE id = $1 AND ticket_id = $2", &[&id, &ticket_id]).await?;
    Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
}

/// author_id is empty for a message of an author without an account.
pub async fn insert_ticket_message<C: GenericClient>(c: &C, ticket_id: i64, staff: bool, author_id: Option<i64>, body: &str, at: i64) -> Result<i64, DbError> {
    Ok(c.query_one("INSERT INTO ticket_messages (ticket_id, staff, author_id, body, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id", &[&ticket_id, &staff, &author_id, &body, &at]).await?.get(0))
}

pub async fn insert_ticket_file<C: GenericClient>(c: &C, message_id: i64, ticket_id: i64, name: &str, mime: &str, data: &[u8]) -> Result<(), DbError> {
    c.execute("INSERT INTO ticket_files (message_id, ticket_id, name, mime, size, data) VALUES ($1, $2, $3, $4, $5, $6)", &[&message_id, &ticket_id, &name, &mime, &(data.len() as i32), &data]).await?;
    Ok(())
}

pub async fn ticket_message_count<C: GenericClient>(c: &C, ticket_id: i64) -> Result<i64, DbError> {
    Ok(c.query_one("SELECT count(*) FROM ticket_messages WHERE ticket_id = $1", &[&ticket_id]).await?.get(0))
}

/// После нового сообщения: статус, время изменения и отметка прочтения написавшей стороны.
pub async fn ticket_after_message<C: GenericClient>(c: &C, id: i64, status: &str, at: i64, staff: bool) -> Result<(), DbError> {
    let mark = if staff { "staff_read_at" } else { "user_read_at" };
    c.execute(&format!("UPDATE tickets SET status = $2, updated_at = $3, {mark} = $3 WHERE id = $1"), &[&id, &status, &at]).await?;
    Ok(())
}

pub async fn set_ticket_status<C: GenericClient>(c: &C, id: i64, status: &str, at: i64) -> Result<(), DbError> {
    c.execute("UPDATE tickets SET status = $2, updated_at = $3 WHERE id = $1", &[&id, &status, &at]).await?;
    Ok(())
}

/// Обращение прочитано стороной: отметка не раньше последнего сообщения и не уходит назад.
pub async fn mark_ticket_read<C: GenericClient>(c: &C, id: i64, staff: bool, now: i64) -> Result<(), DbError> {
    let mark = if staff { "staff_read_at" } else { "user_read_at" };
    c.execute(
        &format!("UPDATE tickets SET {mark} = GREATEST({mark}, $2, COALESCE((SELECT max(created_at) FROM ticket_messages WHERE ticket_id = $1), 0)) WHERE id = $1"),
        &[&id, &now],
    )
    .await?;
    Ok(())
}

pub struct TicketMessage {
    pub id: i64,
    pub staff: bool,
    pub body: String,
    pub created_at: i64,
}

pub async fn ticket_messages<C: GenericClient>(c: &C, ticket_id: i64) -> Result<Vec<TicketMessage>, DbError> {
    let rows = c.query("SELECT id, staff, body, created_at FROM ticket_messages WHERE ticket_id = $1 ORDER BY id", &[&ticket_id]).await?;
    Ok(rows.iter().map(|r| TicketMessage { id: r.get(0), staff: r.get(1), body: r.get(2), created_at: r.get(3) }).collect())
}

pub struct TicketFile {
    pub id: i64,
    pub message_id: i64,
    pub name: String,
    pub mime: String,
    pub size: i32,
}

/// Вложения обращения без содержимого.
pub async fn ticket_files<C: GenericClient>(c: &C, ticket_id: i64) -> Result<Vec<TicketFile>, DbError> {
    let rows = c.query("SELECT id, message_id, name, mime, size FROM ticket_files WHERE ticket_id = $1 ORDER BY id", &[&ticket_id]).await?;
    Ok(rows.iter().map(|r| TicketFile { id: r.get(0), message_id: r.get(1), name: r.get(2), mime: r.get(3), size: r.get(4) }).collect())
}

/// Вложение (имя, тип, содержимое), если его обращение принадлежит viewer или viewer — поддержка.
pub async fn ticket_file<C: GenericClient>(c: &C, id: i64, viewer: i64, staff: bool) -> Result<Option<(String, String, Vec<u8>)>, DbError> {
    let row = c
        .query_opt(&format!("SELECT f.name, f.mime, f.data FROM ticket_files f JOIN tickets t ON t.id = f.ticket_id WHERE f.id = $1 AND (t.user_id = $2 OR ($3::boolean AND {TICKET_VISIBLE}))"), &[&id, &viewer, &staff])
        .await?;
    Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
}

/// Сколько своих обращений с непрочитанным ответом поддержки.
pub async fn tickets_unread<C: GenericClient>(c: &C, user_id: i64) -> Result<i64, DbError> {
    let r = c
        .query_one(
            "SELECT count(*) FROM tickets t WHERE t.user_id = $1 AND EXISTS (SELECT 1 FROM ticket_messages m WHERE m.ticket_id = t.id AND m.staff AND m.created_at > t.user_read_at)",
            &[&user_id],
        )
        .await?;
    Ok(r.get(0))
}

/// Очередь поддержки: обращения всех пользователей, ждущие ответа.
pub async fn tickets_open<C: GenericClient>(c: &C) -> Result<i64, DbError> {
    Ok(c.query_one(&format!("SELECT count(*) FROM tickets t WHERE t.status = 'open' AND {TICKET_VISIBLE}"), &[]).await?.get(0))
}

pub async fn setting<C: GenericClient>(c: &C, key: &str) -> Result<Option<String>, DbError> {
    Ok(c.query_opt("SELECT value FROM settings WHERE key = $1", &[&key]).await?.map(|r| r.get(0)))
}

pub async fn set_setting<C: GenericClient>(c: &C, key: &str, value: &str) -> Result<(), DbError> {
    c.execute("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", &[&key, &value]).await?;
    Ok(())
}
