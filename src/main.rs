/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! tabora-server: аккаунты Tabora, устройства, ящики и алиасы на почтовом сервере,
//! синхронизация данных браузера и обращения в поддержку.
//!
//! Слушает только локальный адрес (наружу его публикует nginx за туннелем Cloudflare).
//! Настройки — переменные окружения (на сервере /etc/tabora/server.env):
//!   TABORA_DOMAIN            домен почты, например tabora.app
//!   TABORA_LISTEN            адрес и порт, по умолчанию 127.0.0.1:7700
//!   TABORA_DB                строка подключения PostgreSQL
//!   APP_SIGNING_KEY          секрет сервера, hex, не короче 32 байт
//!   STALWART_URL             адрес JMAP почтового сервера (пусто — без почты)
//!   STALWART_API_KEY         служебный ключ с правом на учётки пользователей
//!   TABORA_MAIL_HOST         имя почтового хоста для клиентов, по умолчанию mx.<домен>
//!   TABORA_MAIL_QUOTA_MB     место под ящик, по умолчанию 2048
//!   TABORA_SIGNUP            open | closed, по умолчанию open
//!   TABORA_SIGNUP_DAILY_CAP  новых аккаунтов в сутки на весь сервер, по умолчанию 50
//!   TABORA_SIGNUP_PER_IP     новых аккаунтов в сутки с одного адреса, по умолчанию 3
//!   TABORA_ALIAS_MAX         алиасов на аккаунт, по умолчанию 100
//!   TABORA_MAIL_DAILY_CAP    писем от сервера в сутки (коды, уведомления), по умолчанию 500
//!   TABORA_MAIL_OUTBOX       только для проверок: каталог, куда письма складываются файлами
//!   TABORA_SUPPORT_STAFF     адреса аккаунтов сотрудников поддержки через запятую (пусто — их нет)
//!   TABORA_SUPPORT_NOTIFY    адрес для писем о новых обращениях и ответах пользователей (пусто — не слать)

mod api;
mod db;
mod i18n;
mod limit;
mod mail;
mod pair;
mod pgp;
mod security;
mod support;
mod sync;
mod util;
mod webmail;

use std::sync::Arc;
use std::time::Duration;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    env(name).parse().unwrap_or(default)
}

fn fail(text: &str) -> ! {
    eprintln!("tabora-server: {text}");
    std::process::exit(2);
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("обработчик SIGTERM");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    eprintln!("tabora-server: остановка");
}

#[tokio::main]
async fn main() {
    let domain = env("TABORA_DOMAIN");
    if domain.is_empty() {
        fail("не задан TABORA_DOMAIN");
    }
    let listen = Some(env("TABORA_LISTEN")).filter(|s| !s.is_empty()).unwrap_or_else(|| "127.0.0.1:7700".to_string());
    let master = hex::decode(env("APP_SIGNING_KEY")).ok().filter(|k| k.len() >= 32).unwrap_or_else(|| fail("APP_SIGNING_KEY должен быть hex не короче 32 байт"));
    // независимые ключи из секрета сервера: «перец» для хешей входа и основа основных паролей ящиков
    let pepper = util::hmac256(&master, &[b"tabora/login-pepper/v1"]);
    let mail_key = util::hmac256(&master, &[b"tabora/mail-primary/v1"]);
    // секрет TOTP в базе зашифрован; от резервных кодов и кодов из писем там только HMAC
    let totp_key = util::hmac256(&master, &[b"tabora/totp-secret/v1"]);
    let code_key = util::hmac256(&master, &[b"tabora/short-codes/v1"]);
    // копии ключей шифрования почты приходят уже зашифрованными браузером; этим ключом они запечатаны в базе
    let pgp_key = util::hmac256(&master, &[b"tabora/mail-keys/v1"]);

    let pool = db::pool(&env("TABORA_DB")).unwrap_or_else(|e| fail(&e));
    // база может подняться позже сервера (загрузка системы): ждём до минуты
    let mut ready = false;
    for attempt in 0..30 {
        match pool.get().await {
            Ok(c) => match c.batch_execute(db::SCHEMA).await {
                Ok(()) => {
                    ready = true;
                    break;
                }
                Err(e) => fail(&format!("схема базы не применена: {e}")),
            },
            Err(e) => {
                if attempt == 29 {
                    fail(&format!("база недоступна: {e}"));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    if !ready {
        fail("база недоступна");
    }

    let mail_host = Some(env("TABORA_MAIL_HOST")).filter(|s| !s.is_empty()).unwrap_or_else(|| format!("mx.{domain}"));
    let quota = env_num::<u64>("TABORA_MAIL_QUOTA_MB", 2048) * 1024 * 1024;
    let outbox = Some(env("TABORA_MAIL_OUTBOX")).filter(|s| !s.is_empty()).map(std::path::PathBuf::from);
    if let Some(dir) = &outbox {
        eprintln!("tabora-server: письма не отправляются, а пишутся в {} (режим проверок)", dir.display());
    }
    // сотрудником поддержки становится тот, кто владеет аккаунтом с таким адресом: в списке
    // должны быть только адреса уже существующих аккаунтов
    let support_staff = support::staff_list(&env("TABORA_SUPPORT_STAFF"));
    let support_notify = match env("TABORA_SUPPORT_NOTIFY") {
        s if s.is_empty() => None,
        s => Some(util::clean_address(&s).unwrap_or_else(|| fail("TABORA_SUPPORT_NOTIFY должен быть адресом электронной почты"))),
    };
    let stalwart = mail::Stalwart::new(&env("STALWART_URL"), &env("STALWART_API_KEY"), &domain, mail_key, quota, outbox);
    let app = Arc::new(api::App {
        domain: domain.clone(),
        mail_host,
        pool: pool.clone(),
        mail: stalwart,
        limiter: limit::Limiter::default(),
        pepper,
        totp_key,
        code_key,
        pgp_key,
        mail_daily_cap: env_num("TABORA_MAIL_DAILY_CAP", 500),
        signup_open: env("TABORA_SIGNUP") != "closed",
        signup_daily_cap: env_num("TABORA_SIGNUP_DAILY_CAP", 50),
        signup_per_ip_day: env_num("TABORA_SIGNUP_PER_IP", 3),
        alias_max: env_num("TABORA_ALIAS_MAX", 100),
        support_staff,
        support_notify,
    });

    // уборка раз в час: истёкшие сессии и nonce, старые счётчики ограничителей
    let housekeeping = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let now = util::now_ms();
            housekeeping.limiter.sweep(now);
            if let Ok(c) = housekeeping.pool.get().await {
                if let Err(e) = db::purge_expired(&c, now).await {
                    eprintln!("уборка: {e:?}");
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap_or_else(|e| fail(&format!("не удалось занять {listen}: {e}")));
    eprintln!(
        "tabora-server {}: {listen}, домен {domain}, почта {}, сотрудников поддержки: {}",
        env!("CARGO_PKG_VERSION"),
        if app.mail.enabled() { "включена" } else { "выключена" },
        app.support_staff.len()
    );
    if let Err(e) = axum::serve(listener, api::router(app)).with_graceful_shutdown(shutdown()).await {
        fail(&format!("сервер остановился с ошибкой: {e}"));
    }
}
