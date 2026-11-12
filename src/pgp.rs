/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Ключи шифрования почты (OpenPGP): копия закрытого ключа аккаунта и каталог открытых ключей.
//!
//! Закрытый ключ сервер получает уже зашифрованным: браузер шифрует его случайным ключом данных,
//! а ключ данных — ключом из пароля аккаунта и, отдельно, ключом из ключа восстановления. Ни
//! пароля, ни ключа восстановления у сервера нет, поэтому прочитать копию он не может; новый
//! компьютер после входа с паролем получает её и расшифровывает сам. Поверх клиентского
//! шифрования блоки запечатаны ключом сервера: утечка одной только базы не даёт даже материала
//! для подбора пароля.
//!
//! Открытый ключ публикуется по Web Key Directory (draft-koch-openpgp-webkey-service): его
//! находят почтовые программы и браузер Tabora, когда пишут на адрес аккаунта.
//!
//! Запись меняется с проверкой номера версии (rev): два устройства, создающие ключ одновременно,
//! не затирают работу друг друга — второе получает отказ, читает запись и подстраивается.
//!
//! Первый ключ аккаунта создаётся по одной лишь сессии. Замена ключа и обёртка ключа данных
//! паролем требуют ещё и хеш входа: украденной сессии мало, чтобы подменить ключ аккаунта или
//! привязать копию к чужому паролю.

use crate::api::{bad, client_ip, err, local_of, parse, too_many, wait_text, ApiError, ApiResult, App};
use crate::db::{self, MailKeys};
use crate::util::{is_hex, iso, now_ms, open, same, seal, sha1, valid_local};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_PUBLIC_KEY: usize = 16 * 1024;
const MAX_BLOB: usize = 24 * 1024;
const MAX_WRAP: usize = 256;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// z-base-32: так WKD кодирует хеш имени ящика.
pub fn zbase32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Имя записи в каталоге: z-base-32 от SHA-1 имени ящика в нижнем регистре.
pub fn wkd_hash(local: &str) -> String {
    zbase32(&sha1(local.to_lowercase().as_bytes()))
}

/// Первый пакет ключа: (версия, тело пакета). None, если это не пакет открытого ключа OpenPGP.
fn public_key_packet(key: &[u8]) -> Option<(u8, &[u8])> {
    let first = *key.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (tag, body_at, len): (u8, usize, usize) = if first & 0x40 != 0 {
        // новый формат заголовка
        let l0 = *key.get(1)? as usize;
        match l0 {
            0..=191 => (first & 0x3f, 2, l0),
            192..=223 => (first & 0x3f, 3, ((l0 - 192) << 8) + *key.get(2)? as usize + 192),
            255 => (first & 0x3f, 6, u32::from_be_bytes(key.get(2..6)?.try_into().ok()?) as usize),
            _ => return None, // частичная длина у ключа не встречается
        }
    } else {
        match first & 0x03 {
            0 => ((first >> 2) & 0x0f, 2, *key.get(1)? as usize),
            1 => ((first >> 2) & 0x0f, 3, u16::from_be_bytes(key.get(1..3)?.try_into().ok()?) as usize),
            2 => ((first >> 2) & 0x0f, 5, u32::from_be_bytes(key.get(1..5)?.try_into().ok()?) as usize),
            _ => return None,
        }
    };
    let body = key.get(body_at..body_at.checked_add(len)?)?;
    (tag == 6 && !body.is_empty()).then(|| (body[0], body))
}

/// Ключ принимается, если это открытый ключ OpenPGP и названный отпечаток — действительно его.
/// У ключей версии 4 отпечаток пересчитывается; у более новых сверяется только длина.
pub fn check_public_key(key: &[u8], fingerprint: &str) -> bool {
    let Some((version, body)) = public_key_packet(key) else { return false };
    let hex_ok = |len: usize| fingerprint.len() == len && fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match version {
        4 => {
            let mut data = Vec::with_capacity(body.len() + 3);
            data.push(0x99);
            data.extend_from_slice(&(body.len() as u16).to_be_bytes());
            data.extend_from_slice(body);
            body.len() <= u16::MAX as usize && hex_ok(40) && hex::encode(sha1(&data)) == fingerprint
        }
        5 | 6 => hex_ok(64),
        _ => false,
    }
}

fn aad(user_id: i64, what: &str) -> Vec<u8> {
    format!("tabora/mail-keys/{what}/{user_id}").into_bytes()
}

fn unseal(app: &App, user_id: i64, what: &str, blob: &Option<Vec<u8>>) -> Value {
    match blob.as_deref().and_then(|b| open(&app.pgp_key, &aad(user_id, what), b)) {
        Some(plain) => Value::String(B64.encode(plain)),
        None => Value::Null,
    }
}

fn keys_json(app: &App, user_id: i64, k: &MailKeys) -> Value {
    json!({
        "rev": k.rev,
        "fingerprint": k.fingerprint,
        "publicKey": k.public_key.as_deref().map(|b| B64.encode(b)),
        "blob": unseal(app, user_id, "blob", &k.blob),
        "wrapPassword": unseal(app, user_id, "wrap-pw", &k.wrap_pw),
        "wrapRecovery": unseal(app, user_id, "wrap-rk", &k.wrap_rk),
        "updatedAt": if k.updated_at > 0 { Value::String(iso(k.updated_at)) } else { Value::Null },
    })
}

/// Копия ключа и обёртки ключа данных для вошедшего пользователя.
pub async fn keys_get(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("pgp:{}", user.id), 240, 3_600_000)?;
    let c = app.pool.get().await?;
    let k = db::mail_keys(&c, user.id).await?.unwrap_or_default();
    Ok(Json(keys_json(&app, user.id, &k)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeysBody {
    rev: i64,
    fingerprint: Option<String>,
    public_key: Option<String>,
    blob: Option<String>,
    wrap_password: Option<String>,
    /// Обёртка ключом восстановления: пустая строка убирает её (ключ восстановления отозван).
    wrap_recovery: Option<String>,
    /// Ключ на сервере заменяется другим: прежний потерян вместе с сейфом.
    #[serde(default)]
    replace: bool,
    /// Хеш входа: обязателен вместе с wrapPassword и с replace.
    login_hash: Option<String>,
}

fn decode(field: &'static str, value: &str, min: usize, max: usize) -> Result<Vec<u8>, ApiError> {
    let wrong = || bad("pgp-invalid", format!("Ключи шифрования не сохранены: поле {field} неверно"));
    if value.len() > max * 4 / 3 + 8 {
        return Err(wrong());
    }
    let bytes = B64.decode(value).map_err(|_| wrong())?;
    (bytes.len() >= min && bytes.len() <= max).then_some(bytes).ok_or_else(wrong)
}

/// Сохранить ключ и обёртки. Каждое поле необязательно; ключ, его отпечаток и зашифрованная
/// копия приходят только вместе. Отказ `pgp-conflict` — запись успели изменить или у аккаунта
/// уже есть другой ключ: клиент читает её заново.
pub async fn keys_put(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("pgp-put:{}", user.id), 60, 3_600_000)?;
    let b: KeysBody = parse(&body)?;
    if b.wrap_password.is_some() || b.replace {
        // пароль подтверждается заново, как при любой перемене в настройках входа
        let now = now_ms();
        let key = format!("pw:{}:{}", user.id, client_ip(&headers));
        let locked = app.limiter.locked(&key, now);
        if locked > 0 {
            return Err(too_many(format!("Слишком много неудачных попыток. Повторите через {}", wait_text(locked))));
        }
        let hash = b.login_hash.as_deref().unwrap_or("");
        if !is_hex(hash, 64) || !same(&app.verifier(&user.salt, hash), &user.verifier) {
            app.limiter.fail(&key, now);
            return Err(err(StatusCode::UNAUTHORIZED, "bad-credentials", "Неверный пароль"));
        }
        app.limiter.clear(&key);
    }
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let mut k = db::mail_keys_for_update(&tx, user.id).await?.unwrap_or_default();
    let conflict = || err(StatusCode::CONFLICT, "pgp-conflict", "Ключи шифрования изменились на другом устройстве");
    if b.rev != k.rev {
        return Err(conflict());
    }
    let key_parts = [b.fingerprint.is_some(), b.public_key.is_some(), b.blob.is_some()];
    if key_parts.iter().any(|x| *x) {
        if !key_parts.iter().all(|x| *x) {
            return Err(bad("pgp-invalid", "Ключ, его отпечаток и зашифрованная копия сохраняются только вместе"));
        }
        let fingerprint = b.fingerprint.as_deref().unwrap_or("").to_lowercase();
        let public_key = decode("publicKey", b.public_key.as_deref().unwrap_or(""), 32, MAX_PUBLIC_KEY)?;
        let blob = decode("blob", b.blob.as_deref().unwrap_or(""), 64, MAX_BLOB)?;
        if !check_public_key(&public_key, &fingerprint) {
            return Err(bad("pgp-invalid", "Это не открытый ключ OpenPGP или отпечаток не от него"));
        }
        if let Some(existing) = k.fingerprint.as_deref() {
            if existing != fingerprint && !b.replace {
                return Err(conflict());
            }
        }
        k.fingerprint = Some(fingerprint);
        k.public_key = Some(public_key);
        k.wkd_hash = Some(wkd_hash(local_of(&user.email)));
        k.blob = Some(seal(&app.pgp_key, &aad(user.id, "blob"), &blob));
    }
    if let Some(w) = b.wrap_password.as_deref() {
        k.wrap_pw = Some(seal(&app.pgp_key, &aad(user.id, "wrap-pw"), &decode("wrapPassword", w, 44, MAX_WRAP)?));
    }
    if let Some(w) = b.wrap_recovery.as_deref() {
        k.wrap_rk = if w.is_empty() { None } else { Some(seal(&app.pgp_key, &aad(user.id, "wrap-rk"), &decode("wrapRecovery", w, 44, MAX_WRAP)?)) };
    }
    k.rev += 1;
    k.updated_at = now_ms();
    db::save_mail_keys(&tx, user.id, &k).await?;
    tx.commit().await?;
    Ok(Json(keys_json(&app, user.id, &k)))
}

#[derive(Deserialize)]
pub struct WkdQuery {
    l: Option<String>,
}

fn key_response(key: Vec<u8>) -> Response {
    ([(CONTENT_TYPE, "application/octet-stream")], key).into_response()
}

/// Каталог открытых ключей: `/.well-known/openpgpkey/hu/<хеш>?l=<имя>`. Ответ — двоичный ключ.
/// Ключ есть только у основного адреса аккаунта: алиасы своих ключей не имеют.
pub async fn wkd_key(State(app): State<Arc<App>>, headers: HeaderMap, Path(hash): Path<String>, Query(q): Query<WkdQuery>) -> Result<Response, ApiError> {
    let none = || err(StatusCode::NOT_FOUND, "not-found", "Ключа для этого адреса нет");
    app.window(&format!("wkd:{}", client_ip(&headers)), 600, 3_600_000)?;
    let hash = hash.to_lowercase();
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(none());
    }
    if let Some(local) = q.l.as_deref() {
        // имя в запросе должно соответствовать хешу: иначе это не запрос почтовой программы
        if !valid_local(&local.to_lowercase()) || wkd_hash(local) != hash {
            return Err(none());
        }
    }
    let c = app.pool.get().await?;
    db::public_key_by_wkd(&c, &hash).await?.map(key_response).ok_or_else(none)
}

/// Файл политики: его наличие говорит программам, что каталог на домене есть.
pub async fn wkd_policy() -> Response {
    ([(CONTENT_TYPE, "text/plain")], "").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wkd_names() {
        // пример из черновика WKD: Joe.Doe@Example.ORG
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
        assert_eq!(zbase32(b""), "");
        assert_eq!(zbase32(&[0xff]), "9h");
        assert_eq!(wkd_hash("anna").len(), 32);
    }

    #[test]
    fn public_key_checks() {
        // ключ Ed25519 версии 4 (старый формат заголовка): пакет открытого ключа и хвост других пакетов
        let body: Vec<u8> = [&[4u8, 0x5f, 0x00, 0x00, 0x00, 22][..], &[9, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01], &[0x01, 0x07, 0x40], &[7u8; 32]].concat();
        let mut data = vec![0x99, 0, body.len() as u8];
        data.extend_from_slice(&body);
        let fingerprint = hex::encode(sha1(&data));
        let mut key = vec![0x98, body.len() as u8];
        key.extend_from_slice(&body);
        key.extend_from_slice(&[0xb4, 3, b'a', b'@', b'b']);
        assert!(check_public_key(&key, &fingerprint));
        assert!(!check_public_key(&key, &"0".repeat(40)), "чужой отпечаток");
        assert!(!check_public_key(&key, &fingerprint.to_uppercase()), "отпечаток только в нижнем регистре");
        // тот же ключ с заголовком нового формата
        let mut modern = vec![0xc6, body.len() as u8];
        modern.extend_from_slice(&body);
        assert!(check_public_key(&modern, &fingerprint));
        // закрытый ключ (пакет 5), обрезанный пакет и мусор не принимаются
        let mut secret = key.clone();
        secret[0] = 0x94;
        assert!(!check_public_key(&secret, &fingerprint));
        assert!(!check_public_key(&key[..10], &fingerprint));
        assert!(!check_public_key(b"-----BEGIN PGP PUBLIC KEY BLOCK-----", &fingerprint));
        assert!(!check_public_key(&[], &fingerprint));
    }
}
