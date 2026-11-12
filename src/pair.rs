// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Вход на новом устройстве по QR-коду: устройство, где человек уже вошёл, показывает QR-код,
//! новое считывает его и входит без ввода пароля.
//!
//! Сервер здесь — почтовый ящик между двумя устройствами и тот, кто выдаёт сессию:
//!
//! 1. Вошедшее устройство заводит обмен (`POST /v1/pair/start`) и показывает его номер в QR-коде
//!    вместе со своим одноразовым открытым ключом.
//! 2. Новое устройство присоединяется (`POST /v1/pair/join`): свой одноразовый открытый ключ,
//!    номер и имя устройства и отпечаток секрета, которым оно потом докажет, что это оно.
//! 3. Вошедшее устройство видит присоединившееся (`GET /v1/pair/:id`), показывает человеку имя
//!    устройства и код сверки (он выводится из общего секрета двух ключей и одинаков на обоих
//!    экранах) и после подтверждения кладёт в обмен ключ данных аккаунта, зашифрованный общим
//!    секретом (`POST /v1/pair/:id/approve`).
//! 4. Новое устройство забирает результат (`POST /v1/pair/poll`): сессию от сервера и
//!    зашифрованный ключ от первого устройства.
//!
//! Чего сервер не может: прочитать ключ данных (он зашифрован секретом, которого у сервера нет) и
//! незаметно подменить устройство (код сверки на экранах разойдётся). Сессия выдаётся только после
//! подтверждения с устройства владельца и только тому, кто присоединился первым. Обмен живёт три
//! минуты, хранится в памяти сервера и одноразов.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::api::{bad, check_device, client_ip, err, parse, ApiError, ApiResult, App};
use crate::db;
use crate::util::{clean_name, is_hex, now_ms, random, same, sha256};

const TTL_MS: i64 = 3 * 60_000;
const MAX_ACTIVE: usize = 3;
const MAX_PAYLOAD: usize = 4096;

#[derive(PartialEq, Clone, Copy)]
enum Stage {
    New,
    Joined,
    Approved,
    Denied,
}

struct Pairing {
    user_id: i64,
    expires: i64,
    stage: Stage,
    claim: [u8; 32],
    public: String,
    device_id: String,
    device_name: String,
    payload: String,
}

static PAIRS: LazyLock<Mutex<HashMap<String, Pairing>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn gone() -> ApiError {
    err(StatusCode::NOT_FOUND, "pair-gone", "Код для входа устарел. Покажите новый на устройстве, где вы уже вошли")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn stage_name(s: Stage) -> &'static str {
    match s {
        Stage::New => "new",
        Stage::Joined => "joined",
        Stage::Approved => "approved",
        Stage::Denied => "denied",
    }
}

/// Ключ X25519 в Base64 (url или обычный алфавит, без или с дополнением): 32 байта.
fn is_key(s: &str) -> bool {
    (43..=44).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '='))
}

fn with_pairs<T>(f: impl FnOnce(&mut HashMap<String, Pairing>) -> T) -> T {
    let mut pairs = PAIRS.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_ms();
    pairs.retain(|_, p| p.expires > now);
    f(&mut pairs)
}

/// Начать обмен: вызывает устройство, где человек уже вошёл.
pub async fn start(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("pair-start:{}", user.id), 30, 3_600_000)?;
    let id = hex(&random::<16>());
    let expires = now_ms() + TTL_MS;
    with_pairs(|pairs| {
        // новый код отменяет лишние прежние: больше трёх ожидающих обменов аккаунту не нужно
        let mut mine: Vec<(String, i64)> = pairs.iter().filter(|(_, p)| p.user_id == user.id).map(|(k, p)| (k.clone(), p.expires)).collect();
        mine.sort_by_key(|(_, e)| *e);
        while mine.len() >= MAX_ACTIVE {
            pairs.remove(&mine.remove(0).0);
        }
        pairs.insert(id.clone(), Pairing { user_id: user.id, expires, stage: Stage::New, claim: [0; 32], public: String::new(), device_id: String::new(), device_name: String::new(), payload: String::new() });
    });
    Ok(Json(json!({ "id": id, "expiresAt": expires })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinBody {
    id: String,
    /// одноразовый открытый ключ нового устройства
    public: String,
    /// SHA-256 секрета, которым устройство потом заберёт результат
    claim: String,
    device_id: String,
    device_name: String,
}

/// Присоединиться к обмену: вызывает новое устройство, считав QR-код. Без сессии.
pub async fn join(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    app.window(&format!("pair-join-ip:{}", client_ip(&headers)), 30, 60_000)?;
    let b: JoinBody = parse(&body)?;
    check_device(&b.device_id)?;
    if !is_hex(&b.id, 32) || !is_key(&b.public) || !is_hex(&b.claim, 64) {
        return Err(bad("pair-invalid", "Неверный запрос входа по коду"));
    }
    let mut claim = [0u8; 32];
    for (i, byte) in claim.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&b.claim[i * 2..i * 2 + 2], 16).map_err(|_| bad("pair-invalid", "Неверный запрос входа по коду"))?;
    }
    let name = clean_name(&b.device_name, "Устройство");
    with_pairs(|pairs| {
        // присоединиться можно один раз: второй, кто считал тот же код, получает отказ
        let p = pairs.get_mut(&b.id).filter(|p| p.stage == Stage::New).ok_or_else(gone)?;
        p.stage = Stage::Joined;
        p.claim = claim;
        p.public = b.public.clone();
        p.device_id = b.device_id.clone();
        p.device_name = name;
        Ok(Json(json!({ "ok": true, "expiresAt": p.expires })))
    })
}

/// Состояние обмена для устройства, которое его начало.
pub async fn status(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    with_pairs(|pairs| {
        let p = pairs.get(&id).filter(|p| p.user_id == user.id).ok_or_else(gone)?;
        let joined = p.stage != Stage::New;
        Ok(Json(json!({
            "state": stage_name(p.stage),
            "public": if joined { Some(&p.public) } else { None },
            "deviceName": if joined { Some(&p.device_name) } else { None },
            "expiresAt": p.expires,
        })))
    })
}

#[derive(Deserialize)]
struct ApproveBody {
    /// ключ данных аккаунта, зашифрованный общим секретом двух устройств (Base64)
    payload: String,
}

/// Разрешить вход: человек сверил код на обоих экранах и подтвердил на своём устройстве.
pub async fn approve(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: ApproveBody = parse(&body)?;
    if b.payload.is_empty() || b.payload.len() > MAX_PAYLOAD || !b.payload.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=')) {
        return Err(bad("pair-invalid", "Неверный запрос входа по коду"));
    }
    with_pairs(|pairs| {
        let p = pairs.get_mut(&id).filter(|p| p.user_id == user.id && p.stage == Stage::Joined).ok_or_else(gone)?;
        p.stage = Stage::Approved;
        p.payload = b.payload.clone();
        Ok(Json(json!({ "ok": true })))
    })
}

/// Отклонить вход: устройство не то или коды не совпали.
pub async fn deny(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    with_pairs(|pairs| {
        let p = pairs.get_mut(&id).filter(|p| p.user_id == user.id).ok_or_else(gone)?;
        p.stage = Stage::Denied;
        Ok(Json(json!({ "ok": true })))
    })
}

#[derive(Deserialize)]
struct PollBody {
    id: String,
    /// секрет, отпечаток которого устройство передало при присоединении
    secret: String,
}

/// Забрать результат: вызывает новое устройство. После разрешения получает сессию и зашифрованный
/// ключ данных; обмен на этом заканчивается.
pub async fn poll(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    app.window(&format!("pair-poll-ip:{}", client_ip(&headers)), 120, 60_000)?;
    let b: PollBody = parse(&body)?;
    if !is_hex(&b.id, 32) || b.secret.len() < 32 || b.secret.len() > 128 {
        return Err(bad("pair-invalid", "Неверный запрос входа по коду"));
    }
    let proof = sha256(b.secret.as_bytes());
    // сессия выдаётся один раз: одобренный обмен вынимается из списка здесь же
    let taken = with_pairs(|pairs| {
        let p = pairs.get(&b.id).filter(|p| p.stage != Stage::New && same(&p.claim, &proof)).ok_or_else(gone)?;
        match p.stage {
            Stage::Approved => Ok(pairs.remove(&b.id)),
            Stage::Denied => {
                pairs.remove(&b.id);
                Err(err(StatusCode::FORBIDDEN, "pair-denied", "Вход отклонён на устройстве, где вы уже вошли"))
            }
            _ => Ok(None),
        }
    })?;
    let Some(p) = taken else {
        return Ok(Json(json!({ "state": "joined" })));
    };
    let now = now_ms();
    let c = app.pool.get().await?;
    let user = db::user_by_id(&c, p.user_id).await?.ok_or_else(gone)?;
    let known = db::device_known(&c, user.id, &p.device_id).await?;
    let old_cred = db::upsert_device(&c, user.id, &p.device_id, &p.device_name, now).await?;
    let session = app.new_session(&c, user.id, &p.device_id, now).await?;
    crate::i18n::remember(&c, user.id, &headers).await;
    if !known {
        app.security_notice(&c, &user, "Tabora: вход с нового устройства", &format!("В аккаунт вошли с устройства, которого раньше не было: «{}». Вход подтверждён по коду с другого вашего устройства.\n\nЕсли это были вы, делать ничего не нужно. Если нет — смените пароль в настройках аккаунта: остальные устройства выйдут из него.", p.device_name)).await;
    }
    drop(c);
    // почта — по сессии, как у веб-версии и приложения для телефона
    let mail = app.device_mail(&user, &p.device_id, &p.device_name, old_cred, Some("session")).await;
    Ok(Json(json!({ "state": "approved", "userId": user.public_id, "email": user.email, "session": session, "kdf": user.kdf, "mail": mail, "payload": p.payload })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_stages() {
        assert!(is_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(is_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!is_key("короткий"));
        assert!(!is_key(&"A".repeat(60)));
        assert_eq!(stage_name(Stage::Joined), "joined");
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
    }
}
