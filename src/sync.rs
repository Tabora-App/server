/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Синхронизация данных браузера между устройствами аккаунта.
//!
//! Сервер хранит непрозрачные записи: браузер шифрует каждую ключом, которого у сервера нет, и
//! сервер её содержимое не разбирает. Он знает только раздел (`c`), ключ записи (`id`), размер
//! блока и порядок изменений.
//!
//! У пользователя один счётчик изменений `rev`: каждая сохранённая запись получает следующий
//! номер, и устройство забирает всё, что новее номера, который оно уже видело. Запись
//! сохраняется, только если устройство видело её последнюю версию (`base` равен её `rev` на
//! сервере); иначе она возвращается в `conflicts` с тем, что лежит на сервере, и устройство
//! само решает, как слить изменения. Удаление — тоже запись: надгробие без блока, чтобы о нём
//! узнали остальные устройства.
//!
//! `gen` — поколение данных: растёт при сбросе, и устройство со старым поколением получает
//! отказ `sync-reset` вместо того, чтобы дописать свои записи к чужим новым. `keyId` — отпечаток
//! ключа шифрования: запись другим ключом отклоняется (`sync-key`), иначе устройства копили бы
//! блоки, которые не могут прочитать друг у друга. Счётчик `rev` при сбросе не обнуляется.

use crate::api::{bad, err, sized, ApiError, ApiResult, App};
use crate::db::{self, SyncItem, SyncState};
use crate::util::{is_hex, now_ms};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio_postgres::IsolationLevel;

/// Предел тела запроса: записи большего общего размера браузер присылает порциями.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REQUEST_ITEMS: usize = 200;
const MAX_BLOB: usize = 96 * 1024;
/// Записей на пользователя (вместе с надгробиями) и байт в их блоках.
const MAX_ITEMS: i64 = 30_000;
const MAX_BYTES: i64 = 64 * 1024 * 1024;
const PAGE_DEFAULT: i64 = 500;
const PAGE_MAX: i64 = 1000;
/// Блоков в одном ответе — не больше этого объёма (первая запись входит всегда): тысяча самых
/// больших записей иначе дала бы ответ за сотню мегабайт. Остальное клиент дочитывает по `more`.
const PAGE_BYTES: i64 = 8 * 1024 * 1024;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn invalid(message: impl Into<String>) -> ApiError {
    bad("sync-invalid", message)
}

fn limit(message: impl Into<String>) -> ApiError {
    err(StatusCode::PAYLOAD_TOO_LARGE, "sync-limit", message)
}

/// Отказ, после которого устройству нужно знать, что сейчас на сервере: поколение и ключ.
fn refused(code: &'static str, message: &'static str, state: &SyncState) -> ApiError {
    err(StatusCode::CONFLICT, code, message).with("gen", json!(state.gen)).with("keyId", json!(state.key_id))
}

fn parse<'a, T: Deserialize<'a>>(body: &'a Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| invalid("Синхронизация: некорректный запрос"))
}

/// Раздел: от 1 до 16 строчных латинских букв.
fn valid_coll(s: &str) -> bool {
    (1..=16).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase())
}

/// Ключ записи: от 1 до 64 знаков из латиницы, цифр, `_` и `-`.
fn valid_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn check_key_id(key_id: &str) -> Result<(), ApiError> {
    if is_hex(key_id, 16) {
        Ok(())
    } else {
        Err(invalid("Синхронизация: неверный отпечаток ключа"))
    }
}

fn state_json(s: &SyncState) -> Value {
    json!({ "rev": s.rev, "gen": s.gen, "keyId": s.key_id })
}

fn item_json(i: &SyncItem) -> Value {
    json!({ "c": i.coll, "id": i.id, "rev": i.rev, "deleted": i.deleted, "blob": i.blob.as_deref().map(|b| B64.encode(b)) })
}

/* ---- чтение ---- */

#[derive(Deserialize)]
pub struct PullQuery {
    since: Option<String>,
    limit: Option<String>,
}

/// `since` (по умолчанию 0) и `limit` (по умолчанию 500, не больше 1000) из строки запроса.
fn page_params(since: Option<&str>, limit: Option<&str>) -> Result<(i64, i64), ApiError> {
    let number = |v: Option<&str>, min: i64, default: i64| match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => s.parse::<i64>().ok().filter(|n| *n >= min).ok_or_else(|| invalid("Синхронизация: неверные параметры запроса")),
    };
    Ok((number(since, 0, 0)?, number(limit, 1, PAGE_DEFAULT)?.min(PAGE_MAX)))
}

/// Сколько из найденных записей (rev, размер блока) войдёт в ответ: не больше `limit`, и блоки
/// укладываются в `cap` байт; первая запись входит всегда.
fn page_len(sizes: &[(i64, i64)], limit: usize, cap: i64) -> usize {
    let mut total = 0i64;
    let mut n = 0;
    for (_, size) in sizes.iter().take(limit) {
        if n > 0 && total + size > cap {
            break;
        }
        total += size;
        n += 1;
    }
    n
}

/// Записи новее `since` по возрастанию `rev`. `more` — остались ещё: клиент повторяет запрос с
/// `since`, равным `rev` последней полученной записи.
pub async fn pull(State(app): State<Arc<App>>, headers: HeaderMap, Query(q): Query<PullQuery>) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("sync:{}", user.id), 600, 3_600_000)?;
    let (since, limit) = page_params(q.since.as_deref(), q.limit.as_deref())?;
    let mut c = app.pool.get().await?;
    // один снимок базы на все запросы: счётчик в ответе не отстаёт от записей и не обгоняет их
    let tx = c.build_transaction().isolation_level(IsolationLevel::RepeatableRead).read_only(true).start().await?;
    let state = db::sync_state(&tx, user.id).await?;
    let sizes = db::sync_sizes(&tx, user.id, since, limit + 1).await?;
    let n = page_len(&sizes, limit as usize, PAGE_BYTES);
    let items = if n == 0 { Vec::new() } else { db::sync_items(&tx, user.id, since, sizes[n - 1].0).await? };
    tx.commit().await?;
    let mut out = state_json(&state);
    out["items"] = Value::Array(items.iter().map(item_json).collect());
    out["more"] = json!(sizes.len() > n);
    Ok(Json(out))
}

/* ---- запись ---- */

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushBody {
    gen: i64,
    key_id: String,
    #[serde(default)]
    items: Vec<PushItem>,
}

#[derive(Deserialize)]
pub struct PushItem {
    c: String,
    id: String,
    /// rev, который устройство видело у этой записи; 0 — записи ещё нет
    base: i64,
    #[serde(default)]
    blob: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
}

/// Проверенная запись запроса. `blob: None` — надгробие.
#[derive(Debug)]
struct Change {
    coll: String,
    id: String,
    base: i64,
    blob: Option<Vec<u8>>,
}

fn check_items(items: Vec<PushItem>) -> Result<Vec<Change>, ApiError> {
    if items.len() > MAX_REQUEST_ITEMS {
        return Err(limit(format!("Синхронизация: в одном запросе не больше {MAX_REQUEST_ITEMS} записей")));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if !valid_coll(&item.c) || !valid_id(&item.id) {
            return Err(invalid("Синхронизация: неверный раздел или ключ записи"));
        }
        if item.base < 0 {
            return Err(invalid("Синхронизация: неверный номер версии записи"));
        }
        let blob = if item.deleted == Some(true) {
            None
        } else {
            let text = item.blob.as_deref().unwrap_or("");
            let too_big = || limit(format!("Синхронизация: запись больше {} КБ", MAX_BLOB / 1024));
            if text.len() > MAX_BLOB * 4 / 3 + 8 {
                return Err(too_big());
            }
            let bytes = B64.decode(text).map_err(|_| invalid("Синхронизация: содержимое записи не в Base64"))?;
            if bytes.is_empty() {
                return Err(invalid("Синхронизация: у записи нет содержимого"));
            }
            if bytes.len() > MAX_BLOB {
                return Err(too_big());
            }
            Some(bytes)
        };
        out.push(Change { coll: item.c, id: item.id, base: item.base, blob });
    }
    Ok(out)
}

/// Что станет с записями запроса.
struct Plan {
    /// по каждой записи запроса: её новый rev, если она сохраняется; None — расхождение
    revs: Vec<Option<i64>>,
    /// счётчик изменений пользователя после запроса
    rev: i64,
    /// на сколько вырастут число записей и объём блоков
    rows: i64,
    bytes: i64,
}

/// Записи разбираются по порядку. `known` — что сервер знает о записях запроса: ключ →
/// (rev, размер блока); по ходу разбора он обновляется, поэтому повтор ключа в одном запросе
/// сверяется уже с только что сохранённой версией.
fn plan(known: &mut HashMap<(String, String), (i64, i64)>, changes: &[Change], mut rev: i64) -> Plan {
    let (mut rows, mut bytes) = (0i64, 0i64);
    let mut revs = Vec::with_capacity(changes.len());
    for ch in changes {
        let key = (ch.coll.clone(), ch.id.clone());
        let current = known.get(&key).copied();
        if current.map(|(r, _)| r).unwrap_or(0) != ch.base {
            revs.push(None);
            continue;
        }
        rev += 1;
        let size = ch.blob.as_ref().map(|b| b.len() as i64).unwrap_or(0);
        match current {
            Some((_, old)) => bytes += size - old,
            None => {
                rows += 1;
                bytes += size;
            }
        }
        known.insert(key, (rev, size));
        revs.push(Some(rev));
    }
    Plan { revs, rev, rows, bytes }
}

/// Разделы и ключи записей запроса с этими номерами: два столбца для запроса к базе.
fn keys<'a>(changes: &'a [Change], which: &[usize]) -> (Vec<&'a str>, Vec<&'a str>) {
    which.iter().map(|i| (changes[*i].coll.as_str(), changes[*i].id.as_str())).unzip()
}

/// Сохранить записи. Запрос с чужим ключом или старым поколением отклоняется целиком; запись,
/// которую устройство видело не в последней версии, попадает в `conflicts`, остальные
/// сохраняются. Номера раздаются под блокировкой строки состояния: одновременные запросы
/// одного пользователя идут по очереди.
pub async fn push(State(app): State<Arc<App>>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("sync-put:{}", user.id), 600, 3_600_000)?;
    let body = sized(body, || limit(format!("Синхронизация: запрос больше {} МБ, записи нужно отправлять частями", MAX_BODY / 1024 / 1024)))?;
    let b: PushBody = parse(&body)?;
    drop(body);
    check_key_id(&b.key_id)?;
    if b.gen < 1 {
        return Err(invalid("Синхронизация: неверное поколение данных"));
    }
    let changes = check_items(b.items)?;
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let mut state = db::sync_state_for_update(&tx, user.id).await?;
    if state.key_id.as_deref().is_some_and(|k| k != b.key_id) {
        return Err(refused("sync-key", "Данные синхронизации зашифрованы другим ключом", &state));
    }
    if b.gen != state.gen {
        return Err(refused("sync-reset", "Данные синхронизации были сброшены: нужно начать заново", &state));
    }
    let mut known: HashMap<(String, String), (i64, i64)> = if changes.is_empty() {
        HashMap::new()
    } else {
        let (colls, ids) = keys(&changes, &(0..changes.len()).collect::<Vec<usize>>());
        db::sync_known(&tx, user.id, &colls, &ids).await?.into_iter().map(|(coll, id, rev, size)| ((coll, id), (rev, size))).collect()
    };
    let plan = plan(&mut known, &changes, state.rev);
    if plan.rows > 0 || plan.bytes > 0 {
        // предел не мешает запросу, который места не прибавляет: удалять и уменьшать можно всегда
        let (count, total) = db::sync_usage(&tx, user.id).await?;
        if plan.rows > 0 && count + plan.rows > MAX_ITEMS {
            return Err(limit(format!("Хранилище синхронизации заполнено: записей не может быть больше {MAX_ITEMS}")));
        }
        if plan.bytes > 0 && total + plan.bytes > MAX_BYTES {
            return Err(limit(format!("Хранилище синхронизации заполнено: данных не может быть больше {} МБ", MAX_BYTES / 1024 / 1024)));
        }
    }
    // в базу идёт последняя сохранённая версия каждого ключа (при повторе ключа в запросе)
    let mut last: HashMap<(&str, &str), usize> = HashMap::new();
    let mut failed: Vec<usize> = Vec::new();
    for (i, ch) in changes.iter().enumerate() {
        match plan.revs[i] {
            Some(_) => {
                last.insert((&ch.coll, &ch.id), i);
            }
            None => {
                if !failed.iter().any(|j| changes[*j].coll == ch.coll && changes[*j].id == ch.id) {
                    failed.push(i);
                }
            }
        }
    }
    let mut write: Vec<usize> = last.into_values().collect();
    write.sort_unstable();
    if !write.is_empty() {
        let (colls, ids) = keys(&changes, &write);
        let revs: Vec<i64> = write.iter().map(|i| plan.revs[*i].unwrap_or(0)).collect();
        let deleted: Vec<bool> = write.iter().map(|i| changes[*i].blob.is_none()).collect();
        let blobs: Vec<Option<&[u8]>> = write.iter().map(|i| changes[*i].blob.as_deref()).collect();
        db::sync_write(&tx, user.id, &colls, &ids, &revs, &deleted, &blobs, now_ms()).await?;
    }
    state.rev = plan.rev;
    if state.key_id.is_none() {
        state.key_id = Some(b.key_id);
    }
    db::save_sync_state(&tx, user.id, &state).await?;
    let current = if failed.is_empty() {
        Vec::new()
    } else {
        let (colls, ids) = keys(&changes, &failed);
        db::sync_lookup(&tx, user.id, &colls, &ids).await?
    };
    tx.commit().await?;
    let saved: Vec<Value> = changes.iter().zip(&plan.revs).filter_map(|(ch, rev)| rev.map(|rev| json!({ "c": ch.coll, "id": ch.id, "rev": rev }))).collect();
    let conflicts: Vec<Value> = failed
        .iter()
        .map(|i| {
            let ch = &changes[*i];
            match current.iter().find(|item| item.coll == ch.coll && item.id == ch.id) {
                Some(item) => item_json(item),
                // устройство ссылается на запись, которой на сервере нет: для него она удалена
                None => json!({ "c": ch.coll, "id": ch.id, "rev": 0, "deleted": true, "blob": null }),
            }
        })
        .collect();
    let mut out = state_json(&state);
    out["saved"] = Value::Array(saved);
    out["conflicts"] = Value::Array(conflicts);
    Ok(Json(out))
}

/* ---- сброс ---- */

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetBody {
    key_id: String,
}

/// Начать заново с новым ключом: записи удаляются, поколение растёт. Счётчик изменений не
/// обнуляется: устройства со старым номером не должны принять новые записи за уже виденные.
pub async fn reset(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    let b: ResetBody = parse(&body)?;
    check_key_id(&b.key_id)?;
    app.window(&format!("sync-reset:{}", user.id), 6, 3_600_000)?;
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let mut state = db::sync_state_for_update(&tx, user.id).await?;
    db::sync_clear(&tx, user.id).await?;
    state.rev += 1;
    state.gen += 1;
    state.key_id = Some(b.key_id);
    db::save_sync_state(&tx, user.id, &state).await?;
    tx.commit().await?;
    Ok(Json(state_json(&state)))
}

/// Синхронизация выключена, данные с сервера стёрты: записей и ключа больше нет, поколение растёт.
pub async fn wipe(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (user, _, _) = app.auth(&headers).await?;
    app.window(&format!("sync-wipe:{}", user.id), 30, 3_600_000)?;
    let mut c = app.pool.get().await?;
    let tx = c.transaction().await?;
    let mut state = db::sync_state_for_update(&tx, user.id).await?;
    db::sync_clear(&tx, user.id).await?;
    state.gen += 1;
    state.key_id = None;
    db::save_sync_state(&tx, user.id, &state).await?;
    tx.commit().await?;
    Ok(Json(state_json(&state)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(c: &str, id: &str, base: i64, blob: Option<&[u8]>, deleted: Option<bool>) -> PushItem {
        PushItem { c: c.to_string(), id: id.to_string(), base, blob: blob.map(|b| B64.encode(b)), deleted }
    }

    fn refusal(items: Vec<PushItem>) -> (u16, &'static str) {
        let e = check_items(items).expect_err("запрос должен быть отклонён");
        (e.status.as_u16(), e.code)
    }

    #[test]
    fn names() {
        for ok in ["a", "bookmarks", "abcdefghijklmnop"] {
            assert!(valid_coll(ok), "{ok}");
        }
        for bad in ["", "Bookmarks", "book-marks", "tabs2", "abcdefghijklmnopq", "закладки", "a b"] {
            assert!(!valid_coll(bad), "{bad}");
        }
        for ok in ["a", "A-b_9", "0", &"x".repeat(64)] {
            assert!(valid_id(ok), "{ok}");
        }
        for bad in ["", "a/b", "a.b", "a b", "ключ", "a\n", &"x".repeat(65)] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(check_key_id("0123456789abcdef").is_ok());
        for bad in ["", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF", "0123456789abcdeg"] {
            assert_eq!(check_key_id(bad).expect_err(bad).code, "sync-invalid");
        }
    }

    #[test]
    fn page_query() {
        assert_eq!(page_params(None, None).ok(), Some((0, 500)));
        assert_eq!(page_params(Some("17"), Some("20")).ok(), Some((17, 20)));
        assert_eq!(page_params(Some(""), Some(" 5000 ")).ok(), Some((0, 1000)));
        for (since, limit) in [(Some("-1"), None), (Some("x"), None), (Some("1.5"), None), (None, Some("0")), (None, Some("-3")), (None, Some("много"))] {
            let e = page_params(since, limit).expect_err("неверные параметры");
            assert_eq!((e.status.as_u16(), e.code), (400, "sync-invalid"));
        }
    }

    #[test]
    fn page_cut() {
        let sizes = [(1, 40), (2, 40), (3, 40), (4, 0)];
        assert_eq!(page_len(&sizes, 10, 1000), 4);
        assert_eq!(page_len(&sizes, 2, 1000), 2, "не больше limit");
        assert_eq!(page_len(&sizes, 10, 80), 2, "блоки укладываются в предел");
        assert_eq!(page_len(&sizes, 10, 10), 1, "первая запись входит всегда");
        assert_eq!(page_len(&[], 10, 10), 0);
    }

    #[test]
    fn item_checks() {
        let ok = check_items(vec![item("tabs", "a1", 0, Some(b"x"), None), item("tabs", "a2", 7, None, Some(true)), item("tabs", "a3", 1, Some(&vec![1u8; MAX_BLOB]), Some(false))]).expect("верные записи");
        assert_eq!(ok.len(), 3);
        assert_eq!(ok[0].blob.as_deref(), Some(&b"x"[..]));
        assert!(ok[1].blob.is_none() && ok[1].base == 7, "надгробие без блока");
        assert_eq!(ok[2].blob.as_ref().map(Vec::len), Some(MAX_BLOB));
        // у надгробия присланный блок отбрасывается
        assert!(check_items(vec![item("tabs", "a1", 1, Some(b"x"), Some(true))]).expect("надгробие")[0].blob.is_none());
        assert_eq!(refusal(vec![item("Tabs", "a1", 0, Some(b"x"), None)]), (400, "sync-invalid"));
        assert_eq!(refusal(vec![item("tabs", "a/1", 0, Some(b"x"), None)]), (400, "sync-invalid"));
        assert_eq!(refusal(vec![item("tabs", "a1", -1, Some(b"x"), None)]), (400, "sync-invalid"));
        assert_eq!(refusal(vec![item("tabs", "a1", 0, None, None)]), (400, "sync-invalid"), "нет блока");
        assert_eq!(refusal(vec![item("tabs", "a1", 0, Some(b""), None)]), (400, "sync-invalid"), "пустой блок");
        assert_eq!(refusal(vec![PushItem { c: "tabs".into(), id: "a1".into(), base: 0, blob: Some("@@@".into()), deleted: None }]), (400, "sync-invalid"), "не Base64");
        assert_eq!(refusal(vec![item("tabs", "a1", 0, Some(&vec![1u8; MAX_BLOB + 1]), None)]), (413, "sync-limit"));
        assert_eq!(refusal(vec![PushItem { c: "tabs".into(), id: "a1".into(), base: 0, blob: Some("A".repeat(MAX_BLOB * 2)), deleted: None }]), (413, "sync-limit"));
        assert_eq!(refusal((0..=MAX_REQUEST_ITEMS).map(|i| item("tabs", &format!("k{i}"), 0, Some(b"x"), None)).collect()), (413, "sync-limit"));
        assert_eq!(check_items((0..MAX_REQUEST_ITEMS).map(|i| item("tabs", &format!("k{i}"), 0, Some(b"x"), None)).collect()).expect("ровно предел").len(), MAX_REQUEST_ITEMS);
    }

    #[test]
    fn body_shape() {
        let good: PushBody = parse(&Bytes::from_static(br#"{"gen":1,"keyId":"0123456789abcdef","items":[{"c":"tabs","id":"a","base":0,"blob":"eA=="},{"c":"tabs","id":"b","base":3,"deleted":true}]}"#)).expect("верное тело");
        assert_eq!((good.gen, good.items.len(), good.items[1].deleted), (1, 2, Some(true)));
        for raw in [&br#"{"gen":1,"items":[]}"#[..], br#"{"gen":"1","keyId":"0123456789abcdef"}"#, br#"{"gen":1,"keyId":"0123456789abcdef","items":[{"c":"tabs","id":"a","base":1.5}]}"#, br#"{"gen":1,"keyId":"0123456789abcdef","items":[{"c":"tabs","base":0}]}"#, b"[]", b"{"] {
            let e = parse::<PushBody>(&Bytes::copy_from_slice(raw)).err().expect("неверное тело");
            assert_eq!((e.status.as_u16(), e.code), (400, "sync-invalid"));
        }
    }

    fn change(id: &str, base: i64, size: Option<usize>) -> Change {
        Change { coll: "tabs".to_string(), id: id.to_string(), base, blob: size.map(|n| vec![0u8; n]) }
    }

    fn key(id: &str) -> (String, String) {
        ("tabs".to_string(), id.to_string())
    }

    #[test]
    fn planning() {
        // на сервере: a (rev 3, 100 байт), b (rev 5, надгробие)
        let mut known = HashMap::from([(key("a"), (3, 100)), (key("b"), (5, 0))]);
        let changes = [
            change("a", 3, Some(40)),  // обновление виденной версии
            change("b", 4, Some(10)),  // устаревшая версия
            change("c", 0, Some(25)),  // новая запись
            change("a", 0, Some(1)),   // «записи ещё нет», а она есть
            change("d", 2, Some(1)),   // записи нет, а устройство её видело
            change("b", 5, None),      // надгробие поверх надгробия
            change("c", 12, None),     // повтор ключа: сверяется с только что сохранённым rev
        ];
        let p = plan(&mut known, &changes, 10);
        assert_eq!(p.revs, vec![Some(11), None, Some(12), None, None, Some(13), Some(14)]);
        assert_eq!(p.rev, 14);
        assert_eq!(p.rows, 1, "новая запись одна: c");
        assert_eq!(p.bytes, (40 - 100) + 25 - 25);
        assert_eq!(known[&key("a")], (11, 40));
        assert_eq!(known[&key("c")], (14, 0));
        // ничего не сохранено: счётчик на месте
        let p = plan(&mut known, &[change("a", 3, Some(1))], 14);
        assert_eq!((p.revs, p.rev, p.rows, p.bytes), (vec![None], 14, 0, 0));
    }
}
