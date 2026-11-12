//! Languages of the server's replies and e-mails. The source language is Russian: messages in the
//! code are written in Russian and translated on the way out, where the text goes to a person:
//!
//! - an error reply (`{ code, message }`): by the language of the request (Accept-Language);
//! - an e-mail: by the language of the account it is addressed to (column users.lang, which the
//!   apps keep up to date with their requests).
//!
//! Dictionaries are `i18n/<lang>.json`: "Russian text -> translation". A text with substituted
//! values ("Код: 123 456…") is found by a pattern with placeholders `{0}`, `{1}`…
//! (`tools/i18n.mjs` collects the patterns from `format!` strings). What is missing from a
//! dictionary stays in Russian. Without a language header the reply is Russian: this is how
//! earlier versions of the apps were answered.

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{ACCEPT_LANGUAGE, CONTENT_LENGTH};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub const LANGS: [&str; 4] = ["ru", "en", "uk", "es"];

struct Pattern {
    /// куски текста между местами подстановки: их на один больше, чем подстановок
    parts: Vec<String>,
    /// номер подстановки для каждого промежутка между кусками
    slots: Vec<usize>,
    value: String,
    weight: usize,
    /// короткий образец («{0} мин»): подходит только для куска, подставленного в другое сообщение
    small: bool,
}

struct Catalog {
    exact: HashMap<String, String>,
    patterns: Vec<Pattern>,
}

fn split(key: &str) -> Option<(Vec<String>, Vec<usize>)> {
    let mut parts = vec![String::new()];
    let mut slots = Vec::new();
    let mut rest = key;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) if close > 0 && after[..close].bytes().all(|b| b.is_ascii_digit()) => {
                parts.last_mut()?.push_str(&rest[..open]);
                slots.push(after[..close].parse().ok()?);
                parts.push(String::new());
                rest = &after[close + 1..];
            }
            _ => {
                parts.last_mut()?.push_str(&rest[..=open]);
                rest = after;
            }
        }
    }
    parts.last_mut()?.push_str(rest);
    if slots.is_empty() {
        None
    } else {
        Some((parts, slots))
    }
}

fn load(text: &str) -> Catalog {
    let map: HashMap<String, String> = serde_json::from_str(text).unwrap_or_default();
    let mut patterns = Vec::new();
    for (key, value) in &map {
        if value.is_empty() {
            continue;
        }
        if let Some((parts, slots)) = split(key) {
            let weight: usize = parts.iter().map(|p| p.chars().count()).sum();
            // образец почти без своего текста («{0}: {1}») подошёл бы к чему угодно
            let inner_gap = parts[1..parts.len() - 1].iter().any(|p| p.is_empty());
            let letters: usize = parts.iter().map(|p| p.chars().filter(|c| c.is_alphabetic()).count()).sum();
            if letters >= 1 && !inner_gap {
                patterns.push(Pattern { parts, slots, value: value.clone(), weight, small: weight < 6 });
            }
        }
    }
    patterns.sort_by(|a, b| b.weight.cmp(&a.weight));
    Catalog { exact: map.into_iter().filter(|(_, v)| !v.is_empty()).collect(), patterns }
}

fn catalog(lang: &str) -> Option<&'static Catalog> {
    static EN: OnceLock<Catalog> = OnceLock::new();
    static UK: OnceLock<Catalog> = OnceLock::new();
    static ES: OnceLock<Catalog> = OnceLock::new();
    match lang {
        "en" => Some(EN.get_or_init(|| load(include_str!("../i18n/en.json")))),
        "uk" => Some(UK.get_or_init(|| load(include_str!("../i18n/uk.json")))),
        "es" => Some(ES.get_or_init(|| load(include_str!("../i18n/es.json")))),
        _ => None,
    }
}

fn captures<'a>(p: &Pattern, text: &'a str) -> Option<Vec<&'a str>> {
    let first = p.parts.first()?;
    let last = p.parts.last()?;
    if !text.starts_with(first.as_str()) || !text.ends_with(last.as_str()) || first.len() + last.len() > text.len() {
        return None;
    }
    let mut pos = first.len();
    let end = text.len() - last.len();
    let mut out = Vec::with_capacity(p.slots.len());
    for part in &p.parts[1..p.parts.len() - 1] {
        let at = text.get(pos..end)?.find(part.as_str())?;
        out.push(&text[pos..pos + at]);
        pos += at + part.len();
    }
    out.push(text.get(pos..end)?);
    Some(out)
}

fn translate(cat: &Catalog, text: &str, depth: u8) -> Option<String> {
    if let Some(hit) = cat.exact.get(text) {
        return Some(hit.clone());
    }
    for p in &cat.patterns {
        if p.small && depth == 0 {
            continue;
        }
        let Some(caps) = captures(p, text) else { continue };
        let mut values: HashMap<usize, String> = HashMap::new();
        for (slot, cap) in p.slots.iter().zip(caps) {
            // подставленный кусок сам может быть сообщением (текст уведомления внутри письма)
            let inner = if depth < 2 { translate(cat, cap, depth + 1) } else { None };
            values.insert(*slot, inner.unwrap_or_else(|| cap.to_string()));
        }
        let (parts, slots) = split(&p.value)?;
        let mut out = String::new();
        for (i, part) in parts.iter().enumerate() {
            out.push_str(part);
            if let Some(slot) = slots.get(i) {
                out.push_str(values.get(slot).map(String::as_str).unwrap_or(""));
            }
        }
        return Some(out);
    }
    None
}

/// Перевод готового русского текста на язык `lang`; чего нет в словаре — возвращается как есть.
pub fn tr(lang: &str, text: &str) -> String {
    match catalog(lang) {
        Some(cat) => translate(cat, text, 0).unwrap_or_else(|| text.to_string()),
        None => text.to_string(),
    }
}

/// Язык запроса: первый язык из Accept-Language. Заголовка нет (или «*») — русский, как отвечали
/// прежние версии приложений; язык не из наших — английский.
pub fn lang_of(headers: &HeaderMap) -> &'static str {
    let Some(value) = headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()) else { return "ru" };
    let first = value.split(',').next().unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if first.is_empty() || first == "*" {
        return "ru";
    }
    let base = first.split('-').next().unwrap_or("");
    LANGS.iter().copied().find(|l| *l == base).unwrap_or("en")
}

/// Запомнить язык аккаунта для писем. В базу пишется только когда язык изменился; после
/// перезапуска сервера — один раз на аккаунт.
pub async fn remember(c: &impl deadpool_postgres::GenericClient, user_id: i64, headers: &HeaderMap) {
    if headers.get(ACCEPT_LANGUAGE).is_none() {
        return; // приложение без заголовка языка не меняет язык писем
    }
    let lang = lang_of(headers);
    static SEEN: OnceLock<Mutex<HashMap<i64, &'static str>>> = OnceLock::new();
    {
        let mut seen = SEEN.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        if seen.get(&user_id) == Some(&lang) {
            return;
        }
        if seen.len() > 200_000 {
            seen.clear();
        }
        seen.insert(user_id, lang);
    }
    if let Err(e) = c.execute("UPDATE users SET lang = $2 WHERE id = $1 AND lang <> $2", &[&user_id, &lang]).await {
        eprintln!("язык аккаунта не записан: {e}");
    }
}

/// Ответы с ошибкой переводятся на язык запроса: поле `message` в теле `{ code, message }`.
pub async fn localize(req: Request, next: Next) -> Response {
    let lang = lang_of(req.headers());
    let res = next.run(req).await;
    if lang == "ru" || !(res.status().is_client_error() || res.status().is_server_error()) {
        return res;
    }
    let (mut parts, body) = res.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 256 * 1024).await else {
        return Response::from_parts(parts, Body::empty());
    };
    if let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) {
        if let Some(message) = json.get("message").and_then(Value::as_str) {
            let translated = tr(lang, message);
            json["message"] = Value::String(translated);
            if let Ok(out) = serde_json::to_vec(&json) {
                parts.headers.remove(CONTENT_LENGTH);
                return Response::from_parts(parts, Body::from(out));
            }
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalog {
        load(r#"{
            "Неверный адрес или пароль": "Wrong address or password",
            "Код подтверждения: {0}\n\nЕго запросили для аккаунта {1}.": "Confirmation code: {0}\n\nIt was requested for the account {1}.",
            "{0}\n\nАккаунт: {1}\n\nПисьмо отправлено автоматически.": "{0}\n\nAccount: {1}\n\nThis message was sent automatically.",
            "В аккаунт вошли с устройства «{0}».": "Someone signed in from the device “{0}”.",
            "{0}: {1}": "{1} — {0}",
            "Слишком много запросов. Повторите через {0}": "Too many requests. Try again in {0}",
            "{0} мин": "{0} min"
        }"#)
    }

    #[test]
    fn exact_and_patterns() {
        let c = cat();
        assert_eq!(translate(&c, "Неверный адрес или пароль", 0).as_deref(), Some("Wrong address or password"));
        assert_eq!(
            translate(&c, "Код подтверждения: 123 456\n\nЕго запросили для аккаунта anna@tabora.app.", 0).as_deref(),
            Some("Confirmation code: 123 456\n\nIt was requested for the account anna@tabora.app.")
        );
        // письмо-уведомление: внутренний текст переводится своим образцом
        assert_eq!(
            translate(&c, "В аккаунт вошли с устройства «Мак».\n\nАккаунт: anna@tabora.app\n\nПисьмо отправлено автоматически.", 0).as_deref(),
            Some("Someone signed in from the device “Мак”.\n\nAccount: anna@tabora.app\n\nThis message was sent automatically.")
        );
        assert_eq!(translate(&c, "Совсем другой текст", 0), None);
        // образец без своего текста в словарь образцов не попадает
        assert_eq!(translate(&c, "раз: два", 0), None);
        // короткий образец переводит только кусок внутри другого сообщения
        assert_eq!(translate(&c, "Слишком много запросов. Повторите через 5 мин", 0).as_deref(), Some("Too many requests. Try again in 5 min"));
        assert_eq!(translate(&c, "5 мин", 0), None);
    }

    #[test]
    fn request_language() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(ACCEPT_LANGUAGE, v.parse().unwrap());
            m
        };
        assert_eq!(lang_of(&HeaderMap::new()), "ru");
        assert_eq!(lang_of(&h("*")), "ru");
        assert_eq!(lang_of(&h("uk-UA,uk;q=0.9,en;q=0.8")), "uk");
        assert_eq!(lang_of(&h("es")), "es");
        assert_eq!(lang_of(&h("en-GB,en;q=0.9")), "en");
        assert_eq!(lang_of(&h("de-DE,de;q=0.9")), "en");
        assert_eq!(lang_of(&h("ru-RU,ru")), "ru");
    }
}
