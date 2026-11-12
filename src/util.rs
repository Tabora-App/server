/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Мелочи без состояния: время, случайные значения, хеши, проверка входных строк, коды
//! двухфакторной защиты и шифрование небольших секретов ключом сервера.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Сравнение без утечки по времени.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Время в виде 2026-11-10T17:05:09.123Z.
pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // гражданская дата из числа дней (алгоритм Говарда Хиннанта)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60, millis)
}

pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Имя ящика: 3–32 знака, латиница, цифры, точка, дефис, подчёркивание; начинается и
/// заканчивается буквой или цифрой, разделители не идут подряд. То же правило у браузера.
pub fn valid_local(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 3 || b.len() > 32 {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let sep = |c: u8| c == b'.' || c == b'-' || c == b'_';
    if !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return false;
    }
    let mut prev_sep = false;
    for &c in b {
        if sep(c) {
            if prev_sep {
                return false;
            }
            prev_sep = true;
        } else if alnum(c) {
            prev_sep = false;
        } else {
            return false;
        }
    }
    true
}

/// Имена, которые нельзя занять: служебные адреса и то, чем удобно выдавать себя за Tabora.
const RESERVED: &[&str] = &[
    "abuse", "account", "accounts", "admin", "administrator", "api", "autoconfig", "autodiscover", "billing", "contact",
    "daemon", "dev", "dmarc", "ftp", "hello", "help", "hostmaster", "imap", "info", "jobs", "legal", "mail", "mailer-daemon",
    "moderator", "mx", "news", "newsletter", "no-reply", "nobody", "noreply", "notification", "notifications", "ns1", "ns2",
    "null", "official", "ops", "owner", "pop", "pop3", "postmaster", "press", "privacy", "root", "sales", "security", "service",
    "services", "smtp", "staff", "support", "sysadmin", "system", "tabora", "team", "tls", "webmaster", "www",
];

pub fn reserved_local(s: &str) -> bool {
    RESERVED.contains(&s) || s.starts_with("tabora-") || s.starts_with("tabora.") || s.starts_with("tabora_")
}

/// Base32 (RFC 4648) без дополнения: в таком виде секрет вводят в приложения кодов.
pub fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
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

/// Шаг времени TOTP: 30 секунд.
pub fn totp_step(now_ms: i64) -> i64 {
    now_ms.div_euclid(30_000)
}

/// Код TOTP (RFC 6238: HMAC-SHA1, 6 цифр) для шага времени.
pub fn totp(secret: &[u8], step: i64) -> u32 {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC принимает ключ любой длины");
    m.update(&(step as u64).to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let bin = ((h[o] as u32 & 0x7f) << 24) | ((h[o + 1] as u32) << 16) | ((h[o + 2] as u32) << 8) | h[o + 3] as u32;
    bin % 1_000_000
}

/// Шифрование небольшого секрета ключом сервера (AES-256-GCM): nonce (12 байт) и шифртекст с
/// меткой. `aad` привязывает блок к владельцу: чужой блок, подставленный в базу, не расшифруется.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random::<12>();
    let cipher = Aes256Gcm::new(key.into());
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad }).expect("шифрование AES-GCM"));
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce, body) = blob.split_at(12);
    Aes256Gcm::new(key.into()).decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad }).ok()
}

/// Случайный код из n десятичных цифр (без смещения: лишние значения байта отбрасываются).
pub fn digits(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in random::<16>() {
            if b < 250 && out.len() < n {
                out.push((b'0' + b % 10) as char);
            }
        }
    }
    out
}

const CODE_ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789"; // без похожих l/1, o/0

/// Резервный код входа: 8 знаков (40 бит), записывается как `xxxx-xxxx`.
pub fn backup_code() -> String {
    let s: String = random::<8>().iter().map(|b| CODE_ALPHABET[(*b as usize) % 32] as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// Резервный код, как его ввёл человек → 8 знаков алфавита или None.
pub fn clean_backup_code(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_lowercase()).collect();
    (s.len() == 8 && s.bytes().all(|b| CODE_ALPHABET.contains(&b))).then_some(s)
}

/// Код из письма или приложения, как его ввёл человек: только цифры, без пробелов и дефисов.
pub fn clean_digits(input: &str, len: usize) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (s.len() == len && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// Адрес электронной почты для писем от сервера: `имя@домен.зона`, только ASCII, в нижнем
/// регистре. Проверка намеренно простая: настоящую проверку делает письмо с кодом.
pub fn clean_address(input: &str) -> Option<String> {
    let s = input.trim().to_lowercase();
    if s.len() < 6 || s.len() > 254 || !s.is_ascii() {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    let local_ok = !local.is_empty() && local.len() <= 64 && local.bytes().all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b)) && !local.starts_with('.') && !local.ends_with('.') && !local.contains("..");
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !l.starts_with('-') && !l.ends_with('-'))
        && labels.last().map(|t| t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic())).unwrap_or(false);
    (local_ok && domain_ok).then_some(s)
}

/// Адрес для показа человеку, который его и так знает: `a***@example.com`.
pub fn mask_address(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => format!("{}***@{}", local.chars().next().unwrap_or('*'), domain),
        None => "***".to_string(),
    }
}

/// Название устройства для списка устройств: без управляющих знаков, не длиннее 64 знаков.
pub fn clean_name(s: &str, fallback: &str) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).take(64).collect();
    let t = t.trim();
    if t.is_empty() { fallback.to_string() } else { t.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_794_330_309_123), "2026-11-10T17:05:09.123Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn local_names() {
        for ok in ["anna", "a.b", "kot.test", "x-y_z9", "abc", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"] {
            assert!(valid_local(ok), "{ok}");
        }
        for bad in ["", "ab", "a", ".abc", "abc.", "a..b", "a.-b", "Abc", "абв", "a b", "a@b", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"] {
            assert!(!valid_local(bad), "{bad}");
        }
        assert!(reserved_local("postmaster") && reserved_local("tabora-team") && !reserved_local("anna"));
    }

    #[test]
    fn hex_check() {
        assert!(is_hex("00ff", 4) && !is_hex("00FF", 4) && !is_hex("00f", 4) && !is_hex("zz00", 4));
    }

    #[test]
    fn totp_vectors() {
        // RFC 6238, приложение B (SHA-1, секрет «12345678901234567890»): последние 6 цифр
        let secret = b"12345678901234567890";
        assert_eq!(totp(secret, totp_step(59_000)), 287_082);
        assert_eq!(totp(secret, totp_step(1_111_111_109_000)), 81_804);
        assert_eq!(totp(secret, totp_step(1_234_567_890_000)), 5_924);
        assert_eq!(totp(secret, totp_step(20_000_000_000_000)), 353_130);
        // RFC 4648
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(secret), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn sealed_secrets() {
        let key = [3u8; 32];
        let blob = seal(&key, b"u1", b"secret");
        assert_eq!(open(&key, b"u1", &blob).as_deref(), Some(&b"secret"[..]));
        assert!(open(&key, b"u2", &blob).is_none(), "другой владелец");
        assert!(open(&[4u8; 32], b"u1", &blob).is_none(), "другой ключ");
        let mut broken = blob.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"u1", &broken).is_none(), "подправленный блок");
        assert_ne!(seal(&key, b"u1", b"secret"), blob, "nonce каждый раз новый");
    }

    #[test]
    fn codes_and_addresses() {
        let d = digits(8);
        assert!(d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()));
        let c = backup_code();
        assert!(c.len() == 9 && c.as_bytes()[4] == b'-');
        assert_eq!(clean_backup_code(&c.to_uppercase()).as_deref(), Some(c.replace('-', "").as_str()));
        assert_eq!(clean_backup_code(" abcd efgh "), Some("abcdefgh".to_string()));
        assert!(clean_backup_code("abcd-efg").is_none() && clean_backup_code("abcd-efg1").is_none(), "длина и знаки не из алфавита");
        assert_eq!(clean_digits(" 1234-5678 ", 8), Some("12345678".to_string()));
        assert!(clean_digits("12345", 6).is_none() && clean_digits("12345a", 6).is_none());
        for ok in ["anna@example.com", "A.B+tag@Mail.Example.org", "x_y@sub.domain.io"] {
            assert!(clean_address(ok).is_some(), "{ok}");
        }
        assert_eq!(clean_address(" Anna@Example.COM ").as_deref(), Some("anna@example.com"));
        for bad in ["", "anna", "anna@", "@example.com", "anna@example", "anna@@example.com", "an na@example.com", "anna@exa mple.com", "анна@example.com", "anna@пример.рф", ".anna@example.com", "a..b@example.com", "anna@-example.com", "anna@example.c0m", "anna@example.com\r\nBcc: x@y.z"] {
            assert!(clean_address(bad).is_none(), "{bad}");
        }
        assert_eq!(mask_address("anna@example.com"), "a***@example.com");
    }
}
