/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Ограничители в памяти процесса (сервер один): окно «не больше N за период» и счётчик
//! неудач с растущей паузой. После перезапуска счёт начинается заново: это допустимо,
//! потому что перебор пароля и так упирается в тяжёлый хеш на стороне клиента.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default, Clone, Copy)]
struct Entry {
    window_start: i64,
    count: u32,
    fails: u32,
    locked_until: i64,
    touched: i64,
}

#[derive(Default)]
pub struct Limiter {
    inner: Mutex<HashMap<String, Entry>>,
}

/// Пауза после очередной неудачи: первые четыре бесплатно, дальше 1, 2, 4… минут, не больше часа.
fn pause_ms(fails: u32) -> i64 {
    if fails < 5 {
        return 0;
    }
    let minutes = 1i64 << (fails - 5).min(6);
    minutes.min(60) * 60_000
}

impl Limiter {
    /// Событие в окне: Ok, если уложились в max за window_ms, иначе Err(сколько мс ждать).
    pub fn hit(&self, key: &str, max: u32, window_ms: i64, now: i64) -> Result<(), i64> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = map.entry(key.to_string()).or_default();
        if now - e.window_start >= window_ms {
            e.window_start = now;
            e.count = 0;
        }
        e.touched = now;
        if e.count >= max {
            return Err((e.window_start + window_ms - now).max(1000));
        }
        e.count += 1;
        Ok(())
    }

    /// Сколько ещё длится пауза после неудач (0 — можно пробовать).
    pub fn locked(&self, key: &str, now: i64) -> i64 {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).map(|e| (e.locked_until - now).max(0)).unwrap_or(0)
    }

    /// Неудачная попытка: возвращает назначенную паузу в мс (0 — пока без паузы).
    pub fn fail(&self, key: &str, now: i64) -> i64 {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = map.entry(key.to_string()).or_default();
        e.fails = e.fails.saturating_add(1);
        e.touched = now;
        let pause = pause_ms(e.fails);
        e.locked_until = now + pause;
        pause
    }

    /// Неудача со своим расписанием пауз; счёт обнуляется, если quiet_ms было тихо.
    pub fn fail_with(&self, key: &str, now: i64, quiet_ms: i64, pause: fn(i32) -> i64) -> i64 {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = map.entry(key.to_string()).or_default();
        if now - e.touched >= quiet_ms {
            e.fails = 0;
        }
        e.fails = e.fails.saturating_add(1);
        e.touched = now;
        let wait = pause(e.fails.min(i32::MAX as u32) as i32);
        e.locked_until = now + wait;
        wait
    }

    /// Сколько событий уже учтено в текущем окне (без учёта нового).
    pub fn count(&self, key: &str, window_ms: i64, now: i64) -> u32 {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).filter(|e| now - e.window_start < window_ms).map(|e| e.count).unwrap_or(0)
    }

    pub fn clear(&self, key: &str) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }

    /// Записи, которых не касались сутки, удаляются (вызывается по таймеру).
    pub fn sweep(&self, now: i64) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| now - e.touched < 86_400_000 || e.locked_until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window() {
        let l = Limiter::default();
        assert!(l.hit("k", 2, 1000, 0).is_ok());
        assert!(l.hit("k", 2, 1000, 10).is_ok());
        assert!(l.hit("k", 2, 1000, 20).is_err());
        assert!(l.hit("k", 2, 1000, 1001).is_ok());
    }

    #[test]
    fn backoff() {
        let l = Limiter::default();
        for _ in 0..4 {
            assert_eq!(l.fail("k", 0), 0);
        }
        assert_eq!(l.fail("k", 0), 60_000);
        assert_eq!(l.locked("k", 30_000), 30_000);
        assert_eq!(l.fail("k", 60_000), 120_000);
        for _ in 0..20 {
            l.fail("k", 0);
        }
        assert_eq!(l.fail("k", 0), 3_600_000);
        l.clear("k");
        assert_eq!(l.locked("k", 0), 0);
    }

    #[test]
    fn own_schedule_and_count() {
        fn pause(fails: i32) -> i64 {
            if fails < 3 { 0 } else { 1000 * i64::from(fails) }
        }
        let l = Limiter::default();
        assert_eq!(l.fail_with("g", 0, 10_000, pause), 0);
        assert_eq!(l.fail_with("g", 1, 10_000, pause), 0);
        assert_eq!(l.fail_with("g", 2, 10_000, pause), 3000);
        assert_eq!(l.locked("g", 1002), 2000);
        // после тишины счёт начинается заново
        assert_eq!(l.fail_with("g", 20_000, 10_000, pause), 0);
        assert_eq!(l.count("w", 1000, 0), 0);
        assert!(l.hit("w", 5, 1000, 0).is_ok());
        assert!(l.hit("w", 5, 1000, 10).is_ok());
        assert_eq!(l.count("w", 1000, 20), 2);
        assert_eq!(l.count("w", 1000, 1500), 0);
    }
}
