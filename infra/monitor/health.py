#!/usr/bin/env python3
"""Проверка состояния сервера Tabora без внешних сервисов (tabora-health.timer, каждые 5 минут).

  health.py          проверить, записать /run/tabora/health.json, сообщить об изменениях
  health.py show     напечатать последнее состояние (то же показывает motd при входе по SSH)
  health.py test     отправить пробное оповещение (проверка ALERT_URL)
  health.py ack      снять запомненные события журнала (признаки утечки секрета, сбой хука certbot)

Что проверяется: службы (stalwart, nginx, postgresql, fail2ban, ufw; cloudflared и tabora-server,
если установлены) и их порты, свободное место, срок сертификатов, последняя резервная копия и
проверка репозитория, события security.ip-unauthorized в журнале Stalwart (верный секрет
администратора или ключа API предъявлен с чужого адреса — признак утечки), неизменность
привилегированных учёток Stalwart, сбои certbot и его хука, упавшие юниты systemd, синхронизация часов.

Результат — в journald (journalctl -u tabora-health) и /run/tabora/health.json. Оповещение наружу —
если в /etc/tabora/alert.env задан ALERT_URL (ntfy или любой вебхук, см. infra/README.md); уходит при
появлении и исчезновении проблемы и раз в сутки, пока проблема остаётся. В оповещении только имя
сервера и текст проверок, секретов и адресов пользователей там нет.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
LIB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_DIR = "/run/tabora"
HEALTH = f"{RUN_DIR}/health.json"
STATE_DIR = "/var/lib/tabora"
STATE = f"{STATE_DIR}/health-state.json"
BACKUP_STATUS = f"{STATE_DIR}/backup.json"
HOOK_FAILED = f"{STATE_DIR}/certbot-hook.failed"
ALERT_ENV = "/etc/tabora/alert.env"
LEVELS = {"ok": 0, "note": 1, "warn": 2, "crit": 3}
EVENT_TTL = 24 * 3600        # сколько помнить событие журнала как проблему
REMIND_EVERY = 24 * 3600     # повтор оповещения, пока проблема остаётся
BACKUP_MAX_AGE = 36 * 3600
CHECK_MAX_AGE = 9 * 86400
# событие Stalwart вне кавычек (имена учёток и адреса в кавычках задаёт клиент)
UNAUTHORIZED = re.compile(r'^[^"]*\(security\.ip-unauthorized\) (?:[^"]|"(?:[^"\\]|\\.)*")*$')
FIELD = r'(?:^|[ ,])%s = ("(?:[^"\\]|\\.)*"|[^,]*)'


def sh(*cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 255, "", str(e)


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o644):
    tmp = f"{path}.tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


def parse_time(s):
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except (TypeError, ValueError):
        return 0


def ago(seconds):
    seconds = int(seconds)
    if seconds < 5400:
        return f"{seconds // 60} мин назад"
    if seconds < 2 * 86400:
        return f"{seconds // 3600} ч назад"
    return f"{seconds // 86400} дн. назад"


class Report:
    def __init__(self):
        self.checks = []

    def add(self, cid, level, msg):
        self.checks.append({"id": cid, "level": level, "msg": msg})


def unit_exists(name):
    return sh("systemctl", "cat", name)[0] == 0


def listening():
    """Множество (адрес, порт) слушающих TCP-сокетов."""
    out = sh("ss", "-ltnH")[1]
    found = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[3]:
            addr, port = parts[3].rsplit(":", 1)
            found.add((addr.strip("[]"), port))
    return found


def port_open(ports, port, loopback_only=False):
    for addr, p in ports:
        if p == str(port) and (not loopback_only or addr in ("127.0.0.1", "::1")):
            return True
    return False


def check_services(r):
    ports = listening()
    tls = any(os.path.isfile(f"/etc/letsencrypt/live/{d}/fullchain.pem") for d in listdir("/etc/letsencrypt/live"))
    services = [("stalwart", [25, 465, 587, 993, 8080]), ("nginx", [8081] + ([443] if tls else [])),
                ("postgresql", [5432]), ("fail2ban", []), ("ufw", [])]
    if unit_exists("cloudflared.service"):
        services.append(("cloudflared", []))
    if os.access("/opt/tabora/bin/tabora-server", os.X_OK):
        services.append(("tabora-server", [7700]))
    for name, need in services:
        state = sh("systemctl", "is-active", name)[1] or "unknown"
        if state != "active":
            r.add(f"service:{name}", "crit", f"служба {name} не работает ({state})")
            continue
        missing = [str(p) for p in need if not port_open(ports, p)]
        if missing:
            r.add(f"service:{name}", "crit", f"служба {name} работает, но не слушает порт {', '.join(missing)}")
        else:
            r.add(f"service:{name}", "ok", f"{name} работает")
    if sh("pg_isready", "-q", "-h", "127.0.0.1")[0] != 0:
        r.add("postgresql:ready", "crit", "PostgreSQL не принимает соединения")
    if sh("systemctl", "is-active", "stalwart")[1] == "active":
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/healthz/live", timeout=10) as resp:
                ok = resp.status == 200
        except Exception:
            ok = False
        if not ok:
            r.add("stalwart:http", "crit", "Stalwart не отвечает на 127.0.0.1:8080/healthz/live")
    code, out, _ = sh("systemctl", "list-units", "--failed", "--plain", "--no-legend", "--no-pager")
    failed = [line.split()[0] for line in out.splitlines() if line.split()]
    failed = [u for u in failed if u != "tabora-health.service"]
    if failed:
        r.add("systemd:failed", "warn", "упавшие юниты systemd: " + ", ".join(failed[:8]))
    if sh("timedatectl", "show", "-p", "NTPSynchronized", "--value")[1] == "no":
        r.add("time", "warn", "часы не синхронизированы (NTP)")


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def check_disk(r):
    for path in ("/", "/var/backups", "/opt/stalwart/data"):
        if not os.path.exists(path):
            continue
        if path != "/" and os.stat(path).st_dev == os.stat("/").st_dev:
            continue
        u = shutil.disk_usage(path)
        free = u.free * 100 // u.total
        st = os.statvfs(path)
        ifree = st.f_favail * 100 // st.f_files if st.f_files else 100
        level = "crit" if free < 7 or ifree < 5 else "warn" if free < 15 or ifree < 10 else "ok"
        r.add(f"disk:{path}", level, f"диск {path}: свободно {free}% ({u.free // 2**30} ГБ), inode {ifree}%")


def check_certs(r):
    for name in listdir("/etc/letsencrypt/live"):
        cert = f"/etc/letsencrypt/live/{name}/cert.pem"
        if not os.path.isfile(cert):
            continue
        code, out, _ = sh("openssl", "x509", "-enddate", "-noout", "-in", cert)
        try:
            end = time.mktime(time.strptime(out.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")) - time.timezone
        except (IndexError, ValueError):
            r.add(f"cert:{name}", "warn", f"сертификат {name}: не удалось прочитать срок")
            continue
        days = int((end - time.time()) // 86400)
        # certbot продлевает за 30 дней до конца: меньше 20 — продление не работает
        level = "crit" if days < 7 else "warn" if days < 20 else "ok"
        r.add(f"cert:{name}", level, f"сертификат {name}: осталось {days} дн.")
    if os.path.exists(HOOK_FAILED):
        try:
            detail = open(HOOK_FAILED).read().strip()[:200]
        except OSError:
            detail = ""
        r.add("certbot:hook", "crit", f"хук certbot завершился с ошибкой (сертификат не передан nginx/Stalwart): {detail}")
    if sh("systemctl", "is-failed", "certbot.service")[1] == "failed":
        r.add("certbot:renew", "warn", "certbot.service завершился с ошибкой (journalctl -u certbot)")


def check_backup(r):
    b = read_json(BACKUP_STATUS, None)
    if b is None:
        r.add("backup", "crit", "резервных копий ещё нет (systemctl start tabora-backup)")
        return
    now = time.time()
    age = now - parse_time(b.get("last_success"))
    if not b.get("last_success"):
        r.add("backup", "crit", f"резервная копия ни разу не удалась: {b.get('last_error')}")
    elif age > BACKUP_MAX_AGE:
        r.add("backup", "crit", f"последняя удачная резервная копия {ago(age)}" + (f"; ошибка: {b['last_error']}" if b.get("last_error") else ""))
    elif b.get("last_ok") is False:
        r.add("backup", "warn", f"последний запуск резервной копии не удался ({b.get('last_error')}); удачная — {ago(age)}")
    else:
        r.add("backup", "ok", f"резервная копия {b.get('snapshot', '')}: {ago(age)}")
    if b.get("check_ok") is False:
        r.add("backup:check", "crit", "restic check нашёл ошибки в репозитории копий")
    elif b.get("check_time") and now - parse_time(b["check_time"]) > CHECK_MAX_AGE:
        r.add("backup:check", "warn", f"репозиторий копий не проверялся {ago(now - parse_time(b['check_time']))}")
    if b.get("local_only"):
        r.add("backup:local", "note", "копии только локальные (тот же диск): задайте внешнее хранилище в /etc/tabora/backup.env")


def field(line, name):
    m = re.search(FIELD % name, line)
    return m.group(1).strip('"') if m else "?"


def check_journal(r, state):
    """Новые события security.ip-unauthorized: пароль администратора или ключ API верны, но адрес чужой."""
    base = ["journalctl", "-u", "stalwart", "-o", "json", "--output-fields=MESSAGE,__REALTIME_TIMESTAMP", "--no-pager", "--show-cursor"]
    recent = ["--since", "-15min"]
    code, out, err = sh(*base, *(["--after-cursor", state["cursor"]] if state.get("cursor") else recent), timeout=120)
    if code != 0 and state.get("cursor"):
        state.pop("cursor")      # журнал ротирован дальше курсора
        code, out, err = sh(*base, *recent, timeout=120)
    events = state.setdefault("events", [])
    for line in out.splitlines():
        if line.startswith("-- cursor: "):
            state["cursor"] = line[len("-- cursor: "):].strip()
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("MESSAGE")
        if not isinstance(msg, str) or not UNAUTHORIZED.match(msg):
            continue
        events.append({"time": int(rec.get("__REALTIME_TIMESTAMP", "0")) // 1000000 or int(time.time()),
                       "ip": field(msg, "remoteIp"), "account": field(msg, "accountId"), "listener": field(msg, "listenerId")})
    now = time.time()
    events[:] = [e for e in events if now - e["time"] < EVENT_TTL][-200:]
    if events:
        last = events[-1]
        # для JMAP Stalwart пишет в этом событии адрес nginx (127.0.0.1): настоящий — в журнале nginx
        ips = sorted({e["ip"] for e in events if e["ip"] not in ("127.0.0.1", "::1")})
        where = ", ".join(ips[:5]) if ips else "вход через JMAP, адрес — в /var/log/nginx/mx.access.log (403/401 с auth=1)"
        r.add("stalwart:ip-unauthorized", "crit",
              f"верный секрет привилегированной учётки Stalwart предъявлен с чужого адреса ({len(events)} раз за сутки; {where}; "
              f"учётка №{last['account']}) — возможна утечка пароля администратора или ключа API: "
              "смените секрет (infra/README.md), затем health.py ack")


def check_privileged(r):
    """Привилегированные учётки Stalwart те же, что при последнем deploy.sh setup; карта nginx актуальна."""
    code, out, err = sh("python3", f"{LIB}/stalwart/configure.py", "watch", timeout=60)
    try:
        res = json.loads(out.splitlines()[-1]) if out else {}
    except ValueError:
        res = {}
    if code != 0 or "ok" not in res:
        if sh("systemctl", "is-active", "stalwart")[1] == "active":
            r.add("stalwart:admin", "crit", f"администратор Stalwart не входит или проверка учёток не удалась: {(err or out)[-200:]}")
        return
    if res.get("diff"):
        r.add("stalwart:privileged", "crit", "привилегированные учётки Stalwart изменились не через deploy.sh setup: " + "; ".join(res["diff"])[:500])
    else:
        r.add("stalwart:privileged", "ok", f"привилегированные учётки Stalwart без изменений ({res.get('count', '?')})")
    if res.get("map_changed"):
        r.add("nginx:map", "note", "карта привилегированных логинов nginx обновлена")


def check_notes(r):
    if os.path.exists("/var/run/reboot-required"):
        r.add("reboot", "note", "после обновлений нужна перезагрузка (автоматически в 04:30)")
    if not read_env(ALERT_ENV).get("ALERT_URL"):
        r.add("alerts", "note", "оповещения наружу не настроены (ALERT_URL в /etc/tabora/alert.env)")


def send_alert(title, body, priority="default"):
    """True — отправлено; None — ALERT_URL не задан; False — ошибка."""
    env = read_env(ALERT_ENV)
    url = env.get("ALERT_URL", "")
    if not url:
        return None
    if not url.startswith(("https://", "http://")):
        print(f"оповещение: ALERT_URL должен начинаться с https:// ({ALERT_ENV})", file=sys.stderr)
        return False
    fmt = env.get("ALERT_FORMAT", "ntfy")
    headers = {"User-Agent": "tabora-health"}
    if env.get("ALERT_TOKEN"):
        headers["Authorization"] = f"Bearer {env['ALERT_TOKEN']}"
    if fmt == "json":
        # «text» понимают Slack, Mattermost и большинство приёмников, «content» — Discord
        text = f"{title}\n{body}"
        data = json.dumps({"text": text, "content": text[:1900], "title": title, "priority": priority}).encode()
        headers["Content-Type"] = "application/json"
    else:
        data = body.encode()
        headers["Content-Type"] = "text/plain; charset=utf-8"
        # заголовки HTTP — только latin-1: заголовок в RFC 2047, как принимает ntfy
        import base64
        headers["Title"] = "=?UTF-8?B?" + base64.b64encode(title.encode()).decode() + "?="
        headers["Priority"] = {"crit": "urgent", "warn": "high"}.get(priority, "default")
        headers["Tags"] = {"crit": "rotating_light", "warn": "warning"}.get(priority, "white_check_mark")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method="POST"), timeout=20) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"оповещение не отправлено: {e}", file=sys.stderr)
        return False


def notify(report, state):
    now = time.time()
    problems = {c["id"]: c for c in report.checks if LEVELS[c["level"]] >= LEVELS["warn"]}
    known = state.setdefault("problems", {})
    new = [c for cid, c in problems.items() if cid not in known or LEVELS[known[cid]["level"]] < LEVELS[c["level"]]]
    gone = [known[cid] for cid in known if cid not in problems]
    remind = bool(problems) and now - state.get("last_alert", 0) > REMIND_EVERY
    for c in new:
        print(f"ПРОБЛЕМА [{c['level']}] {c['msg']}", file=sys.stderr)
    for c in gone:
        print(f"исправлено: {c['msg']}")
    if new or gone or remind:
        host = socket.gethostname()
        worst = max((c["level"] for c in problems.values()), key=LEVELS.get, default="ok")
        lines = [f"[{c['level']}] {c['msg']}" for c in problems.values()] + [f"исправлено: {c['msg']}" for c in gone]
        title = f"{host}: {'проблемы (' + str(len(problems)) + ')' if problems else 'всё в порядке'}"
        if send_alert(title, "\n".join(lines), worst) is not False:
            state["last_alert"] = now
            state["problems"] = {cid: {"level": c["level"], "msg": c["msg"], "since": known.get(cid, {}).get("since", int(now))}
                                 for cid, c in problems.items()}
        # если отправить не удалось, список известных проблем не обновляется: попытка повторится
    return problems


def run():
    os.makedirs(RUN_DIR, mode=0o755, exist_ok=True)
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    state = read_json(STATE, {})
    r = Report()
    for check in (check_services, check_disk, check_certs, check_backup, check_privileged, check_notes):
        try:
            check(r)
        except Exception as e:   # одна сломанная проверка не должна скрыть остальные
            r.add(f"check:{check.__name__}", "warn", f"проверка {check.__name__} не выполнилась: {e}")
    try:
        check_journal(r, state)
    except Exception as e:
        r.add("check:journal", "warn", f"журнал Stalwart не прочитан: {e}")
    problems = notify(r, state)
    write_json(STATE, state, 0o600)
    worst = max((c["level"] for c in r.checks), key=LEVELS.get, default="ok")
    status = worst if LEVELS[worst] >= LEVELS["warn"] else "ok"
    write_json(HEALTH, {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": socket.gethostname(),
                        "status": status, "problems": len(problems), "checks": r.checks})
    notes = [c for c in r.checks if c["level"] == "note"]
    print(f"состояние: {status}; проверок {len(r.checks)}, проблем {len(problems)}, замечаний {len(notes)}")
    return 0


def show():
    h = read_json(HEALTH, None)
    if not h:
        print("состояние ещё не проверялось (systemctl start tabora-health)")
        return 1
    marks = {"crit": "[!!]", "warn": "[! ]", "note": "[i ]", "ok": "[ok]"}
    print(f"Tabora, {h['host']}: {'проблем — ' + str(h['problems']) if h['problems'] else 'всё в порядке'} (проверено {h['time']})")
    for c in sorted(h["checks"], key=lambda c: -LEVELS[c["level"]]):
        if c["level"] != "ok" or "-a" in sys.argv:
            print(f"  {marks[c['level']]} {c['msg']}")
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        return run()
    if cmd == "show":
        return show()
    if cmd == "test":
        res = send_alert(f"{socket.gethostname()}: проверка оповещений", "Пробное оповещение Tabora: канал работает.")
        print({True: "отправлено", None: f"ALERT_URL не задан в {ALERT_ENV}", False: "ошибка отправки"}[res])
        return 0 if res else 1
    if cmd == "ack":
        state = read_json(STATE, {})
        state["events"] = []
        write_json(STATE, state, 0o600)
        if os.path.exists(HOOK_FAILED):
            os.remove(HOOK_FAILED)
        print("запомненные события сняты")
        return 0
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
