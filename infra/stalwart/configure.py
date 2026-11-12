#!/usr/bin/env python3
"""Настройка Stalwart 1.x через JMAP-объекты администратора (идемпотентно).

  configure.py admin-ok      код 0, если постоянный администратор из stalwart-admin.env входит
  configure.py recovery-on   добавить временного аварийного администратора в stalwart.env
  configure.py recovery-off  убрать его из stalwart.env
  configure.py bootstrap     от имени аварийного администратора: домен и постоянный администратор
  configure.py [apply]       от имени постоянного администратора: всё остальное
  configure.py watch         для мониторинга: обновить карту логинов nginx и сравнить привилегированные
                             учётки с состоянием на момент последнего apply (печатает JSON)

Коды выхода recovery-on/off и apply: 0 — ничего не изменилось, 3 — изменилось, нужен перезапуск
службы stalwart; остальное — ошибка.

Постоянный администратор: учётка <случайное имя>@<домен> с ролью Admin, пароль входит только
с 127.0.0.1/::1 (allowedIps), лежит в /etc/tabora/stalwart-admin.env (root, 600).
tabora-server: отдельная учётка с ролью User плюс управление учётками (создание, изменение,
удаление, алиасы) и чтение доменов; ключ API только с 127.0.0.1/::1 в /etc/tabora/server.env.
"""
import json
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True  # без __pycache__ в /usr/local/lib/tabora
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import (ADMIN_ENV, LOOPBACK, SERVER_ENV, STALWART_ENV, Client, JmapError, admin_client,  # noqa: E402
                  log, new_login, new_secret, read_env, update_env)

DOMAIN = read_env(SERVER_ENV).get("TABORA_DOMAIN") or os.environ.get("DOMAIN", "tabora.app")
MAIL_HOST = os.environ.get("MAIL_HOST", f"mx.{DOMAIN}")
NGINX_MAP = "/etc/nginx/tabora-privileged-logins.map"
ZONE_FILE = f"/etc/tabora/dns-{DOMAIN}.zone"
POSTMASTER_ENV = "/etc/tabora/postmaster.env"      # root:root 600, ящик postmaster@ (служебная почта)
PRIVILEGED_STATE = "/var/lib/tabora/privileged.json"  # привилегированные учётки на момент apply
# служебные адреса (RFC 2142, требования Let's Encrypt и почтовых провайдеров) — алиасы ящика postmaster
# hello@ указан на сайте как адрес для связи
POSTMASTER_ALIASES = ("abuse", "hostmaster", "security", "webmaster", "hello")
DAY_MS = 86400 * 1000
# Сроки встроенных банов Stalwart (x:Security). По умолчанию null — бан навсегда: адреса
# переходят к другим людям, а список растёт без конца.
BAN_PERIODS = {"authBanPeriod": DAY_MS, "abuseBanPeriod": DAY_MS, "loiterBanPeriod": DAY_MS, "scanBanPeriod": 7 * DAY_MS}
CHANGED = 3

# Публикуются в автонастройке и SRV. POP3 и ManageSieve выключены (Sieve есть в JMAP),
# CalDAV/CardDAV/WebDAV не публикуются, пока nginx не проксирует /dav/.
SERVICES = ("jmap", "imap", "smtp")
DROP_LISTENERS = {"pop3", "manageSieve"}   # по протоколу; https (443) занимает nginx

# Права tabora-server сверх роли User. Права User нужны целиком: Stalwart не даёт выдать
# создаваемой учётке права, которых нет у создающего, и не даёт трогать учётки с большими правами
# (администраторов). Ограничить домен в OSS-версии нельзя (тенанты есть только в Enterprise),
# но домен на сервере один.
SERVICE_PERMISSIONS = ["sysAccountGet", "sysAccountQuery", "sysAccountCreate", "sysAccountUpdate",
                       "sysAccountDestroy", "sysDomainGet", "sysDomainQuery"]

STDOUT_TRACER = {"@type": "Stdout", "enable": True, "level": "info", "ansi": False, "multiline": False,
                 "buffered": False, "lossy": False, "events": {}, "eventsPolicy": "exclude"}
# по умолчанию auth.failed уровня debug и не попадает в журнал, а по нему работает fail2ban
EVENT_LEVELS = {"auth.failed": "info"}


def password_cred(secret):
    return {"0": {"@type": "Password", "secret": secret, "allowedIps": LOOPBACK}}


def ensure_domain(c):
    for d in c.get_all("Domain"):
        if d["name"] == DOMAIN:
            return d["id"]
    r = c.call("x:Domain/set", {"create": {"d": {"name": DOMAIN}}})
    log(f"домен {DOMAIN} создан")
    return r["created"]["d"]["id"]


def find_account(c, local, domain_id):
    for a in c.get_all("Account"):
        if a.get("name") == local and a.get("domainId") == domain_id:
            return a
    return None


def local_part(login, prefix=""):
    return login.split("@", 1)[0] if login else new_login(prefix)


# ---- аварийный администратор (только на время создания постоянного) -------------------
def recovery_on():
    if read_env(STALWART_ENV).get("STALWART_RECOVERY_ADMIN"):
        return 0
    update_env(STALWART_ENV, {"STALWART_RECOVERY_ADMIN": f"{new_login('recovery-')}:{new_secret(40)}"},
               mode=0o640, group="stalwart")
    log("временный аварийный администратор добавлен в stalwart.env")
    return CHANGED


def recovery_off():
    if not read_env(STALWART_ENV).get("STALWART_RECOVERY_ADMIN"):
        return 0
    update_env(STALWART_ENV, remove=("STALWART_RECOVERY_ADMIN",), mode=0o640, group="stalwart")
    log("аварийный администратор убран из stalwart.env")
    return CHANGED


def bootstrap():
    user, _, pw = read_env(STALWART_ENV).get("STALWART_RECOVERY_ADMIN", "").partition(":")
    if not user or not pw:
        raise SystemExit("нет STALWART_RECOVERY_ADMIN в stalwart.env: сначала configure.py recovery-on и перезапуск")
    c = Client(user.strip(), pw.strip())
    domain_id = ensure_domain(c)
    local = local_part(read_env(ADMIN_ENV).get("STALWART_ADMIN_USER", ""))
    password = new_secret(48)
    acc = find_account(c, local, domain_id)
    if acc:
        c.call("x:Account/set", {"update": {acc["id"]: {"credentials": password_cred(password), "roles": {"@type": "Admin"}}}})
        log(f"администратор {local}@{DOMAIN}: новый пароль")
    else:
        c.call("x:Account/set", {"create": {"a": {
            "@type": "User", "name": local, "domainId": domain_id, "roles": {"@type": "Admin"},
            "description": "Tabora: администратор (вход только с 127.0.0.1)",
            "credentials": password_cred(password)}}})
        log(f"администратор {local}@{DOMAIN} создан")
    update_env(ADMIN_ENV, {"STALWART_ADMIN_USER": f"{local}@{DOMAIN}", "STALWART_ADMIN_PASS": password},
               mode=0o600, header="Администратор Stalwart (создан stalwart/configure.py). Вход только с 127.0.0.1.")
    if not admin_client().ok():
        raise SystemExit("постоянный администратор не входит")
    return 0


# ---- настройка -------------------------------------------------------------------------------
def configure_listeners(c):
    listeners = c.get_all("NetworkListener")
    update, destroy, create = {}, [], {}
    for li in listeners:
        if li["name"] == "https" or li.get("protocol") in DROP_LISTENERS:
            destroy.append(li["id"])
        elif li["name"] == "http" and list(li["bind"]) != ["127.0.0.1:8080"]:
            update[li["id"]] = {"bind": {"127.0.0.1:8080": True}}
    if not any(li["name"] == "submission" for li in listeners):
        create["sub"] = {"name": "submission", "bind": {"[::]:587": True}, "protocol": "smtp", "useTls": True, "implicitTls": False}
    if update or destroy or create:
        c.call("x:NetworkListener/set", {k: v for k, v in (("update", update), ("destroy", destroy), ("create", create)) if v})
        log(f"слушатели: изменено {len(update)}, удалено {len(destroy)}, создано {len(create)}")
        return True
    return False


def configure_system(c, domain_id):
    ss = c.call("x:SystemSettings/get", {"ids": ["singleton"]})["list"][0]
    patch = {}
    if ss.get("defaultHostname") != MAIL_HOST:
        patch["defaultHostname"] = MAIL_HOST
    if ss.get("defaultDomainId") != domain_id:
        patch["defaultDomainId"] = domain_id
    mx = ss.get("mailExchangers") or {}
    if not mx or list(mx.values())[0].get("hostname") != MAIL_HOST:
        patch["mailExchangers"] = {"0": {"hostname": MAIL_HOST, "priority": 10}}
    services = {s: {"hostname": MAIL_HOST, "cleartext": False} for s in SERVICES}
    if ss.get("services") != services:
        patch["services"] = services
    if patch:
        c.call("x:SystemSettings/set", {"update": {"singleton": patch}})
        log(f"системные настройки: {', '.join(patch)}")
    # адрес клиента из X-Forwarded-For (последний адрес). HTTP-слушатель только на 127.0.0.1,
    # поэтому заголовок могут прислать только местные процессы; nginx пишет туда $remote_addr.
    # Без этого все запросы через nginx считались пришедшими с 127.0.0.1 (а он никогда не банится).
    http = c.call("x:Http/get", {"ids": ["singleton"]})["list"][0]
    hp = {k: v for k, v in (("clientIpSource", "xForwardedFor"), ("forwardedHops", 1)) if http.get(k) != v}
    if hp:
        c.call("x:Http/set", {"update": {"singleton": hp}})
        log(f"HTTP: {', '.join(hp)}")
    return bool(patch or hp)


def configure_security(c):
    sec = c.call("x:Security/get", {"ids": ["singleton"]})["list"][0]
    patch = {k: v for k, v in BAN_PERIODS.items() if sec.get(k) != v}
    if patch:
        c.call("x:Security/set", {"update": {"singleton": patch}})
        log("встроенные баны Stalwart: конечный срок (" + ", ".join(f"{k} = {v // DAY_MS} сут." for k, v in patch.items()) + ")")
    return bool(patch)


def configure_postmaster(c, domain_id):
    """Ящик postmaster@ с алиасами abuse@ и др.: обычный пользователь, пароль в postmaster.env."""
    login = f"postmaster@{DOMAIN}"
    aliases = {str(i): {"name": n, "domainId": domain_id} for i, n in enumerate(POSTMASTER_ALIASES)}
    env = read_env(POSTMASTER_ENV)
    acc = find_account(c, "postmaster", domain_id)
    password = None
    if acc is None:
        password = new_secret(32)
        c.call("x:Account/set", {"create": {"p": {
            "@type": "User", "name": "postmaster", "domainId": domain_id, "roles": {"@type": "User"},
            "description": "Tabora: служебная почта (postmaster, abuse, security)",
            "aliases": aliases, "credentials": {"0": {"@type": "Password", "secret": password}}}}})
        log(f"ящик {login} создан (алиасы: {', '.join(POSTMASTER_ALIASES)})")
    else:
        have = {(a.get("name"), a.get("domainId")) for a in (acc.get("aliases") or {}).values()}
        if have != {(n, domain_id) for n in POSTMASTER_ALIASES}:
            c.call("x:Account/set", {"update": {acc["id"]: {"aliases": aliases}}})
            log(f"ящик {login}: алиасы обновлены")
        if env.get("POSTMASTER_USER") != login or not env.get("POSTMASTER_PASS"):
            password = new_secret(32)
            c.call("x:Account/set", {"update": {acc["id"]: {"credentials": {"0": {"@type": "Password", "secret": password}}}}})
            log(f"ящик {login}: новый пароль")
    if password:
        update_env(POSTMASTER_ENV, {"POSTMASTER_USER": login, "POSTMASTER_PASS": password}, mode=0o600,
                   header="Ящик служебной почты postmaster@/abuse@/security@ (создан stalwart/configure.py). Вход по IMAP/JMAP.")


def configure_tracing(c):
    changed = False
    tracers = c.get_all("Tracer")
    # журнал в stderr → journald (stalwart.service); файловый журнал в /var/log/stalwart
    # не писался вовсе: каталога нет, а служба может писать только в data и logs
    destroy = [t["id"] for t in tracers if t.get("@type") == "Log" and not t.get("path", "").startswith("/opt/stalwart/logs")]
    stdout = [t for t in tracers if t.get("@type") == "Stdout"]
    args = {}
    if destroy:
        args["destroy"] = destroy
    if not stdout:
        args["create"] = {"t": STDOUT_TRACER}
    else:
        diff = {k: v for k, v in STDOUT_TRACER.items() if k != "@type" and stdout[0].get(k) != v}
        if diff:
            args["update"] = {stdout[0]["id"]: diff}
    if args:
        c.call("x:Tracer/set", args)
        log("журнал Stalwart: stderr → journald")
        changed = True
    current = {e["event"]: e for e in c.get_all("EventTracingLevel")}
    create, update = {}, {}
    for i, (event, level) in enumerate(EVENT_LEVELS.items()):
        if event not in current:
            create[f"e{i}"] = {"event": event, "level": level}
        elif current[event].get("level") != level:
            update[current[event]["id"]] = {"level": level}
    if create or update:
        c.call("x:EventTracingLevel/set", {k: v for k, v in (("create", create), ("update", update)) if v})
        log(f"уровни событий: {', '.join(EVENT_LEVELS)}")
        changed = True
    return changed


def configure_service_account(c, domain_id):
    srv = read_env(SERVER_ENV)
    local = local_part(srv.get("STALWART_SERVICE_USER", ""), "svc")
    login = f"{local}@{DOMAIN}"
    perms = {"@type": "Merge", "enabledPermissions": {p: True for p in SERVICE_PERMISSIONS}, "disabledPermissions": {}}
    acc = find_account(c, local, domain_id)
    if acc is None:
        r = c.call("x:Account/set", {"create": {"s": {
            "@type": "User", "name": local, "domainId": domain_id, "roles": {"@type": "User"}, "permissions": perms,
            "description": "Tabora: служба tabora-server (только ключ API с 127.0.0.1)"}}})
        acc_id = r["created"]["s"]["id"]
        log(f"учётка tabora-server {login} создана")
        update_env(SERVER_ENV, {"STALWART_SERVICE_USER": login}, mode=0o640, group="tabora")
    else:
        acc_id = acc["id"]
        if acc.get("permissions") != perms or acc.get("roles") != {"@type": "User"}:
            c.call("x:Account/set", {"update": {acc_id: {"permissions": perms, "roles": {"@type": "User"}}}})
            log(f"учётка tabora-server {login}: права обновлены")
    key = srv.get("STALWART_API_KEY", "")
    if key and Client(bearer=key).ok("x:Domain/get", {"ids": [domain_id]}):
        if update_env(SERVER_ENV, {"STALWART_SERVICE_USER": login}, remove=("STALWART_ADMIN_USER", "STALWART_ADMIN_PASS"),
                      mode=0o640, group="tabora"):
            log("server.env: пароль администратора убран")
        return
    # новый ключ API: временный пароль (только с 127.0.0.1), вход им, ключ, пароль удаляется.
    # Старые ключи при этом пропадают (список учётных данных заменяется целиком).
    tmp_pw = new_secret(48)
    c.call("x:Account/set", {"update": {acc_id: {"credentials": password_cred(tmp_pw)}}})
    svc = Client(login, tmp_pw)
    r = svc.call("x:ApiKey/set", {"create": {"k": {"description": "tabora-server", "permissions": {"@type": "Inherit"},
                                                    "allowedIps": LOOPBACK}}})
    key = r["created"]["k"]["secret"]
    creds = c.call("x:Account/get", {"ids": [acc_id], "properties": ["credentials"]})["list"][0].get("credentials") or {}
    drop = {f"credentials/{k}": None for k, v in creds.items() if v.get("@type") == "Password"}
    if drop:
        c.call("x:Account/set", {"update": {acc_id: drop}})
    update_env(SERVER_ENV, {"STALWART_SERVICE_USER": login, "STALWART_API_KEY": key},
               remove=("STALWART_ADMIN_USER", "STALWART_ADMIN_PASS"), mode=0o640, group="tabora")
    if not Client(bearer=key).ok("x:Domain/get", {"ids": [domain_id]}):
        raise SystemExit("новый ключ API tabora-server не работает")
    log(f"ключ API tabora-server выпущен и записан в {SERVER_ENV}")


def is_privileged(a):
    roles = (a.get("roles") or {}).get("@type")
    perms = (a.get("permissions") or {}).get("@type", "Inherit")
    return roles != "User" or perms != "Inherit"


def write_nginx_map(accounts):
    """Все учётки с ролью не User или с добавленными правами: nginx не пускает их Basic-auth снаружи.

    Файл 640 root:www-data (список логинов администраторов посторонним не нужен), имена
    экранируются для регулярного выражения. True, если файл изменился (nginx перечитан).
    """
    names = sorted({a["name"].lower() for a in accounts if a.get("name") and is_privileged(a)})
    lines = ["# Создано infra/stalwart/configure.py: логины с правами сверх обычного пользователя.",
             '"~*(^|%)admin(@|%|$)" 1;', '"~*(^|%)recovery-" 1;']
    for n in names:
        # буквы, цифры, «-» и «_» пишутся как есть, точка экранируется, любой другой символ
        # заменяется на «.» (любой символ): так в строку nginx и в регулярное выражение не попадает
        # ничего особого, а шаблон может только расшириться (запретить лишнее), но не сузиться
        pattern = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "-_") else "\\." if ch == "." else "." for ch in n)
        lines.append(f'"~*(^|%){pattern}(@|%|$)" 1;')
    text = "\n".join(lines) + "\n"
    try:
        st = os.stat(NGINX_MAP)
        gid = grp_gid("www-data")
        if open(NGINX_MAP).read() == text and st.st_mode & 0o777 == 0o640 and st.st_uid == 0 and st.st_gid == gid:
            return False
    except FileNotFoundError:
        pass
    backup = None
    try:
        backup = open(NGINX_MAP).read()
    except FileNotFoundError:
        pass
    write_map_file(text)
    # карту читает главный процесс nginx (root) при перезагрузке конфигурации
    if shutil.which("nginx") and subprocess.run(["systemctl", "is-active", "-q", "nginx"]).returncode == 0:
        if subprocess.run(["nginx", "-t", "-q"], capture_output=True).returncode != 0:
            if backup is not None:
                write_map_file(backup)
            raise SystemExit("nginx не принял карту привилегированных логинов — возвращена прежняя")
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
    log(f"nginx: логины администраторов ({len(names)}) запрещены снаружи")
    return True


def grp_gid(name):
    import grp
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return 0


def write_map_file(text):
    tmp = NGINX_MAP + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        os.fchown(fd, 0, grp_gid("www-data"))
        os.fchmod(fd, 0o640)
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.replace(tmp, NGINX_MAP)


# ---- привилегированные учётки: снимок для мониторинга -------------------------------------------
def privileged_snapshot(accounts):
    """Учётки с правами сверх пользователя без секретов: по снимку мониторинг замечает, что
    администратора изменили, добавили нового или сняли ограничение по адресам."""
    snap = {}
    for a in accounts:
        if not is_privileged(a):
            continue
        creds = sorted(json.dumps({"type": c.get("@type"), "id": c.get("credentialId"), "allowedIps": sorted(c.get("allowedIps") or {}),
                                   "permissions": c.get("permissions"), "expiresAt": c.get("expiresAt")}, sort_keys=True)
                       for c in (a.get("credentials") or {}).values())
        snap[a["id"]] = {"name": a.get("name"), "type": a.get("@type"), "roles": a.get("roles"), "permissions": a.get("permissions"),
                         "credentials": creds, "aliases": sorted(str(v.get("name")) for v in (a.get("aliases") or {}).values()),
                         "memberGroupIds": sorted(a.get("memberGroupIds") or {})}
    return snap


def snapshot_diff(old, new):
    out = []
    for i in sorted(set(old) | set(new)):
        if i not in old:
            out.append(f"новая привилегированная учётка {new[i]['name']}")
        elif i not in new:
            out.append(f"привилегированная учётка {old[i]['name']} удалена или лишена прав")
        else:
            keys = [k for k in new[i] if old[i].get(k) != new[i][k]]
            if keys:
                out.append(f"учётка {new[i]['name']}: изменились {', '.join(keys)}")
    return out


def save_privileged(accounts):
    os.makedirs(os.path.dirname(PRIVILEGED_STATE), mode=0o755, exist_ok=True)
    tmp = PRIVILEGED_STATE + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(privileged_snapshot(accounts), f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, PRIVILEGED_STATE)


def watch():
    """Для tabora-health: вход администратора, карта nginx, сравнение со снимком. Печатает JSON."""
    accounts = admin_client().get_all("Account")
    map_changed = write_nginx_map(accounts)
    try:
        with open(PRIVILEGED_STATE) as f:
            expected = json.load(f)
    except (OSError, ValueError):
        expected = None
    current = privileged_snapshot(accounts)
    diff = snapshot_diff(expected, current) if expected is not None else ["нет снимка учёток: запустите infra/deploy.sh setup"]
    print(json.dumps({"ok": True, "count": len(current), "diff": diff, "map_changed": map_changed}, ensure_ascii=False))
    return 0


def write_zone(c, domain_id):
    d = c.call("x:Domain/get", {"ids": [domain_id]})["list"][0]
    zone = d.get("dnsZoneFile") or ""
    if not zone:
        log("зоны DNS у домена нет; поля: " + ", ".join(sorted(d)))
        return
    try:
        if open(ZONE_FILE).read() == zone:
            return
    except FileNotFoundError:
        pass
    with open(ZONE_FILE, "w") as f:
        f.write(zone)
    os.chmod(ZONE_FILE, 0o644)
    log(f"DNS-записи домена записаны в {ZONE_FILE}")


def apply():
    c = admin_client()
    changed = configure_listeners(c)
    domain_id = ensure_domain(c)
    changed |= configure_system(c, domain_id)
    changed |= configure_tracing(c)
    changed |= configure_security(c)
    configure_service_account(c, domain_id)
    configure_postmaster(c, domain_id)
    accounts = c.get_all("Account")
    write_nginx_map(accounts)
    save_privileged(accounts)   # состояние после развёртывания — эталон для мониторинга
    write_zone(c, domain_id)
    if not changed:
        log("Stalwart: настройки уже заданы")
    return CHANGED if changed else 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "apply"
    if cmd == "admin-ok":
        try:
            return 0 if admin_client().ok() else 1
        except JmapError:
            return 1
    commands = {"recovery-on": recovery_on, "recovery-off": recovery_off, "bootstrap": bootstrap, "apply": apply, "watch": watch}
    if cmd not in commands:
        raise SystemExit(__doc__)
    try:
        return commands[cmd]()
    except JmapError as e:
        raise SystemExit(f"Stalwart: {e}")


if __name__ == "__main__":
    sys.exit(main())
