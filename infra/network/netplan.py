#!/usr/bin/env python3
"""Сеть сервера без привязки к конкретной машине (/etc/netplan/50-tabora.yaml).

Образ Hetzner настраивает сеть через cloud-init и привязывает netplan к MAC-адресам. cloud-init
у нас отключён (гонится с переименованием интерфейса), поэтому сервер, развёрнутый из снапшота
на новой машине (другие MAC и IPv6), остался бы без сети. Здесь netplan состоит из двух частей:

  z-any     любой интерфейс e* (en*, eth*): DHCP по IPv4. От MAC не зависит — этого достаточно,
            чтобы на новой машине появились адрес, маршрут и вход по SSH.
  a-public  публичный интерфейс этой машины (по MAC): то же плюс статический IPv6 (у Hetzner
            IPv6 не раздаётся автоматически). Если MAC не совпал, интерфейс попадает в z-any.

  netplan.py show         напечатать конфигурацию, которая будет записана
  netplan.py apply        записать и применить, если отличается (с проверкой и автооткатом)
  netplan.py boot         то же при загрузке (tabora-network.service): на новой машине берёт
                          MAC и IPv6 из метаданных Hetzner и дописывает a-public

Порядок важен: systemd-networkd берёт первый подходящий файл по имени
(10-netplan-a-public.network раньше 10-netplan-z-any.network).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.dont_write_bytecode = True
TARGET = "/etc/netplan/50-tabora.yaml"
OLD = "/etc/netplan/50-cloud-init.yaml"
BACKUP_DIR = "/var/backups/tabora/netplan"
METADATA = "http://169.254.169.254/hetzner/v1/metadata/network-config"
ROLLBACK_UNIT = "tabora-netplan-rollback"
ROLLBACK_AFTER = 180  # секунд до автоотката, если проверка не снимет таймер


def log(msg):
    print(f"сеть: {msg}", flush=True)


def run(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def ip_json(*args):
    out = run("ip", "-j", *args, check=False).stdout
    return json.loads(out) if out.strip() else []


def interfaces():
    """Физические интерфейсы e*: имя → MAC."""
    return {l["ifname"]: l.get("address", "") for l in ip_json("link", "show")
            if l["ifname"].startswith("e") and l.get("link_type") == "ether"}


def default_dev():
    for r in ip_json("-4", "route", "show", "default"):
        if r.get("dev"):
            return r["dev"]
    return None


def from_metadata():
    """(mac, [ipv6/префикс], шлюз, [dns]) публичного интерфейса из метаданных Hetzner или None."""
    import yaml  # python3-yaml ставится вместе с netplan
    for attempt in range(3):
        try:
            with urllib.request.urlopen(METADATA, timeout=4) as r:
                data = yaml.safe_load(r.read())
            break
        except Exception:
            if attempt == 2:
                return None
            time.sleep(2)
    for item in (data or {}).get("config") or []:
        if item.get("type") != "physical" or not item.get("mac_address"):
            continue
        addrs, gw, dns = [], None, []
        for s in item.get("subnets") or []:
            if s.get("type") == "static" and ":" in str(s.get("address", "")):
                addrs.append(str(s["address"]))
                gw = s.get("gateway") or gw
                dns += [d for d in s.get("dns_nameservers") or [] if ":" in str(d)]
        return item["mac_address"].lower(), addrs, gw, dns
    return None


def from_current():
    """То же из текущего состояния (если метаданные недоступны, а файла ещё нет)."""
    dev = default_dev()
    if not dev:
        return None
    mac = interfaces().get(dev, "").lower()
    addrs = []
    for a in ip_json("-6", "addr", "show", "dev", dev, "scope", "global"):
        for i in a.get("addr_info", []):
            if i.get("family") == "inet6" and not i.get("dynamic"):
                addrs.append(f"{i['local']}/{i['prefixlen']}")
    gw = next((r.get("gateway") for r in ip_json("-6", "route", "show", "default", "dev", dev) if r.get("gateway")), None)
    return (mac, addrs, gw, []) if mac else None


def render(public):
    lines = ["# Создано infra/network/netplan.py (tabora-network.service обновляет при загрузке на новой машине).",
             "# z-any — DHCP на любом интерфейсе, от MAC не зависит; a-public — статический IPv6 этой машины.",
             "network:", "  version: 2", "  ethernets:"]
    if public:
        mac, addrs, gw, dns = public
        lines += ["    a-public:", "      match:", f'        macaddress: "{mac}"', "      dhcp4: true"]
        if addrs:
            lines += ["      addresses:"] + [f'      - "{a}"' for a in addrs]
            if gw:
                lines += ["      routes:", "      - to: default", f'        via: "{gw}"', "        on-link: true"]
            if dns:
                lines += ["      nameservers:", "        addresses:"] + [f'        - "{d}"' for d in dns]
    lines += ["    z-any:", "      match:", '        name: "e*"', "      dhcp4: true"]
    return "\n".join(lines) + "\n"


def desired(boot):
    public = from_metadata()
    if public is None:
        if os.path.exists(TARGET):
            return None          # метаданных нет (не Hetzner или сеть ещё не поднялась): файл не трогаем
        public = from_current()
    if public and public[0] not in {m.lower() for m in interfaces().values()}:
        log(f"интерфейса с MAC {public[0]} нет — остаётся только DHCP")
        public = None
    return render(public)


def validate(text):
    """netplan generate в отдельном корне: синтаксис и смысл, систему не трогает."""
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(f"{root}/etc/netplan")
        path = f"{root}/etc/netplan/50-tabora.yaml"
        with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(text)
        r = run("netplan", "generate", "--root-dir", root, check=False)
        if r.returncode != 0:
            raise SystemExit(f"сеть: netplan не принял конфигурацию:\n{r.stderr}{text}")
        made = sorted(os.listdir(f"{root}/run/systemd/network"))
        if "10-netplan-z-any.network" not in made:
            raise SystemExit(f"сеть: netplan не создал DHCP для всех интерфейсов: {made}")


def online():
    """Есть маршрут по умолчанию и отвечает шлюз или внешний адрес."""
    routes = ip_json("-4", "route", "show", "default")
    if not routes:
        return False
    targets = [r["gateway"] for r in routes if r.get("gateway")] + ["1.1.1.1", "9.9.9.9"]
    return any(run("ping", "-c1", "-W2", t, check=False).returncode == 0 for t in targets)


def apply(boot=False):
    text = desired(boot)
    if text is None:
        log("метаданные недоступны, конфигурация оставлена как есть")
        return 0
    try:
        current = open(TARGET).read()
    except FileNotFoundError:
        current = None
    if current == text and not os.path.exists(OLD):
        if not boot:
            log("netplan уже без привязки к машине")
        return 0
    validate(text)
    if not online():
        # сети нет и до изменений: откатываться не к чему, проверять нечем
        log("сети нет уже сейчас — конфигурация записывается без проверки связи")
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    saved = {}
    for path in (TARGET, OLD):
        if os.path.exists(path):
            saved[path] = f"{BACKUP_DIR}/{os.path.basename(path)}.{stamp}"
            shutil.copy2(path, saved[path])
    # автооткат: если после применения сервер потеряет сеть (и этот скрипт вместе с SSH-сеансом),
    # через три минуты systemd вернёт прежние файлы
    restore = "; ".join([f"rm -f {TARGET}"] + [f"cp -p {b} {p}" for p, b in saved.items()] + ["netplan apply"])
    run("systemctl", "stop", f"{ROLLBACK_UNIT}.timer", f"{ROLLBACK_UNIT}.service", check=False)
    run("systemctl", "reset-failed", f"{ROLLBACK_UNIT}.service", check=False)
    was_online = online()
    if was_online:
        run("systemd-run", f"--unit={ROLLBACK_UNIT}", f"--on-active={ROLLBACK_AFTER}", "/bin/sh", "-c", restore)
    tmp = TARGET + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write(text)
    os.replace(tmp, TARGET)
    if os.path.exists(OLD):
        os.remove(OLD)           # копия лежит в BACKUP_DIR
    r = run("netplan", "apply", check=False)
    ok = r.returncode == 0
    if ok and was_online:
        ok = False
        for _ in range(20):
            if online():
                ok = True
                break
            time.sleep(2)
    if not ok:
        log(f"после применения сети нет — откат ({r.stderr.strip()[:300]})")
        subprocess.run(["/bin/sh", "-c", restore], check=False)
        run("systemctl", "stop", f"{ROLLBACK_UNIT}.timer", check=False)
        return 1
    run("systemctl", "stop", f"{ROLLBACK_UNIT}.timer", check=False)
    log(f"netplan обновлён ({TARGET}); прежние файлы в {BACKUP_DIR}")
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    if cmd == "show":
        text = desired(False)
        print(text if text is not None else open(TARGET).read(), end="")
        return 0
    if cmd in ("apply", "boot"):
        return apply(boot=cmd == "boot")
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
