"""Общий код скриптов Stalwart: JMAP-вызовы объектов администратора и env-файлы с секретами.

Секреты не передаются в аргументах процессов: всё читается из файлов и пишется в файлы
с нужными правами (файл создаётся с правами до записи содержимого и подменяется атомарно).
"""
import base64
import grp
import json
import os
import secrets
import string
import urllib.error
import urllib.request

URL = os.environ.get("STALWART_URL", "http://127.0.0.1:8080").rstrip("/") + "/jmap"
ADMIN_ENV = "/etc/tabora/stalwart-admin.env"   # root:root 600, постоянный администратор
SERVER_ENV = "/etc/tabora/server.env"          # root:tabora 640, ключ API для tabora-server
STALWART_ENV = "/opt/stalwart/etc/stalwart.env"  # root:stalwart 640, окружение службы
USING = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
LOOPBACK = {"127.0.0.1": True, "::1": True}


class JmapError(Exception):
    pass


def log(msg):
    print(f"\033[1;32m›\033[0m {msg}", flush=True)


def read_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return env


def update_env(path, values=None, remove=(), mode=0o600, group=None, header=None):
    """Задать/убрать переменные в env-файле, сохранив остальные строки. True, если файл изменился."""
    values = dict(values or {})
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        lines = [f"# {header}"] if header else []
    out, seen = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in remove:
            continue
        if key in values:
            if key in seen:
                continue
            line = f"{key}={values[key]}"
            seen.add(key)
        out.append(line)
    out += [f"{k}={v}" for k, v in values.items() if k not in seen]
    text = "\n".join(out) + "\n"
    gid = grp.getgrnam(group).gr_gid if group else 0
    try:
        st = os.stat(path)
        if open(path).read() == text and st.st_mode & 0o777 == mode and st.st_gid == gid:
            return False
    except FileNotFoundError:
        pass
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        os.write(fd, text.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return True


def new_secret(n=40):
    return secrets.token_urlsafe(n)[:n]


def new_login(prefix=""):
    """Неочевидное имя учётки: буква + 11 случайных букв/цифр."""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + secrets.choice(string.ascii_lowercase) + "".join(secrets.choice(alphabet) for _ in range(11))


class Client:
    def __init__(self, user=None, password=None, bearer=None):
        if bearer:
            self.auth = f"Bearer {bearer}"
        else:
            self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def request(self, calls):
        body = json.dumps({"using": USING, "methodCalls": [[m, a, f"c{i}"] for i, (m, a) in enumerate(calls)]}).encode()
        req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json", "Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)["methodResponses"]
        except urllib.error.HTTPError as e:
            raise JmapError(f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from None
        except urllib.error.URLError as e:
            raise JmapError(f"Stalwart недоступен: {e.reason}") from None

    def call(self, method, args):
        name, resp, _ = self.request([(method, args)])[0]
        if name == "error":
            raise JmapError(f"{method}: {json.dumps(resp, ensure_ascii=False)}")
        for key in ("notCreated", "notUpdated", "notDestroyed"):
            if resp.get(key):
                raise JmapError(f"{method} {key}: {json.dumps(resp[key], ensure_ascii=False)}")
        return resp

    def get_all(self, obj):
        return self.call(f"x:{obj}/get", {"ids": None})["list"]

    def ok(self, method="x:SystemSettings/get", args=None):
        try:
            self.call(method, args if args is not None else {"ids": ["singleton"]})
            return True
        except JmapError:
            return False


def admin_client():
    env = read_env(ADMIN_ENV)
    if not env.get("STALWART_ADMIN_USER") or not env.get("STALWART_ADMIN_PASS"):
        raise JmapError(f"нет администратора в {ADMIN_ENV}")
    return Client(env["STALWART_ADMIN_USER"], env["STALWART_ADMIN_PASS"])
