#!/usr/bin/env python3
"""Синхронизация почтовых DNS-записей с Cloudflare (вызывается cloudflare/dns.sh).

Записи: A/AAAA почтового хоста (адреса с интерфейса), зона Stalwart и, если задан $EXTRA_ZONE,
записи из него (подтверждения владения доменом и подобное, infra/dns/extra.zone). Правила:
  A, AAAA, CNAME — одна запись на имя (обновляется, лишние того же типа удаляются);
  MX у домена и все SRV (_*._tcp.<домен>) — ровно как в зоне, лишние удаляются;
  TXT — заменяется запись с тем же префиксом (v=spf1, v=DMARC1, v=STSv1, v=TLSRPTv1, v=DKIM1…),
        одна на имя; TXT с другим содержимым (например, проверки владения) не трогаются;
  TLSA (DANE) и CAA не публикуются: ключ сертификата меняется при каждом продлении.
Токен Cloudflare читается из файла заголовков $CF_HDR (создаёт dns.sh), в аргументах его нет.
С DNS_DRY=1 записи только читаются: печатается, что было бы добавлено, изменено и удалено.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
TTL = 3600
DRY = os.environ.get("DNS_DRY") == "1"


def parse_zone(path):
    text = open(path).read()
    # склеиваем многострочные TXT в скобках: ( "a" "b" ) → "ab"
    text = re.sub(r'\(\s*((?:"[^"]*"\s*)+)\)', lambda m: '"' + "".join(re.findall(r'"([^"]*)"', m.group(1))) + '"', text, flags=re.S)
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+?)\.?\s+(?:\d+\s+)?IN\s+(\w+)\s+(.*)$", line.strip())
        if not m:
            continue
        name, rtype, rest = m.group(1).lower(), m.group(2).upper(), m.group(3).strip()
        if rtype == "TXT":
            out.append({"type": "TXT", "name": name, "content": "".join(re.findall(r'"([^"]*)"', rest))})
        elif rtype == "MX":
            prio, host = rest.split()
            out.append({"type": "MX", "name": name, "content": host.rstrip("."), "priority": int(prio)})
        elif rtype == "CNAME":
            out.append({"type": "CNAME", "name": name, "content": rest.rstrip(".")})
        elif rtype == "SRV":
            prio, weight, port, target = rest.split()
            out.append({"type": "SRV", "name": name, "data": {"priority": int(prio), "weight": int(weight),
                                                                "port": int(port), "target": target.rstrip(".")}})
    return out


def txt_prefix(content):
    return content.strip().strip('"').split(";", 1)[0].split(" ", 1)[0].strip().lower()


def unquote(content):
    c = content.strip()
    if c.startswith('"') and c.endswith('"'):
        c = "".join(re.findall(r'"([^"]*)"', c))
    return c


class Cloudflare:
    def __init__(self, hdr_path, zone_id):
        self.headers = {}
        for line in open(hdr_path):
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip()] = v.strip()
        self.zone = zone_id

    def req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(f"{API}/zones/{self.zone}/dns_records{path}", data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            raise SystemExit(f"Cloudflare {method} {path}: HTTP {e.code} {e.read()[:500].decode(errors='replace')}")

    def list(self, rtype, name=None):
        q = f"?type={rtype}&per_page=500" + (f"&name={name}" if name else "")
        return self.req("GET", q)["result"]

    def create(self, rec):
        if not DRY:
            self.req("POST", "", {**rec, "proxied": False, "ttl": TTL} if rec["type"] != "SRV" else {**rec, "ttl": TTL})
        print(f"  + {rec['type']} {rec['name']} {rec.get('content') or rec.get('data')}")

    def update(self, rid, rec):
        if not DRY:
            self.req("PUT", f"/{rid}", {**rec, "proxied": False, "ttl": TTL} if rec["type"] != "SRV" else {**rec, "ttl": TTL})
        print(f"  ~ {rec['type']} {rec['name']} {rec.get('content') or rec.get('data')}")

    def delete(self, rec):
        if not DRY:
            self.req("DELETE", f"/{rec['id']}")
        print(f"  - {rec['type']} {rec['name']} {rec.get('content')}")


def same(existing, want):
    if want["type"] == "SRV":
        d = existing.get("data") or {}
        return all(str(d.get(k)).rstrip(".").lower() == str(v).lower() for k, v in want["data"].items())
    if want["type"] == "TXT":
        return unquote(existing.get("content", "")) == want["content"] and not existing.get("proxied")
    ok = existing.get("content", "").rstrip(".").lower() == want["content"].lower() and not existing.get("proxied")
    if want["type"] == "MX":
        ok = ok and existing.get("priority") == want["priority"]
    return ok


def sync(cf, records, domain):
    by_key = {}
    for r in records:
        by_key.setdefault((r["type"], r["name"]), []).append(r)
    for (rtype, name), wants in by_key.items():
        if rtype in ("SRV",):
            continue
        existing = cf.list(rtype, name)
        if rtype == "TXT":
            for want in wants:
                group = [e for e in existing if txt_prefix(e.get("content", "")) == txt_prefix(want["content"])]
                if not group:
                    cf.create(want)
                    continue
                keep = next((e for e in group if same(e, want)), None)
                if keep is None:
                    keep = group[0]
                    cf.update(keep["id"], want)
                for e in group:
                    if e is not keep:
                        cf.delete(e)
        elif rtype == "MX":
            left = list(existing)
            for want in wants:
                match = next((e for e in left if same(e, want)), None)
                if match:
                    left.remove(match)
                else:
                    cf.create(want)
            for e in left:
                cf.delete(e)
        else:  # A, AAAA, CNAME: одна запись на имя
            want = wants[0]
            if existing and same(existing[0], want):
                pass
            elif existing:
                cf.update(existing[0]["id"], want)
            else:
                cf.create(want)
            for e in existing[1:]:
                cf.delete(e)
    # SRV: управляются целиком
    want_srv = [r for r in records if r["type"] == "SRV"]
    existing = [e for e in cf.list("SRV") if e["name"].lower().endswith("." + domain)]
    for want in want_srv:
        match = next((e for e in existing if e["name"].lower() == want["name"] and same(e, want)), None)
        if match:
            existing.remove(match)
            continue
        old = next((e for e in existing if e["name"].lower() == want["name"]), None)
        if old:
            existing.remove(old)
            cf.update(old["id"], want)
        else:
            cf.create(want)
    for e in existing:
        cf.delete(e)


def main():
    args = sys.argv[1:]
    dry = args and args[0] == "--print"
    zone_path = args[-1]
    domain, mail_host = os.environ["DOMAIN"].lower(), os.environ["MAIL_HOST"].lower()
    records = [{"type": "A", "name": mail_host, "content": os.environ["IP4"]}]
    if os.environ.get("IP6"):
        records.append({"type": "AAAA", "name": mail_host, "content": os.environ["IP6"]})
    records += parse_zone(zone_path)
    extra = os.environ.get("EXTRA_ZONE", "")
    if extra and os.path.exists(extra):
        records += parse_zone(extra)
    if dry:
        for r in records:
            print(r["type"], r["name"], r.get("priority", ""), r.get("content") or r.get("data"))
        return
    cf = Cloudflare(os.environ["CF_HDR"], os.environ["CF_ZONE_ID"])
    if DRY:
        print("план (ничего не меняется): + добавить, ~ изменить, - удалить")
    sync(cf, records, domain)
    print(f"записей к публикации: {len(records)}")


if __name__ == "__main__":
    main()
