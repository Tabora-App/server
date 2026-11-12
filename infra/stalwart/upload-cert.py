#!/usr/bin/env python3
"""Загрузка сертификата Let's Encrypt в Stalwart (объект x:Certificate) и назначение его
сертификатом по умолчанию. Вызывается enable-tls.sh и хуком продления certbot.
Использование: upload-cert.py /etc/letsencrypt/live/mx.tabora.app
"""
import os
import sys

sys.dont_write_bytecode = True  # без __pycache__ в /usr/local/lib/tabora
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import JmapError, admin_client  # noqa: E402

live = sys.argv[1] if len(sys.argv) > 1 else None
if not live or not os.path.isdir(live):
    raise SystemExit("укажите каталог сертификата, например /etc/letsencrypt/live/mx.tabora.app")
try:
    c = admin_client()
    cert = open(os.path.join(live, "fullchain.pem")).read()
    key = open(os.path.join(live, "privkey.pem")).read()
    # Stalwart 1.1: оба поля — объекты с источником (Text — значение в базе, File — путь);
    # у сертификата текст в value, у ключа в secret
    pem = {"certificate": {"@type": "Text", "value": cert}, "privateKey": {"@type": "Text", "secret": key}}
    existing = c.get_all("Certificate")
    current_id = c.call("x:SystemSettings/get", {"ids": ["singleton"]})["list"][0].get("defaultCertificateId")
    if current_id and any(x["id"] == current_id for x in existing):
        c.call("x:Certificate/set", {"update": {current_id: pem}})
        print(f"сертификат {current_id} обновлён")
    else:
        r = c.call("x:Certificate/set", {"create": {"c": pem}})
        cid = r["created"]["c"]["id"]
        c.call("x:SystemSettings/set", {"update": {"singleton": {"defaultCertificateId": cid}}})
        print(f"сертификат {cid} загружен и назначен по умолчанию")
    # без этого работающая служба продолжает отдавать прежний (или самоподписанный) сертификат
    c.call("x:Action/set", {"create": {"r": {"@type": "ReloadTlsCertificates"}}})
    print("Stalwart перечитал сертификаты")
except JmapError as e:
    raise SystemExit(f"Stalwart: {e}")
