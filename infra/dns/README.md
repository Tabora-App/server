# DNS tabora.app

`tabora.app.zone` — записи, которые публикует Stalwart для домена (DKIM rsa и ed25519, SPF, DMARC, MX,
SRV для JMAP/IMAPS/SUBMISSIONS, MTA-STS, TLS-RPT, автонастройка). Копия `/etc/tabora/dns-tabora.app.zone`,
её пишет `stalwart/configure.py`; в Cloudflare записи публикует `cloudflare/dns.sh`.

`extra.zone` — записи, которых нет в зоне Stalwart: подтверждения владения доменом (Google) и подобное.
Правится руками, публикуется тем же `cloudflare/dns.sh`. Перед публикацией `infra/deploy.sh dns --plan`
показывает, что изменится в Cloudflare, ничего не меняя.

Адресные записи: только `mx` (A и AAAA, серое облако; адреса берутся с интерфейса сервера);
`app` (веб-версия) — CNAME на `mx` в `extra.zone`, тоже серое облако.
`tabora.app`, `www` и `api` — CNAME на Cloudflare Tunnel (`cloudflare/setup-tunnel.sh`), публичного
адреса у них нет. SRV для CalDAV/CardDAV/POP3 не публикуются: эти службы снаружи не доступны.
Ротация DKIM в Stalwart заморожена, ключи не меняются без нашего участия.
