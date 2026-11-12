#!/usr/bin/env bash
# Включение TLS: сертификат Let's Encrypt почтового хоста через DNS-01 Cloudflare, почтовый хост
# в nginx (443), сертификат в Stalwart (SMTP/IMAP), хук продления. Идемпотентно.
# Сайту и API сертификат не нужен (они за туннелем, nginx на 127.0.0.1:8081 без TLS), поэтому
# их имена не выпускаются и лишний раз не попадают в журналы Certificate Transparency.
# Нужен /etc/tabora/certbot-cloudflare.ini (права 600) с токеном только Zone › DNS › Edit.
set -euo pipefail
DOMAIN=${DOMAIN:-tabora.app}
MAIL_HOST=${MAIL_HOST:-mx.$DOMAIN}
API_HOST=${API_HOST:-api.$DOMAIN}
EMAIL=${EMAIL:-postmaster@$DOMAIN}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"

INI=/etc/tabora/certbot-cloudflare.ini
[ -f "$INI" ] || die "нет $INI (см. infra/README.md)"
chown root:root "$INI" && chmod 600 "$INI"
[ -n "$(certbot_dns_token)" ] || die "в $INI не задан dns_cloudflare_api_token"

log "сертификат почтового хоста (DNS-01 через Cloudflare)"
certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$INI" --dns-cloudflare-propagation-seconds 30 \
  -d "$MAIL_HOST" -d "autoconfig.$DOMAIN" -d "autodiscover.$DOMAIN" -d "mta-sts.$DOMAIN" \
  --cert-name "$MAIL_HOST" --non-interactive --agree-tos -m "$EMAIL" --keep-until-expiring
tls_enabled || die "сертификата $MX_LIVE нет"

# веб-версия (app.$DOMAIN) обслуживается напрямую, без туннеля, и потому ей нужен свой сертификат.
# Запись DNS (infra/dns/extra.zone, CNAME на почтовый хост) для выпуска не нужна: проверка идёт через DNS-01.
log "сертификат веб-версии $APP_HOST (DNS-01 через Cloudflare)"
certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$INI" --dns-cloudflare-propagation-seconds 30 \
  -d "$APP_HOST" --cert-name "$APP_HOST" --non-interactive --agree-tos -m "$EMAIL" --keep-until-expiring
app_tls_enabled || die "сертификата $APP_LIVE нет"

install_lib "$HERE"
install_nginx "$HERE/nginx"

log "Stalwart: сертификат почтового хоста"
# Stalwart хранит сертификат в своей базе: загружаем PEM и назначаем по умолчанию; хук certbot повторяет это при продлении
python3 "$LIB/stalwart/upload-cert.py" "$MX_LIVE"
install_certbot_hook "$HERE"
log "готово: https://$MAIL_HOST/jmap, SMTP/IMAP с сертификатом Let's Encrypt; веб-версия https://$APP_HOST. Дальше: infra/deploy.sh dns"
