#!/usr/bin/env bash
# Публикация почтовых DNS-записей в Cloudflare из зоны Stalwart (/etc/tabora/dns-<домен>.zone)
# и адресных записей почтового хоста. Только mx без прокси (серое облако): SMTP/IMAP через прокси
# не ходят. Токен: CF_API_TOKEN из /etc/tabora/cloudflare.env, а если его уже удалили — токен
# certbot (только Zone › DNS › Edit). Идемпотентно; `dns.sh --print` показывает записи без API,
# `dns.sh --plan` сверяет их с Cloudflare и печатает, что изменилось бы, ничего не меняя.
# Кроме почтовых публикуются записи из infra/dns/extra.zone (подтверждения владения доменом).
set -euo pipefail
DOMAIN=${DOMAIN:-tabora.app}
MAIL_HOST=${MAIL_HOST:-mx.$DOMAIN}
API_HOST=${API_HOST:-api.$DOMAIN}
HERE=$(cd "$(dirname "$0")/.." && pwd)
. "$HERE/lib.sh"

# адреса берутся с интерфейса (публичные адреса Hetzner), а не у внешнего сервиса;
# частная сеть Hetzner (10.0.0.0/8) и IPv6 ULA/временные адреса пропускаются
IP4=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -Ev '^10\.' | head -1 || true)
IP6=$(ip -6 -o addr show scope global | grep -Ev 'temporary|deprecated|tentative' | awk '{print $4}' | cut -d/ -f1 | grep -Eiv '^f[cd]' | head -1 || true)
[ -n "$IP4" ] || die "нет публичного IPv4 на интерфейсах"
export DOMAIN MAIL_HOST IP4 IP6
export EXTRA_ZONE="$HERE/dns/extra.zone"
ZONE=/etc/tabora/dns-$DOMAIN.zone
[ -f "$ZONE" ] || die "нет $ZONE: сначала infra/deploy.sh setup"

if [ "${1:-}" = "--print" ]; then
  exec python3 "$HERE/cloudflare/dns.py" --print "$ZONE"
fi
if [ "${1:-}" = "--plan" ]; then export DNS_DRY=1; fi
load_cloudflare_env
[ -n "${CF_ZONE_ID:-}" ] || die "в /etc/tabora/cloudflare.env нет CF_ZONE_ID"
token=${CF_API_TOKEN:-}; [ -n "$token" ] || token=$(certbot_dns_token)
cf_init "$token"; unset token CF_API_TOKEN
export CF_HDR CF_ZONE_ID
python3 "$HERE/cloudflare/dns.py" "$ZONE"
if [ "${DNS_DRY:-}" = "1" ]; then exit 0; fi
log "готово. Проверьте DNSSEC в панели Cloudflare (одна кнопка) и PTR в Hetzner: $IP4 / ${IP6:-нет IPv6} → $MAIL_HOST"
