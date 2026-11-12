#!/usr/bin/env bash
# Cloudflare Tunnel для сайта и API: у tabora.app, www и api нет публичного адреса, трафик идёт
# исходящим соединением сервера к Cloudflare. Наружу открыта только почта (mx.tabora.app).
# Нужны в /etc/tabora/cloudflare.env (600): CF_ACCOUNT_ID, CF_ZONE_ID и CF_API_TOKEN с правами
# Account › Cloudflare Tunnel › Edit и Zone › DNS › Edit. После успешной настройки скрипт сам
# удаляет токен из файла: службе cloudflared он не нужен, dns.sh работает с токеном certbot.
# Повторный запуск (сменить маршруты, пересоздать службу) требует вписать токен снова.
set -euo pipefail
DOMAIN=${DOMAIN:-tabora.app}
MAIL_HOST=${MAIL_HOST:-mx.$DOMAIN}
API_HOST=${API_HOST:-api.$DOMAIN}
TUNNEL_NAME=${TUNNEL_NAME:-tabora}
HERE=$(cd "$(dirname "$0")/.." && pwd)
. "$HERE/lib.sh"

load_cloudflare_env
[ -n "${CF_ACCOUNT_ID:-}" ] && [ -n "${CF_ZONE_ID:-}" ] || die "в /etc/tabora/cloudflare.env нужны CF_ACCOUNT_ID и CF_ZONE_ID"
[ -n "${CF_API_TOKEN:-}" ] || die "в /etc/tabora/cloudflare.env нет CF_API_TOKEN (Tunnel Edit + DNS Edit)"
cf_init "$CF_API_TOKEN"
unset CF_API_TOKEN

command -v cloudflared >/dev/null || die "нет cloudflared: сначала infra/deploy.sh setup"

log "туннель $TUNNEL_NAME"
install -d -m 700 -o root -g root /etc/cloudflared
TUNNEL_ID=$(cf "$CF_API/accounts/$CF_ACCOUNT_ID/cfd_tunnel?name=$TUNNEL_NAME&is_deleted=false" | jq -r '.result[0].id // empty')
if [ -z "$TUNNEL_ID" ]; then
  SECRET=$(openssl rand -base64 32)
  # секрет только в stdin curl (printf — встроенная команда), не в аргументах
  TUNNEL_ID=$(printf '{"name":"%s","tunnel_secret":"%s","config_src":"cloudflare"}' "$TUNNEL_NAME" "$SECRET" \
    | cf -X POST "$CF_API/accounts/$CF_ACCOUNT_ID/cfd_tunnel" -d @- | jq -r '.result.id')
  [ -n "$TUNNEL_ID" ] && [ "$TUNNEL_ID" != null ] || die "туннель не создан"
  ( umask 077
    printf '{"AccountTag":"%s","TunnelSecret":"%s","TunnelID":"%s"}\n' "$CF_ACCOUNT_ID" "$SECRET" "$TUNNEL_ID" > "/etc/cloudflared/$TUNNEL_ID.json" )
  unset SECRET
  log "туннель создан: $TUNNEL_ID"
else
  log "туннель уже есть: $TUNNEL_ID"
  [ -f "/etc/cloudflared/$TUNNEL_ID.json" ] || die "нет файла учётных данных /etc/cloudflared/$TUNNEL_ID.json: удалите туннель в Cloudflare и запустите снова"
fi
chown root:root "/etc/cloudflared/$TUNNEL_ID.json" && chmod 600 "/etc/cloudflared/$TUNNEL_ID.json"

log "маршруты туннеля (ingress) → nginx на 127.0.0.1:8081"
cf -X PUT "$CF_API/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/configurations" -d @- >/dev/null <<JSON
{"config":{"ingress":[
  {"hostname":"$DOMAIN","service":"http://127.0.0.1:8081","originRequest":{"httpHostHeader":"$DOMAIN"}},
  {"hostname":"www.$DOMAIN","service":"http://127.0.0.1:8081","originRequest":{"httpHostHeader":"www.$DOMAIN"}},
  {"hostname":"$API_HOST","service":"http://127.0.0.1:8081","originRequest":{"httpHostHeader":"$API_HOST"}},
  {"service":"http_status:404"}
]}}
JSON

log "DNS: CNAME на туннель для $DOMAIN, www, $API_HOST (с прокси)"
for name in "$DOMAIN" "www.$DOMAIN" "$API_HOST"; do
  # только CNAME: у имени могут быть и другие записи (TXT, CAA), их трогать нельзя
  rid=$(cf "$CF_API/zones/$CF_ZONE_ID/dns_records?type=CNAME&name=$name" | jq -r '.result[0].id // empty')
  body=$(printf '{"type":"CNAME","name":"%s","content":"%s.cfargotunnel.com","proxied":true,"ttl":1}' "$name" "$TUNNEL_ID")
  if [ -n "$rid" ]; then printf '%s' "$body" | cf -X PUT "$CF_API/zones/$CF_ZONE_ID/dns_records/$rid" -d @- >/dev/null
  else printf '%s' "$body" | cf -X POST "$CF_API/zones/$CF_ZONE_ID/dns_records" -d @- >/dev/null; fi
done

log "служба cloudflared"
# старая служба от `cloudflared service install`, если была
[ ! -f /etc/cloudflared/config.yml ] || rm -f /etc/cloudflared/config.yml
render "$HERE/cloudflare/cloudflared.service" /etc/systemd/system/cloudflared.service "s/__TUNNEL_ID__/$TUNNEL_ID/g"
systemctl daemon-reload
systemctl enable cloudflared >/dev/null 2>&1
systemctl restart cloudflared
systemctl is-active -q cloudflared || die "служба cloudflared не запустилась: journalctl -u cloudflared"
log "туннель работает: https://$DOMAIN, https://$API_HOST"
# Токен настройки нужен был только здесь: службе он не нужен, а dns.sh работает с токеном certbot.
# Убираем его с сервера сразу, чтобы токен с правом на туннели аккаунта не лежал без дела.
sed -i '/^CF_API_TOKEN=/d' /etc/tabora/cloudflare.env
log "CF_API_TOKEN удалён из /etc/tabora/cloudflare.env. Если токену не задан срок, отзовите его в Cloudflare (My Profile › API Tokens)"
