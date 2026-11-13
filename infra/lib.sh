# shellcheck shell=bash disable=SC2034
# Общие функции скриптов infra/ (подключается через `. "$HERE/lib.sh"`).
# Ожидает переменные DOMAIN, MAIL_HOST, API_HOST.

LIB=/usr/local/lib/tabora        # копия infra/ на сервере: её используют хук certbot и таймеры
MX_LIVE=/etc/letsencrypt/live/$MAIL_HOST
APP_HOST=${APP_HOST:-app.$DOMAIN}   # веб-версия (nginx/app.conf)
APP_LIVE=/etc/letsencrypt/live/$APP_HOST
SUPPORT_HOST=${SUPPORT_HOST:-support.$DOMAIN}   # the support site (nginx/support.conf)
SUPPORT_LIVE=/etc/letsencrypt/live/$SUPPORT_HOST

log() { printf '\033[1;32m›\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# подстановка имён в шаблон: render <шаблон> <файл> [sed-выражение…]; RENDER_CHANGED=1, если файл изменился
render() {
  local src=$1 dst=$2; shift 2
  local extra=(); for e in "$@"; do extra+=(-e "$e"); done
  sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__MAIL_HOST__/$MAIL_HOST/g" -e "s/__API_HOST__/$API_HOST/g" "${extra[@]}" "$src" > "$dst.tmp"
  if cmp -s "$dst.tmp" "$dst"; then rm -f "$dst.tmp"; RENDER_CHANGED=; else chmod 644 "$dst.tmp"; mv -f "$dst.tmp" "$dst"; RENDER_CHANGED=1; fi
}

# копия infra/ в $LIB: из неё работают хук certbot, таймеры и повторные вызовы скриптов
install_lib() {
  mkdir -p "$LIB"
  rsync -a --delete --chown=root:root --chmod=D755,F644 "$1/" "$LIB/"
  chmod 755 "$LIB"/*.sh "$LIB"/stalwart/*.py "$LIB"/stalwart/*.sh "$LIB"/cloudflare/*.sh "$LIB"/cloudflare/*.py \
            "$LIB"/backup/*.sh "$LIB"/monitor/*.py "$LIB"/monitor/*.sh "$LIB"/network/*.py
}

tls_enabled() { [ -f "$MX_LIVE/fullchain.pem" ] && [ -f "$MX_LIVE/privkey.pem" ]; }
app_tls_enabled() { [ -f "$APP_LIVE/fullchain.pem" ] && [ -f "$APP_LIVE/privkey.pem" ]; }
support_tls_enabled() { [ -f "$SUPPORT_LIVE/fullchain.pem" ] && [ -f "$SUPPORT_LIVE/privkey.pem" ]; }

# Конфигурация nginx одна и та же до и после TLS: сайт и API на 127.0.0.1:8081 (только для туннеля),
# публично только 443; почтовый хост включается, когда есть сертификат. Порт 80 не слушается вовсе:
# сертификаты выпускаются через DNS-01.
install_nginx() {
  local src=$1   # каталог infra/nginx
  log "nginx: общие настройки, сайты на 127.0.0.1:8081, почтовый хост $(tls_enabled && echo 'с TLS' || echo '(ждёт сертификата)')"
  install -m 644 "$src/http.conf" /etc/nginx/conf.d/tabora.conf
  # server_tokens задаётся в conf.d/tabora.conf; в nginx.conf Ubuntu стоит «server_tokens build;»
  sed -i -E 's/^([[:space:]]*)(server_tokens[[:space:]])/\1# \2/' /etc/nginx/nginx.conf
  install -m 644 "$src/security.inc" /etc/nginx/snippets/tabora-security.conf
  install -m 644 "$src/site-headers.inc" /etc/nginx/snippets/tabora-site-headers.conf
  install -m 644 "$src/proxy.inc" /etc/nginx/snippets/tabora-proxy.conf
  install -m 644 "$src/app-headers.inc" /etc/nginx/snippets/tabora-app-headers.conf
  install -m 644 "$src/app-frame-headers.inc" /etc/nginx/snippets/tabora-app-frame-headers.conf
  install -m 644 "$src/app-frame-remote-headers.inc" /etc/nginx/snippets/tabora-app-frame-remote-headers.conf
  # список логинов администраторов Stalwart пишет stalwart/configure.py; до него — только «admin»
  [ -f /etc/nginx/tabora-privileged-logins.map ] || printf '"~*(^|%%)admin(@|%%|$)" 1;\n' > /etc/nginx/tabora-privileged-logins.map
  # список логинов администраторов читает только главный процесс nginx (root)
  chown root:www-data /etc/nginx/tabora-privileged-logins.map && chmod 640 /etc/nginx/tabora-privileged-logins.map
  # старые имена (до разделения http/https) и стандартный сайт
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/mx.http /etc/nginx/sites-enabled/tabora.app.http \
        /etc/nginx/sites-available/mx.http /etc/nginx/sites-available/tabora.app.http
  local name
  for name in default-server tabora.app api; do
    render "$src/$name.conf" "/etc/nginx/sites-available/tabora-$name"
    ln -sfn "/etc/nginx/sites-available/tabora-$name" "/etc/nginx/sites-enabled/tabora-$name"
  done
  rm -f /etc/nginx/sites-enabled/tabora.app /etc/nginx/sites-enabled/api /etc/nginx/sites-enabled/mx \
        /etc/nginx/sites-available/tabora.app /etc/nginx/sites-available/api /etc/nginx/sites-available/mx
  if tls_enabled; then
    render "$src/mx.conf" /etc/nginx/sites-available/tabora-mx
    ln -sfn /etc/nginx/sites-available/tabora-mx /etc/nginx/sites-enabled/tabora-mx
  else
    rm -f /etc/nginx/sites-enabled/tabora-mx /etc/nginx/sites-available/tabora-mx
  fi
  # веб-версия: имя включается, когда выпущен его сертификат (enable-tls.sh)
  install -d -m 755 -o root -g root "/var/www/$APP_HOST"
  if app_tls_enabled; then
    render "$src/app.conf" /etc/nginx/sites-available/tabora-app
    ln -sfn /etc/nginx/sites-available/tabora-app /etc/nginx/sites-enabled/tabora-app
  else
    rm -f /etc/nginx/sites-enabled/tabora-app /etc/nginx/sites-available/tabora-app
  fi
  # the support site: its name is enabled once its certificate is issued (enable-tls.sh)
  install -d -m 755 -o root -g root "/var/www/$SUPPORT_HOST"
  if support_tls_enabled; then
    render "$src/support.conf" /etc/nginx/sites-available/tabora-support
    ln -sfn /etc/nginx/sites-available/tabora-support /etc/nginx/sites-enabled/tabora-support
  else
    rm -f /etc/nginx/sites-enabled/tabora-support /etc/nginx/sites-available/tabora-support
  fi
  nginx -t -q
  systemctl enable nginx >/dev/null 2>&1
  if systemctl is-active -q nginx; then systemctl reload nginx; else systemctl start nginx; fi
}

# хук certbot: после продления сертификата почтового хоста перезагрузить nginx и отдать сертификат Stalwart
install_certbot_hook() {
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  render "$1/certbot/deploy-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/tabora.sh
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/tabora.sh
}

# ---- Cloudflare API: токен только в файле заголовков (не в аргументах curl и не в ps) ----------
# cf_init <токен>; затем cf <curl-аргументы>; тело запроса передавать через stdin (-d @-)
cf_init() {
  [ -n "${1:-}" ] || die "нет токена Cloudflare"
  CF_HDR=$(mktemp)   # mktemp создаёт файл с правами 600
  trap 'rm -f "$CF_HDR"' EXIT
  printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$1" > "$CF_HDR"
}
cf() { curl -fsS -H @"$CF_HDR" "$@"; }
CF_API=https://api.cloudflare.com/client/v4

# читает /etc/tabora/cloudflare.env (CF_ACCOUNT_ID, CF_ZONE_ID и, на время настройки, CF_API_TOKEN)
load_cloudflare_env() {
  [ -f /etc/tabora/cloudflare.env ] || die "нет /etc/tabora/cloudflare.env (см. infra/README.md)"
  chown root:root /etc/tabora/cloudflare.env && chmod 600 /etc/tabora/cloudflare.env
  # shellcheck disable=SC1091
  . /etc/tabora/cloudflare.env
}

# токен только с правом Zone:DNS:Edit из файла certbot (для dns.sh, когда токен настройки уже удалён)
certbot_dns_token() {
  [ -f /etc/tabora/certbot-cloudflare.ini ] || return 0
  sed -n 's/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' /etc/tabora/certbot-cloudflare.ini | head -1
}
