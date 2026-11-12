#!/usr/bin/env bash
# Развёртывание сервера Tabora (Hetzner, Ubuntu 24/26). Идемпотентно: повторный запуск приводит
# сервер к тому же состоянию и ничего не откатывает (TLS, туннель, учётки Stalwart сохраняются).
# Ставит: базовую защиту (ufw, fail2ban, автообновления с перезагрузкой, hidepid), nginx, PostgreSQL,
# Stalwart (почта) с проверкой sha256, каркас службы tabora-server, сайт, резервные копии (restic)
# и мониторинг (tabora-health).
# TLS включает enable-tls.sh, туннель и DNS — cloudflare/setup-tunnel.sh и cloudflare/dns.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
umask 022

DOMAIN=${DOMAIN:-tabora.app}
MAIL_HOST=${MAIL_HOST:-mx.$DOMAIN}
API_HOST=${API_HOST:-api.$DOMAIN}
# Новая версия: поменять обе строки. Хеш архива сверен с .sigstore.json релиза (подпись
# GitHub Actions stalwartlabs/stalwart ci.yml@refs/tags/v1.1.0, проверено `sigstore verify github`).
STALWART_VERSION=${STALWART_VERSION:-v1.1.0}
STALWART_SHA256=${STALWART_SHA256:-62e6fdaf68f6ddfb45aa0dc1c28578a7e05f1e5e9a0c95fccfe1eae709d4ecbc}
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"

# ---- система -----------------------------------------------------------------
log "система: пакеты"
apt-get update -q
apt-get -y -q --with-new-pkgs upgrade   # с новыми пакетами (ядро), без удаления
apt-get -y -q install ufw fail2ban python3-systemd unattended-upgrades needrestart nginx certbot \
  python3-certbot-dns-cloudflare postgresql postgresql-contrib curl jq rsync sqlite3 dnsutils ca-certificates openssl restic python3-yaml

if ! command -v cloudflared >/dev/null; then
  log "cloudflared: пакет из репозитория Cloudflare (обновляется через unattended-upgrades)"
  mkdir -p --mode=0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -q && apt-get install -y -q cloudflared
fi

hostnamectl set-hostname "$MAIL_HOST"
grep -q "$MAIL_HOST" /etc/hosts || echo "127.0.1.1 $MAIL_HOST mx" >> /etc/hosts

if ! swapon --show | grep -q swapfile; then
  log "система: swap 2 ГБ"
  [ -f /swapfile ] || { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null; }
  swapon /swapfile
fi
grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl -q -w vm.swappiness=10; echo 'vm.swappiness=10' > /etc/sysctl.d/90-tabora.conf

log "система: автообновления (с перезагрузкой в 04:30 при необходимости), перезапуск служб после обновлений"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
cat > /etc/apt/apt.conf.d/52tabora-unattended-upgrades <<'CONF'
// Tabora: дополнение к 50unattended-upgrades
// у репозитория cloudflared нет Suite (только Codename: any), поэтому шаблон, а не "origin:archive"
Unattended-Upgrade::Origins-Pattern { "origin=cloudflared,codename=any,label=cloudflared"; };
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
CONF
mkdir -p /etc/needrestart/conf.d
# без этого needrestart при автообновлении только перечисляет службы со старыми библиотеками
echo "\$nrconf{restart} = 'a';" > /etc/needrestart/conf.d/90-tabora.conf

# cloud-init после первичной настройки (сеть, ключи, имя) не нужен, а при перезагрузке гонится с
# переименованием сетевого интерфейса Hetzner (enp1s0 → eth0) и падает. Вернуть:
# rm /etc/cloud/cloud-init.disabled (диск при увеличении в Hetzner без cloud-init расширяется
# вручную: growpart /dev/sda 1 && resize2fs /dev/sda1).
if [ -f /var/lib/cloud/instance/boot-finished ] && [ ! -f /etc/cloud/cloud-init.disabled ]; then
  log "система: cloud-init отключён после первичной настройки"
  touch /etc/cloud/cloud-init.disabled
  systemctl reset-failed 'cloud-init*' 2>/dev/null || true
fi
# Сеть: cloud-init привязал netplan к MAC-адресам этой машины, и сервер, развёрнутый из снапшота
# на другой машине, остался бы без сети (а пароль root заблокирован). network/netplan.py заменяет
# это на DHCP для любого интерфейса плюс статический IPv6 из метаданных Hetzner; при загрузке
# tabora-network.service сверяет IPv6 с метаданными. Применяется с проверкой связи и автооткатом.
if [ -f /etc/cloud/cloud-init.disabled ]; then
  # если cloud-init когда-нибудь включат обратно, сеть он не трогает
  echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-tabora-network.cfg
  python3 "$HERE/network/netplan.py" apply
  # netplan при ранней загрузке подставляет в wait-online имена интерфейсов до переименования udev
  # (eth0, eth1), и ожидание сети падало по таймауту через две минуты. Ждём любой интерфейс с маршрутом.
  mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
  printf '[Service]\nExecStart=\nExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any -o routable --timeout=60\n' \
    > /etc/systemd/system/systemd-networkd-wait-online.service.d/90-tabora.conf
  render "$HERE/systemd/tabora-network.service" /etc/systemd/system/tabora-network.service
  systemctl daemon-reload
  systemctl enable tabora-network.service >/dev/null 2>&1
fi

# SSH: единственное отличие от прежнего файла — проброс портов разрешён только к панели
# администратора Stalwart (ssh -L 8080:127.0.0.1:8080). Проверка sshd -t до перечитывания,
# при ошибке возвращается прежний файл.
SSHD_CONF=/etc/ssh/sshd_config.d/00-tabora.conf
if ! cmp -s "$HERE/ssh/00-tabora.conf" "$SSHD_CONF"; then
  log "ssh: проброс портов только к 127.0.0.1:8080 (панель администратора)"
  [ ! -f "$SSHD_CONF" ] || cp -p "$SSHD_CONF" /root/.00-tabora.conf.prev
  install -m 644 -o root -g root "$HERE/ssh/00-tabora.conf" "$SSHD_CONF"
  if sshd -t; then
    systemctl reload ssh
    rm -f /root/.00-tabora.conf.prev
  else
    if [ -f /root/.00-tabora.conf.prev ]; then mv -f /root/.00-tabora.conf.prev "$SSHD_CONF"; else rm -f "$SSHD_CONF"; fi
    die "sshd не принял $SSHD_CONF — возвращён прежний файл"
  fi
fi

log "система: журнал не больше 500 МБ"
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=500M\n' > /etc/systemd/journald.conf.d/size.conf
systemctl restart systemd-journald

log "система: /proc с hidepid (чужие процессы не видны службам и пользователям)"
getent group proc >/dev/null || groupadd -r proc
PROC_GID=$(getent group proc | cut -d: -f3)
PROC_OPTS="nosuid,nodev,noexec,relatime,hidepid=invisible,gid=$PROC_GID"
if grep -qE '^proc[[:space:]]+/proc[[:space:]]' /etc/fstab; then
  sed -i -E "s|^proc[[:space:]]+/proc[[:space:]].*|proc /proc proc $PROC_OPTS 0 0|" /etc/fstab
else
  echo "proc /proc proc $PROC_OPTS 0 0" >> /etc/fstab
fi
# logind (нет CAP_SYS_PTRACE) и polkit читают /proc чужих процессов: им группа proc
mkdir -p /etc/systemd/system/systemd-logind.service.d
printf '[Service]\nSupplementaryGroups=proc\n' > /etc/systemd/system/systemd-logind.service.d/tabora-hidepid.conf
if id polkitd >/dev/null 2>&1 && ! id -nG polkitd | grep -qw proc; then usermod -aG proc polkitd; systemctl try-restart polkit 2>/dev/null || true; fi
systemctl daemon-reload
findmnt -no OPTIONS /proc | grep -q "hidepid=invisible" || mount -o "remount,hidepid=invisible,gid=$PROC_GID" /proc

# ---- файрвол -------------------------------------------------------------------
log "файрвол: 22, почта (25/465/587/993) и 443 почтового хоста; 80 и 4190 закрыты"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for p in 22 25 443 465 587 993; do ufw allow "$p/tcp" >/dev/null; done
for p in 80 4190; do ufw delete allow "$p/tcp" >/dev/null 2>&1 || true; done
ufw --force enable >/dev/null

# ---- скрипты на сервере ------------------------------------------------------------
log "скрипты: $LIB (хук certbot, таймеры)"
install_lib "$HERE"

# ---- пользователи и секреты ----------------------------------------------------------
id -u tabora >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /opt/tabora tabora
id -u stalwart >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /opt/stalwart stalwart
install -d -m 750 -o root -g tabora /etc/tabora
# Cloudflare: файлы создаются пустыми с правами 600 до того, как в них что-то запишут (см. README)
[ -f /etc/tabora/cloudflare.env ] || cat > /etc/tabora/cloudflare.env <<'CONF'
# Cloudflare для cloudflare/setup-tunnel.sh и cloudflare/dns.sh (права 600, только root).
# CF_API_TOKEN: Account › Cloudflare Tunnel › Edit и Zone › DNS › Edit для зоны; после настройки
# туннеля и DNS строку с токеном удалить, а сам токен отозвать в панели Cloudflare.
CF_ACCOUNT_ID=
CF_ZONE_ID=
CF_API_TOKEN=
CONF
[ -f /etc/tabora/certbot-cloudflare.ini ] || cat > /etc/tabora/certbot-cloudflare.ini <<'CONF'
# Отдельный токен certbot: только Zone › DNS › Edit для зоны (DNS-01 и продление сертификатов).
dns_cloudflare_api_token =
CONF
chown root:root /etc/tabora/cloudflare.env /etc/tabora/certbot-cloudflare.ini
chmod 600 /etc/tabora/cloudflare.env /etc/tabora/certbot-cloudflare.ini
[ ! -f /etc/tabora/stalwart-admin.env ] || { chown root:root /etc/tabora/stalwart-admin.env; chmod 600 /etc/tabora/stalwart-admin.env; }
[ ! -f /etc/tabora/postmaster.env ] || { chown root:root /etc/tabora/postmaster.env; chmod 600 /etc/tabora/postmaster.env; }
install -d -m 755 -o root -g root /var/lib/tabora
# Резервные копии: пароль репозитория создаётся один раз. Без него копии не расшифровать —
# владелец хранит его вне сервера (менеджер паролей).
if [ ! -f /etc/tabora/backup.env ]; then
  ( umask 077
    cat > /etc/tabora/backup.env.new <<CONF
# Резервные копии restic (infra/backup/backup.sh; права 600, только root). См. infra/README.md.
# ПАРОЛЬ СОХРАНИТЕ ВНЕ СЕРВЕРА: без него копии не расшифровать, а сам этот файл в копии бесполезен.
RESTIC_PASSWORD=$(openssl rand -base64 33)
# Куда писать копии. Локальный каталог — только пока нет внешнего хранилища (тот же диск!).
#   Hetzner Storage Box: RESTIC_REPOSITORY=sftp://uXXXXXX@uXXXXXX.your-storagebox.de:23//home/tabora
#                        (открытый ключ /etc/tabora/backup_ed25519.pub добавить в Storage Box)
#   S3 (Hetzner Object Storage, Backblaze B2, AWS):
#                        RESTIC_REPOSITORY=s3:https://<endpoint>/<bucket>/tabora
#                        AWS_ACCESS_KEY_ID=…  AWS_SECRET_ACCESS_KEY=…
RESTIC_REPOSITORY=/var/backups/tabora-restic
CONF
  )
  mv /etc/tabora/backup.env.new /etc/tabora/backup.env
fi
# отдельный ключ SSH для sftp-хранилища (не в ~/.ssh); создаётся один раз
[ -f /etc/tabora/backup_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C "tabora-backup@$MAIL_HOST" -f /etc/tabora/backup_ed25519
[ -f /etc/tabora/alert.env ] || cat > /etc/tabora/alert.env <<'CONF'
# Оповещения мониторинга (infra/monitor/health.py; права 600). Пусто — только журнал и motd.
#   ntfy:    ALERT_URL=https://ntfy.sh/<длинное-случайное-имя-темы>   (ALERT_FORMAT=ntfy)
#   вебхук:  ALERT_URL=https://…  ALERT_FORMAT=json   (Slack, Discord, Mattermost и т. п.)
#   ALERT_TOKEN — необязательный токен (заголовок Authorization: Bearer)
# Проверка: /usr/local/lib/tabora/monitor/health.py test
ALERT_URL=
ALERT_FORMAT=ntfy
ALERT_TOKEN=
CONF
chown root:root /etc/tabora/backup.env /etc/tabora/backup_ed25519 /etc/tabora/backup_ed25519.pub /etc/tabora/alert.env
chmod 600 /etc/tabora/backup.env /etc/tabora/backup_ed25519 /etc/tabora/alert.env
chmod 644 /etc/tabora/backup_ed25519.pub

# ---- PostgreSQL --------------------------------------------------------------
log "PostgreSQL: роль и база tabora"
systemctl enable --now postgresql >/dev/null
if [ ! -f /etc/tabora/server.env ]; then
  ( umask 077
    cat > /etc/tabora/server.env.new <<CONF
# Секреты сервиса tabora-server. Файл создан setup.sh, не коммитить.
TABORA_DOMAIN=$DOMAIN
TABORA_LISTEN=127.0.0.1:7700
TABORA_DB=postgres://tabora:$(openssl rand -hex 24)@127.0.0.1:5432/tabora?sslmode=disable
TABORA_PUBLIC_URL=https://$API_HOST
STALWART_URL=http://127.0.0.1:8080
APP_SIGNING_KEY=$(openssl rand -hex 32)
CONF
  )
  mv /etc/tabora/server.env.new /etc/tabora/server.env
fi
chown root:tabora /etc/tabora/server.env && chmod 640 /etc/tabora/server.env
# роль и база проверяются по отдельности при каждом запуске: сбой посередине не оставляет полдела
DBPASS=$(sed -n 's|^TABORA_DB=postgres://tabora:\([0-9a-f]*\)@.*|\1|p' /etc/tabora/server.env)
[ -n "$DBPASS" ] || die "не разобрать пароль базы в TABORA_DB (/etc/tabora/server.env)"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='tabora'" | grep -q 1; then
  # пароль идёт через stdin (printf — встроенная команда), а не в аргументах psql
  printf "CREATE ROLE tabora LOGIN PASSWORD '%s';\n" "$DBPASS" | sudo -u postgres psql -v ON_ERROR_STOP=1 -q
fi
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='tabora'" | grep -q 1 || sudo -u postgres createdb -O tabora tabora
unset DBPASS

# ---- Stalwart ----------------------------------------------------------------
log "Stalwart $STALWART_VERSION"
install -d -m 755 -o root -g root /opt/stalwart /opt/stalwart/bin
install -d -m 750 -o root -g stalwart /opt/stalwart/etc
install -d -m 750 -o stalwart -g stalwart /opt/stalwart/data /opt/stalwart/logs
# бинарник принадлежит root (служба не может его подменить); хеш бинарника из проверенного архива
# хранится рядом и сверяется при каждом запуске
want_bin_hash=$(cat /opt/stalwart/bin/stalwart.sha256 2>/dev/null || true)
have_bin_hash=$( [ -f /opt/stalwart/bin/stalwart ] && sha256sum /opt/stalwart/bin/stalwart | cut -d' ' -f1 || true)
if [ "$(cat /opt/stalwart/bin/archive.sha256 2>/dev/null || true)" != "$STALWART_SHA256" ] || [ -z "$want_bin_hash" ] || [ "$want_bin_hash" != "$have_bin_hash" ]; then
  tmp=$(mktemp -d)
  curl -fsSL "https://github.com/stalwartlabs/stalwart/releases/download/$STALWART_VERSION/stalwart-x86_64-unknown-linux-gnu.tar.gz" -o "$tmp/stalwart.tgz"
  echo "$STALWART_SHA256  $tmp/stalwart.tgz" | sha256sum -c --quiet - || { rm -rf "$tmp"; die "sha256 архива Stalwart не совпадает"; }
  tar -xzf "$tmp/stalwart.tgz" -C "$tmp" stalwart
  install -m 755 -o root -g root "$tmp/stalwart" /opt/stalwart/bin/stalwart.new
  mv -f /opt/stalwart/bin/stalwart.new /opt/stalwart/bin/stalwart
  sha256sum /opt/stalwart/bin/stalwart | cut -d' ' -f1 > /opt/stalwart/bin/stalwart.sha256
  echo "$STALWART_SHA256" > /opt/stalwart/bin/archive.sha256
  rm -rf "$tmp"
  STALWART_INSTALLED=1
fi
chown root:root /opt/stalwart/bin/* && chmod 755 /opt/stalwart/bin/stalwart && chmod 644 /opt/stalwart/bin/*.sha256
# Stalwart 1.x: config.json описывает только хранилище, всё остальное — JMAP-объекты (stalwart/configure.py)
[ -f /opt/stalwart/etc/config.json ] || cat > /opt/stalwart/etc/config.json <<'CONF'
{
  "@type": "RocksDb",
  "path": "/opt/stalwart/data",
  "blobSize": 16834,
  "bufferSize": 134217728,
  "poolWorkers": null
}
CONF
[ -f /opt/stalwart/etc/stalwart.env ] || printf 'STALWART_HOSTNAME=%s\nSTALWART_PUBLIC_URL=https://%s\n' "$MAIL_HOST" "$MAIL_HOST" > /opt/stalwart/etc/stalwart.env
rm -f /opt/stalwart/etc/config.toml.tabora /root/.stalwart-init.txt   # остатки старой схемы (TOML, init)
chown root:stalwart /opt/stalwart/etc/config.json /opt/stalwart/etc/stalwart.env
chmod 640 /opt/stalwart/etc/config.json /opt/stalwart/etc/stalwart.env
chown -R stalwart:stalwart /opt/stalwart/data /opt/stalwart/logs
render "$HERE/systemd/stalwart.service" /etc/systemd/system/stalwart.service
[ -z "$RENDER_CHANGED" ] || STALWART_INSTALLED=1
systemctl daemon-reload
systemctl enable stalwart >/dev/null 2>&1

stalwart_restart() {
  systemctl restart stalwart
  for _ in $(seq 1 60); do
    case "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/jmap/session)" in 2??|401) return 0 ;; esac
    sleep 1
  done
  die "Stalwart не отвечает на 127.0.0.1:8080"
}
# перезапуск только при новом бинарнике или юните (или если служба не работает)
if [ -n "${STALWART_INSTALLED:-}" ] || ! systemctl is-active -q stalwart; then stalwart_restart; fi

CONFIGURE="python3 $LIB/stalwart/configure.py"
if ! $CONFIGURE admin-ok; then
  log "Stalwart: постоянного администратора нет — создаётся через временного аварийного"
  $CONFIGURE recovery-on || [ $? -eq 3 ]
  stalwart_restart
  $CONFIGURE bootstrap
fi
# аварийный администратор (STALWART_RECOVERY_ADMIN) обходит allowedIps, поэтому в env его нет
rc=0; $CONFIGURE recovery-off || rc=$?
[ $rc -eq 0 ] || [ $rc -eq 3 ] || exit $rc
[ $rc -eq 0 ] || stalwart_restart
rc=0; $CONFIGURE apply || rc=$?
[ $rc -eq 0 ] || [ $rc -eq 3 ] || exit $rc
[ $rc -eq 0 ] || { log "Stalwart: перезапуск, чтобы применить настройки"; stalwart_restart; }
if tls_enabled; then
  python3 "$LIB/stalwart/upload-cert.py" "$MX_LIVE" >/dev/null
  install_certbot_hook "$HERE"
fi

# ---- tabora-server (каркас) --------------------------------------------------
log "tabora-server: пользователь и служба"
install -d -m 755 -o root -g root /opt/tabora /opt/tabora/bin
install -d -m 750 -o tabora -g tabora /opt/tabora/data
[ ! -e /opt/tabora/bin/tabora-server ] || chown root:root /opt/tabora/bin/tabora-server
render "$HERE/systemd/tabora-server.service" /etc/systemd/system/tabora-server.service
systemctl daemon-reload
systemctl enable tabora-server >/dev/null 2>&1 || true
# запускать будет deploy.sh после загрузки бинарника
[ ! -x /opt/tabora/bin/tabora-server ] || systemctl try-restart tabora-server

# ---- проверка новых версий Stalwart (сам Stalwart не обновляется: версия и хеш закреплены) ----
render "$HERE/systemd/tabora-stalwart-release.service" /etc/systemd/system/tabora-stalwart-release.service
render "$HERE/systemd/tabora-stalwart-release.timer" /etc/systemd/system/tabora-stalwart-release.timer
install -m 755 "$HERE/stalwart/motd.sh" /etc/update-motd.d/95-tabora-stalwart
systemctl daemon-reload
systemctl enable --now tabora-stalwart-release.timer >/dev/null 2>&1

# ---- туннель: служба из сохранённых учётных данных (после восстановления из копии) ----------
# setup-tunnel.sh создаёт туннель и службу; если учётные данные уже лежат в /etc/cloudflared
# (сервер восстановлен из резервной копии), службе токен Cloudflare не нужен
if [ ! -f /etc/systemd/system/cloudflared.service ]; then
  cred=
  [ ! -d /etc/cloudflared ] || cred=$(find /etc/cloudflared -maxdepth 1 -name '*.json' | head -1)
  if [ -n "$cred" ]; then
    log "туннель: служба cloudflared из сохранённых учётных данных"
    chown root:root "$cred" && chmod 600 "$cred"
    render "$HERE/cloudflare/cloudflared.service" /etc/systemd/system/cloudflared.service "s/__TUNNEL_ID__/$(basename "$cred" .json)/g"
    systemctl daemon-reload
    systemctl enable --now cloudflared >/dev/null 2>&1 || true
  fi
fi

# ---- nginx + сайт ------------------------------------------------------------
log "сайт: /var/www/tabora.app"
mkdir -p /var/www/tabora.app /var/www/mta-sts/.well-known
install -m 644 "$HERE/mta-sts/mta-sts.txt" /var/www/mta-sts/.well-known/mta-sts.txt
# сайт принадлежит root: nginx (www-data) его только читает
# The site is deployed from its own repository (Tabora-App/site), which leaves a copy next to
# infra/; a rebuilt host serves that copy right away.
if [ -d "$HERE/../site" ]; then
  rsync -a --delete --chown=root:root --chmod=D755,F644 "$HERE/../site/" /var/www/tabora.app/
fi
chown root:root /var/www/tabora.app && chmod 755 /var/www/tabora.app
# журнал почтового хоста нужен fail2ban (tabora-jmap) ещё до включения TLS
[ -f /var/log/nginx/mx.access.log ] || install -m 640 -o www-data -g adm /dev/null /var/log/nginx/mx.access.log
install_nginx "$HERE/nginx"

# ---- fail2ban ------------------------------------------------------------------
log "fail2ban: ssh, JMAP (401/403 с авторизацией), Stalwart (SMTP AUTH, IMAP), recidive без порта 22"
f2b_changed=
for f in "$HERE"/fail2ban/filter.d/*.conf; do
  cmp -s "$f" "/etc/fail2ban/filter.d/$(basename "$f")" || { install -m 644 "$f" /etc/fail2ban/filter.d/; f2b_changed=1; }
done
cmp -s "$HERE/fail2ban/tabora.local" /etc/fail2ban/jail.d/tabora.local || { install -m 644 "$HERE/fail2ban/tabora.local" /etc/fail2ban/jail.d/tabora.local; f2b_changed=1; }
systemctl enable fail2ban >/dev/null 2>&1
# перезапуск только при изменении правил: действующие баны при повторном запуске не теряются
if [ -n "$f2b_changed" ] || ! systemctl is-active -q fail2ban; then
  fail2ban-client -t >/dev/null || die "fail2ban не принял конфигурацию (fail2ban-client -t)"
  systemctl restart fail2ban
fi
for _ in $(seq 1 20); do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done
fail2ban-client status | sed -n 's/.*Jail list:[[:space:]]*/  jail: /p'

# ---- резервные копии и мониторинг ------------------------------------------------
log "резервные копии: restic, ежедневно в 03:15, проверка репозитория по воскресеньям"
install -d -m 700 -o root -g root /var/backups/tabora
for u in tabora-backup.service tabora-backup.timer tabora-backup-check.service tabora-backup-check.timer \
         tabora-health.service tabora-health.timer; do
  render "$HERE/systemd/$u" "/etc/systemd/system/$u"
done
install -m 755 "$HERE/monitor/motd.sh" /etc/update-motd.d/96-tabora-health
systemctl daemon-reload
systemctl enable --now tabora-backup.timer tabora-backup-check.timer >/dev/null 2>&1
if grep -q '^RESTIC_REPOSITORY=/' /etc/tabora/backup.env; then
  log "ВНИМАНИЕ: резервные копии только локальные (тот же диск). Внешнее хранилище: RESTIC_REPOSITORY в /etc/tabora/backup.env (infra/README.md)"
fi
if [ ! -s /var/lib/tabora/backup.json ]; then
  log "резервные копии: первая копия (Stalwart остановится на несколько секунд)"
  systemctl start tabora-backup.service || log "первая копия не удалась: journalctl -u tabora-backup"
fi
log "мониторинг: tabora-health каждые 5 минут (/run/tabora/health.json, motd, оповещения из /etc/tabora/alert.env)"
systemctl enable --now tabora-health.timer >/dev/null 2>&1
systemctl start tabora-health.service || true
python3 "$LIB/monitor/health.py" show || true

log "готово. Stalwart: $(/opt/stalwart/bin/stalwart --version 2>/dev/null | head -1); nginx: $(nginx -v 2>&1 | cut -d/ -f2); PostgreSQL: $(psql --version | awk '{print $3}')"
if tls_enabled; then log "TLS включён ($MAIL_HOST)"; else log "дальше: домен в Cloudflare → infra/deploy.sh tunnel → tls → dns (infra/README.md)"; fi
[ ! -f /var/run/reboot-required ] || log "нужна перезагрузка: $(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
