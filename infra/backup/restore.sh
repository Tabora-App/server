#!/usr/bin/env bash
# Восстановление из резервной копии restic (см. infra/README.md, «Резервные копии»).
#
#   restore.sh list                    список копий
#   restore.sh verify [копия]          проверка копии без изменения сервера: распаковка во временный
#                                      каталог, сверка sha256 данных Stalwart, пробный запуск Stalwart
#                                      на копии в изолированной сети, pg_restore во временную базу
#   restore.sh extract <каталог> [копия]   распаковать копию в каталог (посмотреть, достать файл)
#   restore.sh apply [копия] --yes     восстановить сервер из копии: секреты и настройки, данные
#                                      Stalwart, база tabora. Прежние данные не удаляются, а
#                                      переименовываются (*.before-restore-<время>).
#
# «копия» — идентификатор из list или latest (по умолчанию). Запускать на сервере от root:
#   ssh tabora /usr/local/lib/tabora/backup/restore.sh verify
# Новый сервер: сначала infra/deploy.sh setup, затем вписать RESTIC_REPOSITORY и RESTIC_PASSWORD
# прежнего сервера в /etc/tabora/backup.env, затем apply и ещё раз infra/deploy.sh setup.
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
load_backup_env

WORK_BASE=/var/backups/tabora
CONFIG_PATHS=(/etc/tabora /opt/stalwart/etc /etc/letsencrypt /etc/cloudflared /etc/nginx/sites-available)

# unpack <копия> <каталог>: распаковка и сверка контрольных сумм данных Stalwart
unpack() {
  local snap=$1 dir=$2
  say "распаковка копии $snap в $dir"
  rst restore "$snap" --tag tabora --target "$dir" --verify >/dev/null
  local stage=$dir$STAGE
  [ -d "$stage/stalwart-data" ] || fail "в копии нет данных Stalwart ($STAGE/stalwart-data)"
  [ -s "$stage/tabora.pgdump" ] || fail "в копии нет дампа базы ($STAGE/tabora.pgdump)"
  ( cd "$stage/stalwart-data" && sha256sum --quiet -c "$stage/stalwart-data.sha256" ) \
    || fail "контрольные суммы данных Stalwart не сошлись"
  local current manifest
  current=$(cat "$stage/stalwart-data/CURRENT")
  manifest=$stage/stalwart-data/$current
  [ -s "$manifest" ] || fail "нет файла $current, на который указывает CURRENT"
  say "  данные Stalwart: $(find "$stage/stalwart-data" -type f | wc -l) файлов, $(du -sh "$stage/stalwart-data" | cut -f1), sha256 сошлись, $current на месте"
}

# place_stalwart_data <распакованные данные> <каталог назначения (не должен существовать)>
place_stalwart_data() {
  local src=$1 dst=$2
  [ ! -e "$dst" ] || fail "$dst уже существует"
  cp -a "$src" "$dst"
  chown -R stalwart:stalwart "$dst"
  chmod 750 "$dst"
}

# restore_pg <дамп> <имя базы (не должна существовать)>
restore_pg() {
  local dump=$1 db=$2
  runuser -u postgres -- createdb -O tabora "$db"
  runuser -u postgres -- pg_restore --no-owner --role=tabora --exit-on-error -d "$db" < "$dump"
}

pg_has_db() { runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='$1'" | grep -q 1; }

cmd=${1:-}
case "$cmd" in
  list)
    rst snapshots --tag tabora
    ;;

  extract)
    dir=${2:-}; snap=${3:-latest}
    [ -n "$dir" ] || fail "restore.sh extract <каталог> [копия]"
    install -d -m 700 "$dir"
    unpack "$snap" "$dir"
    say "готово: $dir (внутри секреты — удалите каталог после работы)"
    ;;

  verify)
    snap=${2:-latest}
    install -d -m 700 "$WORK_BASE"
    work=$(mktemp -d "$WORK_BASE/verify.XXXXXX")
    db=tabora_restore_check
    # пробный запуск Stalwart: каталог, куда может зайти пользователь stalwart (WORK_BASE закрыт)
    trial=$(mktemp -d /opt/stalwart/restore-check.XXXXXX)
    cleanup() {
      systemctl stop tabora-restore-check.service 2>/dev/null || true
      systemctl reset-failed tabora-restore-check.service 2>/dev/null || true
      ! pg_has_db "$db" || runuser -u postgres -- dropdb "$db"
      case "$work" in "$WORK_BASE"/verify.*) find "$work" -delete ;; esac
      case "$trial" in /opt/stalwart/restore-check.*) find "$trial" -delete ;; esac
    }
    trap cleanup EXIT
    unpack "$snap" "$work"
    stage=$work$STAGE

    for p in /etc/tabora/server.env /etc/tabora/stalwart-admin.env /opt/stalwart/etc/config.json /opt/stalwart/etc/stalwart.env; do
      [ -s "$work$p" ] || fail "в копии нет $p"
    done
    say "  настройки и секреты: $(cd "$work" && find etc opt/stalwart/etc -type f | wc -l) файлов (server.env, stalwart-admin.env, config.json на месте)"

    # пробный запуск Stalwart на копии данных: отдельная сеть (PrivateNetwork), так что порты
    # не конфликтуют с рабочей службой, а очередь почты никуда не уйдёт
    place_stalwart_data "$stage/stalwart-data" "$trial/data"
    printf '{"@type":"RocksDb","path":"%s","blobSize":16834,"bufferSize":134217728,"poolWorkers":null}\n' "$trial/data" > "$trial/config.json"
    install -m 640 -o root -g stalwart "$work/opt/stalwart/etc/stalwart.env" "$trial/stalwart.env"
    chown root:stalwart "$trial" "$trial/config.json"; chmod 750 "$trial"; chmod 640 "$trial/config.json"
    if systemd-run --quiet --unit=tabora-restore-check --service-type=notify --collect \
         -p User=stalwart -p Group=stalwart -p PrivateNetwork=yes -p AmbientCapabilities=CAP_NET_BIND_SERVICE \
         -p ProtectSystem=strict -p "ReadWritePaths=$trial/data" -p TimeoutStartSec=90 \
         -p EnvironmentFile="$trial/stalwart.env" \
         /opt/stalwart/bin/stalwart --config="$trial/config.json"; then
      sleep 3
      systemctl is-active -q tabora-restore-check.service || fail "Stalwart на восстановленных данных запустился и упал: journalctl -u tabora-restore-check"
      say "  Stalwart запустился на восстановленных данных (изолированно) — база открывается"
      systemctl stop tabora-restore-check.service
    else
      fail "Stalwart не запустился на восстановленных данных: journalctl -u tabora-restore-check"
    fi

    n=$(pg_restore --list "$stage/tabora.pgdump" | grep -vc '^;' || true)
    ! pg_has_db "$db" || runuser -u postgres -- dropdb "$db"
    restore_pg "$stage/tabora.pgdump" "$db"
    tables=$(runuser -u postgres -- psql -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')" "$db")
    say "  PostgreSQL: дамп читается (объектов: $n), восстановлен во временную базу (таблиц: $tables)"
    say "копия $snap пригодна для восстановления"
    ;;

  apply)
    snap=latest; yes=
    shift
    for a in "$@"; do case "$a" in --yes) yes=1 ;; *) snap=$a ;; esac; done
    [ -n "$yes" ] || fail "apply заменяет данные Stalwart, базу tabora и секреты содержимым копии. Запустите: restore.sh apply $snap --yes"
    id -u stalwart >/dev/null 2>&1 && [ -x /opt/stalwart/bin/stalwart ] || fail "сначала infra/deploy.sh setup (нет Stalwart)"
    ts=$(date +%Y%m%d-%H%M%S)
    install -d -m 700 "$WORK_BASE"
    work=$(mktemp -d "$WORK_BASE/restore.XXXXXX")
    unpack "$snap" "$work"
    stage=$work$STAGE

    say "службы останавливаются"
    systemctl stop tabora-server 2>/dev/null || true
    systemctl stop stalwart

    say "настройки и секреты (прежние — рядом, *.before-restore-$ts)"
    for p in "${CONFIG_PATHS[@]}"; do
      [ -e "$work$p" ] || continue
      [ ! -e "$p" ] || cp -a "$p" "$p.before-restore-$ts"
      mkdir -p "$p"
      # backup.env не трогаем: в нём доступ к репозиторию, из которого идёт восстановление
      rsync -a --exclude=/backup.env --exclude=/backup_ed25519 --exclude=/backup_ed25519.pub --exclude=/backup_known_hosts "$work$p/" "$p/"
    done

    say "данные Stalwart"
    [ ! -e /opt/stalwart/data ] || mv /opt/stalwart/data "/opt/stalwart/data.before-restore-$ts"
    place_stalwart_data "$stage/stalwart-data" /opt/stalwart/data

    say "база tabora"
    # пароль роли — из восстановленного server.env (через stdin, не в аргументах)
    dbpass=$(sed -n 's|^TABORA_DB=postgres://tabora:\([0-9a-f]*\)@.*|\1|p' /etc/tabora/server.env)
    [ -n "$dbpass" ] || fail "не разобрать пароль базы в /etc/tabora/server.env"
    if runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='tabora'" | grep -q 1; then
      printf "ALTER ROLE tabora LOGIN PASSWORD '%s';\n" "$dbpass" | runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q
    else
      printf "CREATE ROLE tabora LOGIN PASSWORD '%s';\n" "$dbpass" | runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q
    fi
    unset dbpass
    if pg_has_db tabora; then
      runuser -u postgres -- psql -v ON_ERROR_STOP=1 -qc "ALTER DATABASE tabora RENAME TO \"tabora_before_restore_${ts//-/_}\""
    fi
    restore_pg "$stage/tabora.pgdump" tabora

    say "службы запускаются"
    systemctl start stalwart
    [ ! -x /opt/tabora/bin/tabora-server ] || systemctl start tabora-server
    case "$work" in "$WORK_BASE"/restore.*) find "$work" -delete ;; esac
    say "восстановлено из копии $snap. Дальше: infra/deploy.sh setup (права, nginx, туннель, хук certbot), затем DNS и PTR на новый адрес."
    say "прежние данные: /opt/stalwart/data.before-restore-$ts, база tabora_before_restore_${ts//-/_}, *.before-restore-$ts — удалите, когда убедитесь, что всё работает."
    ;;

  *)
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
