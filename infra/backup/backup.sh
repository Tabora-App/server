#!/usr/bin/env bash
# Резервная копия сервера Tabora в зашифрованный репозиторий restic (tabora-backup.timer, ежедневно).
#
# Что попадает в копию:
#   stage/stalwart-data  данные Stalwart (RocksDB). Копировать файлы работающей базы нельзя
#                        (журнал записи и MANIFEST меняются на ходу), а снимка «на ходу» у
#                        Stalwart нет, поэтому служба останавливается на несколько секунд:
#                        неизменяемые *.sst и *.blob берутся жёсткими ссылками, остальное копируется.
#                        Почта за это время не теряется: отправители повторяют доставку.
#   stage/tabora.pgdump  pg_dump базы tabora (формат custom), stage/pg-globals.sql — роли
#   /etc/tabora, /opt/stalwart/etc, /etc/letsencrypt, /etc/cloudflared, /etc/nginx/sites-available
#
# Хранение: 7 дневных, 4 недельных, 6 месячных копий. Состояние — /var/lib/tabora/backup.json
# (его читает мониторинг). Пока RESTIC_REPOSITORY — локальный каталог, копии лежат на том же диске
# и от потери сервера не спасают: об этом предупреждение в журнале и при входе по SSH.
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
load_backup_env
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DATA=/opt/stalwart/data
SNAP=$STAGE/stalwart-data

was_active=0
start_stalwart() {
  [ "$was_active" = 1 ] || return 0
  was_active=0
  systemctl start stalwart || warn "Stalwart не запустился после снимка данных"
}
on_exit() {
  local rc=$?
  start_stalwart
  if [ $rc -ne 0 ]; then
    status_set "last_run=\"$started\"" "last_ok=false" "last_error=\"шаг «${step:-?}», код $rc\"" || true
    warn "резервная копия НЕ создана: шаг «${step:-?}», код $rc"
  fi
  exit $rc
}
trap on_exit EXIT

step="репозиторий"
if repo_is_local; then
  install -d -m 700 -o root -g root "$RESTIC_REPOSITORY"
  warn "ВНИМАНИЕ: резервные копии только локальные ($RESTIC_REPOSITORY, тот же диск). Задайте внешнее хранилище в $BACKUP_ENV (infra/README.md, «Резервные копии»)."
fi
install -d -m 700 "$RESTIC_CACHE_DIR"
if ! rst cat config >/dev/null 2>&1; then
  say "репозиторий restic создаётся: $RESTIC_REPOSITORY"
  rst init
fi

step="снимок Stalwart"
install -d -m 700 /var/backups/tabora /var/backups/tabora/stage
find /var/backups/tabora/stage -mindepth 1 -delete
systemctl is-active -q stalwart && was_active=1
t0=$(date +%s%N)
[ "$was_active" = 0 ] || systemctl stop stalwart
# жёсткие ссылки на всё, затем изменяемые файлы (не *.sst/*.blob) заменяются настоящими копиями;
# на другой файловой системе ссылки невозможны — тогда обычная копия
if cp -al "$DATA" "$SNAP" 2>/dev/null; then
  find "$SNAP" -type f ! -name '*.sst' ! -name '*.blob' -print0 | while IFS= read -r -d '' f; do
    cp -p --remove-destination "$DATA/${f#"$SNAP/"}" "$f"
  done
else
  find /var/backups/tabora/stage -mindepth 1 -delete
  cp -a "$DATA" "$SNAP"
fi
start_stalwart
down_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
# замок и текстовые журналы RocksDB для восстановления не нужны
find "$SNAP" -type f \( -name LOCK -o -name 'LOG' -o -name 'LOG.old.*' \) -delete
( cd "$SNAP" && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$STAGE/stalwart-data.sha256"
/opt/stalwart/bin/stalwart --version 2>/dev/null | head -1 > "$STAGE/stalwart-version.txt" || true

step="pg_dump"
runuser -u postgres -- pg_dump --format=custom tabora > "$STAGE/tabora.pgdump"
runuser -u postgres -- pg_dumpall --globals-only --no-role-passwords > "$STAGE/pg-globals.sql"
pg_restore --list "$STAGE/tabora.pgdump" > /dev/null

step="restic backup"
paths=("$STAGE")
for p in /etc/tabora /opt/stalwart/etc /etc/letsencrypt /etc/cloudflared /etc/nginx/sites-available; do
  [ ! -e "$p" ] || paths+=("$p")
done
rst backup --tag tabora --host "$(hostname)" "${paths[@]}"
snapshot=$(rst snapshots --tag tabora --latest 1 --json | jq -r '.[-1].short_id')

step="restic forget"
rst forget --tag tabora --group-by host,tags --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune

step="состояние"
# снимок данных Stalwart больше не нужен (жёсткие ссылки держали бы файлы, которые база уже удалила)
find /var/backups/tabora/stage -mindepth 1 -delete
local_only=false; ! repo_is_local || local_only=true
status_set "last_run=\"$started\"" "last_ok=true" "last_success=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"" \
  "last_error=null" "snapshot=\"$snapshot\"" "local_only=$local_only" "stalwart_down_ms=$down_ms"
say "резервная копия $snapshot готова (Stalwart был остановлен на ${down_ms} мс)"
