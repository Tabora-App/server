#!/usr/bin/env bash
# Еженедельная проверка репозитория restic (tabora-backup-check.timer): структура и выборочно
# 10 % данных. Результат — в /var/lib/tabora/backup.json (читает мониторинг).
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
load_backup_env
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if rst check --read-data-subset=10%; then
  status_set "check_time=\"$now\"" "check_ok=true"
  say "репозиторий restic в порядке"
else
  status_set "check_time=\"$now\"" "check_ok=false"
  warn "restic check нашёл ошибки в репозитории $RESTIC_REPOSITORY"
  exit 1
fi
