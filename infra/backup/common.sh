# shellcheck shell=bash
# Общее для backup.sh, check.sh и restore.sh: окружение restic из /etc/tabora/backup.env.
BACKUP_ENV=/etc/tabora/backup.env
STATE_DIR=/var/lib/tabora
STATUS=$STATE_DIR/backup.json
STAGE=/var/backups/tabora/stage          # согласованный снимок данных перед restic
LOCAL_REPO=/var/backups/tabora-restic

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; logger -t tabora-backup -p user.warning -- "$*" 2>/dev/null || true; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

load_backup_env() {
  [ -f "$BACKUP_ENV" ] || fail "нет $BACKUP_ENV (создаёт infra/setup.sh)"
  set -a
  # shellcheck disable=SC1090
  . "$BACKUP_ENV"
  set +a
  [ -n "${RESTIC_REPOSITORY:-}" ] || fail "в $BACKUP_ENV не задан RESTIC_REPOSITORY"
  [ -n "${RESTIC_PASSWORD:-}" ] || fail "в $BACKUP_ENV не задан RESTIC_PASSWORD"
  export RESTIC_CACHE_DIR=/var/cache/tabora-restic
  RESTIC_OPTS=()
  # sftp (Hetzner Storage Box): отдельный ключ и known_hosts в /etc/tabora, ~/.ssh не используется
  case "$RESTIC_REPOSITORY" in
    sftp:*) RESTIC_OPTS+=(-o "sftp.args=-i /etc/tabora/backup_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=/etc/tabora/backup_known_hosts -o StrictHostKeyChecking=accept-new") ;;
  esac
}

repo_is_local() { case "$RESTIC_REPOSITORY" in /*|local:*) return 0 ;; *) return 1 ;; esac; }
rst() { restic "${RESTIC_OPTS[@]}" "$@"; }

# status_set ключ=значение…: обновляет $STATUS (значения — JSON)
status_set() {
  mkdir -p "$STATE_DIR"
  [ -s "$STATUS" ] || echo '{}' > "$STATUS"
  local kv args=() filter='.'
  for kv in "$@"; do
    args+=(--argjson "${kv%%=*}" "${kv#*=}")
    filter="$filter | .${kv%%=*} = \$${kv%%=*}"
  done
  jq "${args[@]}" "$filter" "$STATUS" > "$STATUS.tmp" && mv -f "$STATUS.tmp" "$STATUS"
  chmod 644 "$STATUS"
}
