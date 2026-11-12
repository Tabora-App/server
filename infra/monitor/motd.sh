#!/bin/sh
# /etc/update-motd.d/96-tabora-health: состояние сервера при входе по SSH (см. monitor/health.py)
f=/run/tabora/health.json
[ -r "$f" ] || exit 0
echo
jq -r '
  def mark: {"crit":"[!!]","warn":"[! ]","note":"[i ]"}[.level];
  "Tabora: " + (if .problems > 0 then "ПРОБЛЕМЫ — \(.problems)" else "всё в порядке" end) + " (проверено \(.time))",
  (.checks | map(select(.level != "ok")) | sort_by({"crit":0,"warn":1,"note":2}[.level]) | .[] | "  \(mark) \(.msg)")
' "$f" 2>/dev/null
exit 0
