#!/bin/sh
# Сравнивает установленную версию Stalwart с последним релизом на GitHub (служба
# tabora-stalwart-release). Пишет $STATE_DIRECTORY/notice, его показывает motd.
set -eu
state=${STATE_DIRECTORY:-/var/lib/tabora-release}
installed=v$(/opt/stalwart/bin/stalwart --version 2>/dev/null | head -1 | awk '{print $NF}')
latest=$(curl -fsS --max-time 30 https://api.github.com/repos/stalwartlabs/stalwart/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
if [ -n "$latest" ] && [ "$latest" != "$installed" ]; then
  msg="Stalwart: вышла $latest (установлена $installed). Обновление: STALWART_VERSION и STALWART_SHA256 в infra/setup.sh (хеш сверить с .sigstore.json релиза), затем infra/deploy.sh setup"
  echo "$msg" > "$state/notice"
  echo "<4>$msg"
else
  rm -f "$state/notice"
  echo "Stalwart $installed: новее нет"
fi
