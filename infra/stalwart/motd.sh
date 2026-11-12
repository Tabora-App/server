#!/bin/sh
# /etc/update-motd.d/95-tabora-stalwart: напоминание о новой версии Stalwart (см. check-release.sh)
for f in /var/lib/tabora-release/notice /var/lib/private/tabora-release/notice; do
  [ -r "$f" ] && { echo; cat "$f"; break; }
done
exit 0
