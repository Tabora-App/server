#!/usr/bin/env bash
# Deployment from a laptop: copies infra/ to the server (/root/tabora-infra) and runs the requested
# step there. Usage: infra/deploy.sh [setup|server|nginx|tls|tunnel|dns]
# `infra/deploy.sh dns --plan` shows which DNS records would change without changing anything.
# The website and the web app are deployed from their own repositories (Tabora-App/site and
# Tabora-App/browser): they only copy their files to this host.
set -euo pipefail
HOST=${HOST:-tabora}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
what=${1:-setup}
ssh "$HOST" "install -d -m 700 /root/tabora-infra && mkdir -p /root/tabora-infra/infra"
rsync -az --delete "$ROOT/infra/" "$HOST:/root/tabora-infra/infra/"
case "$what" in
  setup)  ssh "$HOST" 'bash /root/tabora-infra/infra/setup.sh' ;;
  server)
    # tabora-server: built on this machine for the server (Linux x86_64, static; needs the Rust
    # target x86_64-unknown-linux-musl), installed into /opt/tabora/bin and swapped in with a
    # single rename, then the service is restarted and checked to be answering. Settings:
    # /etc/tabora/server.env.
    # Before the swap: a database dump goes to /var/backups/tabora (the service changes the schema
    # itself at start-up) and the previous build is kept next to the new one as tabora-server.prev.
    # If the new build does not answer, the previous one is put back automatically; schema changes
    # only add tables and columns, so they do not get in the way of the previous build.
    (cd "$ROOT" && cargo build --release --target x86_64-unknown-linux-musl)
    bin="$ROOT/target/x86_64-unknown-linux-musl/release/tabora-server"
    echo "local: $(shasum -a 256 "$bin" | cut -d' ' -f1)"
    rsync -az "$bin" "$HOST:/root/tabora-infra/tabora-server.new"
    ssh "$HOST" 'set -e
      umask 077
      bin=/opt/tabora/bin/tabora-server
      alive() {
        for i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -fsS -m 3 http://127.0.0.1:7700/v1/health; then echo; return 0; fi
          sleep 1
        done
        return 1
      }
      install -d -m 700 -o root -g root /var/backups/tabora
      dump=/var/backups/tabora/before-deploy.pgdump
      runuser -u postgres -- pg_dump -Fc tabora > $dump.new
      mv -f $dump.new $dump
      echo "database dump: $dump ($(stat -c %s $dump) bytes)"
      install -m 755 -o root -g root /root/tabora-infra/tabora-server.new $bin.new
      rm -f /root/tabora-infra/tabora-server.new
      [ ! -f $bin ] || cp -pf $bin $bin.prev
      mv -f $bin.new $bin
      echo "on the server: $(sha256sum $bin | cut -d" " -f1)"
      systemctl daemon-reload
      systemctl enable tabora-server >/dev/null 2>&1
      systemctl restart tabora-server
      if alive; then echo "tabora-server is running"; exit 0; fi
      journalctl -u tabora-server -n 30 --no-pager
      if [ -f $bin.prev ]; then
        echo "the new build does not answer — restoring the previous one"
        cp -pf $bin.prev $bin.new && mv -f $bin.new $bin
        systemctl restart tabora-server
        if alive; then echo "the previous build is running"; else echo "the previous build does not answer either"; fi
      fi
      exit 1'
    ;;
  nginx)
    # nginx configuration only (after editing infra/nginx): an nginx -t check and a reload without downtime
    ssh "$HOST" 'set -euo pipefail
      DOMAIN=${DOMAIN:-tabora.app}; MAIL_HOST=${MAIL_HOST:-mx.$DOMAIN}; API_HOST=${API_HOST:-api.$DOMAIN}
      . /root/tabora-infra/infra/lib.sh
      install_nginx /root/tabora-infra/infra/nginx
      echo "nginx: configuration updated"'
    ;;
  tls)    ssh "$HOST" 'bash /root/tabora-infra/infra/enable-tls.sh' ;;
  tunnel) ssh "$HOST" 'bash /root/tabora-infra/infra/cloudflare/setup-tunnel.sh' ;;
  dns)    if [ "${2:-}" = "--plan" ]; then ssh "$HOST" 'bash /root/tabora-infra/infra/cloudflare/dns.sh --plan'; else ssh "$HOST" 'bash /root/tabora-infra/infra/cloudflare/dns.sh'; fi ;;
  *) echo "setup | server | nginx | tls | tunnel | dns"; exit 1 ;;
esac
