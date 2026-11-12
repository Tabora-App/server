#!/bin/sh
# certbot deploy-hook (ставит infra/lib.sh: install_certbot_hook). Скрипты лежат в
# /usr/local/lib/tabora, а не в каталоге развёртывания, поэтому хук не зависит от deploy.sh.
# сбой запоминается в файле: мониторинг (tabora-health) сообщает о нём, пока хук не пройдёт
mark=/var/lib/tabora/certbot-hook.failed
mkdir -p /var/lib/tabora
failed() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1" > "$mark"; logger -t tabora-certbot -p user.err -- "хук certbot: $1"; exit 1; }
case "${RENEWED_LINEAGE:-}" in
  */__MAIL_HOST__) ;;
  # сертификат веб-версии нужен только nginx
  */app.__DOMAIN__) systemctl reload nginx || failed "nginx не перечитал конфигурацию"; exit 0 ;;
  *) exit 0 ;;
esac
systemctl reload nginx || failed "nginx не перечитал конфигурацию"
python3 /usr/local/lib/tabora/stalwart/upload-cert.py "$RENEWED_LINEAGE" || failed "сертификат не загружен в Stalwart"
rm -f "$mark"
