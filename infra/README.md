# Tabora host

One Hetzner server (`ssh tabora`): mail (Stalwart), the tabora.app website (nginx; static files
deployed from the Tabora-App/site repository), and the account and sync API (`tabora-server`,
PostgreSQL).

## Network

- The website `tabora.app`/`www` and `api.tabora.app` are reachable only through Cloudflare
  Tunnel: nginx listens on `127.0.0.1:8081` without TLS (the tunnel encrypts) and works even
  before certificates are issued.
- Only port 22 and the mail host `mx.tabora.app` are open to the outside: 25, 465, 587, 993 and
  443 (JMAP, autoconfiguration, MTA-STS). Ports 80 and 4190 are closed: certificates are issued
  via DNS-01, and Sieve is available through JMAP.
- The web app `app.tabora.app` (`nginx/app.conf`) is served directly on port 443 of the same
  server, without the tunnel: otherwise both the scripts that decrypt data in the browser and the
  plain text of e-mails would pass through Cloudflare. The app (static files in
  `/var/www/app.tabora.app`, built by `tools/web/build.mjs` in the browser repository) and the
  account server (`/v1/…`) answer on the same name. The security headers are `nginx/app-*.inc`;
  they must match `tools/web/headers.mjs` in the browser repository, and the test
  `tools/web/test/headers.test.mjs` there compares the two. Bringing it into service:
  `deploy.sh tls` (certificate for the name), `deploy.sh dns` (CNAME `app` → `mx`), then
  `tools/deploy.sh web` in the Tabora-App/browser repository.
- The support site `support.tabora.app` (`nginx/support.conf`) is served the same way: directly on
  port 443, with its own Let's Encrypt certificate. Static files are in
  `/var/www/support.tabora.app` (built by `tools/web/build-support.mjs` in the browser repository);
  of the account server only the sign-in and the support requests are reachable through this name
  (`/v1/account/prelogin|login|logout`, `/v1/support/…`), everything else answers `404`. Bringing
  it into service: `deploy.sh tls` (certificate), `deploy.sh nginx`, `deploy.sh dns` (CNAME
  `support` → the mail host, `dns/extra.zone`), `deploy.sh server` (the account server must know
  the support sign-in), then `tools/deploy.sh support` from the browser repository.
- nginx serves nothing for the bare IP and for foreign names (443 — the TLS handshake is refused,
  8081 — `444`).
- Stalwart HTTP/JMAP listens only on `127.0.0.1:8080`; it takes the client address from
  `X-Forwarded-For`, which nginx fills with `$remote_addr`.

| What | Where |
|---|---|
| Deployment from a laptop | `infra/deploy.sh setup` (idempotent, can be run at any time), `server`, `nginx` (nginx configuration only), `tunnel`, `tls`, `dns`. The website, the web app and the installer downloads are deployed from their own repositories, which copy files to the same host: Tabora-App/site — `./deploy.sh`; Tabora-App/browser — `tools/deploy.sh web` and `tools/deploy.sh downloads` |
| Mail key directory (WKD) | `https://tabora.app/.well-known/openpgpkey/…` → `tabora-server`; there must be no `openpgpkey` record in DNS: with it, programs look for the key on the subdomain and do not fall back to the main domain |
| Scripts on the server | `/usr/local/lib/tabora` (a copy of `infra/`; the certbot hook and the timers run from it) |
| Stalwart | `/opt/stalwart`: `bin/` (root, sha256 is verified), `etc/config.json` (only the RocksDB storage), `data/`; service `stalwart`, log `journalctl -u stalwart` |
| Stalwart settings | JMAP objects `x:*` via `infra/stalwart/configure.py` |
| nginx | `infra/nginx/*`; the mail host is enabled once there is a certificate |
| tabora-server | `/opt/tabora/bin/tabora-server` (root), data `/opt/tabora/data`, service `tabora-server` |
| PostgreSQL | database `tabora`, role `tabora`, connection string in `server.env` |
| Website | `/var/www/tabora.app` (owned by root, nginx only reads it), deployed from the Tabora-App/site repository with `./deploy.sh`. The per-language pages `/ru/`, `/en/`, `/uk/`, `/es/` are built there by `build.sh` from the template `pages/index.html` and the dictionaries in `i18n/`; nginx redirects `/` to the language from `Accept-Language` |
| Backups | `infra/backup/*`, timers `tabora-backup`, `tabora-backup-check`; state `/var/lib/tabora/backup.json` |
| Monitoring | `infra/monitor/health.py`, timer `tabora-health` (5 minutes), `/run/tabora/health.json`, motd |
| Network | `/etc/netplan/50-tabora.yaml` ← `infra/network/netplan.py`, service `tabora-network` |

## Secrets (all in `/etc/tabora`, directory `root:tabora 750`)

| File | Permissions | What |
|---|---|---|
| `server.env` | `root:tabora 640` | for tabora-server: database, signing key, `STALWART_API_KEY` (the API key of the `STALWART_SERVICE_USER` account) |
| `stalwart-admin.env` | `root 600` | the Stalwart administrator (`STALWART_ADMIN_USER`/`PASS`), sign-in only from 127.0.0.1 |
| `cloudflare.env` | `root 600` | `CF_ACCOUNT_ID`, `CF_ZONE_ID`, and, until the tunnel is set up, `CF_API_TOKEN` |
| `certbot-cloudflare.ini` | `root 600` | the certbot token: only Zone › DNS › Edit and only the tabora.app zone (not "All zones", no account permissions); the file permissions are set by `setup.sh` and `enable-tls.sh` on every run |
| `backup.env` | `root 600` | `RESTIC_REPOSITORY`, `RESTIC_PASSWORD` (and the S3 keys). **Keep the password outside the server as well** |
| `backup_ed25519(.pub)` | `root 600` / `644` | the SSH key for the sftp backup storage (not in `~/.ssh`) |
| `alert.env` | `root 600` | `ALERT_URL`, `ALERT_FORMAT`, `ALERT_TOKEN` — monitoring alerts |
| `postmaster.env` | `root 600` | the login and password of the `postmaster@` mailbox (aliases `abuse@`, `hostmaster@`, `security@`, `webmaster@`, `hello@`) |
| `/etc/cloudflared/<id>.json` | `root 600` | the tunnel credentials (passed to the service through `LoadCredential`) |

Files are created with their permissions before anything is written to them; secrets are not
passed in command arguments (`ps` does not see them).

## Bringing the host into service

Done on 10 November 2026: the domain `tabora.app` is registered at Namesilo (auto-renewal, owner
data hidden), the zone is in Cloudflare (name servers `emerie` and `norm`), DNSSEC is enabled (the
DS record is passed to the registrar), the mail host certificate is issued, the mail records are
published, and mail flows in both directions. The order, in case it has to be repeated:

1. `infra/deploy.sh setup`.
2. Buy the domain, add the zone to Cloudflare, and set the name servers issued by Cloudflare at
   the registrar. After the zone is activated, enable DNSSEC and pass the DS record from
   Cloudflare to the registrar.
3. Create two tokens in Cloudflare (My Profile › API Tokens › Create Custom Token, or
   `POST /user/tokens`):
   - **tabora-setup** — Account › Cloudflare Tunnel › Edit; Zone › DNS › Edit, the tabora.app zone
     only. Temporary (valid for one day): needed by `setup-tunnel.sh` and by the first `dns.sh`.
   - **tabora-certbot** — Zone › DNS › Edit, the tabora.app zone only. Permanent: certificate
     renewal and later `dns.sh` runs.

   Both tokens have the condition "only from the server's addresses" (Client IP Address Filtering:
   the IPv4 address and the IPv6 /64): they do not work from another machine. After a move to a
   new address, issue the certbot token again.
4. On the server, put the values into the files that already exist (with an editor or through
   stdin, not with `echo` — the token would end up in the shell history):
   `/etc/tabora/cloudflare.env` (`CF_ACCOUNT_ID`, `CF_ZONE_ID`, `CF_API_TOKEN` = tabora-setup),
   `/etc/tabora/certbot-cloudflare.ini` (tabora-certbot).
5. `infra/deploy.sh tunnel` — the tunnel, the CNAME records of the website and the API, the
   `cloudflared` service. On success the script itself removes `CF_API_TOKEN` from
   `cloudflare.env`.
6. `infra/deploy.sh tls` — the certificate for `mx`, `autoconfig`, `autodiscover`, `mta-sts`
   (DNS-01), nginx on 443, the certificate in Stalwart, the renewal hook. No certificate is issued
   for the website and API names (they do not need one).
7. `infra/deploy.sh dns` — A/AAAA for `mx`, MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, SRV,
   autoconfiguration.
8. The website, the web app and the installer are deployed from their own repositories, which copy
   files to this host: `./deploy.sh` in Tabora-App/site (the website); `tools/deploy.sh web` and
   `tools/deploy.sh downloads` in Tabora-App/browser (the web app, and the installer from
   `.build/signed`).
9. PTR in Hetzner Console: the server's IPv4 and IPv6 → `mx.tabora.app`. IPv6 has no default
   record at all, and without one Gmail and others reject mail from this address (outgoing mail
   tries IPv4 first).
10. Revoke the tabora-setup token in Cloudflare if it has no expiry: it is already removed from
    the server (step 5), the tunnel does not need it, and `dns.sh` works with the certbot token.
11. After a week without TLS-RPT reports, switch `infra/mta-sts/mta-sts.txt` to `mode: enforce`.

Zone settings in Cloudflare: Always Use HTTPS, minimum TLS 1.2, SSL mode "Full (strict)".
Delivery check: an e-mail from `postmaster@` to `check-auth@verifier.port25.com` returns an
SPF/DKIM report (old verifiers do not understand the Ed25519 signature, so e-mails carry two
signatures — the second one is RSA).

## Stalwart: accounts and access

- **Administrator** — an account with a random name and the Admin role, a 48-character password,
  and `allowedIps` set to 127.0.0.1 and ::1 only: it cannot sign in from outside (IMAP, SMTP, JMAP
  through nginx). In addition, nginx answers 403 to Basic auth with any login that has more than
  user privileges (`admin`, `recovery-*`, the administrator, the service account; `configure.py`
  writes the list to `/etc/nginx/tabora-privileged-logins.map`).
  The forward `ssh -L 8080:127.0.0.1:8080 tabora` is allowed (sshd: `AllowTcpForwarding local`,
  `PermitOpen 127.0.0.1:8080`; forwarding to other ports is forbidden), and through it the
  administrator API works from the laptop: `curl -u '<login>:<password>' http://127.0.0.1:8080/jmap/…`
  (login and password from `stalwart-admin.env`). **Sign-in to the `/admin` web panel does not
  work through the SSH tunnel:** the page opens, but its sign-in is OAuth, and Stalwart issues the
  OAuth client (`/admin/oauth-client.json`) only for the public name (`STALWART_PUBLIC_URL` =
  `https://mx.tabora.app`; on `127.0.0.1:8080` it is 404) and redirects to
  `https://mx.tabora.app/login`, which nginx deliberately does not publish. The public URL must
  not be changed for the sake of the panel (autoconfiguration and user OAuth depend on it). All
  administration is done with the `infra/stalwart/*.py` scripts; if the panel is ever needed,
  decide that separately (a separate name behind Cloudflare Tunnel with Access, or a temporary
  `STALWART_RECOVERY_MODE` with the firewall closed).
- **tabora-server** — an account with the User role plus `sysAccount{Get,Query,Create,Update,Destroy}`,
  `sysDomain{Get,Query}`: creating and deleting users and their aliases. Sign-in only with an API
  key (the account has no password); the key works only from 127.0.0.1/::1. Stalwart does not let
  the account grant permissions it does not have, or touch accounts with greater permissions (the
  administrator). Verified on the server with temporary accounts: the key cannot create an account
  with the Admin role, elevate a user or itself, modify, rename or delete the administrator,
  change the administrator's password or remove `allowedIps` (the response is
  `forbidden: You are not authorized to grant permissions…`); secrets are hidden when accounts are
  read. For an ordinary user the key can change the password and grant permissions from its own
  set — that is its job. The service account must not be given `sysRole*` or
  `sysAuthenticationUpdate`: through the default roles this is a path to administrator rights. On
  top of that, every 5 minutes monitoring compares the privileged accounts with the snapshot from
  the last `deploy.sh setup` (`/var/lib/tabora/privileged.json`) and updates the nginx map.
  The domain cannot be restricted in the OSS version (tenants are an Enterprise feature), but
  there is only one domain. New key: remove `STALWART_API_KEY` from `server.env` and run
  `deploy.sh setup` (the old key is revoked in the process).
- **Emergency administrator** (`STALWART_RECOVERY_ADMIN`) bypasses `allowedIps`, so it is not in
  `stalwart.env`. It appears only while the permanent administrator is being created (`setup.sh`
  does this itself if `stalwart-admin.env` is missing or the password does not work) and is
  removed right after.

- **postmaster@** — an ordinary mailbox (User role) with the aliases `abuse`, `hostmaster`,
  `security`, `webmaster`, `hello` (the contact address on the website);
  the password is in `postmaster.env`; read the mailbox over IMAP/JMAP once TLS is enabled.
- **Mail encryption at rest** (`encryptionAtRest`) is `Disabled` for new accounts (verified). The
  global switch `x:Encryption.atRestEnable` is on, but Stalwart has no "enable for everyone"
  setting: it needs the user's public key. **Requirement for tabora-server:** at registration,
  upload the user's public key (`x:PublicKey`) and set on the account
  `encryptionAtRest: {"@type":"Enabled","publicKey":<id>, "encryptOnAppend":true}`. Until then,
  mail on disk and in Stalwart backups is in the clear (the restic repository is encrypted).

## Backups

`tabora-backup.timer` runs `infra/backup/backup.sh` daily at about 03:15: restic (AES-256
encryption, password in `backup.env`) saves

- the Stalwart data. RocksDB in Stalwart 1.1 has no "live" snapshot (`--export` and any read of
  the database require the service to be stopped), so the service is stopped for 1–2 seconds:
  immutable files are taken as hard links, the rest are copied, and sha256 sums are computed. The
  whole Stalwart state is `/opt/stalwart/data` and `/opt/stalwart/etc`;
- a `pg_dump` of the `tabora` database and the roles (`pg_dumpall --globals-only`);
- `/etc/tabora`, `/opt/stalwart/etc`, `/etc/letsencrypt`, `/etc/cloudflared`,
  `/etc/nginx/sites-available`.

Retention: 7 daily, 4 weekly, 6 monthly. On Sundays `tabora-backup-check.timer` runs
`restic check`, reading 10 % of the data. Monitoring reports failures.

**Right now the backups are local only** (`/var/backups/tabora-restic`, the same disk): they
protect against a mistake or database corruption, but not against the loss of the server; the log
and motd carry a reminder about this. To connect external storage:

1. Save `RESTIC_PASSWORD` from `/etc/tabora/backup.env` in a password manager (without it the
   backups cannot be opened; the copy of this file inside the repository is useless).
2. Set `RESTIC_REPOSITORY` in `backup.env`:
   - Hetzner Storage Box: `sftp://uXXXXXX@uXXXXXX.your-storagebox.de:23//home/tabora`; enable SSH
     in the Storage Box and add the key `/etc/tabora/backup_ed25519.pub`;
   - S3 (Hetzner Object Storage, B2 and others): `s3:https://<endpoint>/<bucket>/tabora` plus
     `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
3. `ssh tabora systemctl start tabora-backup` and
   `ssh tabora /usr/local/lib/tabora/backup/restore.sh verify`. The old local directory can be
   deleted after that.

Checking a backup without changing the server: `restore.sh verify [snapshot]` — extraction, sha256
comparison, a trial start of Stalwart on the copy in an isolated network, `pg_restore` into a
temporary database. `restore.sh list`, `restore.sh extract <directory>`.

### Restoring to a new server

1. A new Hetzner server (Ubuntu 26.04) with the owner's key; fix the address of `tabora` in
   `~/.ssh/config`.
2. `infra/deploy.sh setup` — installs everything, including restic (it creates new secrets; they
   will be replaced).
3. On the server, put the previous `RESTIC_REPOSITORY` and `RESTIC_PASSWORD` into
   `/etc/tabora/backup.env` (and the S3 keys; for a Storage Box, add the new
   `/etc/tabora/backup_ed25519.pub` to it).
4. `ssh tabora /usr/local/lib/tabora/backup/restore.sh list`, then
   `ssh tabora /usr/local/lib/tabora/backup/restore.sh apply latest --yes` — secrets and settings,
   the Stalwart data, the database. The previous state is not deleted but renamed to
   `*.before-restore-<time>`.
5. `infra/deploy.sh setup` once more (permissions, nginx, the tunnel service from
   `/etc/cloudflared`, the certbot hook).
6. `infra/deploy.sh dns` (A/AAAA of `mx` to the new address), PTR in Hetzner Console; the website
   and the API go through the tunnel and need no address. Check: `health.py show`, sign-in to
   mail.

`apply` has not been run on the production server (it replaces data); its steps are the same
functions that `verify` checks.

### Hetzner snapshot and Rescue

A server created from a snapshot on another machine gets its network by itself: netplan is not
bound to a MAC address — DHCP (IPv4) is enabled on any `e*` interface, and sign-in with the
owner's key is preserved in the image. The static IPv6 address of the new machine is added at boot
by `tabora-network.service` from the Hetzner metadata. After such a restore:
`infra/deploy.sh setup`, then DNS and PTR to the new address. A network change is applied with a
connectivity check and an automatic rollback after 3 minutes; the previous files are in
`/var/backups/tabora/netplan`.

If sign-in still does not work (the root password is locked, so the console will not help):
Hetzner Console › server › Rescue › Enable rescue (linux64, your key) › Power cycle;
`ssh root@<address>`; `mount /dev/sda1 /mnt`; fix `/mnt/etc/netplan/50-tabora.yaml` (minimum:
`ethernets: {z-any: {match: {name: "e*"}, dhcp4: true}}`), `/mnt/root/.ssh/authorized_keys`, in
case of a ban — `rm /mnt/var/lib/fail2ban/fail2ban.sqlite3`; look at `/mnt/var/log`;
`umount /mnt`, disable Rescue, reboot.

## Monitoring and alerts

`tabora-health.timer` every 5 minutes: services and ports (stalwart, nginx, postgresql, fail2ban,
ufw; cloudflared and tabora-server once they are installed), disk space and inodes, certificate
expiry (< 20 days means renewal is not working), backup freshness (36 h) and `restic check`,
failed units, the clock, failures of certbot and of its hook, changes to the privileged Stalwart
accounts, `security.ip-unauthorized` events (a correct administrator password or API key was
presented from somewhere other than 127.0.0.1 — a sign of a leak; after changing the secret, run
`health.py ack`).

Where to look: at SSH login (motd), `ssh tabora /usr/local/lib/tabora/monitor/health.py show -a`,
`journalctl -u tabora-health`. Alerts are sent out if `ALERT_URL` is set in
`/etc/tabora/alert.env`:

- ntfy: install the ntfy app, subscribe to a topic with a long random name, and set
  `ALERT_URL=https://ntfy.sh/<name>` (`ALERT_FORMAT=ntfy`). The topic name is a secret: whoever
  knows it can read the alerts.
- a Slack/Discord/Mattermost webhook: `ALERT_URL=<url>`, `ALERT_FORMAT=json`; `ALERT_TOKEN` — if a
  Bearer token is needed.
- test: `ssh tabora /usr/local/lib/tabora/monitor/health.py test`.

An alert is sent when a problem appears, when it goes away, and once a day while it remains; the
text contains only the server name and the check results. If the whole server is unreachable, it
cannot report that from the inside — this needs an external ping (for example, a check of
`https://tabora.app` by any uptime service).

## Logs, bans, updates

- Stalwart writes events to journald (`journalctl -u stalwart`); failed sign-ins are
  `auth.failed`.
- fail2ban (`fail2ban-client status`): `sshd` (10 errors — 10 minutes; sign-in by key only),
  `stalwart` (SMTP AUTH and IMAP, from the Stalwart log; the address is taken only outside quotes,
  so a foreign address cannot be injected through the account name), `tabora-jmap` (401/403 on
  `/jmap`, only for requests with an Authorization header — log `/var/log/nginx/mx.access.log`,
  format `tabora_mx` with the flag `auth=0|1`, without the header itself or the name),
  `nginx-botsearch`, `recidive` (a week, but only the mail ports and 443). Port 22 is closed only
  by `sshd` and only briefly; HTTP errors are counted by one jail and mail errors by another, so a
  series of errors gives one ban. `ignoreip` contains only loopback. To lift a ban: Hetzner
  Console (or Rescue) or another address, then `fail2ban-client unban <address>`.
- Stalwart's built-in auto-ban: 100 failed sign-ins per day from an address — a block
  (`x:BlockedIp`) for a day (`authBanPeriod`; also a day for recipient enumeration and for "hung"
  connections, 7 days for scanning — the default was forever); 127.0.0.1 and ::1 are never
  blocked.
- Ubuntu and `cloudflared` are updated through unattended-upgrades, services are restarted by
  needrestart, and a reboot, when needed, happens at 04:30.
- Stalwart does not update itself: the version and the sha256 of the archive are pinned in
  `setup.sh`. Once a week `tabora-stalwart-release.timer` checks for a new release and writes a
  reminder to the log and to the SSH login message. To update: compare the archive hash with the
  release's `.sigstore.json` (`sigstore verify github --cert-identity
  https://github.com/stalwartlabs/stalwart/.github/workflows/ci.yml@refs/tags/<version> …`),
  change `STALWART_VERSION` and `STALWART_SHA256`, and run `deploy.sh setup`.
- cloud-init is disabled after the initial setup (`/etc/cloud/cloud-init.disabled`): on reboot it
  races with the renaming of the network interface and fails. The network is configured in
  `/etc/netplan/50-tabora.yaml` (see "Hetzner snapshot and Rescue"); the interfaces are named
  `enp1s0` (public) and `enp7s0`. A disk enlarged in Hetzner has to be extended by hand:
  `growpart /dev/sda 1 && resize2fs /dev/sda1`.
- The stalwart, tabora-server and cloudflared services are confined by systemd
  (`systemd-analyze security <service>`: about 1.5); `/proc` is mounted with `hidepid=invisible`
  (logind and polkit are in the `proc` group).
