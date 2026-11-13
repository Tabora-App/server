# tabora-server

The Tabora account server: sign-in, devices, the `name@tabora.app` mailbox and its aliases,
synchronization of browser data between devices, and support tickets. A single static executable
(Rust), PostgreSQL, and the Stalwart mail server reached over JMAP on the same host.

This is the server side of [Tabora](https://github.com/Tabora-App/browser), an ad-free browser
with mail and a wallet built in. The apps that talk to it live in
[browser](https://github.com/Tabora-App/browser) (desktop, Android, web) and
[ios](https://github.com/Tabora-App/ios). The setup of the host itself (nginx, TLS, DNS, the mail
server, backups, monitoring) is in [`infra/`](infra/README.md).

## What the server knows and what it does not

- It never receives the password. The browser derives a login hash from the password (Argon2id
  with 64 MB, then HMAC) and sends that; the database holds only an HMAC of this hash with the
  user's salt and the server secret. The browser derives the vault key separately; it never
  reaches the server.
- Resetting a forgotten password requires a signature made with the recovery key (Ed25519; the
  server has only the public half) and a fresh one-time nonce; after the reset every device is
  signed out.
- The main mailbox password is derived from the server secret and the user ID; it is stored
  nowhere and never given to clients. Each device gets its own app password (IMAP and SMTP),
  which is revoked when the device signs out.
- The address of a deleted alias is never issued again: otherwise the new owner would receive the
  previous owner's mail.
- Two-factor sign-in protection: authenticator app codes (TOTP, RFC 6238) and ten one-time backup
  codes. The secret is stored in the database encrypted with the server key (AES-256-GCM, bound to
  the user); for backup codes only an HMAC is stored. An app code is accepted once.
- The backup address is used to reset a forgotten password with a code sent by e-mail. Such a
  reset proves only access to the backup mailbox, so the second factor stays mandatory for it. The
  server changes only the account password: it does not have the vault key, so the user unlocks
  the vault on the computer themselves. A reset with the recovery key, on the contrary, turns
  two-factor protection off: it is the main fallback way in.
- Server e-mails (codes, notices about sign-in changes) are sent from the `no-reply@<domain>`
  mailbox with ordinary JMAP calls to the local address. The mailbox is created when the first
  e-mail is sent.
- The server cannot read sync data: the browser encrypts every record with a key the server does
  not have. The server sees only the collection and key of a record, its size, the time and order
  of changes, and the fingerprint of the encryption key (16 hex characters).
- Support tickets, on the contrary, are stored in the clear: support staff read the conversation
  and the attachments, and there is no end-to-end encryption here. A ticket is visible only to its
  author and to support staff.
- A ticket from someone without an account (the support site) is known by the e-mail address its
  author gave. Support does not see it, and no letter with the author's words is sent anywhere,
  until that address is confirmed with a link from a letter.

## API

The account contract is defined by the browser:
`src/browser/base/content/tabora/account/Account.sys.mjs` in the browser repository
(Tabora-App/browser), class `HttpBackend`. The server adds:

| Request | Response |
|---|---|
| `POST /v1/account/register`, `/login` | the response additionally contains `mail: { address, login, password, imap, smtp }` — this device's app password (or `null` if the mail server did not respond) |
| `POST /v1/mail/password` (Bearer) | `{ mail }` — a new app password for the device; the previous one stops working |
| `GET /v1/mail/aliases` (Bearer) | `[{ id, address, site, space, by, on, created }]` |
| `POST /v1/mail/aliases { site?, space?, by? }` | a new alias of the form `booking-k3f9@tabora.app` |
| `PATCH /v1/mail/aliases/:id { on?, site?, space? }` | a disabled alias answers the sender with "no such mailbox" |
| `DELETE /v1/mail/aliases/:id` | the alias stops accepting mail for good |
| `GET /v1/health` | `{ ok, mail }` |
| `POST /v1/account/register`, `/login`, `/reset/email/confirm` with `mailAccess: "session"` | mail access by session (web app): no app password is issued, the response contains `mail: { address, session: true }`; the device's previous app password is revoked |
| `GET /v1/mail/jmap/session` (Bearer) | the mailbox description from the mail server (account ID, limits) |
| `POST /v1/mail/jmap { using, methodCalls }` | JMAP calls on behalf of the mailbox owner; only mail capabilities and methods (`Mailbox/*`, `Thread/*`, `Email/*`, `SearchSnippet/get`, `Identity/*`, `EmailSubmission/get\|set`), otherwise `403 mail-forbidden`; body up to 4 MiB, up to 32 calls |
| `GET /v1/mail/jmap/download/:account/:blob/:name?accept=type` | the content of an attachment or a message: `Content-Disposition: attachment`, `nosniff`, no caching |
| `POST /v1/mail/jmap/upload/:account` | upload an attachment or a raw message (up to 52 MiB): `{ accountId, blobId, type, size }` |
| `GET /v1/account/devices` (Bearer) | `[{ id, name, at, current, active }]` — `active`: the device has a live session |
| `POST /v1/account/login { …, scope: "support" }` | a sign-in of the support site: the session reaches only `/v1/support/…` and `/v1/account/logout`, every other request answers `403 session-scope`; no mail access is issued (`mail: null`). An unknown `scope` — `400` |
| `POST /v1/account/devices/:id/revoke { loginHash }` | another device's session is ended: its sessions are deleted, its mail app password is revoked, the device is removed from the list; own device — `400`, unknown device — `404 not-found` |
| `POST /v1/pair/start` (Bearer) | start a sign-in on another device by QR code: `{ id, expiresAt }`; an exchange lives three minutes, an account has at most three pending ones |
| `POST /v1/pair/join { id, public, claim, deviceId, deviceName }` | the new device has scanned the code: its one-time public key and the SHA-256 of the secret with which it will collect the result; joining is possible once, otherwise `404 pair-gone` |
| `GET /v1/pair/:id` (Bearer) | `{ state: new\|joined\|approved\|denied, public?, deviceName?, expiresAt }` — for the device that started the exchange |
| `POST /v1/pair/:id/approve { payload }` (Bearer) | allow the sign-in; `payload` is the account data key encrypted with the shared secret of the two devices (the server cannot read it) |
| `POST /v1/pair/:id/deny` (Bearer) | reject the sign-in or cancel the displayed code |
| `POST /v1/pair/poll { id, secret }` | the new device waits for an answer: `{ state: "joined" }`; after approval — once — `{ state: "approved", userId, email, session, kdf, mail, payload }`; after denial — `403 pair-denied` |
| `POST /v1/account/login { …, totp? }` | with protection enabled and no code — `401 2fa-required`, with a wrong code — `401 bad-2fa`; `totp` is an app code or a backup code |
| `GET /v1/account/security` (Bearer) | `{ mail, twoFactor: { enabled, since, backupCodes }, backupEmail: { address, since }?, backupEmailPending: { address, expiresAt }?, recoveryKey }` |
| `POST /v1/account/2fa/setup { loginHash }` | `{ secret, uri }` — the secret waits 15 minutes for the first code; protection is still off |
| `POST /v1/account/2fa/enable { code }` | `{ backupCodes: [10] }` — shown once |
| `POST /v1/account/2fa/disable { loginHash, code }` | protection is off, backup codes are deleted |
| `POST /v1/account/2fa/codes { loginHash, code }` | `{ backupCodes }` — the previous ones stop working |
| `POST /v1/account/backup-email { loginHash, code?, address }` | a six-digit code is sent to the address; `{ pending: { address, expiresAt } }` |
| `POST /v1/account/backup-email/verify { code }` | `{ address }` — the address is now the backup address |
| `POST /v1/account/backup-email/remove { loginHash, code? }` | the address is removed |
| `POST /v1/account/reset/email { email }` | always `{}`; if the account has a backup address, an eight-digit code is sent to it |
| `POST /v1/account/reset/email/confirm { email, code, newLoginHash, kdf, totp?, deviceId?, deviceName? }` | the password is changed, all sessions are ended; a device that identified itself gets a session right away (`{ userId, session, kdf, mail }`) |
| `POST /v1/account/reset` (recovery key) | the response contains `twoFactorDisabled` |
| `GET /v1/mail/pgp` (Bearer) | `{ rev, fingerprint, publicKey, blob, wrapPassword, wrapRecovery, updatedAt }` — the mail encryption key: the public key, a copy of the private key encrypted by the browser, and the wraps of the data key (Base64; whatever is absent is `null`) |
| `PUT /v1/mail/pgp { rev, fingerprint?, publicKey?, blob?, wrapPassword?, wrapRecovery?, replace?, loginHash? }` | the same after the change; `409 pgp-conflict` — the record has changed or the account already has a different key; `wrapPassword` and `replace` require `loginHash` |
| `GET /.well-known/openpgpkey/hu/<hash>?l=<name>` | the public key of the address in binary form (Web Key Directory), or 404; `…/policy` — an empty policy file |
| `GET /v1/sync?since=<rev>&limit=<n>` (Bearer) | `{ rev, gen, keyId, items: [{ c, id, rev, deleted, blob }], more }` — records newer than `since` in ascending `rev` order; `limit` is 500 by default, at most 1000 |
| `POST /v1/sync { gen, keyId, items: [{ c, id, base, blob?, deleted? }] }` | `{ rev, gen, keyId, saved: [{ c, id, rev }], conflicts: [{ c, id, rev, deleted, blob }] }`; `409 sync-key`, `409 sync-reset` — with the `gen` and `keyId` fields |
| `POST /v1/sync/reset { keyId }` | `{ rev, gen, keyId }` — the records are deleted, the generation is incremented, the key is new |
| `DELETE /v1/sync` | `{ rev, gen, keyId: null }` — sync is turned off, the data is erased |
| `GET /v1/support/tickets?scope=mine\|all&status=open\|answered\|closed` (Bearer) | `{ staff, tickets: [{ id, subject, status, createdAt, updatedAt, messages, unread, author? }] }` — up to 200, most recently changed first; `scope=all` and `author` — staff only |
| `POST /v1/support/tickets { subject, text, meta?, files? }` | the new ticket in the same form as when it is read |
| `GET /v1/support/tickets/:id` | `{ id, subject, status, createdAt, updatedAt, staff, author?, meta?, messages: [{ id, from, text, at, files: [{ id, name, type, size }] }] }`; reading marks the ticket as read |
| `POST /v1/support/tickets/:id/messages { text, files? }` | the whole ticket; a message from the author → `open`, a reply from support → `answered` |
| `POST /v1/support/tickets/:id/status { status: "closed" \| "open" }` | the whole ticket |
| `GET /v1/support/files/:id` | the attachment bytes: the attachment's `Content-Type`, `Content-Disposition: attachment`, `nosniff`, `Cache-Control: private, max-age=3600` |
| `GET /v1/support/unread` | `{ count, staff, queue? }` — the user's own tickets with an unread reply; `queue` (for staff) — everyone's tickets with status `open` |
| `POST /v1/support/guest { email, subject, text, lang? }` (no session) | a ticket from someone without an account: `{ sent: true }`, and a letter with a link goes to `email`. The ticket waits for the link to be opened; an address in the server's own domain — `400 support-invalid` |
| `POST /v1/support/guest/open { key }` | the ticket by the key of its link (`<number>.<secret>`), as its author sees it, plus `guest: true` and `email`. The first opening confirms the address: support now sees the ticket and gets its e-mail. A wrong number or secret — `404 not-found` |
| `POST /v1/support/guest/messages { key, text }` | the author's new message (text only); the whole ticket |
| `POST /v1/support/guest/status { key, status: "closed" \| "open" }` | the whole ticket |
| `POST /v1/support/guest/file { key, id }` | the bytes of an attachment of this ticket (attachments come only from support) |

In the sign-in settings requests, `loginHash` is a repeated password check; `code` is the second
factor and is required when protection is on.

Mail for the web app (`src/webmail.rs`). The browser talks to the mail server itself, with the
device's app password. That does not suit a web page: a mailbox has only a handful of app
passwords (the mail server's limit is five), and a closed tab would keep holding its own until the
session expired. So the web app works with the mailbox through this server, using the session
token: there is no mail password in the browser, signing out or ending the session closes mail
access at once, and only mail methods are available — mailbox settings and app passwords cannot be
reached this way. Requests are forwarded to the mail server on behalf of the mailbox owner (the
main mailbox password, sign-in only from 127.0.0.1); a refused method never reaches the mail
server. The limit is 1500 requests per minute per user. Tests: `tests/webmail.mjs` with the mail
server mock `tests/fake-jmap.mjs`.

Mail keys (`src/pgp.rs`). The private key arrives already encrypted: the browser encrypts it with
a random data key, and encrypts the data key with a key derived from the password (the same heavy
KDF as for the login hash, with a different label) and, separately, with a key derived from the
recovery key. The server cannot read the copy and does not check its content; the blobs are
additionally sealed with the server key, so that a leak of the database alone gives no material
for guessing the password. The public key is checked (it must be an OpenPGP public key packet; the
version 4 key fingerprint is recomputed) and published in the directory. The first key of an
account is created with a session; replacing the key and wrapping with the password require the
login hash. On the main domain the directory is served by nginx (`infra/nginx/tabora.app.conf`);
the browser fetches the keys of Tabora recipients from the same path on the account server.

Sync (`src/sync.rs`). A record is a collection `c` (`^[a-z]{1,16}$`), a key `id`
(`^[A-Za-z0-9_-]{1,64}$`) and a blob `blob` (Base64, from 1 byte to 96 KiB after decoding)
encrypted by the browser. A user has a single change counter `rev`: every saved record gets the
next number, and a device fetches everything newer than the number it has already seen. A record
is saved only if `base` equals its `rev` on the server (0 means the record does not exist yet);
otherwise it goes into `conflicts` together with what the server holds, and the other records of
the request are saved. If a device refers to a record that the server does not have, the record
comes back in `conflicts` as deleted: `rev: 0, deleted: true, blob: null`. `deleted: true` leaves
a tombstone without a blob. Records are processed in order, so a repeated key within one request
is compared against the version that was just saved. `gen` is the data generation: it grows on
reset and on `DELETE`, and a request with an old generation gets `409 sync-reset`. `keyId`
(`^[0-9a-f]{16}$`) is remembered on the first write; a different key gives `409 sync-key`. With
either refusal nothing is saved, and the error body contains, besides `code` and `message`, the
current `gen` and `keyId`. The `rev` counter never decreases: a reset adds one to it, `DELETE`
does not change it.

A read returns at most `limit` records and at most 8 MiB of blobs per response (the first record
is always included); if more remain, `more: true`, and the client repeats the request with `since`
equal to the `rev` of the last record received. Write limits: request body up to 4 MiB, up to 200
records per request, at most 30 000 records per user including tombstones, and 64 MiB of blobs
(tombstones do not count towards the size) — `413 sync-limit`, the whole request is rejected; a
request that does not add to the space used (an update with a smaller blob, a deletion) is not
blocked by the limit. Invalid shape — `400 sync-invalid`.

Support tickets (`src/support.rs`). `subject` is 3–140 characters, `text` is 1–8000; `meta` is a
JSON object up to 2 KiB (browser version, operating system: sent by the client, seen only by
support); `files` is up to four attachments `{ name, type, data }`: `type` is `image/png`,
`image/jpeg`, `image/webp` or `text/plain`, `data` is Base64, from 1 byte to 2 MiB; `/`, `\` and
control characters are removed from the name, and it is truncated to 120 characters. The
attachment content is not checked against the declared type: attachments are served only as files
to save, with type sniffing forbidden. A request body with attachments can be up to 12 MiB (larger
— `400 support-invalid`).

Statuses: `open` — waiting for support, `answered` — support has replied, `closed`. Staff are the
accounts whose addresses are listed in `TABORA_SUPPORT_STAFF`; in someone else's ticket a staff
member acts as support (the response has `staff: true`, `author` and `meta` are visible, their
messages go as `from: "staff"`), in their own ticket — as an ordinary user (`staff: false`). To an
outsider, someone else's ticket and its attachments answer `404 not-found`. `unread` means there
are messages from the other side newer than the read mark; the mark is set by reading the ticket
and by posting one's own message. E-mails: about a new ticket and about the user's replies — to
`TABORA_SUPPORT_NOTIFY`; about a reply from support — to the author, at the address of their
account. E-mails are sent in the background, and a mail failure cancels nothing.

Tickets without an account. The support site (`TABORA_SUPPORT_URL`) lets a person who cannot sign
in, or has no account yet, leave an e-mail address. `POST /v1/support/guest` stores the ticket and
sends a letter with a link `<site>/#t=<number>.<secret>` to that address — in the language given in
`lang` (`ru`, `en`, `uk`, `es`), with a fixed text and nothing of what the author wrote, so the form
cannot be used to send someone a text of the sender's choosing. Until the link is opened the ticket
does not exist for support: it is not in the queue, staff get `404` for it and no e-mail about it.
Opening the link confirms the address. The secret is 24 random bytes; it is the only key to the
ticket, the page keeps it after `#` (a browser does not send that part to a server), and a wrong
number and a wrong secret are answered alike. Support's replies go to the same address with the same
link. In staff responses such a ticket has `guest: true` and the address as `author`. A ticket whose
link nobody opened in two days is deleted by the hourly cleanup.

Support settings: `TABORA_SUPPORT_URL` — the address of the support site that letters link to
(`https://support.<domain>` by default). `TABORA_SUPPORT_STAFF` — comma-separated addresses of staff accounts
(case-insensitive; empty — no staff), `TABORA_SUPPORT_NOTIFY` — the address for e-mails about new
tickets and user replies (empty — no such e-mails are sent). The staff list must contain only
addresses of accounts that already exist: whoever owns the account with such an address becomes
staff, and a free name from the list could be taken by anyone.

### Sessions

A session does not expire with time: once signed in, a person stays in the account on that device
until they sign out themselves. Neither a new session (`expiresAt: null` in sign-in responses) nor
the ones issued earlier have a lifetime; the cleanup of expired data does not touch sessions. Only
the person's own actions end a session:

- signing out on this device (`POST /v1/account/logout`);
- ending a device's session from the device list (`…/devices/:id/revoke`);
- changing the password — the other devices are signed out, this one stays signed in;
- resetting the password — all devices are signed out, the device that did the reset gets a new
  session.

After that, requests with the old token get `401` with the code `session-expired` (the code name
is historical). Tests: `tests/sessions.mjs` — a session "400 days old", sign-out and revocation do
not touch other devices, a server restart does not lose sessions.

Sessions are stored in the database: losing the database without a backup signs everyone out.

A session may be made for one purpose (`sessions.scope`). An ordinary session has an empty scope
and reaches everything. A sign-in with `scope: "support"` — the support site — gets a session that
is accepted only by the support requests and by sign-out; the mail, the keys, the devices, the
sign-in settings and sync answer it `403 session-scope`. So the token the support site keeps in a
browser opens tickets and nothing else. Such a sign-in passes the same password and second-step
checks, appears in the list of devices and is ended from there like any other. Tests:
`tests/contract.mjs`.

### Language of responses and e-mails

Messages in the code are written in Russian and translated on output (`src/i18n.rs`; dictionaries
`i18n/<lang>.json` for English, Ukrainian and Spanish; Russian is the source language):

- an error response is in the language of the request: the first language in `Accept-Language`.
  No header — Russian (this is how earlier app versions were answered); a language outside the
  four — English;
- an e-mail is in the language of the account it is addressed to: the account's own mailbox, the
  backup address, or an address awaiting confirmation. The account language (`users.lang`) is
  updated by the app's requests.

A finished text with substituted values is found by pattern: `tools/i18n.mjs` records `format!`
strings as `…{0}…{1}…`. For a new string in the code: `node tools/i18n.mjs check` reports how many
strings each dictionary is missing, and with `--todo` writes the missing strings to
`.build/i18n-todo.json`; `node tools/i18n.mjs merge <lang> <file.json>` accepts ready
translations; `node tools/i18n.mjs prune` drops strings that no longer occur in the code;
`check --strict` fails if anything is untranslated. Tests: `tests/i18n.mjs` and the unit tests in
`src/i18n.rs`.

Errors are `{ code, message }`; `message` is shown to the user as is (already in their language).
Codes: `bad-credentials`, `session-expired`, `rate-limited`, `taken`, `bad-nonce`, `bad-proof`,
`no-recovery`, `mail-unavailable`, `signup-closed`, `signup-paused`, `alias-limit`, `old-client`,
`2fa-required`, `bad-2fa`, `2fa-on`, `2fa-off`, `2fa-setup-expired`, `bad-address`, `same-address`,
`bad-code`, `no-code`, `sync-invalid`, `sync-limit`, `sync-key`, `sync-reset`, `mail-forbidden`, `support-invalid`,
`support-limit`, `session-scope`, `not-found`.

## Limits

Sign-in is protected against password guessing by three limits at once:

- the pair "account address + IP": five wrong passwords in a row — a one-minute pause, then
  doubling up to an hour;
- IP: twenty failed sign-ins per hour into any accounts — sign-in from this address is closed
  until the end of the hour;
- the account as a whole, for devices that have not signed in to it before: the failure count is
  shared across all addresses and stored in the database (`login_guard`), so neither changing
  addresses nor restarting the server gives new attempts. Four errors are free, then a pause of 1,
  2, 4… minutes, up to a day; the count is reset after a day of silence and after a successful
  sign-in. While sign-in from new devices is closed, the password is not checked at all, and the
  response to a correct and to a wrong password is the same. Devices from which the owner has
  already signed in are not subject to this limit: other people's attempts cannot lock the owner
  out. An owner with two-factor protection can sign in from a new device as well — with the
  correct password together with a correct code (a wrong code is counted as usual). A non-existent
  address behaves the same as an existing one. The owner gets an e-mail about password guessing
  (at most once a day) — to the account mailbox and to the backup address.

The owner also gets an e-mail about a sign-in from a device that was not seen before (to the
mailbox and to the backup address; at most six such e-mails a day per account). The repeated
password check in the settings (`loginHash`) counts failures per account, not per address: a
stolen session does not let anyone brute-force the password. Tests: `tests/guard.mjs`.
Registration: three accounts a day from one IP and an overall daily limit
(`TABORA_SIGNUP_DAILY_CAP`, 50 by default); `TABORA_SIGNUP=closed` closes it entirely. The
counters live in process memory.

Sign-in by QR code (`src/pair.rs`): the server issues a session to the new device only after
approval from a device where the owner is already signed in, and only to the one that scanned the
code first and knows its secret. The password and the second factor are not asked for:
confirmation on the owner's own device replaces them. Exchanges live in process memory for three
minutes; a new code — at most thirty per hour per account, joining — thirty per minute per
address, waiting for an answer — one hundred and twenty per minute per address. The owner gets the
same e-mail as for a sign-in from a new device. If the server substitutes the new device's key,
the verification code shown on both screens reveals it; tests — `tools/web/test/pair.test.mjs` in
the browser repository.

Second factor: five wrong codes in a row — a 15-minute pause, then doubling up to a day; the count
is per account, not per client address, and is stored in the database (six digits are cheap to
enumerate, and a server restart must not reset the pause). Codes from e-mails: five attempts per
code, valid for 30 minutes, a new code replaces the previous one. E-mails: reset code — at most
three a day per account and five requests an hour per address; backup address confirmation — three
an hour and eight a day per account; all e-mails from the server — `TABORA_MAIL_DAILY_CAP` a day
(500 by default).

Sync: 600 reads and 600 writes per hour per user, reset — at most six per hour, `DELETE` — thirty.
Tickets: at most five unclosed tickets per user and ten new ones a day, at most 200 messages in a
ticket and 60 messages an hour from a user (`429 support-limit`). E-mails to support are limited
separately — twelve an hour caused by one user, and half of the server's daily e-mail limit for
everyone: tickets cannot use up the reserve from which password reset codes are sent. A message is
saved even when the e-mail about it was not sent.

Tickets without an account: three new ones an hour and six a day from one network address, 240
calls an hour from it to all the guest requests; for one e-mail address — at most two tickets
waiting for confirmation and three new ones a day, from whatever network addresses they come
(every one is a letter to that address); letters with links — a quarter of the server's daily
e-mail limit; 20 messages an hour in one ticket (`429 support-limit`).

## Build, test, deploy

```sh
cargo test                                   # unit tests
# contract test against a running instance without mail and with an empty database:
TABORA_DOMAIN=tabora.app TABORA_LISTEN=127.0.0.1:7711 TABORA_DB=postgres://… \
  APP_SIGNING_KEY=$(openssl rand -hex 32) TABORA_SIGNUP_PER_IP=6 TABORA_MAIL_OUTBOX=/tmp/tabora-outbox \
  TABORA_SUPPORT_STAFF=kot.test@tabora.app TABORA_SUPPORT_NOTIFY=postmaster@tabora.app cargo run &
node tests/contract.mjs http://127.0.0.1:7711 tabora.app /tmp/tabora-outbox kot.test@tabora.app postmaster@tabora.app
infra/deploy.sh server                       # build for Linux (musl) on this machine and install
infra/deploy.sh nginx                        # nginx configuration (key directory on the main domain)
```

The contract test registers the support staff account itself: its address is the fourth argument
(`kot.test@<domain>` by default), and the same address must be listed in `TABORA_SUPPORT_STAFF` of
the running server; the fifth argument (`postmaster@<domain>` by default) is the address from
`TABORA_SUPPORT_NOTIFY`, and e-mails to support are checked against it. The sync limits test
uploads about 80 MiB to the server.

Building for the server requires the target `rustup target add x86_64-unknown-linux-musl`; all
dependencies are pure Rust, and the linker comes from the Rust distribution
(`.cargo/config.toml`). Settings are environment variables, listed at the top of `src/main.rs`; on
the server they are in `/etc/tabora/server.env`.
