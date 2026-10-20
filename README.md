# Minimal Chat

A minimal real-time chat app: FastAPI + WebSocket + SQLite, vanilla JS frontend.
Public chat room plus private direct messages.

## Run

```bash
python run.py
```

Open http://127.0.0.1:8000 — register, log in, chat.
`run.py` installs dependencies, creates `chat.db` (+ tables) and the
encryption key file automatically. No Node, Docker, env vars, or manual setup.

Optional: `PORT=8001 python run.py` to change the port.

Dependencies: `fastapi`, `uvicorn`, `cryptography` (see `requirements.txt`).

## Settings (.env)

Copy `.env.example` to `.env` and adjust. Everything is optional;
priority is defaults < `.env` file < real environment variables.

| Variable | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Listen address |
| `PIP_INDEX_URL` | empty (PyPI) | Package index for the one-off dependency install in `run.py`. The running app never uses it |
| `PORT` | `8001` | Listen port |
| `REGISTRATION_ENABLED` | `true` | `false` closes registration (existing users unaffected; register page redirects to login, API returns 403) |
| `CHAT_DATA_DIR` | project root | Directory for `chat.db` + `.chat_secret` |
| `DB_BUSY_TIMEOUT_MS` | `10000` | SQLite lock wait before failing (writes retry) |
| `SSL_CERTFILE` / `SSL_KEYFILE` | empty (plain HTTP) | TLS cert+key for HTTPS/WSS. Local self-signed: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 825 -nodes -subj "/CN=127.0.0.1"` |
| `WS_MAX_SIZE_BYTES` | `65536` | Max WebSocket frame size (DoS guard) |
| `MAX_SOCKETS_PER_USER` | `5` | Concurrent WebSockets one user may hold. Bounds the connection flood the message rate limit does not |
| `MAX_SOCKETS_PER_IP` | `20` | Concurrent WebSockets one client IP may hold |
| `TRUSTED_PROXY_CIDRS` | empty (off) | Proxies whose `X-Forwarded-For` is believed. Required behind a reverse proxy, or the per-IP caps become site-wide |
| `SESSION_IDLE_DAYS` | `14` | Idle session lifetime; a session unused this long is dead even inside the absolute window |
| `SESSION_LIFETIME_DAYS` | `30` | Absolute session lifetime |
| `RATE_LOGIN_PER_MIN` / `RATE_REGISTER_PER_MIN` / `RATE_MSG_PER_MIN` | `20` / `30` / `120` | Sliding-window rate limits (per IP / per IP / per user) |
| `ADMIN_LOCKOUT_STEP` / `_GRACE` / `_MAX` | `1` / `5` / `120` | Backoff for failed admin logins: wait `STEP × 2^max(0, failures − GRACE)` seconds, capped at `MAX`. First 5 mistakes are free. `STEP=0` disables it |
| `ADMIN_LOCKOUT_HALF_LIFE` | `300` | Seconds for a failed admin attempt to lose half its weight |
| `ADMIN_PATH` | `/admin` | Address of the admin panel (letters, numbers, `_`, `-`) |
| `ADMIN_PASSWORD` | empty (disabled) | Admin panel password. Empty = panel routes are 404. Use a long random value |
| `ADMIN_PASSWORD_HASH` | empty | PBKDF2 hash of the admin password, preferred over the plaintext above. Wins when both are set |
| `ENC_ENABLED` | `true` | Application-layer encrypted transport (TLS alternative) |
| `ENC_SHOW_FINGERPRINT` | `true` | Show/pin the server key fingerprint (the anti-MITM check) |
| `WORKERS` | `1` | Worker processes. `>1` shares one SQLite database in WAL mode, see below |
| `ALLOW_SPLIT_ROOMS` | `false` | Accept that the public room is split per worker |
| `CHAT_ENCRYPTION_KEY` | auto `.chat_secret` | Fernet key for message storage |

`.env` is git-ignored (may hold secrets); `.env.example` documents all options.

### Installing from a mirror

`run.py` installs dependencies automatically on first run. By default that goes
to PyPI. Set `PIP_INDEX_URL` in `.env` (or as a real environment variable, which
wins) to use an internal mirror instead:

```
PIP_INDEX_URL=https://artifactory.example.com/api/pypi/pypi/simple
```

Leave it unset and pip uses its own default, which is PyPI. The mirror is only
consulted by that one-off install — the running application never makes an
outbound connection. Nothing is installed at all once the dependencies are
present, and the offline bundle's `install.sh` never installs anything.

## Process model (workers)

`WORKERS` defaults to **1**. One process owns the WebSocket fan-out and the
encrypted-channel state, so nothing needs coordinating.

Raising `WORKERS` runs several uvicorn processes against **one shared SQLite
database** (WAL is enabled automatically, which is what makes concurrent
readers and a single writer safe). Before starting, `run.py` fails fast on the
two things that would break silently:

1. **Network filesystem — always a hard error.** SQLite's WAL journal mode
   needs shared memory (`-shm`), which NFS/CIFS/9p/AFS and friends do not
   provide; SQLite documents WAL as unsupported there. The data directory is
   classified by parsing `/proc/self/mountinfo` (longest mount-point match,
   escaped mount names handled), and NFS, CIFS/SMB, 9p, AFS, Ceph, GlusterFS,
   Lustre and `fuse.*` variants are refused. If the filesystem type cannot be
   determined at all, multi-worker is refused rather than assumed safe. With
   `WORKERS=1` the same situation only produces a warning.
2. **Per-process state — refused by default.** With `ENC_ENABLED=true`
   multi-worker is refused outright: a channel session lives in the worker that
   created it, so requests landing on another worker would fail with
   "Session expired". With the encrypted channel off, startup still refuses
   unless `ALLOW_SPLIT_ROOMS=true`, because each worker only broadcasts to its
   own sockets and the public room would silently become one room per worker.

### Why SQLite + several workers means separate rooms

The public room works like a hub: every message is fanned out from the sender's
process to the WebSocket connections **that process holds**. Those connections
live in `manager.active`, which is per-process memory. Nothing in SQLite can
fix that — the database stores messages, it does not deliver them.

So with `WORKERS=4` a message from a client on worker 2 reaches only the
sockets on worker 2. The room is not "slow" or "degraded": from the users'
point of view it is four different rooms, and two people in the same chat room
simply do not see each other. Private messages survive this (they target two
specific sockets, which usually live on one worker each), history survives
this (it is in the database) — only the live public broadcast breaks.

Fixing it properly needs a shared fan-out channel between processes: Redis
pub/sub, a Postgres `LISTEN/NOTIFY`, or a queue table that every worker polls.
All three are new infrastructure, and the first two are new dependencies, so
none of them are in this project.

### Why `ALLOW_SPLIT_ROOMS=true` is dangerous

It is a foot-gun with a name that sounds harmless. When set, startup prints a
loud warning and the chat UI shows a permanent orange banner, but the server
still starts and looks perfectly healthy: HTTP 200s, logins work, history
loads, and the failure only appears as *missing messages* in a busy room.

That failure mode is nasty in practice, because "my messages randomly don't
arrive" is indistinguishable from a flaky network — so people debug the
network, not the config. It is only safe when the split is intentional, e.g.
independent rooms behind a load balancer with sticky sessions that keep each
user pinned to one worker.

### Why `WORKERS=1` is the default

One process keeps every piece of state coherent by construction:

- one broadcast hub, so the public room is one room;
- encrypted-channel handshakes live next to the sockets they authenticate;
- admin sessions and rate-limit counters are consistent (they now also live in
  SQLite, but there is one less moving part to reason about);
- one SQLite writer, which is the configuration WAL is designed for.

It also keeps deployment trivial — no reverse proxy, no sticky-session cookie,
no shared pub/sub to operate. For the target of this project (a small chat on
one box) a single process is the right amount of machinery.

### When to migrate to Postgres

SQLite stops being the right tool when any of these become true — the first
one is usually the real trigger:

1. **You need more than one application instance.** That is the wall discussed
   above: horizontal scaling of the live broadcast needs Postgres `LISTEN/NOTIFY`
   or Redis anyway, so at that point the database move is the smaller change.
2. **Sustained write throughput beyond a few hundred messages/second.** SQLite
   serialises writers; `database is locked` handling and WAL help, but they do
   not create parallelism. Watch `DB_BUSY_TIMEOUT_MS` climbing as a symptom.
3. **You need concurrent writes from several hosts.** A network filesystem is
   rejected here precisely because SQLite cannot do this safely.
4. **You need HA, backups with point-in-time recovery, or replica reads.** SQLite
   gives you a file copy, which is fine until you need to restore to a point in
   time while traffic continues.
5. **You outgrow one box of CPU for the broadcast fan-out** even at
   `WORKERS=1` (see the measured table in *Concurrency & scaling*).

Migration surface is small and well isolated: only `app/db.py` touches SQLite,
and only four tables are involved (`users`, `messages`, `sessions`,
`admin_sessions`). Nothing else in the app knows which database is in use.

What genuinely works across workers: everything stored in SQLite — users,
messages (public and private), chat sessions and admin-panel sessions (moved
into the `admin_sessions` table for exactly this reason).

What does not: the public-room broadcast, and the in-memory rate-limit
counters, which are per worker. Both need a shared store or a sticky-session
proxy; neither is added here, so `WORKERS=1` stays the recommended setting.

When split-rooms mode is active the startup log prints a warning and the chat UI
shows a persistent banner, because the failure is otherwise invisible.

## Concurrency & scaling

Single server, single process is the supported model (SQLite cannot be
shared between machines).

- **WAL journal mode**: readers never block writers; set automatically.
- **Busy timeout + write retries**: `DB_BUSY_TIMEOUT_MS` (default 10s);
  momentarily locked writes wait and retry with backoff instead of failing.
- **No read lock**: every query uses its own short-lived connection.
- **Non-blocking I/O**: SQLite/encryption work runs in worker threads so
  the event loop stays responsive; per-sender message order is preserved.
- Load-tested: 150 concurrent WebSocket clients × 17 messages (2700 total)
  + HTTP pollers — zero errors, zero lost messages, zero `database is locked`.

Honest limits: every public message is fanned out to every connected client,
so cost per message is O(clients) and CPU (not the database) is the ceiling.
Measured on one process, public room, encrypted channel:

| Concurrent clients | Delivery |
|---|---|
| 20 (500 msgs total) | 100% |
| 40 (500 msgs) | 100% |
| 60 (500 msgs) | 100% |
| 100 (500 msgs) | ~84%, then sockets recycle |

So roughly 50-60 simultaneous public-room chatters per process is a safe
operating point; beyond that, split into rooms/processes or add a fan-out
queue. Private messages are cheap (2 recipients) and scale much further.

## Transport security

Passwords, session cookies and messages travel over the wire, so serve
over TLS in any real deployment (`SSL_CERTFILE`/`SSL_KEYFILE`; the browser
then uses `wss://` automatically). Built-in hardening, no extra dependencies:

- `Secure` + `HttpOnly` + `SameSite=Lax` session cookies (`Secure` only
  over HTTPS); server version header disabled.
- Same-origin enforcement on browser POSTs and the WebSocket handshake
  (foreign `Origin` gets 403 / connection refused).
- Rate limits: login/register per IP, messages per user (429 + `Retry-After`).
  Note: behind a reverse proxy, rate-limit there too — `X-Forwarded-For`
  is client-spoofable and intentionally ignored here.
- Security headers (`nosniff`, `DENY` framing, `no-referrer`, HSTS on HTTPS).
- WebSocket frame cap (`WS_MAX_SIZE_BYTES`), absolute session expiry
  (`SESSION_LIFETIME_DAYS`), 0600 file permissions, constant-time login
  path for unknown users (anti-enumeration).

## Encrypted transport (TLS alternative, `chat-enc-v1`)

For deployments where TLS/certificates are not available, the browser
negotiates an encrypted channel with the server itself. Enabled by default
(`ENC_ENABLED=true`), no certificates and no extra dependency.

What it protects: passwords, session tokens and message contents are never
readable on the wire — a network sniffer sees only ciphertext and (to) who
talks to whom.

| Property | How |
|---|---|
| Key agreement | ECDH P-256 (ephemeral, per handshake) |
| Server authentication | ECDSA P-256 signature over the handshake transcript, verified against a **pinned** fingerprint (TOFU) — this is the anti-MITM check |
| Confidentiality/integrity | AES-256-GCM with random nonces per frame |
| Forward secrecy | One-way HKDF chain ratchet per WebSocket frame; keys live only for one channel session (one handshake per page load) |
| Replay / forgery | Monotonic counter bound into the GCM AAD, plus a MAC proof per HTTP call with a timestamp and a nonce store |
| No cookies | Credentials and tokens travel inside the channel. The `enc_sid` cookie only gates HTML page views and is useless without the channel keys |
| Plain endpoints closed | While enabled, `/api/*` and `/ws` refuse cookie-based access (403), so a password can never be POSTed in cleartext |

Scale note: fan-out to every client is O(clients) per public message, and
encryption adds a constant. Measured: 60 simultaneous public-room clients
sustain 100% delivery in a single process; at 100 clients sustained
broadcast saturates it (sockets are recycled and messages may lag). Private
messages only reach two sockets, so they scale much further. Fan-out is
concurrent with a per-socket timeout, and a client whose stream desynchronises
is recycled automatically.

All workers must therefore share one data directory: the ECDSA key in
`enc_keys.json` is what the fingerprint is derived from, so a per-process key
would make every pinned client believe it is being MITM-ed.

The fingerprint is shown in the chat header; copy it to another channel to
verify you talk to the same server. If it changes unexpectedly, the UI warns
and offers an explicit "trust the new identity" (needed after a server move
or key rotation).

**Honest limits**

- This is transport encryption, **not** end-to-end encryption. The server
  decrypts messages to store history, build reply quotes and deliver them,
  so it can still read stored messages (see `app/crypto.py`).
- Metadata is not hidden: the server (and a network observer) still sees who
  talks to whom, when, and message sizes.
- Channel keys live in `sessionStorage`, so a script-injection attacker in
  the origin could read them — the same exposure model as any cookie-based
  app, but now the keys matter more. Keep output escaped (as it is).
- The **admin panel still posts its password over the channel-less path**.
  Put the app behind a tunnel (WireGuard) or TLS if you use the admin panel
  on an untrusted network.
- Set `ENC_ENABLED=false` to fall back to plain HTTP. With TLS configured you
  can keep either mode; TLS remains the better choice when available.

Set `ENC_SHOW_FINGERPRINT=false` only if you accept losing the MITM check.

## Verifying the server identity

`run.py` prints the server's signing-key fingerprint at every startup:

```
Server identity fingerprint (chat-enc-v1 signing key):
  7C1D 2B0B 67C3 3F33 A643 E004 E820 44E2 7EA5 9674 59EA 99FA 6129 F8E8 BB5A 1BDF
```

The fingerprint is derived from the persisted signing key, so it is identical
across restarts and across workers. Reading it here is the point: the browser
can only learn the fingerprint from the very connection it is meant to verify,
so a fingerprint shown in the page proves nothing on its own — anything
intercepting the connection can serve its own key and its own fingerprint. The
console (or the host's logs, or SSH) is a channel the browser cannot influence.

The web UI has a **Server identity** panel on the chat, login and register
pages. It shows what this connection presents, what this browser has pinned,
and takes the expected value to compare against:

- paste the fingerprint from the server log and press **Verify and pin**;
- a match is pinned, and from then on the browser refuses to connect if the
  server identity ever changes;
- a **mismatch is never pinned** — otherwise whoever answers the first request
  could overwrite the pin and make the next reconnect look trustworthy. The
  stale pin is kept and shown in red so the two can be compared;
- spacing, case and separators are normalised, so a value pasted from a
  terminal works;

When the server key changes the panel opens itself, the previous pin is flagged
and both values are shown side by side. Note that the banner's escape hatch
("I verified it — trust and reload") performs *no* verification: it only
forgets the old pin, so use it after checking the console.

There is deliberately no "forget pin" control. Verifying the new value already
replaces a stale pin, so a rotated key, a pin pasted from the wrong server, and
a plain re-pin are all one step — and a permanent one-click way to drop a
verified pin would be a quiet downgrade to trust-on-first-use with nothing to
buy in exchange.

The trust-on-first-use pin still happens automatically, so the panel is an
addition to the MITM check rather than a replacement for it. Note the limit of
that: TOFU cannot detect a MITM on the *very first* connection, because there
is nothing yet to compare against. The panel says "not verified yet" for exactly
that state — paste the fingerprint from the server log to turn a TOFU pin into
a verified one, after which any change to it is caught.

### Rotating the server key

There is no CLI for this, deliberately: the file is 4 KB and hand-rotating it
is a two-minute job, and a rotation tool is code that can be run at the wrong
moment. `enc_keys.json` lives in `CHAT_DATA_DIR` and holds exactly one thing:
the ECDSA P-256 **signing key**, base64-encoded, under the key `"sig"`. That is
the key the published fingerprint is derived from. (The ECDH key is *not*
stored — it is ephemeral per handshake, which is where forward secrecy comes
from — so there is nothing else in this file.)

**Stop the server first.** A client mid-handshake against a key that is
replaced underneath it gets a failed session, which is survivable but noisy.

```bash
# 1. Stop the server, then keep a copy. This is the only way back.
cp enc_keys.json enc_keys.json.bak

# 2. Delete the whole file. `ensure_secret_file()` writes a fresh key on the
#    next startup, so a partial edit is riskier than no edit: a file that is
#    present but missing "sig" is rejected at load and the server refuses to
#    start with a message about restoring the backup.
rm enc_keys.json

# 3. Start the server. It generates a new signing key and prints the new
#    fingerprint in the startup banner.
python run.py
```

Step 3 prints the **new** fingerprint. Every browser that had the old one
pinned will now refuse to connect and show `IDENTITY CHANGED` with both values
side by side — that is the check working, not a failure.

**Telling your users about the new fingerprint is the part that matters.** A
pin is only as good as the channel the new value travels over: if you announce
the new fingerprint on the same chat it authenticates, an attacker who already
controls that channel announces theirs too and the check is bypassed. Use the
server console or SSH — something the browser cannot influence — and say
plainly that the value changed and why. Users paste the new value into the
identity panel; there is no "forget pin" button by design (see above).

Rotating this key does not affect messages at rest: those are Fernet-encrypted
under a different secret, `CHAT_ENCRYPTION_KEY` / `.chat_secret`. Losing *that*
key makes stored history permanently unreadable; losing `enc_keys.json` costs
nothing but the pins.

## Running behind a reverse proxy

Rate limits and the WebSocket cap are keyed on the client IP. By default that
is the direct peer address, because `X-Forwarded-For` is client-spoofable — if
it were believed unconditionally, anyone could put a fresh value in it and
walk straight through every limit.

The cost of that default is that behind a proxy or NAT every user shares one
key: `MAX_SOCKETS_PER_IP=20` becomes a site-wide 20-socket ceiling, and
`RATE_LOGIN_PER_MIN` a site-wide rate. The failure looks like "users can't open
chat" at peak load, not like a config mistake.

Set `TRUSTED_PROXY_CIDRS` to the addresses that actually terminate the
connection:

```
TRUSTED_PROXY_CIDRS=127.0.0.1,::1          # local nginx
TRUSTED_PROXY_CIDRS=10.0.0.0/8             # a pod or service network
```

The header is then believed **only** for requests that arrived from a listed
address, and only its rightmost *untrusted* hop is used. Walking from the right
is what makes this safe: a client can prepend whatever it likes to the header,
but it cannot control what the real proxy appends. Leave the setting empty when
the app is directly exposed.

Make sure the proxy itself is configured to overwrite — not append to —
`X-Forwarded-For` (`proxy_set_header X-Forwarded-For $remote_addr;` in nginx).
An appending proxy passes the client's forged value through, and while the
rightmost-hop walk still protects you, the visible client IP will be wrong.

## Admin panel

Set `ADMIN_PASSWORD` (and optionally `ADMIN_PATH`, default `/admin`) to
enable a minimal admin panel: list users, add users (works even when public
registration is closed), delete users with all their messages, and reset
passwords (active sessions are killed, forcing re-login). The panel uses a
separate password-based session (12h, server-side, `HttpOnly` cookie) — the
admin is not a chat user. Without `ADMIN_PASSWORD` the panel does not exist
(all its URLs are 404).

The password can be stored as a PBKDF2 hash instead of plaintext, which is
preferred: `.env`, `/proc/<pid>/environ` and process listings are all readable
on a shared host, so a plaintext password there is a credential sitting in the
open. Generate the hash once:

```bash
python -c "from app.auth import hash_password; print(hash_password(input()))"
```

Put it in `ADMIN_PASSWORD_HASH`. That alone is enough to enable the panel; if
both are set, the hash wins and `ADMIN_PASSWORD` is never compared.

**Strongness is on you.** One credential guards every user and every message
in the database — it can delete all of them. `run.py` warns at startup when the
configured password is shorter than 12 characters or is a single character
class, and tells you what to do about it; the check is skipped for the hash
form because a hash hides the length. The warning is advisory, not a refusal:
`python run.py` starts either way.

### Brute-force protection

Two independent limits, because they bound different things:

| Limit | Bounds | Default |
|---|---|---|
| `RATE_ADMIN_LOGIN_PER_MIN` | how fast attempts may arrive | 10/min, per IP |
| `ADMIN_LOCKOUT_STEP` / `_GRACE` / `_MAX` | how *many* attempts are worth making | see below |

Below the window, each failure adds to a tally that decays with a 5-minute
half-life, and the delay for the next attempt is
`step × 2^max(0, failures − grace)` seconds:

| Consecutive failures | 1–5 | 6 | 8 | 10 | 12+ |
|---|---|---|---|---|---|
| Wait (s) | 0 | 2 | 8 | 32 | 120 (capped) |

So the first five mistakes are free — an operator who fat-fingers their own
password is never locked out — and after that a scripted attack is down to one
guess every two minutes. The tally clears the moment the right password
arrives, and the half-life means walking away for ten minutes is enough to
start over. Set `ADMIN_LOCKOUT_STEP=0` to keep only the sliding window.

The tally is per client IP, the same scope as the window. A distributed run
gets one tally per address, which is the limit of the single-process model —
that is why the length check above exists rather than being decorative.

## Frontend

Vanilla HTML/CSS/JS with no build step, no framework and no npm. The
design system follows shadcn/ui: a token layer (`--background`,
`--foreground`, `--primary`, `--muted-foreground`, `--border`, `--ring`,
`--radius`, ...) plus component classes (`.btn` with `primary`/`secondary`/
`outline`/`ghost`/`destructive` variants, `.input`, `.card`, `.alert`,
`.badge`, `.separator`), a focus ring in `--ring`, hairline borders and small
radii, in a neutral (zinc) light/dark palette.

shadcn itself is React + Tailwind source code, so what is reproduced here is
its design language rather than its components: there is no React, no Tailwind
and no build step, which keeps the offline Linux bundle self-contained. The
trade-off is that Radix behaviour primitives (focus trapping, roving tabindex,
portalled popovers) are hand-written where needed rather than imported.

### Responsive behaviour

The layout is verified by measuring the rendered page in a real browser at
320/390/768/1024/1440px, not by reading the stylesheet. Four rules matter:

- **The conversation list is a drawer on phones.** At 600px and below the
  sidebar becomes a fixed overlay opened by the header's `☰` button, so the
  message area keeps the full width instead of giving up half the screen to a
  list. It closes on selection, on `Escape` (returning focus to the button) and
  on a backdrop tap, and `aria-expanded` tracks its state.
- **The document never scrolls.** `.main` and `#messages` carry
  `min-height: 0`, otherwise the pane cannot shrink below its content and the
  *document* becomes the scroll container, pushing the composer below the fold.
- **Tap targets are at least 24px tall.** Interactive controls are real
  `<button>`s, not styled text.
- **Line length stays readable.** Message bubbles are capped at `36rem`, which
  bites because the app frame is already capped at `68rem`.

Two details that only a browser shows. Heights use `dvh` (with a `vh`
fallback), because iOS shrinks the viewport when its toolbar hides. And the
header does **not** invert with the theme — `--header` is near-black in both —
so anything inside it takes `--header-ink`, never `--foreground`; the theme
toggle is therefore measured for contrast against the header rather than
assumed, because a wrong ink there leaves a present, clickable button that
paints nothing at all.

### Unread badges

`# Public Chat` and each private conversation carry a count of messages that
arrived while you were looking somewhere else. The counters live in the page
and are gone on reload: nothing is persisted and nothing is sent to the
server. That is the design rather than a shortcut — a badge answers "did
something come in while I was elsewhere", which is a question about this page
load, and storing read state would mean a new table plus write-amplification
on every message to answer a question the current page already answers.

A message in the conversation you are looking at is read on arrival and never
badges. Counts accumulate, cap at `99+`, and clear when you open the
conversation. The badge is `aria-hidden`; the button's accessible name spells
the count out ("Private chat with @bob, 2 unread messages") so the digits are
not read as part of the name. Verified in a real browser against a real
WebSocket in `tests/test_unread_badges.py`.

### Desktop notifications

A 🔕 button in the header turns them on. It appears whenever the permission
has not been refused yet — including on your first visit, which is the only
moment it can be asked for. If you have blocked notifications for the site the
browser reports `denied` and there is nothing left to ask for, so the button
stays hidden rather than offering a toggle that cannot change anything. A
prompt you dismissed or have not answered is *not* a refusal, so the button
stays; only `denied` retires it.

The choice is kept in `localStorage`; permission itself is the browser's, and a
permission revoked later hides the button again on the next load.

A notification appears only for a message in a conversation you are **not**
looking at, and only while the tab is in the background. The unread badge above
already answers "did something arrive"; a toast on top of what you can read is
noise. Clicking a notification focuses the tab and opens the conversation it
came from.

**The text is deliberately generic — "New message" or "New private message",
never a preview and never the sender's name.** A notification is drawn by the
OS on the lock screen, and on some platforms its history syncs between a user's
devices, so a channel that exists to keep message bodies off other people's
screens must not reopen that hole through the notification. The conversation is
carried by an opaque tag rather than the sender's handle, so nothing in the
notification identifies who wrote to you. If you would rather see who, that is
a deliberate trade rather than an oversight.

**Scope, and what it is not.** This runs only while the tab is open and
JavaScript is running. There is no service worker and no push, so a closed tab,
a suspended one, or a browser that froze it in the background gets nothing —
only the tab's title count survives that, and only while the tab exists. That
ceiling is a consequence of the design rather than an omission: the channel keys
live in `sessionStorage`, which a service worker cannot read, so any
background delivery would have to move message bodies or a plaintext count out
of the page, and the server would then learn when each user is at their
keyboard. `tests/test_notifications.py` pins the current ceiling as well as the
behaviour, so widening it has to be a decision made on purpose.

Verified in a real browser against a real WebSocket in
`tests/test_notifications.py`, which also records the `Notification` constructor
to check the text and tag, since a headless browser emits no observable event
for a notification at all.

## Installing it as an app

The app is installable: Chrome offers "Install" in the address bar, and iOS
offers "Add to Home Screen" from the share sheet. The installed copy launches
without browser chrome, with its own icon, and — on a phone — takes the whole
screen.

**It needs HTTPS.** A service worker can only be registered in a secure
context, so on plain HTTP over a network address there is nothing to install
and no prompt appears. `localhost` counts as secure, so a laptop install works
over plain HTTP.

### What "installable" does and does not mean

It means the app can be installed and launched. It does **not** mean:

- **offline.** The service worker caches nothing, so a cold start with no
  network shows a connection error rather than your last messages. That is
  deliberate: the channel keys live in the page's `sessionStorage`, which a
  service worker cannot read, so a cached response would be ciphertext with no
  key beside it — useless — while the message bodies would sit on disk in the
  browser's cache storage regardless.
- **push notifications.** No push service is involved, so the app cannot wake
  you when a message arrives while it is closed. The in-app notifications work
  as described above, while the tab is open.

Both of those are the same ceiling from two directions: background delivery
would mean moving message content, or the keys beside it, out of the page.

Verified against Chrome's own installability verdict — not an interpretation of
the manifest — in `tests/test_pwa.py`, which also pins the ceiling above so it
has to be undone on purpose.

## Features

- Registration / login / logout (PBKDF2 password hashing, server sessions)
- Public chat room, real-time over WebSocket, with history
- Private messaging: search `@username`, open a conversation, messages are
  delivered in real time only to sender + recipient and persist for offline users
- Replies: hover any message for Reply, quotes show sender + preview —
  click a quote to scroll to the original message (public and private)
- Optimistic send: your message appears immediately in a faded "sending…" state
  and is replaced by the server's echo (with its real id and timestamp). If the
  connection drops first, the row disappears and the status line says so, so a
  message is never silently lost.
- Presence: a dot beside each conversation marks who is currently connected.
  It is per-process, so it is only reported when `WORKERS=1` (the default) —
  with several workers a user on another worker would look offline.
- Installable: a web app manifest, icons and a service worker that caches
  nothing, so the app can be added to the home screen and launched without
  browser chrome. See "Installing it as an app" above.
- Desktop notifications for messages in conversations you are not viewing,
  and an unread count in the tab title. Neither carries message text; see
  "Desktop notifications" above for what that feature deliberately cannot do.
- `Ctrl`/`Cmd`+`Enter` sends from the composer as well as clicking Send

## Message encryption (at rest — NOT end-to-end)

All message content in SQLite is Fernet authenticated encryption (ciphertext
only; plaintext is never stored). The server holds the key and decrypts
messages to deliver them to connected clients and load history. Do **not**
describe this as end-to-end encrypted — the server can read messages.

Key management:

- If `CHAT_ENCRYPTION_KEY` is set, it is used (must be a Fernet key, e.g.
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
- Otherwise a secure key is generated on first startup and saved to
  `.chat_secret` (mode 0600, git-ignored).
- Secret files are created with an `flock()` on a sidecar `.lock` file, then
  written to a temp file, fsync'd and atomically `os.replace()`d. That makes
  creation safe for several threads *and* several processes, and guarantees no
  reader ever sees a half-written key. `.chat_secret` and `enc_keys.json` are
  both git-ignored — committing either one destroys the security model.
  `.lock` files stay on disk; they are empty and harmless.

> ⚠️ **If the encryption key is lost, previously stored messages can NEVER be
> decrypted.** Back up `.chat_secret` (or keep `CHAT_ENCRYPTION_KEY` safe) and
> never commit it to git. If decryption fails, the app shows
> `[message unavailable — decryption failed]` instead of crashing — but the
> original text is unrecoverable without the key.

## Database migration

Old databases with plaintext `messages(user_id, content)` are migrated
automatically on startup: rows are copied to the new
`(sender_id, recipient_id, ciphertext)` shape with content encrypted, and only
then is the old table replaced. If migration fails halfway, the old table is
left untouched — no data is destroyed.

## Offline Linux package (no pip installs needed)

`packaging/build.py` vendors all Python dependencies into the bundle:

```bash
python3 packaging/build.py   # -> dist/chat-app-linux-x86_64.tar.gz (~8 MB)
```

The tarball runs on any Linux x86_64 with stock Python 3.12 — no pip,
no internet, no system changes:

```bash
tar -xzf dist/chat-app-linux-x86_64.tar.gz
cd chat-app && ./chat-app    # data goes to ./data (override: CHAT_DATA_DIR)
./install.sh                 # optional: install to ~/.local/{bin,share}
```

See `packaging/templates/README.txt` (also bundled) for details.

## Tests

The suite uses only the standard library, so no test dependencies are needed:

```bash
python -m unittest discover -s tests -v
```

It covers filesystem/network-mount detection, the startup preflight matrix
(which process models are refused and which are allowed with a warning), and
the concurrency guarantees of secret-file creation (threads *and* processes
must converge on one key, and no reader may see a partial file). CI runs the
same suite plus a smoke test against a live server.

`tests/test_responsive_layout.py` additionally drives a real headless Chrome
over the DevTools protocol and asserts there is no sideways scrolling, no
control under 24px, that the composer stays on screen, that the sidebar drawer
opens and closes, and that bubbles respect the line-length cap. It needs a
Chrome/Chromium binary and the `websocket-client` module; when either is absent
it **skips** rather than pretending to pass, so a bare CI runner still reports
green. To run it locally:

```bash
pip install websocket-client   # not a runtime dependency, only for this test
python -m unittest tests.test_responsive_layout -v
```

The seeded content is deliberately hostile -- a 400-character token with no
spaces, a long URL, emoji and a 30-character username -- because an empty room
does not break narrow layouts and makes the suite look green for the wrong
reason.

`tests/test_identity_verification.py` and `tests/test_unread_badges.py` reuse
that DevTools harness (as `tests/test_unread_badges.py` also needs the
`websockets` module) to drive a real browser against a real server: the first
rotates the server key to prove the pin fires, the second has two accounts
talk over a real WebSocket and asserts that badges appear, accumulate, cap and
clear exactly when the conversation they count goes off screen.
