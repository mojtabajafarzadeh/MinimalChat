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
| `PORT` | `8001` | Listen port |
| `REGISTRATION_ENABLED` | `true` | `false` closes registration (existing users unaffected; register page redirects to login, API returns 403) |
| `CHAT_DATA_DIR` | project root | Directory for `chat.db` + `.chat_secret` |
| `DB_BUSY_TIMEOUT_MS` | `10000` | SQLite lock wait before failing (writes retry) |
| `SSL_CERTFILE` / `SSL_KEYFILE` | empty (plain HTTP) | TLS cert+key for HTTPS/WSS. Local self-signed: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 825 -nodes -subj "/CN=127.0.0.1"` |
| `WS_MAX_SIZE_BYTES` | `65536` | Max WebSocket frame size (DoS guard) |
| `SESSION_LIFETIME_DAYS` | `30` | Absolute session lifetime |
| `RATE_LOGIN_PER_MIN` / `RATE_REGISTER_PER_MIN` / `RATE_MSG_PER_MIN` | `20` / `30` / `120` | Sliding-window rate limits (per IP / per IP / per user) |
| `ADMIN_PATH` | `/admin` | Address of the admin panel (letters, numbers, `_`, `-`) |
| `ADMIN_PASSWORD` | empty (disabled) | Admin panel password. Empty = panel routes are 404. Use a long random value |
| `ENC_ENABLED` | `true` | Application-layer encrypted transport (TLS alternative) |
| `ENC_SHOW_FINGERPRINT` | `true` | Show/pin the server key fingerprint (the anti-MITM check) |
| `WORKERS` | `1` | Worker processes. `>1` shares one SQLite database in WAL mode, see below |
| `ALLOW_SPLIT_ROOMS` | `false` | Accept that the public room is split per worker |
| `CHAT_ENCRYPTION_KEY` | auto `.chat_secret` | Fernet key for message storage |

`.env` is git-ignored (may hold secrets); `.env.example` documents all options.

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

## Admin panel

Set `ADMIN_PASSWORD` (and optionally `ADMIN_PATH`, default `/admin`) to
enable a minimal admin panel: list users, add users (works even when public
registration is closed), delete users with all their messages, and reset
passwords (active sessions are killed, forcing re-login). The panel uses a
separate password-based session (12h, server-side, `HttpOnly` cookie) — the
admin is not a chat user. Login attempts are rate-limited. Without
`ADMIN_PASSWORD` the panel does not exist (all its URLs are 404).

## Features

- Registration / login / logout (PBKDF2 password hashing, server sessions)
- Public chat room, real-time over WebSocket, with history
- Private messaging: search `@username`, open a conversation, messages are
  delivered in real time only to sender + recipient and persist for offline users
- Replies: hover any message for Reply, quotes show sender + preview —
  click a quote to scroll to the original message (public and private)
- Dark mode with header toggle (preference saved, follows system by default)

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
