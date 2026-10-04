"""Minimal real-time chat: FastAPI + WebSocket + SQLite. No ORM, no extra services.

Message privacy model:
- messages.recipient_id IS NULL  -> public room message, broadcast to all.
- messages.recipient_id = user   -> private message, delivered only to the
  sender and the recipient.
- messages.content always holds Fernet ciphertext, never plaintext.
  The server decrypts for delivery/history (encryption at rest, NOT
  end-to-end encryption).

Concurrency: blocking work (SQLite + encryption) runs in worker threads via
asyncio.to_thread so the event loop stays responsive under many concurrent
connections. Each connection still awaits its own messages sequentially, so
per-sender order is preserved.
"""
import asyncio
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Form, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import admin, auth, crypto, db, enc
from .config import (
    ADMIN_PATH,
    ALLOW_SPLIT_ROOMS,
    ENC_ENABLED,
    ENC_HANDSHAKE_PER_MIN,
    ENC_SHOW_FINGERPRINT,
    RATE_ADMIN_LOGIN_PER_MIN,
    RATE_LOGIN_PER_MIN,
    RATE_MSG_PER_MIN,
    RATE_REGISTER_PER_MIN,
    REGISTRATION_ENABLED,
    WORKERS,
)
from .security import (
    ChannelOnlyMiddleware,
    SecurityHeadersMiddleware,
    check_rate_limit,
    origin_allowed,
)
from .websocket import manager

log = logging.getLogger("chat")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Minimal Chat")
# Middleware runs bottom-up, so add the channel gate first: it must run before
# the cookie-auth endpoints are reached.
app.add_middleware(SecurityHeadersMiddleware)
if ENC_ENABLED:
    app.add_middleware(ChannelOnlyMiddleware)

SESSION_COOKIE = "session_id"
UNDECRYPTABLE = "[message unavailable — decryption failed]"


@app.on_event("startup")
def startup() -> None:
    db.init_db()


# ---------- helpers ----------


ENC_COOKIE = "enc_sid"


def channel_session_user(request: Request):
    """Channel identity from the enc_sid cookie.

    The cookie only gates page views. It is NOT a credential on its own: every
    channel API call additionally needs a MAC made with the session key that
    never leaves the browser, so a sniffed cookie cannot read or forge anything.
    """
    if not ENC_ENABLED:
        return None
    try:
        return enc.session_user(request.cookies.get(ENC_COOKIE))
    except Exception:
        return None


def page_user(request: Request):
    """Identity for HTML page routes (cookie session or encrypted channel)."""
    return current_user(request) or channel_session_user(request)


def current_user(request: Request):
    # The encrypted channel authenticates via the session bound to the
    # handshake, so it takes precedence over cookies when present.
    channel_user = getattr(request.state, "enc_user", None)
    if channel_user is not None:
        return channel_user
    return auth.get_session_user(request.cookies.get(SESSION_COOKIE))


def page(name: str) -> FileResponse:
    return FileResponse(STATIC_DIR / name)


def valid_username(v: str) -> bool:
    v = v.strip()
    return 3 <= len(v) <= 32 and all(c.isalnum() or c in "_-" for c in v)


def _client_ip(request: Request) -> str:
    # Direct connection only. Behind a reverse proxy, rate-limit there —
    # X-Forwarded-For is client-spoofable and must not be trusted here.
    return request.client.host if request.client else "unknown"


def _cookie_secure(request: Request) -> bool:
    return request.url.scheme == "https"


def _bad_origin(request: Request):
    """403 response if a browser request claims a foreign Origin, else None."""
    if origin_allowed(request.headers.get("origin"), request.headers.get("host", "")):
        return None
    return JSONResponse({"error": "Bad origin."}, status_code=403)


def _too_many(key: str, limit: int):
    """429 response when the sliding window is exhausted, else None."""
    allowed, retry = check_rate_limit(key, limit, 60)
    if allowed:
        return None
    return JSONResponse(
        {"error": "Too many attempts. Try again later."},
        status_code=429,
        headers={"Retry-After": str(retry)},
    )


def safe_content(msg_id, ciphertext: str) -> str:
    """Decrypt for delivery. Never crash, never leak key/plaintext in errors."""
    try:
        return crypto.decrypt(ciphertext)
    except Exception:
        log.warning("Could not decrypt message id=%s", msg_id)
        return UNDECRYPTABLE


def _quote_dict(row) -> dict:
    """Decrypted snapshot of a replied-to message for quote previews."""
    d = dict(row)
    return {
        "id": d["id"],
        "name": d["name"],
        "username": d["username"],
        "content": safe_content(d["id"], d["content"]),
    }


def _quotes_for(ids) -> dict:
    """Batch-load reply targets: {message_id: quote snapshot}."""
    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = db.query_all(
        "SELECT m.id, m.content, u.name, u.username FROM messages m "
        f"JOIN users u ON u.id = m.sender_id WHERE m.id IN ({','.join('?' * len(ids))})",
        tuple(ids),
    )
    return {dict(r)["id"]: _quote_dict(r) for r in rows}


def _reply_target(reply_to, scope: str, me_id: int, peer_id: int | None = None):
    """Validate a reply reference. Replies stay inside their own scope:
    public->public only, DM->same pair only. Returns (quote|None, error|None).
    """
    if reply_to is None:
        return None, None
    try:
        rid = int(reply_to)
    except (TypeError, ValueError):
        return None, "Invalid reply reference."
    if rid <= 0:
        return None, "Invalid reply reference."
    if scope == "public":
        row = db.query_one(
            "SELECT m.id, m.content, u.name, u.username FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            "WHERE m.id = ? AND m.recipient_id IS NULL",
            (rid,),
        )
    else:
        row = db.query_one(
            "SELECT m.id, m.content, u.name, u.username FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            "WHERE m.id = ? AND m.recipient_id IS NOT NULL AND ("
            "(m.sender_id = ? AND m.recipient_id = ?) OR "
            "(m.sender_id = ? AND m.recipient_id = ?))",
            (rid, me_id, peer_id, peer_id, me_id),
        )
    if not row:
        return None, "Replied message not found."
    return _quote_dict(row), None


def public_payload(row, quote=None) -> dict:
    d = dict(row)
    return {
        "kind": "public",
        "id": d["id"],
        "content": safe_content(d["id"], d["content"]),
        "created_at": d["created_at"],
        "name": d["name"],
        "username": d["username"],
        "reply_to": quote,
    }


def dm_payload(row, to_username: str, quote=None) -> dict:
    d = dict(row)
    return {
        "kind": "dm",
        "id": d["id"],
        "content": safe_content(d["id"], d["content"]),
        "created_at": d["created_at"],
        "name": d["name"],
        "username": d["username"],
        "to": to_username,
        "reply_to": quote,
    }


# ---------- pages ----------


@app.get("/")
def index(request: Request):
    if page_user(request):
        return RedirectResponse("/chat", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login")
def login_page(request: Request):
    if page_user(request):
        return RedirectResponse("/chat", status_code=303)
    return page("login.html")


@app.get("/register")
def register_page(request: Request):
    if page_user(request):
        return RedirectResponse("/chat", status_code=303)
    if not REGISTRATION_ENABLED:
        return RedirectResponse("/login", status_code=303)
    return page("register.html")


@app.get("/chat")
def chat_page(request: Request):
    if not page_user(request):
        return RedirectResponse("/login", status_code=303)
    return page("chat.html")


# ---------- API ----------


@app.post("/api/register")
def api_register(
    request: Request,
    name: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    confirm: str = Form(""),
):
    if (resp := _bad_origin(request)) is not None:
        return resp
    if (resp := _too_many(f"register:{_client_ip(request)}", RATE_REGISTER_PER_MIN)) is not None:
        return resp
    if not REGISTRATION_ENABLED:
        return JSONResponse({"error": "Registration is disabled."}, status_code=403)
    name, username = name.strip(), username.strip()
    if not name or len(name) > 64:
        return JSONResponse({"error": "Name is required (max 64 chars)."}, status_code=400)
    if not valid_username(username):
        return JSONResponse(
            {"error": "Username must be 3-32 chars: letters, numbers, _ or -."},
            status_code=400,
        )
    if not password or len(password) > 128:
        return JSONResponse({"error": "Password is required (max 128 chars)."}, status_code=400)
    if len(password) < 4:
        return JSONResponse({"error": "Password must be at least 4 characters."}, status_code=400)
    if password != confirm:
        return JSONResponse({"error": "Passwords do not match."}, status_code=400)
    if db.query_one("SELECT id FROM users WHERE username = ?", (username,)):
        return JSONResponse({"error": "Username is already taken."}, status_code=400)
    try:
        user_id = db.execute(
            "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)",
            (name, username, auth.hash_password(password)),
        )
    except Exception:
        return JSONResponse({"error": "Could not create user. Try again."}, status_code=500)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE,
        auth.create_session(user_id),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
    )
    return resp


@app.post("/api/login")
def api_login(request: Request, username: str = Form(""), password: str = Form("")):
    if (resp := _bad_origin(request)) is not None:
        return resp
    if (resp := _too_many(f"login:{_client_ip(request)}", RATE_LOGIN_PER_MIN)) is not None:
        return resp
    username = username.strip()
    if not username or not password:
        return JSONResponse({"error": "Username and password are required."}, status_code=400)
    row = db.query_one("SELECT * FROM users WHERE username = ?", (username,))
    if not row:
        auth.dummy_verify(password)  # equalize timing (see auth.dummy_verify)
        return JSONResponse({"error": "Invalid username or password."}, status_code=401)
    if not auth.verify_password(password, row["password_hash"]):
        return JSONResponse({"error": "Invalid username or password."}, status_code=401)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE,
        auth.create_session(row["id"]),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
    )
    return resp


@app.post("/api/logout")
def api_logout(request: Request):
    if (resp := _bad_origin(request)) is not None:
        return resp
    auth.delete_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, samesite="lax", secure=_cookie_secure(request))
    return resp


@app.get("/api/me")
def api_me(request: Request):
    user = current_user(request)
    if not user:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"id": user["id"], "name": user["name"], "username": user["username"]}


@app.get("/api/config")
def api_config():
    """Public feature flags for the frontend (no secrets here)."""
    return {
        "registration_enabled": REGISTRATION_ENABLED,
        "enc_enabled": ENC_ENABLED,
        "enc_show_fingerprint": ENC_SHOW_FINGERPRINT,
        # Only meaningful when several worker processes are actually running.
        "split_rooms": bool(ALLOW_SPLIT_ROOMS and WORKERS > 1),
        "workers": WORKERS,
    }


@app.get("/api/messages")
def api_messages(request: Request, limit: int = 50):
    """Public room history only (recipient_id IS NULL)."""
    if not current_user(request):
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    limit = max(1, min(limit, 200))
    rows = db.query_all(
        "SELECT m.id, m.content, m.created_at, m.reply_to_id, u.name, u.username "
        "FROM messages m JOIN users u ON u.id = m.sender_id "
        "WHERE m.recipient_id IS NULL "
        "ORDER BY m.id DESC LIMIT ?",
        (limit,),
    )
    rows = list(reversed(rows))
    quotes = _quotes_for({r["reply_to_id"] for r in rows})
    return [public_payload(r, quotes.get(r["reply_to_id"])) for r in rows]


@app.get("/api/users")
def api_users(request: Request, q: str = "", limit: int = 20):
    """Find users by username (to start a private conversation)."""
    user = current_user(request)
    if not user:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    limit = max(1, min(limit, 20))
    rows = db.query_all(
        "SELECT id, name, username FROM users "
        "WHERE username LIKE ? AND id != ? ORDER BY username LIMIT ?",
        (f"%{q.strip()}%", user["id"], limit),
    )
    return [dict(r) for r in rows]


@app.get("/api/conversations")
def api_conversations(request: Request):
    """Users the current user has private-message history with, most recent first."""
    user = current_user(request)
    if not user:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    rows = db.query_all(
        "SELECT u.id, u.name, u.username, MAX(m.id) AS last_id "
        "FROM messages m JOIN users u ON u.id = "
        "  CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END "
        "WHERE m.recipient_id IS NOT NULL "
        "AND (m.sender_id = ? OR m.recipient_id = ?) "
        "GROUP BY u.id ORDER BY last_id DESC",
        (user["id"], user["id"], user["id"]),
    )
    return [{"id": r["id"], "name": r["name"], "username": r["username"]} for r in rows]


@app.get("/api/dm/{username}")
def api_dm_history(request: Request, username: str, limit: int = 50):
    """Private history with one user. Only participants can read it."""
    user = current_user(request)
    if not user:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    target = db.query_one(
        "SELECT id, name, username FROM users WHERE username = ?", (username.strip(),)
    )
    if not target:
        return JSONResponse({"error": "User not found."}, status_code=404)
    limit = max(1, min(limit, 200))
    rows = db.query_all(
        "SELECT m.id, m.content, m.created_at, m.reply_to_id, u.name, u.username "
        "FROM messages m JOIN users u ON u.id = m.sender_id "
        "WHERE m.recipient_id IS NOT NULL AND ("
        "  (m.sender_id = ? AND m.recipient_id = ?) OR "
        "  (m.sender_id = ? AND m.recipient_id = ?)) "
        "ORDER BY m.id DESC LIMIT ?",
        (user["id"], target["id"], target["id"], user["id"], limit),
    )
    rows = list(reversed(rows))
    quotes = _quotes_for({r["reply_to_id"] for r in rows})
    return [dm_payload(r, target["username"], quotes.get(r["reply_to_id"])) for r in rows]


# ---------- Admin panel ----------
# Registered only when ADMIN_PASSWORD is set; otherwise these URLs are 404.


def _require_admin(request: Request):
    if admin.valid_session(request.cookies.get(admin.ADMIN_COOKIE)):
        return None
    return JSONResponse({"error": "Admin login required."}, status_code=401)


def _valid_new_password(password: str, confirm: str):
    if not password or len(password) > 128:
        return "Password is required (max 128 chars)."
    if len(password) < 4:
        return "Password must be at least 4 characters."
    if password != confirm:
        return "Passwords do not match."
    return None


if admin.enabled():
    _AP = ADMIN_PATH

    @app.get(_AP)
    def admin_page():
        return page("admin.html")

    @app.post(_AP + "/api/login")
    def admin_login(request: Request, password: str = Form("")):
        if (resp := _bad_origin(request)) is not None:
            return resp
        if (resp := _too_many(f"admin:{_client_ip(request)}", RATE_ADMIN_LOGIN_PER_MIN)) is not None:
            return resp
        if not password or not admin.verify_password(password):
            return JSONResponse({"error": "Invalid admin password."}, status_code=401)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(
            admin.ADMIN_COOKIE,
            admin.create_session(),
            httponly=True,
            samesite="lax",
            secure=_cookie_secure(request),
        )
        return resp

    @app.post(_AP + "/api/logout")
    def admin_logout(request: Request):
        if (resp := _bad_origin(request)) is not None:
            return resp
        admin.delete_session(request.cookies.get(admin.ADMIN_COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(admin.ADMIN_COOKIE, samesite="lax",
                           secure=_cookie_secure(request))
        return resp

    @app.get(_AP + "/api/users")
    def admin_list_users(request: Request):
        if (resp := _require_admin(request)) is not None:
            return resp
        rows = db.query_all(
            "SELECT id, name, username, created_at FROM users ORDER BY id"
        )
        # Never expose password hashes.
        return [dict(r) for r in rows]

    @app.post(_AP + "/api/users")
    def admin_create_user(
        request: Request,
        name: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
        confirm: str = Form(""),
    ):
        if (resp := _require_admin(request)) is not None:
            return resp
        name, username = name.strip(), username.strip()
        if not name or len(name) > 64:
            return JSONResponse({"error": "Name is required (max 64 chars)."}, status_code=400)
        if not valid_username(username):
            return JSONResponse(
                {"error": "Username must be 3-32 chars: letters, numbers, _ or -."},
                status_code=400,
            )
        if (err := _valid_new_password(password, confirm)) is not None:
            return JSONResponse({"error": err}, status_code=400)
        if db.query_one("SELECT id FROM users WHERE username = ?", (username,)):
            return JSONResponse({"error": "Username is already taken."}, status_code=400)
        try:
            user_id = db.execute(
                "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)",
                (name, username, auth.hash_password(password)),
            )
        except Exception:
            return JSONResponse({"error": "Could not create user. Try again."}, status_code=500)
        return {"ok": True, "id": user_id}

    @app.delete(_AP + "/api/users/{user_id}")
    def admin_delete_user(request: Request, user_id: int):
        if (resp := _require_admin(request)) is not None:
            return resp
        if not db.query_one("SELECT id FROM users WHERE id = ?", (user_id,)):
            return JSONResponse({"error": "User not found."}, status_code=404)
        try:
            db.execute(
                "DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?",
                (user_id, user_id),
            )
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        except Exception:
            log.exception("Admin failed to delete user id=%s", user_id)
            return JSONResponse({"error": "Could not delete user."}, status_code=500)
        return {"ok": True}

    @app.post(_AP + "/api/users/{user_id}/password")
    def admin_set_password(
        request: Request, user_id: int, password: str = Form(""), confirm: str = Form("")
    ):
        if (resp := _require_admin(request)) is not None:
            return resp
        if not db.query_one("SELECT id FROM users WHERE id = ?", (user_id,)):
            return JSONResponse({"error": "User not found."}, status_code=404)
        if (err := _valid_new_password(password, confirm)) is not None:
            return JSONResponse({"error": err}, status_code=400)
        try:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (auth.hash_password(password), user_id),
            )
            # Force re-login everywhere: the old password may be compromised.
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        except Exception:
            log.exception("Admin failed to set password for user id=%s", user_id)
            return JSONResponse({"error": "Could not set password."}, status_code=500)
        return {"ok": True}


# ---------- WebSocket ----------
# Shared by the plain socket (/ws) and the encrypted socket (/enc/ws); only the
# frame codec differs, so all message logic lives in one place.


async def _tell(ws: WebSocket, message: dict) -> None:
    """Send one payload back to this socket, sealed if it is on a channel."""
    peer = manager.peer(ws)
    sock = peer.get("sock")
    try:
        if sock:
            await ws.send_json({"e": enc.seal_ws(sock, message)})
        else:
            await ws.send_json(message)
    except Exception:
        pass


async def handle_public(ws: WebSocket, user: dict, content: str, data: dict) -> None:
    quote, err = _reply_target(data.get("reply_to"), "public", user["id"])
    if err:
        await _tell(ws, {"kind": "error", "error": err})
        return
    # Blocking store runs in a thread (event loop stays responsive).
    # Awaited inline, so each connection's messages keep their order.
    row = await asyncio.to_thread(
        _store_public, user["id"], content,
        quote["id"] if quote else None,
    )
    if row is None:
        return  # DB/crypto error: skip broadcast, keep connection alive
    # Plaintext is already in hand; broadcast it (never re-read ciphertext).
    # The manager seals per-socket when the recipient is on an encrypted channel.
    await manager.broadcast(
        {
            "kind": "public",
            "id": row["id"],
            "content": content,
            "created_at": row["created_at"],
            "name": user["name"],
            "username": user["username"],
            "reply_to": quote,
        }
    )


def _store_public(user_id: int, content: str, reply_to_id=None):
    """Blocking part of public send: encrypt + insert + reload. Runs in a thread."""
    try:
        msg_id = db.execute(
            "INSERT INTO messages (sender_id, recipient_id, reply_to_id, content)"
            " VALUES (?, NULL, ?, ?)",
            (user_id, reply_to_id, crypto.encrypt(content)),
        )
        row = db.query_one(
            "SELECT m.id, m.created_at FROM messages m WHERE m.id = ?",
            (msg_id,),
        )
        return dict(row) if row else None
    except Exception:
        log.exception("Failed to store public message")
        return None


async def handle_dm(ws: WebSocket, user: dict, data: dict, content: str) -> None:
    # Sender identity always comes from the session, never from the client.
    to_username = str(data.get("to", "")).strip()
    if not to_username:
        await _tell(ws, {"kind": "error", "error": "No recipient given."})
        return
    target = db.query_one(
        "SELECT id, name, username FROM users WHERE username = ?", (to_username,)
    )
    if not target:
        await _tell(ws, {"kind": "error", "error": "User not found."})
        return
    if target["id"] == user["id"]:
        await _tell(ws, {"kind": "error",
                         "error": "You cannot message yourself."})
        return
    quote, err = _reply_target(
        data.get("reply_to"), "dm", user["id"], target["id"]
    )
    if err:
        await _tell(ws, {"kind": "error", "error": err})
        return
    # Blocking store runs in a thread (event loop stays responsive).
    row = await asyncio.to_thread(
        _store_dm, user["id"], target["id"], content,
        quote["id"] if quote else None,
    )
    if row is None:
        await _tell(ws, {"kind": "error", "error": "Could not send message."})
        return
    payload = {
        "kind": "dm",
        "id": row["id"],
        "content": content,
        "created_at": row["created_at"],
        "name": user["name"],
        "username": user["username"],
        "to": target["username"],
        "reply_to": quote,
    }
    # Deliver ONLY to sender and recipient — never broadcast.
    await manager.send_to_user(target["id"], payload)
    await manager.send_to_user(user["id"], payload)


def _store_dm(sender_id: int, recipient_id: int, content: str, reply_to_id=None):
    """Blocking part of DM send: encrypt + insert + reload. Runs in a thread."""
    try:
        msg_id = db.execute(
            "INSERT INTO messages (sender_id, recipient_id, reply_to_id, content)"
            " VALUES (?, ?, ?, ?)",
            (sender_id, recipient_id, reply_to_id, crypto.encrypt(content)),
        )
        row = db.query_one(
            "SELECT id, created_at FROM messages WHERE id = ?", (msg_id,)
        )
        return dict(row) if row else None
    except Exception:
        log.exception("Failed to store private message")
        return None


async def _ws_loop(ws: WebSocket, user: dict, decode) -> None:
    """Shared receive loop. `decode` turns one wire frame into an app dict."""
    while True:
        try:
            raw = await ws.receive_text()
        except Exception:
            break
        try:
            data = decode(raw)
        except enc.EncError as exc:
            await _tell(ws, {"kind": "error", "error": str(exc)})
            continue
        except Exception:
            break
        if not isinstance(data, dict):
            continue
        content = str(data.get("content", "")).strip()
        if not content:
            continue
        if len(content) > 1000:
            content = content[:1000]
        allowed, _ = check_rate_limit(f"msg:{user['id']}", RATE_MSG_PER_MIN, 60)
        if not allowed:
            await _tell(ws, {"kind": "error",
                             "error": "You're sending too quickly. Slow down."})
            continue
        msg_type = str(data.get("type", "public"))
        try:
            if msg_type == "dm":
                await handle_dm(ws, user, data, content)
            else:
                await handle_public(ws, user, content, data)
        except enc.EncError as exc:
            await _tell(ws, {"kind": "error", "error": str(exc)})
        except Exception:
            log.exception("WebSocket frame handling failed")
            await _tell(ws, {"kind": "error", "error": "Could not process message."})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    if ENC_ENABLED:
        # Plain sockets would bypass the encrypted channel entirely.
        await ws.close(code=4404)
        return
    # Fail fast on cross-site WebSocket hijacking attempts.
    if not origin_allowed(ws.headers.get("origin"), ws.headers.get("host", "")):
        await ws.close(code=4403)
        return
    user = auth.get_session_user(ws.cookies.get(SESSION_COOKIE))
    if not user:
        await ws.close(code=4401)
        return
    await manager.connect(ws, user["id"])
    try:
        await _ws_loop(ws, user, json.loads)
    except Exception:
        pass
    finally:
        await manager.disconnect(ws)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------- Encrypted transport (TLS alternative) ----------
# Everything below only exists when ENC_ENABLED is true. It provides an
# application-layer encrypted channel so credentials, tokens and messages are
# never readable on the wire, without needing certificates.
#
# Wire format:
#   GET  /enc/hello          -> ephemeral key + signing key + fingerprint
#   POST /enc/hello/finish   <- {"sid","eph"} -> {"sig"}
#   POST /enc/login          <- encrypted {username,password} + MAC proof
#   POST /enc/api/<logical>  <- encrypted {q,b} + MAC proof, encrypted response
#   WS   /enc/ws?sid=...     <- {"e": <sealed frame>} both directions
# MAC proof headers: X-Enc-Sid, X-Enc-Ts, X-Enc-Mac (see app/enc.py).

ENC_SID_HDR = "x-enc-sid"
ENC_TS_HDR = "x-enc-ts"
ENC_MAC_HDR = "x-enc-mac"
ENC_RATE_PER_MIN = 600  # generous ceiling for channel API calls per session
# Endpoints reachable before login (login itself has its own route).
ENC_PUBLIC_PATHS = {"/api/register"}


def _enc_disabled():
    return JSONResponse({"error": "Encrypted transport disabled."},
                        status_code=404)


def _enc_response(result) -> tuple:
    """Normalize a handler result into (json-able value, status code)."""
    if isinstance(result, JSONResponse):
        try:
            return json.loads(result.body.decode()), result.status_code
        except Exception:
            return {"error": "Malformed response."}, result.status_code
    return result, 200


def _enc_dispatch(logical: str, request: Request, payload: dict):
    """Route an authenticated channel request to the existing handlers."""
    q = payload.get("q") or {}
    b = payload.get("b") or payload  # accept flat or nested bodies
    if logical == "/api/me":
        return api_me(request)
    if logical == "/api/messages":
        return api_messages(request, int(q.get("limit", 50)))
    if logical == "/api/users":
        return api_users(request, str(q.get("q", "")), int(q.get("limit", 20)))
    if logical == "/api/conversations":
        return api_conversations(request)
    if logical == "/api/logout":
        return api_logout(request)
    if logical.startswith("/api/dm/") and len(logical) > len("/api/dm/"):
        return api_dm_history(request, logical[len("/api/dm/"):],
                              int(q.get("limit", 50)))
    if logical == "/api/register":
        return api_register(request, name=str(b.get("name", "")),
                            username=str(b.get("username", "")),
                            password=str(b.get("password", "")),
                            confirm=str(b.get("confirm", "")))
    raise enc.EncError("Unknown endpoint.")


async def _enc_authenticated_call(request: Request, logical: str) -> JSONResponse:
    """Verify the channel proof, decrypt the body, dispatch, encrypt the reply."""
    sid = request.headers.get(ENC_SID_HDR)
    try:
        raw = await request.body()
        enc.verify_request(sid, request.method, logical,
                           int(request.headers.get(ENC_TS_HDR, "0") or 0),
                           request.headers.get(ENC_MAC_HDR, ""), raw)
        payload = enc.decrypt_request_body(sid, raw.decode("ascii", "replace"))
        user = enc.session_user(sid)
        if not user and logical not in ENC_PUBLIC_PATHS:
            return JSONResponse({"error": "Not logged in."}, status_code=401)
        allowed, retry = check_rate_limit(f"encapi:{sid}", ENC_RATE_PER_MIN, 60)
        if not allowed:
            return JSONResponse({"error": "Too many requests."}, status_code=429,
                                headers={"Retry-After": str(retry)})
        request.state.enc_user = user
        result = _enc_dispatch(logical, request, payload)
        value, status = _enc_response(result)
        signed_in = user is not None
        if logical == "/api/register" and status < 400 and not signed_in:
            # Cookie auth logs a new user straight in; over the channel there is
            # no cookie, so bind the session to the freshly created user.
            row = db.query_one("SELECT id, name, username FROM users WHERE username = ?",
                               (str(payload.get("username", "")).strip(),))
            if row:
                fresh = {"id": row["id"], "name": row["name"],
                         "username": row["username"]}
                enc.bind_user(sid, fresh)
                signed_in = True
                value = {"ok": True, "user": fresh}
        sealed = enc.encrypt_response_body(sid, {"status": status, "data": value})
        gate_cookie = signed_in
    except enc.EncError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except ValueError:
        return JSONResponse({"error": "Malformed request."}, status_code=400)
    except Exception:
        log.exception("Encrypted API call failed (%s)", logical)
        return JSONResponse({"error": "Server error."}, status_code=500)
    resp = JSONResponse({"e": sealed})
    if gate_cookie:
        # Page gate only; useless without the channel keys (see ENC_COOKIE).
        resp.set_cookie(ENC_COOKIE, sid, httponly=True, samesite="lax")
    if logical == "/api/logout":
        resp.delete_cookie(ENC_COOKIE, samesite="lax")
        enc.drop_session(sid)  # after sealing, so the reply still decrypts
    return resp


if ENC_ENABLED:

    @app.get("/enc/status")
    def enc_status():
        """Server signing key + fingerprint (public, needed for pinning)."""
        info = enc.status()
        info["show_fingerprint"] = ENC_SHOW_FINGERPRINT
        return info

    @app.get("/enc/hello")
    def enc_hello():
        return enc.hello()

    @app.post("/enc/hello/finish")
    async def enc_hello_finish(request: Request):
        if (resp := _bad_origin(request)) is not None:
            return resp
        if (resp := _too_many(f"enchello:{_client_ip(request)}",
                              ENC_HANDSHAKE_PER_MIN)) is not None:
            return resp
        try:
            body = await request.json()
            return enc.finish(str(body.get("sid", "")), str(body.get("eph", "")))
        except enc.EncError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except Exception:
            return JSONResponse({"error": "Malformed request."}, status_code=400)

    @app.post("/enc/login")
    async def enc_login(request: Request):
        """Credentials travel inside the channel; no cookie is ever set."""
        if (resp := _bad_origin(request)) is not None:
            return resp
        if (resp := _too_many(f"enclogin:{_client_ip(request)}",
                              RATE_LOGIN_PER_MIN)) is not None:
            return resp
        sid = request.headers.get(ENC_SID_HDR)
        try:
            raw = await request.body()
            enc.verify_request(sid, "POST", "/enc/login",
                               int(request.headers.get(ENC_TS_HDR, "0") or 0),
                               request.headers.get(ENC_MAC_HDR, ""), raw)
            payload = enc.decrypt_request_body(sid, raw.decode("ascii", "replace"))
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            if not username or not password:
                return _enc_seal_error(sid, "Username and password are required.")
            row = db.query_one("SELECT * FROM users WHERE username = ?", (username,))
            if not row:
                auth.dummy_verify(password)
                return _enc_seal_error(sid, "Invalid username or password.", 401)
            if not auth.verify_password(password, row["password_hash"]):
                return _enc_seal_error(sid, "Invalid username or password.", 401)
            user = {"id": row["id"], "name": row["name"],
                    "username": row["username"]}
            enc.bind_user(sid, user)
            sealed = enc.encrypt_response_body(
                sid, {"status": 200, "data": {"ok": True, "user": user}})
        except enc.EncError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except Exception:
            log.exception("Encrypted login failed")
            return JSONResponse({"error": "Server error."}, status_code=500)
        resp = JSONResponse({"e": sealed})
        resp.set_cookie(ENC_COOKIE, sid, httponly=True, samesite="lax")
        return resp

    def _enc_seal_error(sid: str, message: str, status: int = 401) -> JSONResponse:
        """Login errors are sealed too, so the reason stays confidential."""
        try:
            sealed = enc.encrypt_response_body(
                sid, {"status": status, "data": {"error": message}})
            return JSONResponse({"e": sealed})
        except enc.EncError:
            return JSONResponse({"error": message}, status_code=status)

    @app.api_route("/enc/{logical:path}", methods=["GET", "POST", "DELETE"])
    async def enc_api(request: Request, logical: str):
        # Only the public chat API is reachable over the channel; the admin
        # panel and cookie-auth endpoints are deliberately not bridged.
        logical = "/" + logical.lstrip("/")
        if not logical.startswith("/api/"):
            return JSONResponse({"error": "Unknown endpoint."}, status_code=404)
        return await _enc_authenticated_call(request, logical)

    @app.websocket("/enc/ws")
    async def enc_ws(ws: WebSocket):
        if not origin_allowed(ws.headers.get("origin"), ws.headers.get("host", "")):
            await ws.close(code=4403)
            return
        sid = ws.query_params.get("sid")
        user = enc.session_user(sid)
        if not user:
            await ws.close(code=4401)
            return
        await manager.connect(ws, user["id"], sid=sid)
        # Per-socket keys: a reloaded page opens a new socket while the old one
        # may still be registered, so counters must not be shared across sockets.
        salt, ws_c2s, ws_s2c = enc.new_socket_material(sid)
        sock = {"chain_c2s": ws_c2s, "chain_s2c": ws_s2c, "ctr_c2s": 0, "ctr_s2c": 0}
        manager.peers[ws]["sock"] = sock
        await ws.send_json({"hello": {"salt": salt, "sid": sid}})

        def decode(raw: str):
            # {"e": "<sealed frame>"} -> inner app dict
            frame = json.loads(raw)
            if not isinstance(frame, dict) or "e" not in frame:
                raise enc.EncError("Expected an encrypted frame.")
            return enc.open_ws(sock, str(frame["e"]))

        try:
            await _ws_loop(ws, user, decode)
        except Exception:
            pass
        finally:
            await manager.disconnect(ws)
