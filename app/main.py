"""Minimal real-time chat: FastAPI + WebSocket + SQLite. No ORM, no extra services."""
from pathlib import Path

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import auth, db
from .websocket import manager

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Minimal Chat")

SESSION_COOKIE = "session_id"


@app.on_event("startup")
def startup() -> None:
    db.init_db()


# ---------- helpers ----------


def current_user(request: Request):
    return auth.get_session_user(request.cookies.get(SESSION_COOKIE))


def page(name: str) -> FileResponse:
    return FileResponse(STATIC_DIR / name)


def valid_username(v: str) -> bool:
    v = v.strip()
    return 3 <= len(v) <= 32 and all(c.isalnum() or c in "_-" for c in v)


# ---------- pages ----------


@app.get("/")
def index(request: Request):
    if current_user(request):
        return RedirectResponse("/chat", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login")
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/chat", status_code=303)
    return page("login.html")


@app.get("/register")
def register_page(request: Request):
    if current_user(request):
        return RedirectResponse("/chat", status_code=303)
    return page("register.html")


@app.get("/chat")
def chat_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return page("chat.html")


# ---------- API ----------


@app.post("/api/register")
def api_register(
    name: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    confirm: str = Form(""),
):
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
        SESSION_COOKIE, auth.create_session(user_id), httponly=True, samesite="lax"
    )
    return resp


@app.post("/api/login")
def api_login(username: str = Form(""), password: str = Form("")):
    username = username.strip()
    if not username or not password:
        return JSONResponse({"error": "Username and password are required."}, status_code=400)
    row = db.query_one("SELECT * FROM users WHERE username = ?", (username,))
    if not row or not auth.verify_password(password, row["password_hash"]):
        return JSONResponse({"error": "Invalid username or password."}, status_code=401)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE, auth.create_session(row["id"]), httponly=True, samesite="lax"
    )
    return resp


@app.post("/api/logout")
def api_logout(request: Request):
    auth.delete_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/me")
def api_me(request: Request):
    user = current_user(request)
    if not user:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"id": user["id"], "name": user["name"], "username": user["username"]}


@app.get("/api/messages")
def api_messages(request: Request, limit: int = 50):
    if not current_user(request):
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    limit = max(1, min(limit, 200))
    rows = db.query_all(
        "SELECT m.id, m.content, m.created_at, u.name, u.username "
        "FROM messages m JOIN users u ON u.id = m.user_id "
        "ORDER BY m.id DESC LIMIT ?",
        (limit,),
    )
    return list(reversed([dict(r) for r in rows]))


# ---------- WebSocket ----------


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    user = auth.get_session_user(ws.cookies.get(SESSION_COOKIE))
    if not user:
        await ws.close(code=4401)
        return
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_json()
            content = str(data.get("content", "")).strip()
            if not content:
                continue
            if len(content) > 1000:
                content = content[:1000]
            try:
                msg_id = db.execute(
                    "INSERT INTO messages (user_id, content) VALUES (?, ?)",
                    (user["id"], content),
                )
                row = db.query_one(
                    "SELECT m.id, m.content, m.created_at, u.name, u.username "
                    "FROM messages m JOIN users u ON u.id = m.user_id WHERE m.id = ?",
                    (msg_id,),
                )
            except Exception:
                continue  # DB error: skip broadcast, keep connection alive
            if row:
                await manager.broadcast(dict(row))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await manager.disconnect(ws)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
