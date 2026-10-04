"""Transport-layer hardening. Stdlib only, single-process friendly.

- Sliding-window rate limiter (in-memory; fits the single-process model).
- Same-origin check for browser-initiated POST / WebSocket requests.
- Security headers middleware.
"""
import threading
import time
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()


def check_rate_limit(key: str, limit: int, window_sec: int) -> tuple[bool, int]:
    """Sliding-window check. Returns (allowed, retry_after_seconds)."""
    now = time.monotonic()
    with _hits_lock:
        recent = [t for t in _hits.get(key, []) if t > now - window_sec]
        if len(recent) >= limit:
            retry = int(recent[0] + window_sec - now) + 1
            _hits[key] = recent
            return False, max(retry, 1)
        recent.append(now)
        _hits[key] = recent
        if len(_hits) > 20000:  # bound memory: purge fully-expired keys
            _hits.update(
                {k: v for k, v in _hits.items() if v and v[-1] > now - window_sec}
            )
        return True, 0


def origin_allowed(origin: str | None, host: str) -> bool:
    """Browsers always send Origin on cross-origin POST/WS. Same-origin (or
    non-browser clients like curl, which send none) is allowed; anything
    else claiming a foreign origin is rejected."""
    if not origin:
        return True
    try:
        return urlparse(origin).netloc.lower() == (host or "").lower()
    except Exception:
        return False


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Minimal hardening headers. HSTS only over HTTPS (else it would brick
    plain-HTTP local dev in browsers that cache it)."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


class ChannelOnlyMiddleware(BaseHTTPMiddleware):
    """When the encrypted transport is enabled, the cookie-authenticated data
    endpoints must be unreachable.

    Otherwise the app would still accept a plaintext POST /api/login, and a
    password could cross the network in cleartext -- defeating the whole point.
    /api/config stays public (it advertises which transport is in use) and the
    admin panel lives under its own prefix.
    """

    def __init__(self, app, blocked_prefixes: tuple = ("/api/",), allowed: tuple = ("/api/config",)):
        super().__init__(app)
        self.blocked_prefixes = blocked_prefixes
        self.allowed = allowed

    async def dispatch(self, request, call_next):
        path = request.url.path
        for prefix in self.blocked_prefixes:
            if path.startswith(prefix) and path not in self.allowed:
                return JSONResponse(
                    {"error": "This endpoint requires the encrypted channel."},
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
        return await call_next(request)
