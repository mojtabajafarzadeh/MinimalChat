"""Transport-layer hardening. Stdlib only, single-process friendly.

- Sliding-window rate limiter (in-memory; fits the single-process model).
- Same-origin check for browser-initiated POST / WebSocket requests.
- Security headers middleware.
"""
import threading
import time
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()
_purges = 0

# Populated once from config; see client_ip() for why this is opt-in.
_trusted_proxies: list = []


def configure_trusted_proxies(cidrs: list) -> None:
    """Declare which peers may have their X-Forwarded-For believed.

    Parsed once at startup. Anything unparseable is dropped with a warning
    rather than silently ignored, so a typo cannot quietly turn the trusted
    list into "no proxies" while the operator believes it is active.
    """
    global _trusted_proxies
    nets = []
    for raw in cidrs or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            nets.append(ip_network(text, strict=False))
        except ValueError:
            # Startup logs the warning; here we just refuse the entry.
            continue
    _trusted_proxies = nets


def trusted_proxies() -> list:
    return list(_trusted_proxies)


def is_trusted_proxy(address: str) -> bool:
    if not address or not _trusted_proxies:
        return False
    try:
        ip = ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in _trusted_proxies)


def client_ip(peer: str, forwarded_for: str | None) -> str:
    """Rate-limit key for a request.

    Defaults to the direct peer address, which is the only thing that cannot
    be spoofed by the client. That is correct on a directly-exposed server and
    WRONG behind a reverse proxy: every user then shares one key, so
    MAX_SOCKETS_PER_IP becomes a site-wide socket ceiling and the login limit
    becomes a site-wide login rate (I-01).

    When TRUSTED_PROXY_CIDRS names the proxy, X-Forwarded-For is consulted --
    but only from a request that actually arrived from a listed peer, and the
    RIGHTMOST untrusted entry is taken. Walking from the right is what makes it
    safe: a client can prepend anything to the header, but it cannot control
    what the real proxy appends.
    """
    if not forwarded_for or not is_trusted_proxy(peer):
        return peer or "unknown"

    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    if not hops:
        return peer or "unknown"

    for candidate in reversed(hops):
        if not is_trusted_proxy(candidate):
            return candidate
    # Every hop was a listed proxy: the leftmost is the closest to the client.
    return hops[0]


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
        # Bound memory. Purging rebuilds the dict, so under a flood of fresh
        # keys this is O(n) per insert -- amortised by only doing it every
        # 512 inserts instead of on every one past the cap (I-09).
        global _purges
        _purges += 1
        if len(_hits) > 20000 and _purges >= 512:
            _hits.update(
                {k: v for k, v in _hits.items() if v and v[-1] > now - window_sec}
            )
            _purges = 0
        return True, 0


# --- admin brute-force backoff (A-04) ---
#
# The sliding window above bounds the *rate* of attempts; it does not bound
# the *total*. An attacker who keeps guessing inside a generous window still
# gets an unbounded number of tries, which is what makes an online dictionary
# attack on a single admin credential practical. So below the window, failures
# accrue their own tally and the delay grows exponentially:
#
#     delay = step * 2 ** max(0, failures - grace)     capped at max
#
# The grace period is what keeps this from being an own goal: the first few
# mistakes are free, because an operator who fat-fingers their own password
# twice should not be shown a 429. From there the curve is steep enough that a
# scripted run is hopeless -- with the defaults, the 11th failure in a row
# costs two minutes per guess, and a dictionary of any size becomes academic.
#
# The tally decays with a half-life, so a real operator who fumbles is never
# locked out: the delay fades while they read the README.
#
# Per client IP, which is the same scope as the rate limit and the only one
# available without shared state. A botnet gets one tally per address; that
# limit is inherent to the single-process model and is why the password
# strength warning (see app.admin.password_strength) exists alongside this.
#
# The thresholds are bound to a few names at import time, on purpose: the
# module must never reach back into app.config (config imports nothing from
# the package, and keeping it that way is what lets run.py read settings
# before the app is importable). `configure_admin_lockout` sets them, and it
# is called once at startup by app.admin.apply_lockout_config.
_lockouts: dict[str, tuple[float, float]] = {}
_lockouts_lock = threading.Lock()
_lockout_purges = 0
_admin_delay_step = 0.0
_admin_delay_grace = 0.0
_admin_max_delay = 0.0
_admin_half_life = 300.0


def configure_admin_lockout(step: float, grace: float, maximum: float,
                            half_life: float) -> None:
    """Set the backoff curve. Called once at startup, and by tests."""
    global _admin_delay_step, _admin_delay_grace, _admin_max_delay
    global _admin_half_life
    _admin_delay_step = max(0.0, float(step))
    _admin_delay_grace = max(0.0, float(grace))
    _admin_max_delay = max(0.0, float(maximum))
    _admin_half_life = max(1.0, float(half_life))


def _decayed(fails: float, last: float, now: float, half_life: float) -> float:
    """A failure tally aged by one half-life per `half_life` seconds.

    elapsed is clamped at zero: a negative one would make 0.5 ** negative
    LARGER than 1, i.e. a backwards clock would inflate the tally rather than
    fade it, and time.monotonic() going backwards is not worth defending
    against -- but free failures that decay into a real delay is not worth
    allowing either.
    """
    elapsed = max(0.0, now - last)
    return fails * (0.5 ** (elapsed / half_life))


def admin_failures(key: str, now: float | None = None) -> float:
    """Current decayed failure count for `key`. 0 when there are none."""
    now = time.monotonic() if now is None else now
    with _lockouts_lock:
        fails, last = _lockouts.get(key, (0.0, now))
    return _decayed(fails, last, now, _admin_half_life)


def admin_delay(fails: float) -> float:
    """Seconds an admin login attempt should wait, for a decayed tally.

    0 means "try now". Step 0 disables the whole curve, leaving only the
    sliding window above.
    """
    excess = max(0.0, fails - _admin_delay_grace)
    if excess <= 0:
        return 0.0
    # 2**excess, capped: a long-running attack must not reach an overflow or
    # an absurd Retry-After, so the exponent is clamped before it is used.
    return min(_admin_delay_step * (2.0 ** min(excess, 30.0)), _admin_max_delay)


def register_admin_failure(key: str, now: float | None = None) -> float:
    """Count one failed admin login; return the resulting delay in seconds."""
    global _lockout_purges
    now = time.monotonic() if now is None else now
    with _lockouts_lock:
        fails, last = _lockouts.get(key, (0.0, now))
        tally = _decayed(fails, last, now, _admin_half_life) + 1.0
        _lockouts[key] = (tally, now)
        # Bound memory; same amortised shape as check_rate_limit.
        _lockout_purges += 1
        if len(_lockouts) > 1000 and _lockout_purges >= 128:
            _lockouts.update(
                {k: v for k, v in _lockouts.items()
                 if _decayed(v[0], v[1], now, _admin_half_life) >= 1.0}
            )
            _lockout_purges = 0
        return admin_delay(tally)


def clear_admin_failures(key: str) -> None:
    """A correct password wipes the tally -- the operator is back in."""
    with _lockouts_lock:
        _lockouts.pop(key, None)


def clear_admin_state() -> None:
    """Forget every tally. Tests only."""
    with _lockouts_lock:
        _lockouts.clear()


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
    plain-HTTP local dev in browsers that cache it).

    The CSP is the layer that would contain a future XSS. Everything the app
    loads is same-origin -- static files, no third parties, no CDN -- so a
    strict policy costs nothing, and nothing forces 'unsafe-inline':
    every page's logic is an external .js file (login.js, register.js,
    admin.js), so `script-src` is plain `'self'`. `style-src` still needs
    'unsafe-inline' for two reasons: no nonce plumbing, and the identity
    banner in api.js builds its own rules with element.style.cssText.

    connect-src is built per response from the Host the client actually
    reached. `'self'` alone would NOT permit the WebSocket -- a `ws:` scheme
    is not same-origin with an `http:` page as far as CSP is concerned -- so
    the app's own origin has to be spelled out in both forms. Deriving it
    from Host is what keeps the policy tight: an injected script can reach no
    host other than the one serving the page.
    """

    @staticmethod
    def _connect_src(host: str, scheme: str) -> str:
        """Same-origin fetches plus the WebSocket, and nothing else.

        An empty/unparseable Host yields no host sources at all. A broken Host
        cannot widen the policy: without a host source a connect is refused
        rather than allowed anywhere.
        """
        host = (host or "").strip()
        if not host or any(c in host for c in " \t\r\n/\\\"'<>"):
            return ""
        # Plain HTTP may legitimately need ws://, but announcing it over TLS
        # would hand an injected script a cleartext channel out.
        ws_scheme = "wss" if scheme == "https" else "ws"
        return f"'self' {ws_scheme}://{host}"

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        directives = [
            "default-src 'self'",
            # No 'unsafe-inline': every page's logic is an external file.
            "script-src 'self'",
            # Still needed: api.js styles the identity banner through
            # element.style, and there are no inline <style> blocks.
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            # The service worker is same-origin and does nothing but claim
            # clients. Stating it here means the worker stays same-origin
            # even if default-src is ever widened, and it documents that the
            # worker is allowed at all.
            "worker-src 'self'",
        ]
        # connect-src is built from the Host the client reached. An absent or
        # unusable Host yields NO connect-src at all, and with no directive
        # the policy falls back to default-src -- which is 'self'. That blocks
        # the WebSocket for that one response rather than for the app.
        if connect_src := self._connect_src(request.headers.get("host"),
                                             request.url.scheme):
            directives.append(f"connect-src {connect_src}")
        directives += [
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(directives)
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
