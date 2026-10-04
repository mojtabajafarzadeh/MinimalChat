"""Application-layer encrypted transport ("Option B"): replaces TLS inside the app.

Threat model: the network is hostile and TLS is unavailable. Goals are traffic
confidentiality plus authentication of the server, so a network attacker can
neither read the traffic nor impersonate the server (MITM).

Design -- all primitives come from `cryptography` (server) and WebCrypto
(client); no custom primitive is invented, only a documented composition:

  Handshake
    1. GET  /enc/hello          -> {sid, server ephemeral ECDH P-256 pub,
                                   signing pub, fingerprint, ts}
    2. POST /enc/hello/finish   <- {eph: client ephemeral pub}
         shared = ECDH(server_eph_private, client_pub)
         transcript = "chat-enc-v1"|sid|client_pub|server_eph|signing_pub
         signature = ECDSA-SHA256(server_signing_private, transcript)  [r||s wire]
    3. client verifies that signature against the PINNED signing key. This is
       the anti-MITM step: without pinning, any server could impersonate us.
    4. both sides derive sub-keys (see _subkeys)

  Transport
    Frame = nonce(12 random bytes) || AES-256-GCM(key, plaintext, aad)
    The nonce is random per frame (no counter arithmetic to get wrong) and the
    AAD binds the transport, direction and a monotonic counter, so WebSocket
    replays/reordering are rejected. HTTP bodies carry their counter inside the
    ciphertext instead, because HTTP requests may be concurrent.
    Each transport/direction pair owns an independent one-way HKDF chain
    (chain_{i+1} = HKDF(chain_i, nonce_i)); HKDF is one-way, so earlier chain
    states cannot be recomputed from a later one -> forward secrecy per session.

  Request proofs (HTTP without cookies)
    A cookie would travel in cleartext and could be stolen by a snooper, so the
    encrypted mode uses no cookies. Every API call instead carries a MAC over
    method/path/timestamp/nonce/body under a channel MAC key, and the body is
    encrypted. Possession of the token alone is useless without the channel key.

Scope: this encrypts the transport. It is NOT end-to-end encryption of stored
history -- the server can still read messages at rest (see app/crypto.py).
"""
import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .paths import data_dir, ensure_secret_file

log = logging.getLogger("chat")

PROTOCOL = "chat-enc-v1"
KEYS_FILE = "enc_keys.json"
KEYS_PATH = data_dir() / KEYS_FILE
HANDSHAKE_TTL = 30      # seconds a pending handshake stays valid
SESSION_TTL = 3600      # idle session lifetime
REPLAY_WINDOW = 60      # accepted clock skew for request proofs (seconds)


class EncError(Exception):
    """Channel failure. Messages are safe to show to the client."""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode((text or "").encode("ascii"), validate=True)
    except Exception as exc:
        raise EncError("Malformed value.") from exc


def _hkdf(ikm: bytes, salt: bytes, info: str, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info.encode()).derive(ikm)


# --------------------------------------------------------------------------
# persistent server keys
# --------------------------------------------------------------------------

_keys_lock = threading.Lock()
_keys: dict | None = None


def _pub_raw(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def _fingerprint(pub: bytes) -> str:
    digest = hashlib.sha256(pub).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def _build_key_json() -> bytes:
    dh = ec.generate_private_key(ec.SECP256R1())
    sig = ec.generate_private_key(ec.SECP256R1())
    return json.dumps({
        "dh": b64e(dh.private_numbers().private_value.to_bytes(32, "big")),
        "sig": b64e(sig.private_numbers().private_value.to_bytes(32, "big")),
    }).encode("utf-8")


def _parse_key_json(raw: bytes) -> dict:
    stored = json.loads(raw.decode("utf-8"))
    return {
        "dh": ec.derive_private_key(
            int.from_bytes(b64d(stored["dh"]), "big"), ec.SECP256R1()),
        "sig": ec.derive_private_key(
            int.from_bytes(b64d(stored["sig"]), "big"), ec.SECP256R1()),
    }


def server_keys() -> dict:
    """Long-term ECDH + signing keys, persisted so the fingerprint is stable.

    Creation goes through ensure_secret_file(), so all workers -- threads and
    processes -- end up with the SAME key. That matters more here than for the
    message key: a per-process signing key would change the published
    fingerprint and make every pinned client believe it is being MITM-ed,
    which would silently destroy the TOFU model.
    """
    global _keys
    with _keys_lock:
        if _keys is not None:
            return _keys
        path = KEYS_PATH
        try:
            _keys = _parse_key_json(ensure_secret_file(path, _build_key_json))
        except Exception as exc:
            raise RuntimeError(
                f"{path} is unreadable or malformed ({exc}). Restore it from a "
                "backup: replacing the server signing key changes the published "
                "fingerprint and every pinned client will warn about a possible "
                "MITM attack."
            ) from exc
        return _keys


# --------------------------------------------------------------------------
# handshake state
# --------------------------------------------------------------------------

_state_lock = threading.RLock()
_pending: dict[str, dict] = {}
_sessions: dict[str, dict] = {}

CHAIN_LABELS = ("ws:c2s", "ws:s2c", "http:c2s", "http:s2c")
CHAIN_KEYS = ("chain_ws_c2s", "chain_ws_s2c", "chain_http_c2s", "chain_http_s2c")
MAC_KEYS = ("mac_c2s", "mac_s2c")


def _purge_locked(now: float) -> None:
    for sid in [s for s, v in _pending.items() if v["expires"] <= now]:
        _pending.pop(sid, None)
    for sid in [s for s, v in _sessions.items() if v["last_seen"] + SESSION_TTL <= now]:
        _sessions.pop(sid, None)


def _subkeys(shared: bytes, transcript: bytes, sid: str) -> dict:
    """One root secret -> independent per-transport/direction sub-keys.

    The salt is the protocol label (never empty): WebCrypto is happier with a
    non-empty HKDF salt, and both sides must agree byte for byte.
    """
    root = _hkdf(shared, hashlib.sha256(transcript).digest(),
                 f"{PROTOCOL}:root:{sid}")
    keys = {}
    for label, name in zip(CHAIN_LABELS, CHAIN_KEYS):
        keys[name] = _hkdf(root, PROTOCOL.encode(), f"{PROTOCOL}:{label}")
    keys["mac_c2s"] = _hkdf(root, PROTOCOL.encode(), f"{PROTOCOL}:mac:c2s")
    keys["mac_s2c"] = _hkdf(root, PROTOCOL.encode(), f"{PROTOCOL}:mac:s2c")
    return keys


def _transcript(label: str, client_pub: bytes, server_eph: bytes, signing: bytes) -> bytes:
    return b"|".join([PROTOCOL.encode(), label.encode(),
                      b64e(client_pub).encode(), b64e(server_eph).encode(),
                      b64e(signing).encode()])


def _der_to_raw(der: bytes) -> bytes:
    """ECDSA DER -> fixed 64-byte r||s (what WebCrypto expects)."""
    if len(der) < 8 or der[0] != 0x30:
        raise EncError("Malformed signature.")
    idx = 2
    if der[1] & 0x80:
        idx = 2 + (der[1] & 0x7F)
    parts = []
    for _ in range(2):
        if idx + 2 > len(der) or der[idx] != 0x02:
            raise EncError("Malformed signature.")
        length = der[idx + 1]
        parts.append(der[idx + 2:idx + 2 + length].lstrip(b"\x00"))
        idx += 2 + length
    r, s = parts
    return r.rjust(32, b"\x00")[-32:] + s.rjust(32, b"\x00")[-32:]


def hello() -> dict:
    """Step 1: ephemeral key, signing key, fingerprint."""
    keys = server_keys()
    eph = ec.generate_private_key(ec.SECP256R1())
    sid = secrets.token_hex(16)
    now = time.monotonic()
    with _state_lock:
        _purge_locked(now)
        _pending[sid] = {"eph": eph, "eph_pub": _pub_raw(eph), "expires": now + HANDSHAKE_TTL}
    signing_pub = _pub_raw(keys["sig"])
    return {
        "v": PROTOCOL,
        "sid": sid,
        "eph": b64e(_pub_raw(eph)),
        "signing": b64e(signing_pub),
        "fingerprint": _fingerprint(signing_pub),
        "ts": int(time.time()),
    }


def finish(sid: str, client_pub_b64: str) -> dict:
    """Step 2: derive the channel and sign the transcript for the client."""
    keys = server_keys()
    with _state_lock:
        _purge_locked(time.monotonic())
        pending = _pending.pop(sid, None)
    if pending is None:
        raise EncError("Handshake expired or unknown. Try again.")
    client_pub_raw = b64d(client_pub_b64)
    if len(client_pub_raw) != 65:
        raise EncError("Invalid client key.")
    try:
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), client_pub_raw)
    except Exception as exc:
        raise EncError("Invalid client key.") from exc
    signing_pub = _pub_raw(keys["sig"])
    transcript = _transcript(sid, client_pub_raw, pending["eph_pub"], signing_pub)
    shared = pending["eph"].exchange(ec.ECDH(), client_pub)
    signature = _der_to_raw(keys["sig"].sign(transcript, ec.ECDSA(hashes.SHA256())))
    now = time.monotonic()
    with _state_lock:
        _sessions[sid] = {
            **_subkeys(shared, transcript, sid),
            "sid": sid,
            "transcript": b64e(transcript),
            "ctr_c2s": 0,
            "ctr_s2c": 0,
            "user": None,
            "seen_nonces": set(),
            "last_seen": now,
        }
    return {"sig": b64e(signature), "sid": sid, "ts": int(time.time())}


def verify_signature(sid: str, signing_pub_b64: str, signature_b64: str) -> None:
    """Reference implementation of the client-side anti-MITM check.

    The browser performs the identical verification in enc.js; this exists so
    the Python test harness can prove the server's signature is checkable.
    """
    with _state_lock:
        session = _sessions.get(sid)
    if session is None:
        raise EncError("Unknown session.")
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b64d(signing_pub_b64))
        raw = b64d(signature_b64)
        if len(raw) != 64:
            raise EncError("Malformed signature.")
        pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                        int.from_bytes(raw[32:], "big")),
                   b64d(session["transcript"]), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, InvalidTag) as exc:
        raise EncError("Server signature invalid (possible MITM).") from exc
    except EncError:
        raise
    except Exception as exc:
        raise EncError("Signature check failed.") from exc


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------

def get_session(sid: str | None) -> dict:
    if not sid:
        raise EncError("Missing session.")
    with _state_lock:
        session = _sessions.get(sid)
        if session is None:
            raise EncError("Session expired. Reconnect.")
        session["last_seen"] = time.monotonic()
        return session


def session_user(sid: str | None):
    try:
        return get_session(sid).get("user")
    except EncError:
        return None


def bind_user(sid: str, user: dict) -> None:
    get_session(sid)["user"] = user


def drop_session(sid: str | None) -> None:
    if not sid:
        return
    with _state_lock:
        session = _sessions.pop(sid, None)
    if session:
        for key in CHAIN_KEYS + MAC_KEYS:
            session[key] = b"\x00" * 32
        session["seen_nonces"].clear()


# --------------------------------------------------------------------------
# WebSocket frames (ordered stream -> counter in AAD)
# --------------------------------------------------------------------------
# Chain keys and counters are per SOCKET, not per session: a page reload opens a
# new socket while the old one may still linger, and a shared counter would
# desynchronise the client's AES-GCM nonces (silently dropping messages).


def _step(chain: bytes, nonce: bytes, label: str) -> tuple[bytes, bytes]:
    return (_hkdf(chain, nonce, f"{PROTOCOL}:msg:{label}"),
            _hkdf(chain, nonce, f"{PROTOCOL}:chain:{label}"))


def new_socket_material(sid: str) -> tuple:
    """Fresh per-socket keys + salt, derived from the session's ws chains."""
    session = get_session(sid)
    salt = secrets.token_bytes(16)
    c2s = _hkdf(session["chain_ws_c2s"], salt, f"{PROTOCOL}:ws:c2s")
    s2c = _hkdf(session["chain_ws_s2c"], salt, f"{PROTOCOL}:ws:s2c")
    return b64e(salt), c2s, s2c


def seal_ws(sock: dict, obj: dict) -> str:
    """Encrypt one outbound frame for a single socket."""
    nonce = secrets.token_bytes(12)
    counter = sock["ctr_s2c"]
    sock["ctr_s2c"] = counter + 1
    msg_key, sock["chain_s2c"] = _step(sock["chain_s2c"], nonce, "ws:s2c")
    payload = json.dumps({"c": counter, "p": obj}, separators=(",", ":")).encode()
    aad = f"{PROTOCOL}|ws|s2c|{counter}".encode()
    return b64e(nonce + AESGCM(msg_key).encrypt(nonce, payload, aad))


def open_ws(sock: dict, blob_b64: str) -> dict:
    """Decrypt one inbound frame for a single socket."""
    blob = b64d(blob_b64)
    if len(blob) < 12 + 16:
        raise EncError("Frame too short.")
    nonce = blob[:12]
    counter = sock["ctr_c2s"]
    sock["ctr_c2s"] = counter + 1
    msg_key, sock["chain_c2s"] = _step(sock["chain_c2s"], nonce, "ws:c2s")
    aad = f"{PROTOCOL}|ws|c2s|{counter}".encode()
    try:
        envelope = json.loads(AESGCM(msg_key).decrypt(nonce, blob[12:], aad))
    except (InvalidSignature, InvalidTag):
        raise EncError("Frame failed authentication.")
    except Exception as exc:
        raise EncError("Frame could not be decoded.") from exc
    if envelope.get("c") != counter:
        raise EncError("Out-of-order frame.")
    return envelope["p"]


# --------------------------------------------------------------------------
# HTTP bodies (may be concurrent -> counter inside the ciphertext)
# --------------------------------------------------------------------------

def _enc_body(session: dict, chain_key: str, label: str, obj: dict) -> str:
    """HTTP bodies use the session key directly with a random nonce.

    No ratchet here on purpose: HTTP is request/response and a rejected
    request must not desynchronize the channel. These keys live only as long as
    the channel session (one handshake per page load).
    """
    nonce = secrets.token_bytes(12)
    body = json.dumps(obj, separators=(",", ":")).encode()
    aad = f"{PROTOCOL}|http|{label}".encode()
    return b64e(nonce + AESGCM(session[chain_key]).encrypt(nonce, body, aad))


def _dec_body(session: dict, chain_key: str, label: str, blob_b64: str) -> dict:
    blob = b64d(blob_b64)
    if len(blob) < 12 + 16:
        raise EncError("Body too short.")
    nonce = blob[:12]
    aad = f"{PROTOCOL}|http|{label}".encode()
    try:
        return json.loads(AESGCM(session[chain_key]).decrypt(nonce, blob[12:], aad))
    except (InvalidSignature, InvalidTag):
        raise EncError("Body failed authentication.")
    except Exception as exc:
        raise EncError("Body could not be decoded.") from exc


def encrypt_request_body(sid: str, obj: dict) -> str:
    return _enc_body(get_session(sid), "chain_http_c2s", "http:c2s", obj)


def decrypt_request_body(sid: str, blob: str) -> dict:
    return _dec_body(get_session(sid), "chain_http_c2s", "http:c2s", blob)


def encrypt_response_body(sid: str, obj: dict) -> str:
    return _enc_body(get_session(sid), "chain_http_s2c", "http:s2c", obj)


def decrypt_response_body(sid: str, blob: str) -> dict:
    return _dec_body(get_session(sid), "chain_http_s2c", "http:s2c", blob)


# --------------------------------------------------------------------------
# request proofs (auth without cookies)
# --------------------------------------------------------------------------

def _one_off_mac_key(mac_key: bytes, nonce: bytes) -> bytes:
    return _hkdf(mac_key, nonce, f"{PROTOCOL}:mac")


def mac_input(method: str, path: str, ts: int, nonce: bytes, body: bytes) -> bytes:
    return b"|".join([PROTOCOL.encode(), method.upper().encode(), path.encode(),
                      str(ts).encode(), b64e(nonce).encode(),
                      hashlib.sha256(body or b"").hexdigest().encode()])


def sign_request(mac_c2s: bytes, method: str, path: str, ts: int,
                 nonce: bytes, body: bytes) -> str:
    """Reference client-side MAC, used by the Python harness.

    Wire format: base64(nonce || gcm_tag), where the tag authenticates empty
    plaintext under the one-off MAC key with the request as AAD.
    """
    key = _one_off_mac_key(mac_c2s, nonce)
    tag = AESGCM(key).encrypt(nonce, b"", mac_input(method, path, ts, nonce, body))
    return b64e(nonce + tag)


def verify_request(sid: str, method: str, path: str, ts: int,
                   mac_b64: str, body: bytes) -> None:
    """Verify a channel request proof.

    The proof blob already carries the nonce (base64(nonce||tag)), so the
    replay marker is derived from that real nonce -- never from a constant.
    """
    session = get_session(sid)
    if abs(int(time.time()) - int(ts)) > REPLAY_WINDOW:
        raise EncError("Stale request.")
    blob = b64d(mac_b64)
    if len(blob) != 12 + 16:
        raise EncError("Malformed proof.")
    nonce, tag = blob[:12], blob[12:]
    marker = f"{ts}:{b64e(nonce)}"
    seen = session["seen_nonces"]
    if marker in seen:
        raise EncError("Replayed request.")
    key = _one_off_mac_key(session["mac_c2s"], nonce)
    try:
        AESGCM(key).decrypt(nonce, tag, mac_input(method, path, ts, nonce, body))
    except (InvalidSignature, InvalidTag):
        raise EncError("Request proof invalid.")
    seen.add(marker)
    if len(seen) > 512:
        session["seen_nonces"] = set(list(seen)[-256:])


# --------------------------------------------------------------------------
# public info
# --------------------------------------------------------------------------

def status() -> dict:
    signing_pub = _pub_raw(server_keys()["sig"])
    return {"v": PROTOCOL, "signing": b64e(signing_pub),
            "fingerprint": _fingerprint(signing_pub)}