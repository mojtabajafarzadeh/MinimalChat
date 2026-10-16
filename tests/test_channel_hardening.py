"""Encrypted-channel hardening: A-10, C-02, C-05, C-09.

Each of these is invisible in the DOM and in a normal request/response:

- A-10 (cookie Secure flag) only differs on an HTTPS deployment.
- C-02 (replay claim atomicity) needs two threads calling verify_request with
  the same captured proof at the same moment.
- C-05 (the unused long-term dh key) is a secret nobody reads, so its absence
  from new key files is the only observable change -- and old key files that
  still contain it must keep working.
- C-09 (future timestamps) is a window only a skewed or hostile client opens.
"""
import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import enc


class _FreshKeyFile:
    """Point enc at a throwaway key file and reset the cached keys."""

    def __init__(self, tmp: Path):
        self.path = tmp / "enc_keys.json"
        self.saved_path = enc.KEYS_PATH
        self.saved_keys = enc._keys

    def __enter__(self):
        enc.KEYS_PATH = self.path
        enc._keys = None
        return self

    def __exit__(self, *exc):
        enc.KEYS_PATH = self.saved_path
        enc._keys = self.saved_keys
        return False


class SigningKeyTests(unittest.TestCase):
    """C-05: the long-term dh key was dead weight."""

    def test_new_key_files_contain_only_the_signing_key(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with _FreshKeyFile(Path(d)):
                raw = enc.ensure_secret_file(enc.KEYS_PATH, enc._build_key_json)
                stored = json.loads(raw)
        self.assertIn("sig", stored)
        self.assertNotIn(
            "dh", stored,
            "a long-term ECDH key is being generated again; nothing reads it, "
            "and it implies forward secrecy the handshake does not provide")

    def test_a_key_file_that_still_contains_dh_still_loads(self):
        """Existing installations have it on disk; they must keep the same
        fingerprint, not be treated as a corrupt key file."""
        import tempfile
        from cryptography.hazmat.primitives.asymmetric import ec
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            legacy = {
                "dh": enc.b64e(ec.generate_private_key(
                    ec.SECP256R1()).private_numbers().private_value
                    .to_bytes(32, "big")),
                "sig": enc.b64e(ec.generate_private_key(
                    ec.SECP256R1()).private_numbers().private_value
                    .to_bytes(32, "big")),
            }
            (tmp / "enc_keys.json").write_text(json.dumps(legacy))
            with _FreshKeyFile(tmp):
                keys = enc.server_keys()
                status = enc.status()
        self.assertIn("sig", keys)
        self.assertEqual(
            status["fingerprint"],
            enc.normalize_fingerprint(status["fingerprint"]),
            "a legacy key file produced a non-canonical fingerprint")

    def test_a_key_file_without_a_signing_key_is_rejected_clearly(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "enc_keys.json").write_text(json.dumps({"nope": "x"}))
            with _FreshKeyFile(tmp):
                with self.assertRaises(Exception) as ctx:
                    enc.server_keys()
        self.assertIn("signing key", str(ctx.exception).lower())


class TimestampWindowTests(unittest.TestCase):
    """C-09: abs() accepted timestamps up to the window in the future."""

    def _session(self, now=None):
        import time
        return {"mac_c2s": b"\x01" * 32,
                "seen_nonces": enc.OrderedDict(),
                "last_seen": time.monotonic()}

    def _proof(self, session, ts):
        import time
        nonce = enc.secrets.token_bytes(12)
        key = enc._one_off_mac_key(session["mac_c2s"], nonce)
        body = b'{"x":1}'
        tag = enc.AESGCM(key).encrypt(
            nonce, b"", enc.mac_input("POST", "/api/me", ts, nonce, body))
        return enc.b64e(nonce + tag), body

    def _verify(self, ts_delta):
        """Run verify_request with ts offset by ts_delta seconds."""
        import time
        sid = "ts-test"
        session = self._session()
        with enc._state_lock:
            enc._sessions[sid] = session
        try:
            ts = int(time.time()) + ts_delta
            blob, body = self._proof(session, ts)
            enc.verify_request(sid, "POST", "/api/me", ts, blob, body)
            return None
        except enc.EncError as e:
            return str(e)
        finally:
            with enc._state_lock:
                enc._sessions.pop(sid, None)

    def test_now_is_accepted(self):
        self.assertIsNone(self._verify(0))

    def test_slightly_stale_is_accepted(self):
        self.assertIsNone(self._verify(-30), "30s of clock skew was rejected")

    def test_very_stale_is_rejected(self):
        self.assertIn("Stale", self._verify(-3600))

    def test_a_far_future_timestamp_is_rejected(self):
        """The gap C-09: abs() accepted up to REPLAY_WINDOW ahead."""
        self.assertIn(
            "Stale", self._verify(enc.REPLAY_WINDOW),
            "a timestamp a full window in the future is still accepted, so "
            "the future side of the window is as wide as the past side")

    def test_a_slightly_fast_clock_is_tolerated(self):
        self.assertIsNone(
            self._verify(enc.REPLAY_FUTURE_TOLERANCE),
            "a client whose clock runs a few seconds fast was rejected")


class ReplayClaimTests(unittest.TestCase):
    """C-02: the marker was claimed in two steps, check then insert.

    Honest scoping: the window between `if marker in seen` and
    `seen[marker] = True` contains no I/O, so under CPython's GIL a plain
    thread preemption cannot land inside it -- measured directly: eight threads
    racing the same key, 50k iterations each, exactly one ever passed. A
    behavioural test cannot tell the two versions apart.

    What the fix buys is independence from that: the claim is one critical
    section, so it stays correct if anyone later adds a log line, a callback
    or an await inside the check. These tests assert that shape, and the two
    properties that actually have observable behaviour.
    """

    def _arm(self, sid):
        import time
        session = {"mac_c2s": b"\x01" * 32,
                   "seen_nonces": enc.OrderedDict(),
                   "last_seen": time.monotonic()}
        with enc._state_lock:
            enc._sessions[sid] = session
        return session

    def _proof(self, session, ts, body=b'{"x":1}'):
        nonce = enc.secrets.token_bytes(12)
        key = enc._one_off_mac_key(session["mac_c2s"], nonce)
        tag = enc.AESGCM(key).encrypt(
            nonce, b"", enc.mac_input("POST", "/api/me", ts, nonce, body))
        return enc.b64e(nonce + tag), body

    def _with_session(self, fn):
        sid = "claim-test"
        session = self._arm(sid)
        try:
            return fn(sid, session)
        finally:
            with enc._state_lock:
                enc._sessions.pop(sid, None)

    def test_a_captured_request_is_rejected_on_replay(self):
        """The property the mechanism exists to provide."""
        import time

        def run(sid, session):
            ts = int(time.time())
            blob, body = self._proof(session, ts)
            enc.verify_request(sid, "POST", "/api/me", ts, blob, body)
            with self.assertRaises(enc.EncError) as ctx:
                enc.verify_request(sid, "POST", "/api/me", ts, blob, body)
            self.assertIn("Replayed", str(ctx.exception))
            return True

        self.assertTrue(self._with_session(run))

    def test_concurrent_copies_of_one_proof_are_accepted_once(self):
        import time

        def run(sid, session):
            ts = int(time.time())
            blob, body = self._proof(session, ts)
            accepted = []
            rejected = []
            barrier = threading.Barrier(8)

            def attempt():
                barrier.wait()
                try:
                    enc.verify_request(sid, "POST", "/api/me", ts, blob, body)
                    accepted.append(1)
                except enc.EncError:
                    rejected.append(1)

            threads = [threading.Thread(target=attempt) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            self.assertEqual(
                len(accepted), 1,
                f"{len(accepted)} of 8 concurrent copies were accepted")
            self.assertEqual(len(rejected), 7)
            return True

        self.assertTrue(self._with_session(run))

    def test_the_marker_is_claimed_under_the_state_lock(self):
        """Structural: check and insert must be one critical section."""
        import ast
        src = (ROOT / "app" / "enc.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "verify_request")
        body = ast.get_source_segment(src, fn) or ""

        claim_at = body.index("seen[marker] = True")
        check_at = body.index("if marker in seen")
        lock_at = body.rindex("with _state_lock:", 0, claim_at)
        self.assertLess(
            check_at, claim_at, "the insert happens before the check")
        self.assertLess(
            lock_at, check_at,
            "the replay check is outside the lock, so claim and check are two "
            "critical sections again")

    def test_an_invalid_proof_does_not_consume_a_cache_slot(self):
        """Verification must precede the claim: otherwise an attacker sending
        junk proofs could fill the dedupe cache and evict real markers, which
        is precisely how replay protection would be defeated."""
        import time

        def run(sid, session):
            ts = int(time.time())
            before = len(session["seen_nonces"])
            for i in range(50):
                blob, body = self._proof(session, ts)
                with self.assertRaises(enc.EncError):
                    # Same nonce, different body: the MAC must not verify.
                    enc.verify_request(sid, "POST", "/api/me", ts, blob,
                                       b'{"tampered":true}')
            self.assertEqual(
                len(session["seen_nonces"]), before,
                "a request that failed verification still claimed a marker")
            return True

        self.assertTrue(self._with_session(run))


class CookieSecureFlagTests(unittest.TestCase):
    """A-10: the gate cookie was set without Secure while every other
    cookie in the app used it."""

    def test_enc_cookie_is_set_with_secure_on_https(self):
        src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        occurrences = src.count("set_cookie(ENC_COOKIE")
        self.assertGreaterEqual(occurrences, 2,
                                "expected the enc_sid cookie in two places")
        self.assertEqual(
            src.count("set_cookie(ENC_COOKIE, sid, httponly=True, "
                      'samesite="lax")'),
            0,
            "an enc_sid set_cookie call is still missing the secure flag")
        # Every set_cookie for ENC_COOKIE must carry secure=.
        for chunk in src.split("set_cookie(ENC_COOKIE")[1:]:
            call = chunk[:chunk.index(")\n") if ")\n" in chunk else 200]
            with self.subTest(call=call.strip()[:80]):
                self.assertIn("secure=", call,
                              "enc_sid cookie is set without the Secure flag")

    def test_every_cookie_in_the_app_uses_the_same_secure_policy(self):
        src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        for name in ("SESSION_COOKIE", "admin.ADMIN_COOKIE", "ENC_COOKIE"):
            for chunk in src.split(f"set_cookie({name}")[1:]:
                call = chunk[:chunk.index(")\n") if ")\n" in chunk else 200]
                with self.subTest(cookie=name):
                    self.assertIn(
                        "secure=", call,
                        f"{name} is set without the Secure flag, so it can "
                        "ride plaintext even on an HTTPS deployment")


if __name__ == "__main__":
    unittest.main()