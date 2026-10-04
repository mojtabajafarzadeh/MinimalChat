"""Secret-file creation tests.

A secret file must be created exactly once, even when several threads or
several processes race for it, and no reader may ever observe a partially
written key. This is a regression test for a real bug: without the flock,
concurrent first-use generated competing keys and silently dropped messages.
"""
import hashlib
import multiprocessing as mp
import os
import tempfile
import threading
import unittest
from pathlib import Path

from app.paths import ensure_secret_file


class _Body:
    """Collects what each caller read/wrote, via a picklable helper."""

    def __init__(self):
        self.lock = threading.Lock()
        self.payloads = []
        self.errors = []
        self.observed_partial = []


def _read_or_create(path, body, build_value, marker):
    try:
        value = ensure_secret_file(Path(path), lambda: build_value(marker))
        with body.lock:
            body.payloads.append(value)
    except Exception as exc:                                # noqa: BLE001
        with body.lock:
            body.errors.append(f"{type(exc).__name__}: {exc}")


def _thread_probe(path, body, value):
    _read_or_create(path, body, lambda v: v, value)


def _process_probe(args):
    path, value = args
    return ensure_secret_file(Path(path), lambda: value.encode())


class EnsureSecretFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "secret.key"

    def test_creates_once_and_reads_back(self):
        builds = []

        def build():
            builds.append(1)
            return b"the-key"

        first = ensure_secret_file(self.path, build)
        second = ensure_secret_file(self.path, build)
        self.assertEqual(first, b"the-key")
        self.assertEqual(second, b"the-key")
        self.assertEqual(len(builds), 1, "build must run only when the file is missing")

    def test_permissions_are_owner_only(self):
        ensure_secret_file(self.path, lambda: b"k" * 32)
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")

    def test_creates_missing_parent_directory(self):
        nested = Path(self.dir.name) / "a" / "b" / "secret.key"
        self.assertEqual(ensure_secret_file(nested, lambda: b"deep"), b"deep")
        self.assertTrue(nested.exists())

    def test_leaves_no_temp_files_behind(self):
        ensure_secret_file(self.path, lambda: b"k" * 32)
        leftovers = [p.name for p in Path(self.dir.name).iterdir()
                     if p.name != self.path.name]
        self.assertEqual(leftovers, [self.path.name + ".lock"])

    def test_failing_build_does_not_leave_a_file(self):
        def boom():
            raise ValueError("generator failed")

        with self.assertRaises(ValueError):
            ensure_secret_file(self.path, boom)
        self.assertFalse(self.path.exists())

    def test_threads_agree_on_one_payload(self):
        body = _Body()
        threads = [
            threading.Thread(target=_thread_probe,
                             args=(str(self.path), body, f"key-{i}".encode()))
            for i in range(8)
        ]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(body.errors, [])
        self.assertEqual(len(set(body.payloads)), 1,
                         f"threads disagreed: {set(body.payloads)}")

    def test_processes_agree_on_one_payload(self):
        with mp.Pool(8) as pool:
            results = pool.map(_process_probe,
                               [(str(self.path), f"key-{i}") for i in range(8)])
        self.assertEqual(len(set(results)), 1,
                         f"processes disagreed: {set(results)}")
        self.assertEqual(self.path.read_bytes(), results[0])

    def test_concurrent_readers_never_see_a_partial_file(self):
        stop = threading.Event()
        seen_partial = []

        def reader():
            while not stop.is_set():
                try:
                    raw = self.path.read_bytes()
                except FileNotFoundError:
                    continue
                if raw and not raw.startswith(b"final-key-"):
                    seen_partial.append(raw)

        with mp.Pool(8) as pool:
            writers = [pool.apply_async(_process_probe,
                                        ((str(self.path), f"final-key-{i}"),))
                       for i in range(8)]
            readers = [threading.Thread(target=reader) for _ in range(4)]
            [t.start() for t in readers]
            [w.get() for w in writers]
            stop.set()
            [t.join() for t in readers]
        self.assertEqual(seen_partial, [],
                         f"a reader observed a partial file: {seen_partial[:2]}")

    def test_key_material_is_readable_after_the_fact(self):
        ensure_secret_file(self.path, lambda: b"persisted-key")
        self.assertEqual(self.path.read_bytes(), b"persisted-key")


class CryptoKeyStabilityTests(unittest.TestCase):
    """The message-encryption key must be identical for every worker."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        os.environ["CHAT_DATA_DIR"] = self.dir.name

    def _reload_crypto(self):
        import importlib
        import app.crypto as crypto
        import app.paths as paths
        paths = importlib.reload(paths)
        crypto = importlib.reload(crypto)
        crypto._cipher = None          # force lazy init inside each worker
        return crypto

    def test_first_encrypt_creates_a_usable_key_file(self):
        crypto = self._reload_crypto()
        token = crypto.encrypt("hello")
        self.assertEqual(crypto.decrypt(token), "hello")
        secret = Path(self.dir.name) / ".chat_secret"
        self.assertTrue(secret.exists())
        self.assertEqual(oct(secret.stat().st_mode & 0o777), "0o600")

    def test_key_file_matches_the_cipher_in_use(self):
        crypto = self._reload_crypto()
        crypto.encrypt("hello")
        from cryptography.fernet import Fernet
        on_disk = (Path(self.dir.name) / ".chat_secret").read_bytes().strip()
        Fernet(on_disk)                 # raises if unusable
        self.assertEqual(crypto._load_key(), on_disk)

    def test_encrypt_and_decrypt_are_consistent_across_reloads(self):
        crypto = self._reload_crypto()
        token = crypto.encrypt("persisted across reload")
        crypto = self._reload_crypto()  # simulate a restarted process
        self.assertEqual(crypto.decrypt(token), "persisted across reload")

    def test_corrupt_key_file_raises_instead_of_silently_regenerating(self):
        secret = Path(self.dir.name) / ".chat_secret"
        secret.write_bytes(b"not-a-fernet-key")
        crypto = self._reload_crypto()
        with self.assertRaises(RuntimeError) as ctx:
            crypto._load_key()
        self.assertIn("cannot be decrypted", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)