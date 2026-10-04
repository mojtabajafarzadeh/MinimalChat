"""Startup preflight tests (run.py).

These lock in what the process model refuses to start, and what it accepts
with a loud warning. The branches matter because two of them are silent
data-corrupting failure modes in production:

  * a network filesystem breaks SQLite's WAL (no shared memory);
  * several workers split the public room into one room per process.

`preflight` reads app.config and app.paths at call time, so the settings are
injected here with unittest.mock instead of by re-importing the modules.
"""
import io
import logging
import unittest
from contextlib import redirect_stdout
from unittest import mock

import run as runner


class PreflightTests(unittest.TestCase):
    """workers x {nfs, split_rooms allowed, encrypted channel} -> allowed/blocked."""

    def setUp(self):
        self.logs = []
        handler = logging.Handler()
        handler.emit = lambda record: self.logs.append(record.getMessage())
        self._root_add = logging.getLogger().handlers
        logging.getLogger().addHandler(handler)
        self.addCleanup(lambda: logging.getLogger().handlers.pop())

    def preflight(self, workers, *, fstype="ext4", split_rooms=False, enc=True):
        """Run preflight with the environment faked; returns (outcome, output)."""
        import app.config as config
        patches = [
            mock.patch.object(config, "ENC_ENABLED", enc),
            mock.patch.object(config, "ALLOW_SPLIT_ROOMS", split_rooms),
            mock.patch("app.paths.filesystem_type",
                       lambda *a, **k: fstype),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                runner.preflight(workers, split_rooms)
                return "allowed", buf.getvalue()
            except SystemExit as exc:
                return "blocked", str(exc)
            except RuntimeError as exc:
                return "blocked", str(exc)

    # ---------- the three cases that were requested explicitly ----------

    def test_two_workers_split_rooms_false_is_blocked(self):
        outcome, message = self.preflight(2, split_rooms=False, enc=False)
        self.assertEqual(outcome, "blocked")
        self.assertIn("one room per worker", message)
        self.assertIn("ALLOW_SPLIT_ROOMS=true", message)

    def test_two_workers_split_rooms_true_with_encrypted_channel_is_blocked(self):
        outcome, message = self.preflight(2, split_rooms=True, enc=True)
        self.assertEqual(outcome, "blocked")
        self.assertIn("ENC_ENABLED=true", message)
        self.assertIn("Session expired", message)
        self.assertIn("WORKERS=1", message)

    def test_two_workers_split_rooms_true_plain_is_allowed_with_warning(self):
        outcome, output = self.preflight(2, split_rooms=True, enc=False)
        self.assertEqual(outcome, "allowed")
        # Warning must be visible on the console AND in the log.
        self.assertIn("Split-rooms mode is active", output)
        self.assertTrue(any("Split-rooms mode is active" in m for m in self.logs),
                        f"expected a log warning, got {self.logs}")

    # ---------- surrounding behaviour ----------

    def test_single_worker_is_allowed_on_local_disk(self):
        self.assertEqual(self.preflight(1, fstype="ext4", split_rooms=False,
                                        enc=True)[0], "allowed")

    def test_single_worker_on_nfs_only_warns(self):
        # One process does not share the database file, so this is survivable.
        outcome, message = self.preflight(1, fstype="nfs4")
        self.assertEqual(outcome, "allowed")
        self.assertTrue(any("network filesystem" in m for m in self.logs),
                        f"expected a warning, got {self.logs}")

    def test_multi_worker_on_nfs_is_blocked(self):
        outcome, message = self.preflight(2, fstype="nfs4", split_rooms=True,
                                          enc=False)
        self.assertEqual(outcome, "blocked")
        self.assertIn("network filesystem", message)
        self.assertIn("WAL", message)

    def test_multi_worker_on_cifs_is_blocked(self):
        outcome, message = self.preflight(2, fstype="cifs", split_rooms=True,
                                          enc=False)
        self.assertEqual(outcome, "blocked")
        self.assertIn("cifs", message)

    def test_multi_worker_with_undetectable_filesystem_is_blocked(self):
        outcome, message = self.preflight(2, fstype="", split_rooms=True,
                                          enc=False)
        self.assertEqual(outcome, "blocked")
        self.assertIn("determine", message)

    def test_many_workers_allowed_when_split_rooms_accepted(self):
        outcome, output = self.preflight(8, split_rooms=True, enc=False)
        self.assertEqual(outcome, "allowed")
        self.assertIn("Split-rooms mode is active", output)

    def test_encrypted_channel_blocks_multi_worker_regardless_of_split_flag(self):
        # Split rooms are meaningless with the encrypted channel: the channel
        # session is pinned to one worker, so this is refused either way.
        for split in (False, True):
            outcome, message = self.preflight(4, split_rooms=split, enc=True)
            self.assertEqual(outcome, "blocked", f"split_rooms={split}")
            self.assertIn("ENC_ENABLED=true", message)

    def test_encrypted_channel_blocks_even_two_workers_on_local_disk(self):
        outcome, message = self.preflight(2, fstype="ext4", split_rooms=True,
                                          enc=True)
        self.assertEqual(outcome, "blocked")
        self.assertIn("ENC_ENABLED=true", message)


class WarningTextTests(unittest.TestCase):
    def test_warning_text_mentions_the_operator_impact(self):
        text = runner.SPLIT_ROOMS_WARNING
        self.assertIn("Split-rooms mode is active", text)
        self.assertIn("do not see each other's messages", text)
        self.assertIn("one room per worker", text)

    def test_warning_is_not_emitted_for_single_worker(self):
        logs = []
        handler = logging.Handler()
        handler.emit = lambda record: logs.append(record.getMessage())
        logging.getLogger().addHandler(handler)
        self.addCleanup(lambda: logging.getLogger().handlers.pop())
        with mock.patch("app.paths.filesystem_type", lambda *a, **k: "ext4"):
            with redirect_stdout(io.StringIO()):
                runner.preflight(1, False)
        self.assertFalse(any("Split-rooms" in m for m in logs))


if __name__ == "__main__":
    unittest.main(verbosity=2)