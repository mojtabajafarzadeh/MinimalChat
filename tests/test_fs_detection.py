"""Filesystem detection tests.

NFS/CIFS and friends are rejected because SQLite's WAL journal mode needs
shared memory, which network filesystems do not provide. Detecting them is the
difference between a clear startup error and a database that silently loses
writes under load, so these paths deserve permanent regression tests.

The tests use a synthetic /proc/self/mountinfo: the parser takes it as an
argument, so no real NFS mount (or privileges) is required in CI.
"""
import tempfile
import unittest
from pathlib import Path

from app.paths import (
    NETWORK_FS_TYPES,
    check_local_filesystem,
    filesystem_type,
)

# Covers: overlay root, a local disk, nested mounts under a network mount
# (longest-prefix must win), octal-escaped spaces in mount points, and a
# cifs share.
MOUNTINFO = """\
23 28 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b
31 23 0:26 / /mnt/local rw - ext4 /dev/sda1 rw
44 23 0:52 / /mnt/nfs/data rw,relatime - nfs4 remote:/export rw
45 23 0:53 / /mnt/nfs rw - nfs4 remote:/other rw
46 23 0:54 / /mnt/nfs/data/inner rw - ext4 /dev/sdb rw
47 23 0:55 / /srv/shared\\040volume rw - cifs //fileserver/share rw
48 23 0:56 / /home/user\\040x/project rw - 9p host:/home rw
49 23 0:57 / /mnt/ceph rw - ceph 10.0.0.1:6789 rw
"""


class FilesystemTypeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.mountinfo = Path(self.dir.name) / "mountinfo"
        self.mountinfo.write_text(MOUNTINFO, encoding="utf-8")

    def fstype(self, path):
        return filesystem_type(Path(path), self.mountinfo)

    def test_detects_plain_filesystems(self):
        self.assertEqual(self.fstype("/mnt/local"), "ext4")
        self.assertEqual(self.fstype("/"), "overlay")

    def test_detects_nfs_and_nfs4(self):
        self.assertEqual(self.fstype("/mnt/nfs/data"), "nfs4")
        self.assertEqual(self.fstype("/mnt/nfs"), "nfs4")

    def test_longest_mount_point_wins(self):
        # /mnt/nfs/data is nfs4 but has an ext4 filesystem mounted inside it;
        # the most specific mount must be reported.
        self.assertEqual(self.fstype("/mnt/nfs/data/inner"), "ext4")
        self.assertEqual(self.fstype("/mnt/nfs/data/inner/deep/file.db"), "ext4")
        # ...while a sibling path that is NOT under the inner mount stays nfs4.
        self.assertEqual(self.fstype("/mnt/nfs/data/deep/file.txt"), "nfs4")

    def test_detects_mount_point_with_escaped_spaces(self):
        # /proc encodes spaces as \040; an unescaped path would not match.
        self.assertEqual(self.fstype("/srv/shared volume"), "cifs")
        self.assertEqual(self.fstype("/srv/shared volume/sub dir"), "cifs")

    def test_detects_detected_home_directory_with_spaces(self):
        self.assertEqual(self.fstype("/home/user x/project"), "9p")

    def test_detects_ceph(self):
        self.assertEqual(self.fstype("/mnt/ceph"), "ceph")

    def test_unmounted_path_falls_back_to_parent_mount(self):
        self.assertEqual(self.fstype("/mnt/local/sub/dir/file.db"), "ext4")

    def test_network_types_cover_common_systems(self):
        for fs in ("nfs", "nfs4", "cifs", "smbfs", "9p", "ceph", "afs", "fuse.sshfs"):
            self.assertIn(fs, NETWORK_FS_TYPES, f"{fs} must be treated as network")


class CheckLocalFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.mountinfo = Path(self.dir.name) / "mountinfo"
        self.mountinfo.write_text(MOUNTINFO, encoding="utf-8")

    def check(self, path, require_local):
        return check_local_filesystem(Path(path), require_local, self.mountinfo)

    def test_nfs_is_rejected_in_multiprocess_mode(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.check("/mnt/nfs/data", True)
        message = str(ctx.exception)
        self.assertIn("network filesystem", message)
        self.assertIn("nfs4", message)
        self.assertIn("WAL", message)
        self.assertIn("CHAT_DATA_DIR", message)

    def test_cifs_is_rejected_in_multiprocess_mode(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.check("/srv/shared volume", True)
        self.assertIn("cifs", str(ctx.exception))

    def test_network_path_with_spaces_is_rejected(self):
        # Regression: mount names with spaces must not silently pass.
        with self.assertRaises(RuntimeError) as ctx:
            self.check("/srv/shared volume/sub dir", True)
        self.assertIn("cifs", str(ctx.exception))

    def test_9p_home_directory_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check("/home/user x/project", True)

    def test_ceph_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check("/mnt/ceph", True)

    def test_local_filesystem_is_allowed(self):
        self.assertEqual(self.check("/mnt/local", True), "ext4")
        self.assertEqual(self.check("/", True), "overlay")

    def test_nested_local_mount_under_nfs_is_allowed(self):
        self.assertEqual(self.check("/mnt/nfs/data/inner", True), "ext4")

    def test_single_worker_tolerates_network_path(self):
        # WORKERS=1 does not share the database, so this is only a warning.
        self.assertEqual(self.check("/mnt/nfs/data", False), "nfs4")

    def test_unknown_filesystem_is_rejected_in_multiprocess_mode(self):
        empty = Path(self.dir.name) / "empty_mountinfo"
        empty.write_text("", encoding="utf-8")
        with self.assertRaises(RuntimeError) as ctx:
            check_local_filesystem(Path("/mnt/local"), True, empty)
        self.assertIn("determine", str(ctx.exception))

    def test_unknown_filesystem_is_tolerated_in_single_worker_mode(self):
        empty = Path(self.dir.name) / "empty_mountinfo2"
        empty.write_text("", encoding="utf-8")
        self.assertEqual(check_local_filesystem(Path("/mnt/local"), False, empty), "")

    def test_malformed_mountinfo_lines_are_skipped(self):
        noisy = Path(self.dir.name) / "noisy"
        noisy.write_text(
            "garbage line with no separator\n"
            "1 2 3:4 / /mnt/x rw - ext4 /dev/sda rw\n"
            "\n"
            "malformed - only fstype here\n",
            encoding="utf-8",
        )
        self.assertEqual(filesystem_type(Path("/mnt/x"), noisy), "ext4")


if __name__ == "__main__":
    unittest.main(verbosity=2)