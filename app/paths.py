"""Filesystem locations and atomic secret-file creation.

chat.db and .chat_secret live in CHAT_DATA_DIR when that env var is set,
otherwise in the project root (development default, unchanged behavior).
The packaged launcher sets CHAT_DATA_DIR to a user-writable directory so
the bundle itself can stay read-only.
"""
import fcntl
import logging
import os
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    p = Path(os.environ.get("CHAT_DATA_DIR", str(PROJECT_ROOT))).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def ensure_secret_file(path: Path, build) -> bytes:
    """Return the contents of `path`, generating it exactly once if absent.

    Safe across threads AND processes, and never exposes a partial file:

    * an flock() on a sidecar `<path>.lock` serialises creation. flock is tied
      to the open file description, so it also blocks other threads of the same
      process (POSIX record locks would not).
    * O_CREAT|O_EXCL on its own would NOT be enough: the winner publishes the
      file name before writing any content, so a second party can read a
      truncated (even zero-byte) key file.
    * the content is written to a private temp file, fsync'd, then moved into
      place with os.replace(), which is atomic within a filesystem. The
      directory is fsync'd too so the rename survives a crash.

    `build` is called (without the lock held) only when the file is missing,
    and must return the exact bytes to store.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            existing = path.read_bytes()
        except FileNotFoundError:
            existing = None
        if existing:
            return existing

        payload = build()
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                        prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, path)   # atomic: readers see old or new, never partial
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return payload
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def new_fernet_key() -> bytes:
    """Generate a fresh Fernet key (kept here so both callers stay identical)."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key()


# --------------------------------------------------------------------------
# filesystem detection
# --------------------------------------------------------------------------

# SQLite's WAL mode needs shared memory (-shm), which network filesystems do
# not provide. SQLite documents WAL as unsupported on NFS and warns about other
# network filesystems too, so we refuse them outright instead of silently
# corrupting behaviour (missing locks -> "database is locked" or worse).
NETWORK_FS_TYPES = {
    "nfs", "nfs4", "nfs3", "cifs", "smbfs", "smb3", "9p", "afs", "afs3",
    "ceph", "glusterfs", "lustre", "ncpfs", "gfs2", "gfs", "fuse.sshfs",
    "fuse.glusterfs", "fuse.rclone", "davfs", "coda",
}


def _unescape_mount(field: str) -> str:
    # /proc mount fields encode spaces and other specials as octal escapes.
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def filesystem_type(path: Path, mountinfo: Path | None = None) -> str:
    """Filesystem type backing `path` (e.g. "ext4", "overlay", "nfs").

    Returns "" when it cannot be determined (non-Linux, /proc unavailable).
    `mountinfo` is injectable so the parsing can be tested directly.
    """
    target = str(Path(path).resolve())
    mountinfo = mountinfo or Path("/proc/self/mountinfo")
    if not mountinfo.exists():
        return ""
    best_len, best_type = -1, ""
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in lines:
        parts = line.split(" ")
        # id parent maj:min root mount_point options... - fstype source superopts
        try:
            sep = parts.index("-")
        except ValueError:
            continue
        if sep + 1 >= len(parts):
            continue
        mount_point = _unescape_mount(parts[4])
        fstype = parts[sep + 1]
        if (target == mount_point or target.startswith(mount_point.rstrip("/") + "/")) \
                and len(mount_point) > best_len:
            best_len, best_type = len(mount_point), fstype
    return best_type


def check_local_filesystem(path: Path, require_local: bool,
                         mountinfo: Path | None = None) -> str:
    """Fail fast when the data directory lives on a network filesystem.

    `require_local` is only True for multi-worker setups, where a shared
    SQLite file over NFS would be actively dangerous. Single-worker local
    installs still get a warning instead of an error.

    Returns the detected filesystem type ("" = unknown).
    """
    fstype = filesystem_type(path, mountinfo)
    if fstype in NETWORK_FS_TYPES:
        message = (
            f"Refusing to start: the data directory {path} is on a network "
            f"filesystem ({fstype}). SQLite's WAL journal mode requires shared "
            "memory and is not supported there, which corrupts locking and can "
            "lose writes. Put CHAT_DATA_DIR on a local disk."
        )
        if require_local:
            raise RuntimeError(message)
        logging.getLogger("chat").warning(message)
    elif not fstype and require_local:
        raise RuntimeError(
            f"Cannot determine the filesystem type of {path} (is /proc "
            "available?). Multi-worker SQLite needs a verified local "
            "filesystem; run with WORKERS=1 if this is a local single process."
        )
    return fstype

