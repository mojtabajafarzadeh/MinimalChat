"""Build the offline Linux bundle.

Copies the exact installed dependency closure (fastapi, uvicorn,
cryptography, ...) from the current interpreter into chat-app/lib/,
plus the app source and launcher scripts, then packs it as
dist/chat-app-linux-x86_64.tar.gz.

Usage:  python3 packaging/build.py
"""
import importlib.metadata as md
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / "dist" / "chat-app"
TEMPLATES = ROOT / "packaging" / "templates"

TOP_LEVEL_DISTS = ["fastapi", "uvicorn", "cryptography", "websockets"]

try:
    from packaging.requirements import Requirement

    def deps_of(name: str) -> list:
        out = []
        for r in (md.distribution(name).requires or []):
            req = Requirement(r)
            if req.marker is not None and not req.marker.evaluate({"extra": ""}):
                continue
            out.append(req.name)
        return out

except ImportError:

    def deps_of(name: str) -> list:
        out = []
        for r in (md.distribution(name).requires or []):
            if "extra ==" in r:
                continue
            out.append(r.split()[0].split(";")[0].strip())
        return out


def closure() -> dict:
    seen: dict = {}
    stack = list(TOP_LEVEL_DISTS)
    while stack:
        name = stack.pop()
        key = name.lower().replace("-", "_")
        if key in seen:
            continue
        dist = md.distribution(name)
        real = dist.metadata["Name"]
        seen[key] = dist
        print(f"  vendoring {real}=={dist.version}")
        stack.extend(deps_of(real))
    return seen


def top_level_modules(dist) -> list:
    """Top-level import names provided by a distribution."""
    try:
        text = (Path(str(dist._path)) / "top_level.txt").read_text()
        return [t.strip() for t in text.split() if t.strip()]
    except OSError:
        pass
    # Fallback: first path segment of RECORD entries.
    tops = []
    try:
        for line in (Path(str(dist._path)) / "RECORD").read_text().splitlines():
            first = line.split(",", 1)[0].split("/")[0]
            if first and not first.endswith((".dist-info", ".egg-info")):
                if first not in tops:
                    tops.append(first)
    except OSError:
        pass
    return tops


def copy_dist(dist, lib_dir: Path) -> None:
    dist_info = Path(str(dist._path))
    site_root = dist_info.parent
    for top in top_level_modules(dist):
        # Guard against odd metadata entries ('' , '.', '..', absolute paths).
        if not top or top in (".", "..") or top.startswith(("/", "\\")) or ".." in top:
            print(f"  skipping odd entry {top!r} of {dist.metadata['Name']}")
            continue
        if (site_root / top).is_file():
            # Single-file module, e.g. typing_extensions.py
            shutil.copy2(site_root / top, lib_dir / Path(top).name)
            continue
        src_dir = site_root / top
        if src_dir.is_dir():
            shutil.copytree(
                src_dir, lib_dir / top, ignore=shutil.ignore_patterns("__pycache__")
            )
            continue
        if (site_root / f"{top}.py").is_file():
            shutil.copy2(site_root / f"{top}.py", lib_dir / f"{top}.py")
            continue
        # Top-level extension modules, e.g. _cffi_backend...so
        sos = sorted(site_root.glob(f"{top}*.so"))
        if sos:
            for so in sos:
                shutil.copy2(so, lib_dir / so.name)
            continue
        print(f"  WARNING: could not locate top-level {top!r} of {dist.metadata['Name']}")
    # Keep version metadata (some tools read it at runtime).
    shutil.copytree(dist_info, lib_dir / dist_info.name,
                    ignore=shutil.ignore_patterns("__pycache__"))


def main() -> None:
    if sys.version_info[:2] != (3, 12):
        sys.exit("Build must run on Python 3.12 (bundled .so files are 3.12-specific).")
    if os.uname().machine != "x86_64":
        sys.exit("Build must run on x86_64.")
    print("Resolving dependency closure...")
    dists = closure()

    print(f"Staging bundle at {STAGE} ...")
    shutil.rmtree(STAGE, ignore_errors=True)
    lib_dir = STAGE / "lib"
    lib_dir.mkdir(parents=True)
    for dist in dists.values():
        copy_dist(dist, lib_dir)

    print("Copying app source...")
    shutil.copytree(ROOT / "app", STAGE / "app",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for f in ["run.py", "requirements.txt"]:
        shutil.copy2(ROOT / f, STAGE / f)
    for f in ["chat-app", "install.sh", "README.txt"]:
        shutil.copy2(TEMPLATES / f, STAGE / f)
    for exe in [STAGE / "chat-app", STAGE / "install.sh"]:
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    out = ROOT / "dist" / "chat-app-linux-x86_64.tar.gz"
    print(f"Packing {out} ...")
    with tarfile.open(out, "w:gz") as tar:
        tar.add(STAGE, arcname="chat-app")
    size_mb = out.stat().st_size / 1e6
    n_files = sum(1 for _ in STAGE.rglob("*") if _.is_file())
    print(f"Done: {out} ({size_mb:.1f} MB, {n_files} files)")

    # Sanity: every top-level import resolves inside the bundle.
    print("Verifying bundled imports...")
    env = dict(os.environ, PYTHONPATH=str(lib_dir))
    subprocess.check_call(
        [sys.executable, "-S", "-c",
         "import fastapi, uvicorn, cryptography, websockets, pydantic, "
         "starlette, anyio, click, h11; print('bundled imports OK')"],
        env=env,
    )


if __name__ == "__main__":
    main()
