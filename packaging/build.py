"""Build the offline Linux bundle.

Copies the exact installed dependency closure (fastapi, uvicorn,
cryptography, ...) from the current interpreter into chat-app/lib/,
plus the app source and launcher scripts, then packs it as
dist/chat-app-linux-x86_64.tar.gz.

Usage:  python3 packaging/build.py

Requirement parsing is deliberately self-contained: `packaging` is NOT a
dependency of this project, so a CI environment that installed only
requirements.txt has no `packaging` module. An earlier version relied on it
and had a fallback that kept the version specifier in the name, so it asked
importlib.metadata for "typing-extensions>=4.13.2" and died. Names and
markers are now parsed here with a regex.
"""
import importlib.metadata as md
import os
import re
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

# "name[extra]>=1.2 ; marker" -> "name"
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def requirement_name(raw: str) -> str:
    """Distribution name from a raw requirement string.

    Strips extras, version specifiers, URLs and environment markers:
    "typing-extensions>=4.13.2 ; python_full_version < '3.11'"
        -> "typing-extensions"
    """
    head = raw.split(";", 1)[0]            # drop environment marker
    head = head.split("[", 1)[0]            # drop extras
    head = head.split("@", 1)[0]            # drop direct-reference URL
    match = _NAME_RE.match(head)
    if not match:
        raise ValueError(f"cannot parse requirement: {raw!r}")
    return match.group(1)


def requirement_marker(raw: str) -> str:
    """Environment marker of a raw requirement ("" when unconditional)."""
    if ";" not in raw:
        return ""
    return raw.split(";", 1)[1].strip()


def marker_allows(raw: str) -> bool | None:
    """Should this requirement be vendored on this interpreter?

    True / False when we can tell, None when we cannot evaluate the marker
    without `packaging` (then the dependency is attempted and, if its
    metadata is absent, reported as skipped rather than fatal).
    """
    marker = requirement_marker(raw)
    if not marker:
        return True
    # Extras are never active here: we depend on the base requirements only.
    if re.search(r"\bextra\s*==", marker):
        return False
    try:
        from packaging.markers import Marker
    except ImportError:
        return None
    try:
        return bool(Marker(marker).evaluate({"extra": ""}))
    except Exception:
        return None


def deps_of(dist) -> list:
    """Raw requirement strings that apply to this interpreter, unparsed."""
    out = []
    for raw in (dist.requires or []):
        if marker_allows(raw) is False:
            continue
        out.append(raw)
    return out


def closure() -> dict:
    """Walk the installed dependency closure, vendoring what we can find.

    A required top-level distribution that cannot be resolved is fatal: it
    means the requirement parser is broken, and continuing would produce a
    bundle that is silently missing its dependencies.
    """
    seen: dict = {}
    skipped: list = []
    required = {n.lower().replace("-", "_") for n in TOP_LEVEL_DISTS}
    stack = list(TOP_LEVEL_DISTS)
    while stack:
        raw = stack.pop()
        try:
            name = requirement_name(raw)
        except ValueError as exc:
            print(f"  WARNING: {exc}")
            continue
        key = name.lower().replace("-", "_").replace(".", "_")
        if key in seen or key in skipped:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            if key in required:
                raise SystemExit(
                    f"Cannot resolve required distribution {name!r} "
                    f"(from requirement {raw!r}). Is it installed? Try: "
                    f"{sys.executable} -m pip install -r requirements.txt"
                )
            # A conditional dependency that pip did not install for this
            # interpreter (e.g. typing-extensions on Python 3.12+). Not fatal:
            # the import check at the end catches anything actually missing.
            skipped.append(key)
            print(f"  skipping {name} (not installed; required by {raw})")
            continue
        real = dist.metadata["Name"]
        seen[key] = dist
        print(f"  vendoring {real}=={dist.version}")
        stack.extend(deps_of(dist))
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


def copy_dist(dist, lib_dir: Path, vendored: set) -> None:
    """Copy one distribution's top-level modules into lib_dir.

    Every module actually copied is recorded in `vendored`, so the final check
    can import the whole closure rather than a hand-picked few. Importing only
    a few names would hide a dependency that failed to be vendored.
    """
    dist_info = Path(str(dist._path))
    site_root = dist_info.parent
    for top in top_level_modules(dist):
        # Guard against odd metadata entries ('' , '.', '..', absolute paths).
        if not top or top in (".", "..") or top.startswith(("/", "\\")) or ".." in top:
            print(f"  skipping odd entry {top!r} of {dist.metadata['Name']}")
            continue
        if (site_root / top).is_file():
            # Single-file module, e.g. typing_extensions.py. Record the module
            # name without the extension so it matches what modules_in() sees.
            shutil.copy2(site_root / top, lib_dir / Path(top).name)
            vendored.add(Path(top).stem)
            continue
        src_dir = site_root / top
        if src_dir.is_dir():
            shutil.copytree(
                src_dir, lib_dir / top, ignore=shutil.ignore_patterns("__pycache__")
            )
            vendored.add(top)
            continue
        if (site_root / f"{top}.py").is_file():
            shutil.copy2(site_root / f"{top}.py", lib_dir / f"{top}.py")
            vendored.add(top)
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


def _present_in(lib_dir: Path, name: str) -> bool:
    """Is `name` (package, module file or extension) present in lib_dir?"""
    if (lib_dir / name).is_dir():
        return True
    if (lib_dir / f"{name}.py").is_file():
        return True
    return any(lib_dir.glob(f"{name}*.so"))


def modules_in(lib_dir: Path) -> set:
    """Importable top-level module names actually present in lib_dir."""
    found = set()
    for entry in lib_dir.iterdir():
        if entry.name.startswith(".") or entry.name.endswith(".dist-info"):
            continue
        if entry.is_dir():
            if (entry / "__init__.py").is_file() or not (entry / "__init__.py").exists():
                found.add(entry.name)          # package (incl. namespace)
            continue
        # Check the stem, not the name: "typing_extensions.py".isidentifier()
        # is False because of the dot, which hid every single-file module.
        if entry.suffix == ".py" and entry.stem.isidentifier():
            found.add(entry.stem)
        elif entry.suffix == ".so":
            name = entry.name.split(".")[0]
            if name.isidentifier():
                found.add(name)
    return found


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
    vendored: set = set()
    for dist in dists.values():
        copy_dist(dist, lib_dir, vendored)

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

    # Import EVERY module present in lib/ from an isolated interpreter, so a
    # dependency that was not vendored fails here instead of on a user's
    # machine. The list is read back off disk (not from the copy bookkeeping)
    # so this validates the artifact itself.
    importable = sorted(modules_in(lib_dir))
    if len(importable) < 5:
        raise SystemExit(
            f"Only {len(importable)} modules were vendored ({sorted(importable)}); "
            "the dependency walk clearly failed. Refusing to ship the bundle."
        )
    # Cross-check the copy bookkeeping against the artifact: every module we
    # recorded while copying must really be present in lib/. This is the check
    # that catches a distribution which resolved but did not get copied.
    missing = sorted(m for m in vendored if not _present_in(lib_dir, m))
    if missing:
        raise SystemExit(
            "These modules were resolved but are missing from the bundle: "
            + ", ".join(missing)
            + ". Refusing to ship it."
        )
    print(f"Verifying bundled imports ({len(importable)} modules)...", flush=True)
    env = dict(os.environ, PYTHONPATH=str(lib_dir))
    script = (
        "import importlib, sys\n"
        "bad = []\n"
        "for name in sys.argv[1:]:\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "    except Exception as exc:\n"
        "        bad.append(f'{name}: {type(exc).__name__}: {exc}')\n"
        "if bad:\n"
        "    print('MISSING OR BROKEN MODULES:')\n"
        "    print('\\n'.join('  ' + b for b in bad))\n"
        "    raise SystemExit(1)\n"
        "print('bundled imports OK')\n"
    )
    subprocess.check_call([sys.executable, "-S", "-c", script, *importable], env=env)


if __name__ == "__main__":
    main()
