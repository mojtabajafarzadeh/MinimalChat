"""Single-command startup: `python run.py`. Installs deps, creates DB, serves the app."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def ensure_deps() -> None:
    try:
        import fastapi, uvicorn  # noqa: F401
        return
    except ImportError:
        print("Installing dependencies (fastapi, uvicorn)...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-i", "https://mirror.ferdowsi.cloud/artifactory/api/pypi/pip-virtual/simple", '-r', str(ROOT / "requirements.txt")]
        )


def main() -> None:
    ensure_deps()
    import uvicorn

    sys.path.insert(0, str(ROOT))
    from app.db import init_db

    init_db()
    port = int(os.environ.get("PORT", "8001"))
    print(f"Chat app running at http://127.0.0.1:{port}", flush=True)
    uvicorn.run("app.main:app", host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
