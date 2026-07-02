from __future__ import annotations

import os
from pathlib import Path

_LOCAL_ENV_LOADED = False


def load_local_env_files() -> None:
    global _LOCAL_ENV_LOADED
    if _LOCAL_ENV_LOADED:
        return

    repo_root = Path(__file__).resolve().parent
    for env_path in (repo_root / ".env.local", repo_root / ".env"):
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'").strip('"'))

    _LOCAL_ENV_LOADED = True
