from __future__ import annotations

import sys
from typing import Any

from rich.console import Console


def ensure_utf8_output() -> None:
    """Best-effort UTF-8 console setup for Windows and redirected streams."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                continue


def build_console(**kwargs: Any) -> Console:
    ensure_utf8_output()
    return Console(**kwargs)
