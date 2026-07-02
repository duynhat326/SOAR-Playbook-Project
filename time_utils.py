from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def utc_isoformat_z() -> str:
    """Return an ISO-8601 UTC timestamp with a Z suffix."""
    return utc_now().isoformat().replace("+00:00", "Z")
