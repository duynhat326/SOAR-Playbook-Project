from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def path_value(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
            continue
        if isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            if not part.isdigit():
                return None
            index = int(part)
            if index < 0 or index >= len(current):
                return None
            current = current[index]
            continue
        return None
    return current


def first_present(payload: Any, *paths: str, default: Any = None) -> Any:
    for path in paths:
        candidate = path_value(payload, path)
        if candidate is None:
            continue
        if isinstance(candidate, str) and not candidate.strip():
            continue
        return candidate
    return default


def require_string(provider: str, field_name: str, value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{provider} payload missing {field_name}.")
    return text


def basename(raw_path: str) -> str:
    sanitized = raw_path.replace("\\", "/").rstrip("/")
    name = sanitized.rsplit("/", 1)[-1].strip()
    return name.lower()


def normalize_hostname(raw_value: str) -> str:
    hostname = raw_value.strip().split(".", 1)[0]
    return hostname.upper()


def normalize_username(raw_value: str) -> str:
    sanitized = raw_value.strip().replace("/", "\\")
    if "\\" in sanitized:
        sanitized = sanitized.rsplit("\\", 1)[-1]
    return sanitized.lower()
