from __future__ import annotations

import os
from collections.abc import Iterable

DEFAULT_WORKSPACE = "default"
WILDCARD_WORKSPACE = "*"


def get_default_workspace() -> str:
    candidate = str(os.getenv("SOAR_DEFAULT_WORKSPACE") or "").strip()
    return candidate.casefold() or DEFAULT_WORKSPACE


def normalize_workspace(value: str | None) -> str:
    candidate = str(value or "").strip()
    return candidate.casefold() or get_default_workspace()


def normalize_workspace_set(values: Iterable[str] | None) -> frozenset[str]:
    normalized: set[str] = set()
    for value in values or ():
        candidate = str(value or "").strip()
        if not candidate:
            continue
        if candidate == WILDCARD_WORKSPACE:
            normalized.add(WILDCARD_WORKSPACE)
            continue
        normalized.add(normalize_workspace(candidate))
    return frozenset(normalized)


def effective_workspaces(values: Iterable[str] | None) -> frozenset[str]:
    normalized = normalize_workspace_set(values)
    if normalized:
        return normalized
    return frozenset({get_default_workspace()})


def can_access_workspace(allowed_workspaces: Iterable[str] | None, workspace: str | None) -> bool:
    allowed = effective_workspaces(allowed_workspaces)
    if WILDCARD_WORKSPACE in allowed:
        return True
    return normalize_workspace(workspace) in allowed


def resolve_workspace_for_request(
    allowed_workspaces: Iterable[str] | None,
    requested_workspace: str | None,
) -> str:
    allowed = effective_workspaces(allowed_workspaces)
    if requested_workspace is not None and str(requested_workspace).strip():
        resolved = normalize_workspace(requested_workspace)
        if not can_access_workspace(allowed, resolved):
            raise ValueError("Authenticated principal is not authorized for the requested workspace.")
        return resolved

    if WILDCARD_WORKSPACE in allowed:
        return get_default_workspace()

    explicit = sorted(workspace for workspace in allowed if workspace != WILDCARD_WORKSPACE)
    if len(explicit) == 1:
        return explicit[0]

    default_workspace = get_default_workspace()
    if default_workspace in explicit:
        return default_workspace

    raise ValueError("Authenticated principal can access multiple workspaces; specify workspace explicitly.")
