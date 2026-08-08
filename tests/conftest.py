from __future__ import annotations

import json
from collections.abc import Callable, Iterator

import pytest

import api.app as api_app
from security import (
    ROLE_INCIDENT_PROCESS,
    ROLE_INCIDENT_READ,
    AuthenticatedPrincipal,
    clear_auth_cache,
)


@pytest.fixture(autouse=True)
def isolate_test_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep tests deterministic even when local .env files enable live services.
    monkeypatch.setenv("SOAR_INTEL_PROVIDER", "mock")
    monkeypatch.setenv("SUPABASE_DB_URL", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")


@pytest.fixture(autouse=True)
def clear_cached_services() -> Iterator[None]:
    api_app.get_workflow_service.cache_clear()
    clear_auth_cache()
    yield
    api_app.get_workflow_service.cache_clear()
    clear_auth_cache()


@pytest.fixture
def principal_factory() -> Callable[..., AuthenticatedPrincipal]:
    def build(
        principal_id: str,
        *,
        roles: list[str] | tuple[str, ...],
        workspaces: list[str] | tuple[str, ...] = ("*",),
        principal_type: str = "user",
        agent_id: str | None = None,
    ) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            principal_id=principal_id,
            principal_type=principal_type,  # type: ignore[arg-type]
            roles=frozenset(roles),
            workspaces=frozenset(workspaces),
            agent_id=agent_id,
        )

    return build


@pytest.fixture
def incident_operator_principal(principal_factory: Callable[..., AuthenticatedPrincipal]) -> AuthenticatedPrincipal:
    return principal_factory(
        "incident-operator",
        roles=[ROLE_INCIDENT_PROCESS, ROLE_INCIDENT_READ],
    )


@pytest.fixture
def auth_token_config_factory(monkeypatch: pytest.MonkeyPatch) -> Callable[[list[dict]], str]:
    def install(tokens: list[dict]) -> str:
        payload = json.dumps({"tokens": tokens})
        monkeypatch.setenv("SOAR_AUTH_TOKENS_JSON", payload)
        clear_auth_cache()
        return payload

    return install


def build_default_auth_tokens() -> list[dict]:
    return [
        {
            "token": "incident-process-token",
            "principal_id": "incident-processor",
            "principal_type": "user",
            "roles": [ROLE_INCIDENT_PROCESS],
            "workspaces": ["*"],
        },
        {
            "token": "incident-read-token",
            "principal_id": "incident-reader",
            "principal_type": "user",
            "roles": [ROLE_INCIDENT_READ],
            "workspaces": ["*"],
        },
    ]
