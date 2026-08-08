from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Literal, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError, model_validator


ROLE_INCIDENT_PROCESS = "incident_process"
ROLE_INCIDENT_READ = "incident_read"

PrincipalType = Literal["user", "agent"]


class AuthTokenDefinition(BaseModel):
    token: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    principal_type: PrincipalType = "user"
    roles: list[str] = Field(default_factory=list)
    workspaces: list[str] = Field(default_factory=list)
    agent_id: Optional[str] = None

    @model_validator(mode="after")
    def validate_agent_identity(self) -> "AuthTokenDefinition":
        if self.principal_type == "agent" and not self.agent_id:
            raise ValueError("Agent principals must define agent_id")
        return self


class AuthConfig(BaseModel):
    tokens: list[AuthTokenDefinition]


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    principal_id: str
    principal_type: PrincipalType
    roles: frozenset[str]
    workspaces: frozenset[str]
    agent_id: Optional[str] = None

    def has_role(self, role: str) -> bool:
        return role in self.roles


class AuthConfigurationError(RuntimeError):
    pass


class AuthorizationError(ValueError):
    pass


http_bearer = HTTPBearer(auto_error=False)


@lru_cache
def _load_token_map() -> dict[str, AuthenticatedPrincipal]:
    raw = os.getenv("SOAR_AUTH_TOKENS_JSON")
    if not raw:
        raise AuthConfigurationError(
            "SOAR_AUTH_TOKENS_JSON is not configured. Protected API operations are disabled until auth tokens are configured."
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthConfigurationError("SOAR_AUTH_TOKENS_JSON must be valid JSON") from exc

    if isinstance(data, list):
        data = {"tokens": data}

    try:
        config = AuthConfig.model_validate(data)
    except ValidationError as exc:
        raise AuthConfigurationError(f"Invalid SOAR auth token config: {exc}") from exc

    token_map: dict[str, AuthenticatedPrincipal] = {}
    for item in config.tokens:
        token_map[item.token] = AuthenticatedPrincipal(
            principal_id=item.principal_id,
            principal_type=item.principal_type,
            roles=frozenset(item.roles),
            workspaces=frozenset(item.workspaces),
            agent_id=item.agent_id,
        )
    return token_map


def clear_auth_cache() -> None:
    _load_token_map.cache_clear()


def authenticate_token(token: str) -> AuthenticatedPrincipal:
    try:
        token_map = _load_token_map()
    except AuthConfigurationError as exc:
        raise AuthorizationError(str(exc)) from exc

    principal = token_map.get(token)
    if principal is None:
        raise AuthorizationError("Invalid authentication token.")
    return principal


def resolve_cli_principal(token: Optional[str] = None) -> AuthenticatedPrincipal:
    resolved_token = token or os.getenv("SOAR_AUTH_TOKEN")
    if not resolved_token:
        raise AuthorizationError("Missing auth token. Pass --token or set SOAR_AUTH_TOKEN.")
    return authenticate_token(resolved_token)


def ensure_roles(principal: AuthenticatedPrincipal, *roles: str) -> AuthenticatedPrincipal:
    if roles and not any(principal.has_role(role) for role in roles):
        raise AuthorizationError("Authenticated principal lacks the required role.")
    return principal


def _http_auth_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
) -> AuthenticatedPrincipal:
    try:
        _load_token_map()
    except AuthConfigurationError as exc:
        raise _http_auth_error(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _http_auth_error(status.HTTP_401_UNAUTHORIZED, "Bearer authentication is required.")

    try:
        return authenticate_token(credentials.credentials)
    except AuthorizationError as exc:
        raise _http_auth_error(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc


def require_roles(*roles: str) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    def dependency(
        principal: AuthenticatedPrincipal = Depends(get_current_principal),
    ) -> AuthenticatedPrincipal:
        try:
            return ensure_roles(principal, *roles)
        except AuthorizationError as exc:
            raise _http_auth_error(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    return dependency
