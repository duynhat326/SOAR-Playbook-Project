from __future__ import annotations

import os
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

_LOCAL_ENV_LOADED = False


def load_local_env_files() -> None:
    global _LOCAL_ENV_LOADED
    if _LOCAL_ENV_LOADED:
        return

    repo_root = Path(__file__).resolve().parent.parent
    for env_path in (repo_root / ".env.local", repo_root / ".env"):
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            os.environ.setdefault(key, value)

    _LOCAL_ENV_LOADED = True


def normalize_postgres_dsn(raw_dsn: str) -> str:
    if raw_dsn.startswith("postgres://"):
        return "postgresql://" + raw_dsn[len("postgres://") :]
    return raw_dsn


def is_postgres_target(raw_target: str | Path | None) -> bool:
    if raw_target is None:
        return False
    value = str(raw_target)
    return value.startswith("postgresql://") or value.startswith("postgres://")


def resolve_database_url(
    raw_url: str | Path | None,
    *,
    preferred_env: str,
) -> str:
    load_local_env_files()

    if raw_url is not None:
        return normalize_postgres_dsn(str(raw_url))

    for env_name in (preferred_env, "SUPABASE_DB_URL"):
        env_value = os.getenv(env_name)
        if env_value:
            return normalize_postgres_dsn(env_value)

    raise RuntimeError(
        f"Supabase Postgres is not configured. Set {preferred_env} or SUPABASE_DB_URL."
    )


class PostgresDatabase:
    def __init__(self, db_url: str, schema_statements: Iterable[str]) -> None:
        self.db_url = normalize_postgres_dsn(db_url)
        self._schema_statements = tuple(
            statement.strip() for statement in schema_statements if statement.strip()
        )
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[psycopg.Connection]:
        with psycopg.connect(self.db_url, row_factory=dict_row) as connection:
            yield connection

    def _initialize(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                for statement in self._schema_statements:
                    cursor.execute(statement)
