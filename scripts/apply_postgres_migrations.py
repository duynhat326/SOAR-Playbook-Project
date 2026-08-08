from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import psycopg

from storage.postgres import normalize_postgres_dsn, resolve_database_url

DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations" / "postgres"


def discover_migrations(migrations_dir: str | Path = DEFAULT_MIGRATIONS_DIR) -> list[Path]:
    root = Path(migrations_dir)
    if not root.exists():
        raise FileNotFoundError(f"Migration directory was not found: {root}")
    return sorted(path for path in root.glob("*.sql") if path.is_file())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply ordered Postgres schema migrations for the SOAR repository.")
    parser.add_argument(
        "--database-url",
        default=None,
        help="Optional Postgres DSN override. Falls back to SOAR_DATABASE_URL or SUPABASE_DB_URL.",
    )
    parser.add_argument(
        "--migrations-dir",
        default=str(DEFAULT_MIGRATIONS_DIR),
        help="Directory containing ordered *.sql migration files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List pending migrations without applying them.",
    )
    return parser.parse_args()


def _ensure_migration_table(connection: psycopg.Connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )


def _applied_migrations(connection: psycopg.Connection) -> dict[str, str]:
    with connection.cursor() as cursor:
        rows = cursor.execute(
            "SELECT filename, checksum FROM schema_migrations ORDER BY filename ASC"
        ).fetchall()
    return {str(filename): str(checksum) for filename, checksum in rows}


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pending_migrations(
    migrations: Iterable[Path],
    applied: dict[str, str],
) -> list[Path]:
    pending: list[Path] = []
    for migration in migrations:
        checksum = _checksum(migration)
        applied_checksum = applied.get(migration.name)
        if applied_checksum is None:
            pending.append(migration)
            continue
        if applied_checksum != checksum:
            raise RuntimeError(
                f"Migration checksum mismatch for {migration.name}. "
                "The database recorded a different version of this file."
            )
    return pending


def apply_migrations(
    connection: psycopg.Connection,
    migrations_dir: str | Path = DEFAULT_MIGRATIONS_DIR,
    *,
    dry_run: bool = False,
) -> list[str]:
    _ensure_migration_table(connection)
    migrations = discover_migrations(migrations_dir)
    applied = _applied_migrations(connection)
    pending = pending_migrations(migrations, applied)
    if dry_run:
        return [migration.name for migration in pending]

    applied_now: list[str] = []
    for migration in pending:
        sql = migration.read_text(encoding="utf-8")
        checksum = _checksum(migration)
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(sql)
                cursor.execute(
                    """
                    INSERT INTO schema_migrations (filename, checksum)
                    VALUES (%s, %s)
                    ON CONFLICT (filename) DO UPDATE
                    SET checksum = EXCLUDED.checksum,
                        applied_at = NOW()
                    """,
                    (migration.name, checksum),
                )
        applied_now.append(migration.name)
    return applied_now


def main() -> int:
    args = parse_args()
    db_url = resolve_database_url(args.database_url, preferred_env="SOAR_DATABASE_URL")
    with psycopg.connect(normalize_postgres_dsn(db_url)) as connection:
        applied = apply_migrations(
            connection,
            args.migrations_dir,
            dry_run=args.dry_run,
        )

    if args.dry_run:
        if applied:
            print("Pending migrations:")
            for item in applied:
                print(f"  - {item}")
        else:
            print("No pending migrations.")
        return 0

    if applied:
        print("Applied migrations:")
        for item in applied:
            print(f"  - {item}")
    else:
        print("No migrations applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
