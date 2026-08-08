# Environment Profiles

These files separate deployment configuration by environment without committing secrets into the runtime code.

- `development.env`
  - runnable local Docker Compose profile
  - defaults to shared SQLite persistence under `/app/output/soar-local.db`
- `staging.env.example`
  - staging template
  - expects external Postgres and integration credentials
- `production.env.example`
  - production template
  - expects external Postgres, real integrations, and locked-down origins

Recommended usage:

1. Copy the template that matches the target environment.
2. Fill in secrets and endpoints outside git.
3. Validate it with:

```bash
python scripts/validate_env.py config/environments/<file>
```

For Postgres-backed local verification with Docker Compose:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml --profile postgres up -d
python scripts/apply_postgres_migrations.py
```
