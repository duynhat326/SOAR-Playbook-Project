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

## Real credentials locally (Docker)

Create `config/environments/local.env` (git-ignored) with e.g. `SOAR_DB_TARGET=`, `SUPABASE_DB_URL`, `SOAR_INTEL_PROVIDER=virustotal`, `VIRUSTOTAL_API_KEY` and your own `SOAR_AUTH_TOKENS_JSON`. `docker compose up --build` loads it after `development.env` when it exists; without it the stack runs on mock data.
