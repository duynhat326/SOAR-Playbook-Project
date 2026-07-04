# Supabase setup

This repo now uses Supabase Postgres as the default runtime persistence target for:

- incident storage
- report artifact metadata
- A2A collaboration storage

If you do not pass an explicit local database path, the Python runtime will try to use the Supabase/Postgres connection.

## 1. Create or open your Supabase project

- Open the Supabase dashboard
- Copy a Postgres connection string from the Connect panel
- Prefer the direct connection if your environment supports it
- If your network path is limited, use the Supavisor session string on port `5432`

## 2. Configure environment variables

Start from `.env.example`.

Minimum runtime setup:

```env
SUPABASE_DB_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require
SOAR_AUTH_TOKENS_JSON={"tokens":[{"token":"<generate-a-long-random-token>","principal_id":"incident-operator","principal_type":"user","roles":["incident_process","incident_read"],"workspaces":["*"]}]}
SOAR_API_PROXY_TARGET=http://127.0.0.1:8000
```

Optional overrides:

```env
SOAR_DATABASE_URL=postgresql://...
SOAR_A2A_DB_URL=postgresql://...
SOAR_API_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
VITE_SOAR_API_BASE_URL=
```

Behavior:

- `SUPABASE_DB_URL` is the common fallback connection
- `SOAR_DATABASE_URL` overrides the incident repository target
- `SOAR_A2A_DB_URL` overrides the A2A repository target
- `SOAR_API_PROXY_TARGET` is read by `dashboard/vite.config.ts`
- `dashboard/api/*.js` uses the same `SOAR_API_PROXY_TARGET` value for production proxying on Vercel
- repo-root `.env.local` is visible to Vite because the dashboard uses `envDir: ".."`

Dashboard auth note:

- the proxy no longer injects a shared bearer token
- after the UI loads, paste the operator token into the dashboard session prompt
- the browser stores that token only in tab-scoped `sessionStorage`

## 3. Optional live VirusTotal enrichment

If you want live hash enrichment:

```env
SOAR_INTEL_PROVIDER=virustotal
VIRUSTOTAL_API_KEY=...
```

If you leave this unset, the runtime can still use mock or limited local-safe enrichment behavior depending on the code path.

## 4. Install dependencies

Python:

```bash
pip install -r requirements.txt
```

Dashboard:

```bash
npm --prefix dashboard install
```

## 5. Start the services

FastAPI:

```bash
python -m uvicorn api.app:app --reload
```

React dashboard:

```bash
npm --prefix dashboard run dev
```

Optional CLI smoke:

```bash
python main.py --scenario mixed --no-report
```

## 6. Dashboard auth and sensitive field behavior

The React dashboard is expected to run with an operator principal that has:

- `incident_process`
- `incident_read`

That matters because:

- default incident detail reads are still redacted
- the dashboard requests detail with `include_sensitive=true`
- only operator-capable principals can read the original `file_hash`, `file_path`, `command_line`, and `username`

Read-only principals still receive redacted values by design.

## 7. Intake guardrail

Do not paste sanitized dashboard output back into the intake form.

The process API now rejects payloads that already look redacted, for example:

- `username = [redacted]`
- `command_line = [redacted]`
- `file_path = [redacted-path]`
- `file_hash = 0000...`

Use the original raw alert JSON if you want real enrichment and policy behavior.

## 8. Notes on local-only development

Tests and explicit local workflows can still use SQLite by passing a concrete local database path into the workflow service or repository layer.

The default runtime path without an explicit database target is Supabase/Postgres.
