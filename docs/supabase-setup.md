# Supabase Setup

This repo now expects **Supabase Postgres** for the default runtime persistence path.

## 1. Create or open your Supabase project

- Open the Supabase dashboard.
- Copy a Postgres connection string from the **Connect** panel.
- Prefer the **direct** connection if your environment supports it.
- If your network only supports IPv4, use the **Supavisor session** connection string on port `5432`.

## 2. Configure environment variables

Create local environment variables from [.env.example](/C:/Users/duynh/Documents/Code/Project/SOAR%20Playbook/.env.example).

Required:

```env
SUPABASE_DB_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require
```

Optional explicit overrides:

```env
SOAR_DATABASE_URL=postgresql://...
SOAR_A2A_DB_URL=postgresql://...
```

`SOAR_DATABASE_URL` controls the incident repository.

`SOAR_A2A_DB_URL` controls the A2A collaboration bus repository.

If those two are omitted, both fall back to `SUPABASE_DB_URL`.

## 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

## 4. Let the app create tables automatically

The Python repositories initialize their tables on startup.

You do not need a separate migration step for the first run, but you should still keep schema changes under version control later.

## 5. Start the app

```bash
python main.py --scenario mixed --no-report
python -m uvicorn api.app:app --reload
streamlit run dashboard/app.py
```

## 6. Optional note about `supabase-js`

The `@supabase/supabase-js` and `@supabase/ssr` packages are for JavaScript and frameworks like Next.js.

This repository is Python-based, so server-side persistence uses the Postgres driver instead of the JS SSR helpers.
