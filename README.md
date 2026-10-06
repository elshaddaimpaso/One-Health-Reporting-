# One Health Reporting

Cross-sector (human health, agriculture, veterinary, environment) community hazard reporting.
Express API + Supabase Postgres, static frontend. Deploys on Vercel.

```
public/index.html   frontend (served by Vercel's CDN)
api/index.js        Express API (runs as a Vercel serverless function)
server.js           local development server only
schema.sql          run once in Supabase SQL Editor
seed.sql            optional demo data
vercel.json         /api rewrite + security headers
```

## Deploy: Supabase + Vercel

### 1. Supabase
1. Create a project at supabase.com (pick the closest region, save the database password).
2. SQL Editor -> New query -> paste `schema.sql` -> Run. (Optional: run `seed.sql` for demo data.)
3. Click **Connect** -> **Transaction pooler** string (port 6543). Replace `[YOUR-PASSWORD]` with your password.
   Do not add `?sslmode=...` to it.

### 2. Vercel
1. Push this repo to GitHub.
2. Vercel -> Add New -> Project -> import the repo. No build settings needed.
3. Environment Variables (all three required):
   - `DATABASE_URL`: the Supabase pooler string
   - `ADMIN_PASSWORD`: at least 12 characters, long and random
   - `SESSION_SECRET`: at least 32 characters (`openssl rand -hex 32`)
4. Deploy, then open `https://YOUR-APP.vercel.app/api/health`. You should see `{"ok":true}`.
   If you see `{"error":"Server error."}`, check Vercel -> Logs (usually a wrong `DATABASE_URL`).

Changing an env var requires a redeploy to take effect.

## Local development
```
npm install
cp .env.example .env     # fill in the values
npm run dev              # http://localhost:3000
```

## Notes
- The app refuses to start if `ADMIN_PASSWORD` is under 12 chars or `SESSION_SECRET` is under 32.
- The feed refreshes by polling every 15 seconds (serverless functions can't hold live streams open).
- Rate limits (10 submissions/min, 10 login attempts/15 min per IP) are stored in Postgres so they work across instances.
- `reports` and `rate_limits` have row level security enabled with no policies, so the public Supabase API cannot read or write them; only this server can.

## API
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | /api/meta | - | sectors, hazards, districts |
| GET | /api/health | - | checks DB connection |
| GET | /api/reports | - | filters: sector, area, status; limit, offset |
| POST | /api/reports | - | submit a report |
| POST | /api/admin/login | - | returns 8h token |
| GET | /api/admin/session | admin | token check |
| PATCH | /api/reports/:id | admin | update status |
| DELETE | /api/reports/:id | admin | delete report |
| GET | /api/admin/stats | admin | counts |
