# One Health backend

Express + SQLite API that serves the reporting page (`public/index.html`).

## Run
    npm install
    ADMIN_PASSWORD=choose-a-strong-one npm start     # http://localhost:3000

If `ADMIN_PASSWORD` is not set, a random one is generated on first start,
printed once, and saved to `data/admin-password.txt`.

Env vars: `PORT`, `DATA_DIR` (default `./data`), `ADMIN_PASSWORD`,
`SESSION_SECRET`, `NO_SEED=1` (skip the 4 demo reports).

## API (`/api`)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | /meta | - | sectors, hazards, districts |
| GET | /reports?sector=&area=&status=&limit=&offset= | - | list, newest first |
| POST | /reports | - | submit (validated, rate-limited 10/min) |
| GET | /stream | - | Server-Sent Events: report:created / updated / deleted |
| POST | /admin/login `{password}` | - | returns 8h bearer token |
| GET | /admin/session, /admin/stats | admin | check token, dashboard counts |
| PATCH | /reports/:id `{status}` | admin | Open / Investigating / Resolved |
| DELETE | /reports/:id | admin | delete |

Deploy behind HTTPS (e.g. Render, Railway or Fly with a persistent volume for `DATA_DIR`).
