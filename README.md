# LaKiniela ⚽

Modern soccer pool app (web MVP).

## What it does
- User signup/login
- Create pool or join with code
- Choose Liga MX, Champions League, or FIFA World Cup 2026 first-stage pools
- Enter score predictions per match
- Auto scoring rules:
  - **3 points** = correct match result (win/draw/loss)
  - **5 points** = exact score
- Pool standings dashboard
- Automatic fixture/results import + scoring sync every minute during each match's live window (ESPN public feed)

## Run
```bash
npm install
npm start
```
Open: `http://localhost:3090`

## Environment
- `ADMIN_KEY` → protects admin endpoints (`/admin/matches/:id/final`, `/admin/sync`)
- `SESSION_SECRET`
- `DB_PATH` → SQLite file path. **Required in production** and must point to
  the existing persistent disk's exact mount path plus `/lakiniela.db`.
- `PUBLIC_BASE_URL` → canonical HTTPS origin used in invite links (for example
  `https://lakiniela.onrender.com`).

Production startup fails closed when `SESSION_SECRET`, `ADMIN_KEY`, or `DB_PATH`
is missing. Configure a single web instance when using SQLite; the database-backed
job lock prevents duplicate syncs only when every process shares the same DB file.
Configure Render health checks to use `/health`. `/ready` is also available for
readiness probes.

## Notes
- Sync now uses ESPN public scoreboard feed (no API key required).
- DB file: `data/lakiniela.db`

## Faster delivery (CI/CD)
This repo now includes GitHub Actions at `.github/workflows/ci-deploy.yml`.

What it does:
- Runs smoke, migration, and HTTP checks on PRs and pushes to `main`
- Triggers a Render deploy hook after CI passes
- Polls `/health` until the exact Git commit is live

To enable instant Render trigger after push:
1. In Render, copy your service Deploy Hook URL
2. In GitHub repo settings → Secrets and variables → Actions, add:
   - `RENDER_DEPLOY_HOOK_URL` = your hook URL
   - `RENDER_HEALTHCHECK_URL` = your production URL ending in `/health`

The deploy job fails when either secret is absent or when Render never reaches the
expected revision. Render auto-deploy should be disabled when the deploy hook is
used, avoiding duplicate deploys.
