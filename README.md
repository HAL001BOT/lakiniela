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
  persistent storage (for example `/var/data/lakiniela.db` on a mounted Render disk).

Production startup fails closed when `SESSION_SECRET`, `ADMIN_KEY`, or `DB_PATH`
is missing. Configure a single web instance when using SQLite; the database-backed
job lock prevents duplicate syncs only when every process shares the same DB file.

## Notes
- Sync now uses ESPN public scoreboard feed (no API key required).
- DB file: `data/lakiniela.db`

## Faster delivery (CI/CD)
This repo now includes GitHub Actions at `.github/workflows/ci-deploy.yml`.

What it does:
- Runs smoke checks on PRs to `main`
- Runs smoke checks on pushes to `main`
- Optionally triggers a Render deploy hook after CI passes

To enable instant Render trigger after push:
1. In Render, copy your service Deploy Hook URL
2. In GitHub repo settings → Secrets and variables → Actions, add:
   - `RENDER_DEPLOY_HOOK_URL` = your hook URL

If that secret is not set, deployment still works via Render auto-deploy from `main`.
