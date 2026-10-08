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

## Match-first redesign (October 2026)

The approved soccer-motion logo is `public/img/lakiniela-mark.png`. The light
forest-green visual system is in `public/redesign.css`, loaded after the legacy
layout stylesheet. Desktop navigation uses a persistent rail; mobile pool pages
switch between predictions and standings. General/Jornada ranking controls retain
both scopes. No database migration or scoring-rule changes are required.

Complete individual score pairs can be saved without filling the entire round.
Unsaved edits are labelled per match and protected by a browser leave warning.
One-sided or invalid scores remain unsaved; clearing an existing prediction does
not delete it. Match deadlines are enforced by the server; the UI also disables
controls as deadlines pass. Displayed fixture and closing times use Monterrey time.

Run `npm test` for domain, migration, security and HTTP regressions.
Run `npm run test:ui` for an isolated browser test (install Chromium with
`npx playwright install chromium` if `/usr/bin/chromium` is unavailable).
Tests use a temporary SQLite database and do not touch production records.
Set `UI_SCREENSHOTS=/path/to/output` to retain desktop/mobile screenshots.

### Light and dark modes

Use **Modo oscuro / Modo claro** in the header (or at the top of sign-in pages).
The first visit follows your device preference. An explicit choice is saved in
this browser's local storage and applies across pages and tabs. It does not modify
account records or sync between devices. Theme initialization runs before CSS to
avoid a light flash on dark-mode navigation. Themes still toggle for the current
page when local storage is unavailable. Standings image exports retain a light,
print-friendly surface.
