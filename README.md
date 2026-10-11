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

### Graphite / Cobalt palette

Direction A replaces the green scheme: graphite surfaces, white text, cobalt
primary actions, and pale-blue links for dark-mode readability. Light mode uses
cool neutral surfaces with cobalt accents. The approved soccer mark is displayed
in monochrome via CSS; its original image file is preserved. Existing saved theme
choices and the device-preference default are unchanged.

### Profile photos and round-specific statistics

Open **Perfil** → **Foto de perfil** to upload, replace or remove your own photo.
Accepted inputs: JPEG, PNG, WebP, AVIF, up to 5 MB and 25 megapixels. The server
normalizes orientation, center-crops to 256×256 WebP and removes metadata. Images
are stored in the additive `user_avatars` SQLite table on the existing persistent
disk; they survive deployments and are included in database backups. Only signed-in
users can retrieve avatars. No-photo users get a local silhouette placeholder.

In the predictions matrix, Aciertos/Exactos percentages and counts use only
finished matches with known scores and a prediction in the selected round. Missing
predictions and unplayed matches are not in the denominator; no qualifying picks
shows “—”. Correct-result counts include exact scores. The overall pool standings
retain their all-round statistics.

## Classification rules v1 (2026-10-11)

All standings and matchday awards share `services/ranking.js`: points descending,
then exact-score count, then correct-result count (including exacts). Existing
5/3/0 match scoring is unchanged; only finished matches with known scores count.
Selected-round tables use only that round, never previous rounds or overall
performance as a tiebreaker. Percentages remain descriptive, not competitive
criteria: fewer submitted picks must not confer a percentage-based advantage.
Names and IDs provide stable visual order only. Equal sporting keys share the
same competition rank (1,1,3), and every positive-points co-leader is identified.
No evaluated predictions means no rank; all-zero rounds award no win. Shared
closed-round wins count once for each winner, not fractions. Incomplete or
postponed rounds are provisional. Result corrections can change derived rankings.

The in-app expandable rules cite Superbru's persistent-tie principle and
Kicktipp's emphasis on published rules/matchday wins. These are our own adapted
rules, not a claim of identical platform scoring. No random, submission-time,
registration-age or alphabetical sporting tiebreak. The same criteria now apply
to overall tables and exported share cards, using the full pool scope there.

Verification: `npm test` includes deterministic ranking regressions;
`node scripts/ranking-browser.js` uses a disposable database to exercise shared
winners/positions and provisional labels at phone/desktop widths. No live data
is modified by these scripts.
