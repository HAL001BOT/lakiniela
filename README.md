# LaKiniela ⚽

Modern Liga MX pool app (web MVP).

## What it does
- User signup/login
- Create pool or join with code
- Enter score predictions per match
- Auto scoring rules:
  - **3 points** = correct match result (win/draw/loss)
  - **5 points** = exact score
- Pool standings dashboard
- Automatic fixture/results import + scoring sync every 20 minutes
  - Uses `API_FOOTBALL_KEY` if present
  - Falls back to `FOOTBALL_DATA_KEY`
  - If neither works, falls back to ESPN public scoreboard feed (no key)

## Run
```bash
npm install
npm start
```
Open: `http://localhost:3090`

## Env (optional)
- `FOOTBALL_DATA_KEY` → enables Liga MX auto fixture+score sync via football-data API
- `ADMIN_KEY` → protects admin endpoints (`/admin/matches/:id/final`, `/admin/sync`)
- `SESSION_SECRET`

## Notes
- If no external API key is present, app still works and you can load final results via admin endpoint.
- DB file: `data/lakiniela.db`
