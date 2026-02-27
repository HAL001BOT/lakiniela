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
- Automatic score sync job every 20 minutes (when API key is configured)

## Run
```bash
npm install
npm start
```
Open: `http://localhost:3090`

## Env (optional)
- `FOOTBALL_DATA_KEY` → enables Liga MX auto-score sync via football-data API
- `ADMIN_KEY` → protects manual result endpoint (`/admin/matches/:id/final`)
- `SESSION_SECRET`

## Notes
- If no external API key is present, app still works and you can load final results via admin endpoint.
- DB file: `data/lakiniela.db`
