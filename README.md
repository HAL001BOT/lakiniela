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
- Automatic fixture/results import + scoring sync every 20 minutes (ESPN public feed)

## Run
```bash
npm install
npm start
```
Open: `http://localhost:3090`

## Env (optional)
- `ADMIN_KEY` → protects admin endpoints (`/admin/matches/:id/final`, `/admin/sync`)
- `SESSION_SECRET`

## Notes
- Sync now uses ESPN public scoreboard feed (no API key required).
- DB file: `data/lakiniela.db`
