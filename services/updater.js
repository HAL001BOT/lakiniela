const axios = require('axios');
const db = require('../db');

function resultPoints(predHome, predAway, realHome, realAway) {
  if (predHome === realHome && predAway === realAway) return 5;
  const predResult = Math.sign(predHome - predAway);
  const realResult = Math.sign(realHome - realAway);
  return predResult === realResult ? 3 : 0;
}

function recalcPointsForMatch(matchId) {
  const match = db.prepare('SELECT * FROM matches WHERE id = ?').get(matchId);
  if (!match || match.home_score === null || match.away_score === null) return;

  const preds = db.prepare('SELECT * FROM predictions WHERE match_id = ?').all(matchId);
  const update = db.prepare('UPDATE predictions SET points = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');

  for (const p of preds) {
    const points = resultPoints(p.pred_home, p.pred_away, match.home_score, match.away_score);
    update.run(points, p.id);
  }
}

async function syncLigaMxScores() {
  const key = process.env.FOOTBALL_DATA_KEY;
  if (!key) return { ok: false, reason: 'FOOTBALL_DATA_KEY missing' };

  // Placeholder for an external provider. This endpoint may vary by plan.
  const url = 'https://api.football-data.org/v4/competitions/MX1/matches?status=FINISHED';
  const { data } = await axios.get(url, { headers: { 'X-Auth-Token': key }, timeout: 15000 });

  const updateMatch = db.prepare(`
    UPDATE matches
    SET home_score = ?, away_score = ?, status = 'finished'
    WHERE external_id = ?
  `);

  for (const m of data.matches || []) {
    updateMatch.run(
      m.score?.fullTime?.home ?? null,
      m.score?.fullTime?.away ?? null,
      String(m.id)
    );
  }

  const finished = db.prepare("SELECT id FROM matches WHERE status = 'finished'").all();
  finished.forEach(({ id }) => recalcPointsForMatch(id));

  return { ok: true, updated: finished.length };
}

module.exports = { resultPoints, recalcPointsForMatch, syncLigaMxScores };
