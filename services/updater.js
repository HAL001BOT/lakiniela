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

function normalizeStatus(apiStatus) {
  if (apiStatus === 'FINISHED') return 'finished';
  if (apiStatus === 'IN_PLAY' || apiStatus === 'PAUSED') return 'live';
  return 'scheduled';
}

async function fetchLigaMxMatches() {
  const key = process.env.FOOTBALL_DATA_KEY;
  if (!key) throw new Error('FOOTBALL_DATA_KEY missing');

  const url = 'https://api.football-data.org/v4/competitions/MX1/matches';
  const { data } = await axios.get(url, {
    headers: { 'X-Auth-Token': key },
    params: { status: 'SCHEDULED,IN_PLAY,PAUSED,FINISHED' },
    timeout: 20000,
  });

  return data.matches || [];
}

function upsertMatchFromApi(match) {
  const externalId = String(match.id);
  const existing = db.prepare('SELECT id FROM matches WHERE external_id = ?').get(externalId);

  const home = match.homeTeam?.shortName || match.homeTeam?.name;
  const away = match.awayTeam?.shortName || match.awayTeam?.name;
  const kickoff = match.utcDate;
  const season = `${match.season?.startDate || ''}..${match.season?.endDate || ''}`;
  const matchday = match.matchday || null;

  const status = normalizeStatus(match.status);
  const homeScore = Number.isInteger(match.score?.fullTime?.home) ? match.score.fullTime.home : null;
  const awayScore = Number.isInteger(match.score?.fullTime?.away) ? match.score.fullTime.away : null;

  if (existing) {
    db.prepare(`
      UPDATE matches
      SET league = 'Liga MX', season = ?, matchday = ?, home_team = ?, away_team = ?,
          kickoff_at = ?, home_score = ?, away_score = ?, status = ?
      WHERE id = ?
    `).run(season, matchday, home, away, kickoff, homeScore, awayScore, status, existing.id);

    if (status === 'finished' && homeScore !== null && awayScore !== null) recalcPointsForMatch(existing.id);
    return { created: false, matchId: existing.id };
  }

  const info = db.prepare(`
    INSERT INTO matches (external_id, league, season, matchday, home_team, away_team, kickoff_at, home_score, away_score, status)
    VALUES (?, 'Liga MX', ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(externalId, season, matchday, home, away, kickoff, homeScore, awayScore, status);

  if (status === 'finished' && homeScore !== null && awayScore !== null) recalcPointsForMatch(info.lastInsertRowid);
  return { created: true, matchId: info.lastInsertRowid };
}

async function syncLigaMxScores() {
  const matches = await fetchLigaMxMatches();
  let created = 0;
  let updated = 0;
  let finished = 0;

  for (const match of matches) {
    const result = upsertMatchFromApi(match);
    if (result.created) created += 1;
    else updated += 1;
    if (normalizeStatus(match.status) === 'finished') finished += 1;
  }

  return { ok: true, total: matches.length, created, updated, finished };
}

module.exports = { resultPoints, recalcPointsForMatch, syncLigaMxScores };