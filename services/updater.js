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


function upsertMatch(match) {
  if (!match.home || !match.away || !match.kickoffAt || !match.externalId) return null;

  const existing = db.prepare('SELECT id FROM matches WHERE external_id = ?').get(match.externalId);
  if (existing) {
    db.prepare(`
      UPDATE matches
      SET league = ?, season = ?, matchday = ?, home_team = ?, away_team = ?, kickoff_at = ?,
          home_score = ?, away_score = ?, status = ?
      WHERE id = ?
    `).run(
      match.league,
      match.season,
      match.matchday,
      match.home,
      match.away,
      match.kickoffAt,
      match.homeScore,
      match.awayScore,
      match.status,
      existing.id
    );

    if (match.status === 'finished' && match.homeScore !== null && match.awayScore !== null) recalcPointsForMatch(existing.id);
    return { created: false, id: existing.id };
  }

  const info = db.prepare(`
    INSERT INTO matches (external_id, league, season, matchday, home_team, away_team, kickoff_at, home_score, away_score, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    match.externalId,
    match.league,
    match.season,
    match.matchday,
    match.home,
    match.away,
    match.kickoffAt,
    match.homeScore,
    match.awayScore,
    match.status
  );

  if (match.status === 'finished' && match.homeScore !== null && match.awayScore !== null) recalcPointsForMatch(info.lastInsertRowid);
  return { created: true, id: info.lastInsertRowid };
}

async function fetchEspnLigaMx() {
  const now = new Date();
  const from = new Date(now);
  from.setDate(from.getDate() - 7);
  const to = new Date(now);
  to.setDate(to.getDate() + 14);
  const fmt = (d) => d.toISOString().slice(0, 10).replace(/-/g, '');

  const url = 'https://site.api.espn.com/apis/site/v2/sports/soccer/mex.1/scoreboard';
  const { data } = await axios.get(url, {
    params: { dates: `${fmt(from)}-${fmt(to)}` },
    timeout: 20000,
  });

  return (data.events || []).map((ev) => {
    const comp = ev.competitions?.[0] || {};
    const home = (comp.competitors || []).find((c) => c.homeAway === 'home');
    const away = (comp.competitors || []).find((c) => c.homeAway === 'away');
    const completed = !!comp.status?.type?.completed;
    const state = comp.status?.type?.state;
    const status = completed ? 'finished' : (state === 'in' ? 'live' : 'scheduled');

    const homeScore = Number.isFinite(Number(home?.score)) ? Number(home.score) : null;
    const awayScore = Number.isFinite(Number(away?.score)) ? Number(away.score) : null;

    return {
      externalId: `espn:${ev.id}`,
      league: 'Liga MX',
      season: String(ev.season?.year || ''),
      matchday: comp.week?.number || null,
      home: home?.team?.displayName,
      away: away?.team?.displayName,
      kickoffAt: ev.date,
      homeScore,
      awayScore,
      status,
    };
  });
}

async function syncLigaMxScores() {
  const source = 'espn-public';
  const fixtures = await fetchEspnLigaMx();

  let created = 0;
  let updated = 0;
  let finished = 0;

  for (const f of fixtures || []) {
    const result = upsertMatch(f);
    if (!result) continue;
    if (result.created) created += 1;
    else updated += 1;
    if (f.status === 'finished') finished += 1;
  }

  return { ok: true, source, total: (fixtures || []).length, created, updated, finished };
}

module.exports = { resultPoints, recalcPointsForMatch, syncLigaMxScores };
