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

function normalizeApiFootballStatus(short) {
  if (['FT', 'AET', 'PEN', 'AWD', 'WO'].includes(short)) return 'finished';
  if (['1H', 'HT', '2H', 'ET', 'BT', 'P', 'INT', 'LIVE'].includes(short)) return 'live';
  return 'scheduled';
}

async function fetchApiFootballLigaMx() {
  const key = process.env.API_FOOTBALL_KEY;
  if (!key) return null;

  const client = axios.create({
    baseURL: 'https://v3.football.api-sports.io',
    timeout: 20000,
    headers: {
      'x-apisports-key': key,
    },
  });

  const leagueId = Number(process.env.API_FOOTBALL_LEAGUE_ID || 262);

  // Resolve current season if not explicitly provided.
  let season = Number(process.env.API_FOOTBALL_SEASON || 0);
  if (!season) {
    const leaguesResp = await client.get('/leagues', { params: { id: leagueId } });
    const leagueInfo = leaguesResp.data?.response?.[0];
    const currentSeason = (leagueInfo?.seasons || []).find((s) => s.current) || (leagueInfo?.seasons || []).slice(-1)[0];
    season = Number(currentSeason?.year);
    if (!season) throw new Error('Could not resolve Liga MX season from API-Football');
  }

  const now = new Date();
  const from = new Date(now);
  from.setDate(from.getDate() - 7);
  const to = new Date(now);
  to.setDate(to.getDate() + 14);
  const fmt = (d) => d.toISOString().slice(0, 10);

  const fetchFixtures = async (seasonToUse) => {
    const resp = await client.get('/fixtures', {
      params: {
        league: leagueId,
        season: seasonToUse,
        from: fmt(from),
        to: fmt(to),
        timezone: 'America/Mexico_City',
      },
    });
    return resp.data;
  };

  let fixturesRespData = await fetchFixtures(season);

  // Free plan fallback: API-Football may limit latest seasons (e.g. only up to 2024).
  const planError = fixturesRespData?.errors?.plan || '';
  if (!fixturesRespData?.results && /try from\s+\d{4}\s+to\s+\d{4}/i.test(planError)) {
    const m = planError.match(/try from\s+(\d{4})\s+to\s+(\d{4})/i);
    const maxAllowed = m ? Number(m[2]) : null;
    if (maxAllowed) {
      season = maxAllowed;
      fixturesRespData = await fetchFixtures(season);
    }
  }

  const fixtures = fixturesRespData?.response || [];
  return fixtures.map((f) => ({
    externalId: `af:${f.fixture?.id}`,
    league: 'Liga MX',
    season: String(season),
    matchday: f.league?.round || null,
    home: f.teams?.home?.name,
    away: f.teams?.away?.name,
    kickoffAt: f.fixture?.date,
    homeScore: Number.isInteger(f.goals?.home) ? f.goals.home : null,
    awayScore: Number.isInteger(f.goals?.away) ? f.goals.away : null,
    status: normalizeApiFootballStatus(f.fixture?.status?.short),
  }));
}

async function fetchFootballDataLigaMx() {
  const key = process.env.FOOTBALL_DATA_KEY;
  if (!key) return null;

  const url = 'https://api.football-data.org/v4/competitions/MX1/matches';
  const now = new Date();
  const from = new Date(now);
  from.setDate(from.getDate() - 7);
  const to = new Date(now);
  to.setDate(to.getDate() + 14);
  const fmt = (d) => d.toISOString().slice(0, 10);

  const { data } = await axios.get(url, {
    headers: { 'X-Auth-Token': key },
    params: { dateFrom: fmt(from), dateTo: fmt(to) },
    timeout: 20000,
  });

  return (data.matches || []).map((m) => ({
    externalId: `fd:${m.id}`,
    league: 'Liga MX',
    season: `${m.season?.startDate || ''}..${m.season?.endDate || ''}`,
    matchday: m.matchday || null,
    home: m.homeTeam?.shortName || m.homeTeam?.name,
    away: m.awayTeam?.shortName || m.awayTeam?.name,
    kickoffAt: m.utcDate,
    homeScore: Number.isInteger(m.score?.fullTime?.home) ? m.score.fullTime.home : null,
    awayScore: Number.isInteger(m.score?.fullTime?.away) ? m.score.fullTime.away : null,
    status: m.status === 'FINISHED' ? 'finished' : (m.status === 'IN_PLAY' || m.status === 'PAUSED' ? 'live' : 'scheduled'),
  }));
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
  let source = null;
  let fixtures = [];

  if (process.env.API_FOOTBALL_KEY) {
    source = 'api-football';
    fixtures = await fetchApiFootballLigaMx();
  }

  if ((!fixtures || fixtures.length === 0) && process.env.FOOTBALL_DATA_KEY) {
    source = 'football-data';
    fixtures = await fetchFootballDataLigaMx();
  }

  if (!fixtures || fixtures.length === 0) {
    source = 'espn-public';
    fixtures = await fetchEspnLigaMx();
  }

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
