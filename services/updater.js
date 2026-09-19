const axios = require('axios');
const db = require('../db');
const { inferMissingMatchdays } = require('./matchday-selector');

const COMPETITIONS = {
  LIGA_MX: {
    key: 'liga_mx',
    leagueLabel: 'Liga MX',
    espnPath: 'mex.1',
    fullCalendarYear: true,
    dateLookbackDays: 45,
    dateAheadDays: 150,
  },
  CHAMPIONS_LEAGUE: {
    key: 'champions_league',
    leagueLabel: 'UEFA Champions League',
    espnPath: 'uefa.champions',
    dateLookbackDays: 7,
    dateAheadDays: 45,
  },
  WORLD_CUP_2026: {
    key: 'world_cup_2026',
    leagueLabel: 'FIFA World Cup',
    espnPath: 'fifa.world',
    dateRanges: [
      ['20260611', '20260617'],
      ['20260618', '20260624'],
      ['20260625', '20260701'],
      ['20260702', '20260708'],
      ['20260709', '20260715'],
      ['20260716', '20260719'],
    ],
  },
};

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

function mergeMatchRows(keepId, duplicateId) {
  if (!keepId || !duplicateId || Number(keepId) === Number(duplicateId)) return;
  db.transaction(() => {
    db.prepare('UPDATE OR IGNORE predictions SET match_id = ? WHERE match_id = ?').run(keepId, duplicateId);
    db.prepare('UPDATE OR IGNORE pool_matches SET match_id = ? WHERE match_id = ?').run(keepId, duplicateId);
    db.prepare('DELETE FROM predictions WHERE match_id = ?').run(duplicateId);
    db.prepare('DELETE FROM pool_matches WHERE match_id = ?').run(duplicateId);
    db.prepare('DELETE FROM matches WHERE id = ?').run(duplicateId);
  })();
}

function upsertMatch(match) {
  if (!match.home || !match.away || !match.kickoffAt || !match.externalId) return null;

  const externalMatch = db.prepare('SELECT id FROM matches WHERE external_id = ?').get(match.externalId);
  const fixtureMatch = db.prepare(`
    SELECT id
    FROM matches
    WHERE league = ? AND home_team = ? AND away_team = ? AND kickoff_at = ?
  `).get(match.league, match.home, match.away, match.kickoffAt);
  const existing = externalMatch || fixtureMatch;
  if (existing) {
    if (externalMatch && fixtureMatch && externalMatch.id !== fixtureMatch.id) {
      mergeMatchRows(externalMatch.id, fixtureMatch.id);
    }
    db.prepare(`
      UPDATE matches
      SET external_id = ?, league = ?, season = ?, season_key = ?, matchday = ?, home_team = ?, away_team = ?, home_logo = ?, away_logo = ?, kickoff_at = ?,
          home_score = ?, away_score = ?, home_penalty_score = ?, away_penalty_score = ?, winner_side = ?, status = ?
      WHERE id = ?
    `).run(
      match.externalId,
      match.league,
      match.season,
      match.seasonKey,
      match.matchday,
      match.home,
      match.away,
      match.homeLogo || null,
      match.awayLogo || null,
      match.kickoffAt,
      match.homeScore,
      match.awayScore,
      match.homePenaltyScore,
      match.awayPenaltyScore,
      match.winnerSide,
      match.status,
      existing.id
    );

    if (match.status === 'finished' && match.homeScore !== null && match.awayScore !== null) recalcPointsForMatch(existing.id);
    return { created: false, id: existing.id };
  }

  const info = db.prepare(`
    INSERT INTO matches (
      external_id, league, season, matchday, home_team, away_team, home_logo, away_logo, kickoff_at,
      season_key,
      home_score, away_score, home_penalty_score, away_penalty_score, winner_side, status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    match.externalId,
    match.league,
    match.season,
    match.matchday,
    match.home,
    match.away,
    match.homeLogo || null,
    match.awayLogo || null,
    match.kickoffAt,
    match.seasonKey,
    match.homeScore,
    match.awayScore,
    match.homePenaltyScore,
    match.awayPenaltyScore,
    match.winnerSide,
    match.status
  );

  if (match.status === 'finished' && match.homeScore !== null && match.awayScore !== null) recalcPointsForMatch(info.lastInsertRowid);
  return { created: true, id: info.lastInsertRowid };
}

function normalizeEspnEvents(config, events) {
  return (events || []).map((ev) => {
    const comp = ev.competitions?.[0] || {};
    const home = (comp.competitors || []).find((c) => c.homeAway === 'home');
    const away = (comp.competitors || []).find((c) => c.homeAway === 'away');
    const completed = !!comp.status?.type?.completed;
    const state = comp.status?.type?.state;
    const shortDetail = String(comp.status?.type?.shortDetail || '').toLowerCase();
    const isLive = state === 'in' || /\b\d{1,3}'/.test(shortDetail) || shortDetail.includes('ht');
    const status = completed ? 'finished' : (isLive ? 'live' : 'scheduled');

    const parsedHome = Number.isFinite(Number(home?.score)) ? Number(home.score) : null;
    const parsedAway = Number.isFinite(Number(away?.score)) ? Number(away.score) : null;
    const homeScore = (status === 'finished' || status === 'live') ? parsedHome : null;
    const awayScore = (status === 'finished' || status === 'live') ? parsedAway : null;
    const parsedHomePenalty = Number.isFinite(Number(home?.shootoutScore)) ? Number(home.shootoutScore) : null;
    const parsedAwayPenalty = Number.isFinite(Number(away?.shootoutScore)) ? Number(away.shootoutScore) : null;
    const homePenaltyScore = status === 'finished' ? parsedHomePenalty : null;
    const awayPenaltyScore = status === 'finished' ? parsedAwayPenalty : null;
    const winnerSide = status === 'finished'
      ? (home?.winner ? 'home' : away?.winner ? 'away' : null)
      : null;

    const externalId = config.key === 'liga_mx' ? `espn:${ev.id}` : `espn:${config.key}:${ev.id}`;
    const seasonYear = String(ev.season?.year || '');
    const seasonSlug = String(ev.season?.slug || ev.season?.type || 'unknown');

    return {
      externalId,
      league: config.leagueLabel,
      season: seasonYear,
      seasonKey: `${seasonYear || 'unknown'}:${seasonSlug}`,
      matchday: comp.week?.number || null,
      home: home?.team?.displayName,
      away: away?.team?.displayName,
      homeLogo: home?.team?.logo || null,
      awayLogo: away?.team?.logo || null,
      kickoffAt: ev.date,
      homeScore,
      awayScore,
      homePenaltyScore,
      awayPenaltyScore,
      winnerSide,
      status,
    };
  });
}

function parseCompactDate(value) {
  const match = String(value || '').match(/^(\d{4})(\d{2})(\d{2})$/);
  if (!match) throw new Error(`Invalid ESPN date: ${value}`);
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
}

function espnYearQueriesForRange(dates) {
  const [fromRaw, toRaw = fromRaw] = String(dates || '').split('-');
  const fromMs = parseCompactDate(fromRaw);
  const toExclusiveMs = parseCompactDate(toRaw) + (24 * 60 * 60 * 1000);
  if (toExclusiveMs <= fromMs) throw new Error(`Invalid ESPN date range: ${dates}`);

  const years = [];
  for (let year = new Date(fromMs).getUTCFullYear(); year <= new Date(toExclusiveMs - 1).getUTCFullYear(); year += 1) {
    years.push(String(year));
  }
  return { fromMs, toExclusiveMs, years };
}

async function fetchEspnCompetitionRange(config, dates) {
  const url = `https://site.api.espn.com/apis/site/v2/sports/soccer/${config.espnPath}/scoreboard`;
  const { fromMs, toExclusiveMs, years } = espnYearQueriesForRange(dates);
  const byId = new Map();

  // ESPN's scoreboard stopped accepting YYYYMMDD-YYYYMMDD values in 2026.
  // Year queries still work and include the complete schedule, so fetch each
  // touched year once and filter locally to the requested date window.
  for (const year of years) {
    const { data } = await axios.get(url, {
      params: { dates: year, limit: 1000 },
      timeout: 20000,
    });
    for (const event of data.events || []) {
      const kickoff = new Date(event.date).getTime();
      if (!Number.isFinite(kickoff) || kickoff < fromMs || kickoff >= toExclusiveMs) continue;
      byId.set(String(event.id), event);
    }
  }

  return normalizeEspnEvents(config, [...byId.values()]);
}

async function fetchEspnCompetition(config) {
  const fmt = (d) => d.toISOString().slice(0, 10).replace(/-/g, '');

  if (Array.isArray(config.dateRanges) && config.dateRanges.length) {
    const first = config.dateRanges[0][0];
    const last = config.dateRanges[config.dateRanges.length - 1][1];
    return fetchEspnCompetitionRange(config, `${first}-${last}`);
  }

  const now = new Date();
  if (config.fullCalendarYear) {
    const year = now.getUTCFullYear();
    return fetchEspnCompetitionRange(config, `${year}0101-${year}1231`);
  }

  const from = new Date(now);
  from.setDate(from.getDate() - (config.dateLookbackDays || 7));
  const to = new Date(now);
  to.setDate(to.getDate() + (config.dateAheadDays || 21));

  return fetchEspnCompetitionRange(config, `${fmt(from)}-${fmt(to)}`);
}

async function syncCompetition(config) {
  const source = 'espn-public';
  const fetchedFixtures = await fetchEspnCompetition(config);
  const fixtures = config.key === 'liga_mx'
    ? inferMissingMatchdays(fetchedFixtures)
    : fetchedFixtures;

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

  return { ok: true, source, competition: config.key, total: (fixtures || []).length, created, updated, finished };
}

async function syncLigaMxScores() {
  return syncCompetition(COMPETITIONS.LIGA_MX);
}

async function syncChampionsLeagueScores() {
  return syncCompetition(COMPETITIONS.CHAMPIONS_LEAGUE);
}

async function syncWorldCupScores() {
  return syncCompetition(COMPETITIONS.WORLD_CUP_2026);
}

module.exports = {
  resultPoints,
  recalcPointsForMatch,
  upsertMatch,
  syncLigaMxScores,
  syncChampionsLeagueScores,
  syncWorldCupScores,
  fetchEspnCompetitionRange,
  espnYearQueriesForRange,
  COMPETITIONS,
};
