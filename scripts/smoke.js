const fs = require('fs');
const path = require('path');

function mustExist(p) {
  if (!fs.existsSync(p)) {
    throw new Error(`Missing required file: ${p}`);
  }
}

function checkEjsDir(dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.ejs'));
  if (!files.length) throw new Error('No EJS templates found');
}

function main() {
  mustExist(path.join(__dirname, '..', 'server.js'));
  mustExist(path.join(__dirname, '..', 'db.js'));
  mustExist(path.join(__dirname, '..', 'services', 'updater.js'));
  mustExist(path.join(__dirname, '..', 'public', 'style.css'));
  checkEjsDir(path.join(__dirname, '..', 'views'));

  // Require core modules to catch syntax/runtime import issues early.
  require('../db');
  const updater = require('../services/updater');
  if (typeof updater.syncWorldCupScores !== 'function') {
    throw new Error('Missing World Cup sync export');
  }
  const predictionsDashboard = require('../services/predictions-dashboard');
  if (predictionsDashboard.predictionStatus({ pred_home: 2, pred_away: 1 }, { status: 'finished', home_score: 2, away_score: 1 }) !== 'exact') {
    throw new Error('Exact prediction classification failed');
  }
  if (predictionsDashboard.predictionStatus({ pred_home: 1, pred_away: 0 }, { status: 'finished', home_score: 3, away_score: 2 }) !== 'result') {
    throw new Error('Correct result classification failed');
  }
  if (predictionsDashboard.predictionStatus({ pred_home: 0, pred_away: 1 }, { status: 'finished', home_score: 3, away_score: 2 }) !== 'miss') {
    throw new Error('Failed prediction classification failed');
  }
  const worldCupRounds = predictionsDashboard.groupPredictionMatches(
    Array.from({ length: 72 }, (_, i) => ({ id: i + 1, kickoff_at: new Date(2026, 5, 11, i).toISOString(), matchday: null })),
    'world_cup_2026'
  );
  if (worldCupRounds.length !== 3 || worldCupRounds.some((round) => round.matches.length !== 24)) {
    throw new Error('World Cup prediction rounds failed');
  }
  mustExist(path.join(__dirname, '..', 'views', 'predictions-dashboard.ejs'));

  const { selectActiveMatchday, roundsFromSchedule, inferMissingMatchdays } = require('../services/matchday-selector');
  const makeMatch = (id, matchday, kickoffAt, home, away, status = 'scheduled') => ({
    id,
    matchday,
    kickoff_at: kickoffAt,
    home_team: home,
    away_team: away,
    status,
  });

  const irregularMatchdays = [
    ...Array.from({ length: 8 }, (_, i) => makeMatch(
      i + 1,
      4,
      `2026-08-${String(1 + Math.floor(i / 3)).padStart(2, '0')}T20:00:00Z`,
      `J4 Home ${i}`,
      `J4 Away ${i}`
    )),
    ...Array.from({ length: 10 }, (_, i) => makeMatch(
      i + 20,
      5,
      `2026-08-${String(8 + Math.floor(i / 3)).padStart(2, '0')}T20:00:00Z`,
      `J5 Home ${i}`,
      `J5 Away ${i}`
    )),
  ];
  const selectedIrregularRound = selectActiveMatchday(irregularMatchdays, {
    nowMs: new Date('2026-08-07T12:00:00Z').getTime(),
  });
  if (selectedIrregularRound.matchday !== 5 || selectedIrregularRound.matches.length !== 10) {
    throw new Error('Matchday selection must preserve irregular round sizes');
  }

  const sameNumberDifferentSeasons = selectActiveMatchday([
    { ...makeMatch(80, 7, '2026-05-01T20:00:00Z', 'Clausura Home', 'Clausura Away'), season_key: '2026:torneo-clausura' },
    { ...makeMatch(81, 7, '2026-08-01T20:00:00Z', 'Apertura Home', 'Apertura Away'), season_key: '2026:torneo-apertura' },
  ], {
    nowMs: new Date('2026-07-30T12:00:00Z').getTime(),
  });
  if (
    sameNumberDifferentSeasons.seasonKey !== '2026:torneo-apertura'
    || sameNumberDifferentSeasons.matches.length !== 1
  ) {
    throw new Error('Equal matchday numbers from different seasons must remain isolated');
  }

  const selectedWithIncompleteMetadata = selectActiveMatchday([
    makeMatch(90, null, '2026-08-06T20:00:00Z', 'Unknown Home', 'Unknown Away'),
    ...irregularMatchdays,
  ], {
    nowMs: new Date('2026-08-07T12:00:00Z').getTime(),
  });
  if (
    selectedWithIncompleteMetadata.matchday !== 5
    || selectedWithIncompleteMetadata.matches.length !== 11
    || !selectedWithIncompleteMetadata.matches.some((match) => match.inferred_matchday)
  ) {
    throw new Error('Missing matchday metadata must be attached to the closest explicit round');
  }

  const thursdayMatch = makeMatch(100, 6, '2026-08-13T20:00:00Z', 'Thursday Home', 'Thursday Away');
  const selectedThursdayRound = selectActiveMatchday([thursdayMatch], {
    nowMs: new Date('2026-08-12T12:00:00Z').getTime(),
  });
  if (selectedThursdayRound.matches[0]?.id !== thursdayMatch.id) {
    throw new Error('Matchday selection must include Monday/Thursday fixtures');
  }

  const fallbackRounds = roundsFromSchedule([
    makeMatch(200, null, '2026-08-01T20:00:00Z', 'A', 'B'),
    makeMatch(201, null, '2026-08-02T20:00:00Z', 'C', 'D'),
    makeMatch(202, null, '2026-08-08T20:00:00Z', 'A', 'E'),
  ]);
  if (fallbackRounds.length !== 2 || fallbackRounds[0].matches.length !== 2) {
    throw new Error('Schedule fallback must split rounds when a team repeats');
  }
  const inferredRounds = inferMissingMatchdays([
    makeMatch(210, null, '2026-07-17T20:00:00Z', 'A', 'B'),
    makeMatch(211, null, '2026-07-18T20:00:00Z', 'C', 'D'),
    makeMatch(212, null, '2026-07-24T20:00:00Z', 'A', 'C'),
    makeMatch(213, null, '2026-07-25T20:00:00Z', 'B', 'D'),
  ]);
  if (
    inferredRounds.filter((match) => match.matchday === 1).length !== 2
    || inferredRounds.filter((match) => match.matchday === 2).length !== 2
  ) {
    throw new Error('Missing ESPN week metadata must become sequential numbered matchdays');
  }

  const smokeDb = require('../db');
  const poolColumns = smokeDb.prepare('PRAGMA table_info(pools)').all().map((column) => column.name);
  if (!poolColumns.includes('current_matchday')) {
    throw new Error('Pools must persist their current matchday');
  }
  if (smokeDb.pragma('foreign_keys', { simple: true }) !== 1) {
    throw new Error('SQLite foreign key enforcement must be enabled');
  }
  if (!smokeDb.prepare("SELECT 1 FROM schema_migrations WHERE id = '001_legacy_columns'").get()) {
    throw new Error('Database migrations must be versioned and recorded');
  }

  console.log('Smoke checks passed.');
}

main();
