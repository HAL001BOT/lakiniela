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

  console.log('Smoke checks passed.');
}

main();
