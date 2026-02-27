const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'data', 'lakiniela.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  code TEXT UNIQUE NOT NULL,
  owner_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS pool_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pool_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(pool_id, user_id),
  FOREIGN KEY(pool_id) REFERENCES pools(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT,
  league TEXT DEFAULT 'Liga MX',
  season TEXT,
  matchday INTEGER,
  home_team TEXT NOT NULL,
  away_team TEXT NOT NULL,
  kickoff_at TEXT NOT NULL,
  home_score INTEGER,
  away_score INTEGER,
  status TEXT DEFAULT 'scheduled'
);

CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pool_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  match_id INTEGER NOT NULL,
  pred_home INTEGER NOT NULL,
  pred_away INTEGER NOT NULL,
  points INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(pool_id, user_id, match_id),
  FOREIGN KEY(pool_id) REFERENCES pools(id),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(match_id) REFERENCES matches(id)
);
`);

const countMatches = db.prepare('SELECT COUNT(*) c FROM matches').get().c;
if (!countMatches) {
  const seed = db.prepare(`
    INSERT INTO matches (season, matchday, home_team, away_team, kickoff_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  [
    ['2026 Clausura', 1, 'América', 'Chivas', '2026-03-01T20:00:00-06:00'],
    ['2026 Clausura', 1, 'Tigres', 'Monterrey', '2026-03-01T22:00:00-06:00'],
    ['2026 Clausura', 1, 'Cruz Azul', 'Pumas', '2026-03-02T19:00:00-06:00'],
    ['2026 Clausura', 1, 'León', 'Toluca', '2026-03-02T21:00:00-06:00'],
  ].forEach((m) => seed.run(...m));
}

module.exports = db;
