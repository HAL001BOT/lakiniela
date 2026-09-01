const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'lakiniela.db');
if (process.env.NODE_ENV === 'production' && !process.env.DB_PATH) {
  throw new Error('DB_PATH must point to persistent storage in production.');
}
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('busy_timeout = 5000');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  code TEXT UNIQUE NOT NULL,
  owner_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  competition_type TEXT DEFAULT 'liga_mx',
  current_matchday INTEGER,
  current_season_key TEXT,
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
  season_key TEXT,
  matchday INTEGER,
  home_team TEXT NOT NULL,
  away_team TEXT NOT NULL,
  home_logo TEXT,
  away_logo TEXT,
  kickoff_at TEXT NOT NULL,
  home_score INTEGER,
  away_score INTEGER,
  home_penalty_score INTEGER,
  away_penalty_score INTEGER,
  winner_side TEXT,
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

CREATE TABLE IF NOT EXISTS pool_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pool_id INTEGER NOT NULL,
  match_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(pool_id, match_id),
  FOREIGN KEY(pool_id) REFERENCES pools(id),
  FOREIGN KEY(match_id) REFERENCES matches(id)
);

CREATE TABLE IF NOT EXISTS sessions_store (
  sid TEXT PRIMARY KEY,
  sess TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  scope TEXT NOT NULL,
  subject TEXT NOT NULL,
  count INTEGER NOT NULL,
  reset_at INTEGER NOT NULL,
  PRIMARY KEY (scope, subject)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  actor_user_id INTEGER,
  ip TEXT,
  path TEXT,
  method TEXT,
  ok INTEGER DEFAULT 1,
  detail TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS job_locks (
  name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  locked_until INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_predictions_pool_user ON predictions(pool_id, user_id);
CREATE INDEX IF NOT EXISTS idx_pool_matches_pool ON pool_matches(pool_id);
CREATE INDEX IF NOT EXISTS idx_pool_members_user ON pool_members(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_store_expires_at ON sessions_store(expires_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_reset_at ON rate_limits(reset_at);
`);

function hasColumn(table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some((row) => row.name === column);
}

function addColumn(table, definition) {
  const column = definition.trim().split(/\s+/)[0];
  if (!hasColumn(table, column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
}

function runMigration(id, migrate) {
  if (db.prepare('SELECT 1 FROM schema_migrations WHERE id = ?').get(id)) return;
  db.transaction(() => {
    migrate();
    db.prepare('INSERT INTO schema_migrations (id) VALUES (?)').run(id);
  })();
}

runMigration('001_legacy_columns', () => {
  addColumn('matches', 'home_logo TEXT');
  addColumn('matches', 'away_logo TEXT');
  addColumn('matches', 'home_penalty_score INTEGER');
  addColumn('matches', 'away_penalty_score INTEGER');
  addColumn('matches', 'winner_side TEXT');
  addColumn('users', 'username TEXT');
  addColumn('users', "role TEXT DEFAULT 'user'");
  addColumn('pools', "competition_type TEXT DEFAULT 'liga_mx'");
  addColumn('pools', 'current_matchday INTEGER');
});

runMigration('002_seasons_and_sessions', () => {
  addColumn('matches', 'season_key TEXT');
  addColumn('pools', 'current_season_key TEXT');
  addColumn('users', 'session_version INTEGER NOT NULL DEFAULT 1');
});

runMigration('003_rename_j4_pool', () => {
  db.prepare("UPDATE pools SET name = 'Apertura 2026' WHERE name = 'J4'").run();
});

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_matches_schedule
  ON matches(league, season_key, matchday, kickoff_at);
`);

const duplicateExternalMatches = db.prepare(`
  SELECT external_id, MIN(id) AS keep_id
  FROM matches
  WHERE external_id IS NOT NULL AND TRIM(external_id) != ''
  GROUP BY external_id
  HAVING COUNT(*) > 1
`).all();

for (const row of duplicateExternalMatches) {
  const dupIds = db.prepare('SELECT id FROM matches WHERE external_id = ? AND id != ? ORDER BY id ASC').all(row.external_id, row.keep_id).map(r => r.id);
  for (const dupId of dupIds) {
    db.prepare('UPDATE OR IGNORE predictions SET match_id = ? WHERE match_id = ?').run(row.keep_id, dupId);
    db.prepare('UPDATE OR IGNORE pool_matches SET match_id = ? WHERE match_id = ?').run(row.keep_id, dupId);
    db.prepare('DELETE FROM predictions WHERE match_id = ?').run(dupId);
    db.prepare('DELETE FROM pool_matches WHERE match_id = ?').run(dupId);
    db.prepare('DELETE FROM matches WHERE id = ?').run(dupId);
  }
}

const duplicateFixtureRows = db.prepare(`
  SELECT
    LOWER(TRIM(home_team)) AS home_key,
    LOWER(TRIM(away_team)) AS away_key,
    kickoff_at,
    MIN(id) AS keep_id
  FROM matches
  WHERE league = 'Liga MX'
  GROUP BY home_key, away_key, kickoff_at
  HAVING COUNT(*) > 1
`).all();

for (const row of duplicateFixtureRows) {
  const dupIds = db.prepare(`
    SELECT id
    FROM matches
    WHERE league = 'Liga MX'
      AND LOWER(TRIM(home_team)) = ?
      AND LOWER(TRIM(away_team)) = ?
      AND kickoff_at = ?
      AND id != ?
    ORDER BY id ASC
  `).all(row.home_key, row.away_key, row.kickoff_at, row.keep_id).map(r => r.id);

  for (const dupId of dupIds) {
    db.prepare('UPDATE OR IGNORE predictions SET match_id = ? WHERE match_id = ?').run(row.keep_id, dupId);
    db.prepare('UPDATE OR IGNORE pool_matches SET match_id = ? WHERE match_id = ?').run(row.keep_id, dupId);
    db.prepare('DELETE FROM predictions WHERE match_id = ?').run(dupId);
    db.prepare('DELETE FROM pool_matches WHERE match_id = ?').run(dupId);
    db.prepare('DELETE FROM matches WHERE id = ?').run(dupId);
  }
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_matches_external_id
  ON matches(external_id)
  WHERE external_id IS NOT NULL;

  CREATE UNIQUE INDEX IF NOT EXISTS idx_matches_ligamx_fixture
  ON matches(league, home_team, away_team, kickoff_at)
  WHERE league = 'Liga MX';
`);

const stalePreviewMatches = db.prepare(`
  SELECT m.id
  FROM matches m
  LEFT JOIN predictions p ON p.match_id = m.id
  WHERE m.external_id LIKE 'preview-r32-%'
  GROUP BY m.id
  HAVING COUNT(p.id) = 0
`).all();

if (stalePreviewMatches.length) {
  const removePreviewMatches = db.transaction((rows) => {
    const deletePoolMatch = db.prepare('DELETE FROM pool_matches WHERE match_id = ?');
    const deleteMatch = db.prepare('DELETE FROM matches WHERE id = ?');
    for (const row of rows) {
      deletePoolMatch.run(row.id);
      deleteMatch.run(row.id);
    }
  });
  removePreviewMatches(stalePreviewMatches);
}

db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)');

// backfill usernames from email prefix for legacy users
const legacyUsers = db.prepare("SELECT id, email FROM users WHERE username IS NULL OR TRIM(username) = ''").all();
for (const u of legacyUsers) {
  const base = String((u.email || '').split('@')[0] || `user${u.id}`).toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || `user${u.id}`;
  let candidate = base;
  let i = 1;
  while (db.prepare('SELECT 1 FROM users WHERE username = ? AND id != ?').get(candidate, u.id)) {
    i += 1;
    candidate = `${base}${i}`;
  }
  db.prepare('UPDATE users SET username = ? WHERE id = ?').run(candidate, u.id);
}

// ensure one admin exists (without resetting existing credentials)
const hasAdmin = db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
if (!hasAdmin) {
  const firstUser = db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get();
  if (firstUser) db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(firstUser.id);
}

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
