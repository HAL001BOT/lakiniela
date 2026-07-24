const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const Database = require('better-sqlite3');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lakiniela-migration-'));
const dbPath = path.join(tempDir, 'legacy.db');
const legacy = new Database(dbPath);

legacy.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    owner_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE matches (
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
`);
legacy.close();

const checkScript = `
  const db = require('./db');
  const required = {
    users: ['username', 'role', 'session_version'],
    pools: ['competition_type', 'current_matchday', 'current_season_key'],
    matches: ['home_logo', 'away_logo', 'winner_side', 'season_key'],
  };
  for (const [table, columns] of Object.entries(required)) {
    const actual = new Set(db.prepare('PRAGMA table_info(' + table + ')').all().map((row) => row.name));
    for (const column of columns) if (!actual.has(column)) throw new Error(table + '.' + column + ' missing');
  }
  const migrations = db.prepare('SELECT COUNT(*) c FROM schema_migrations').get().c;
  if (migrations < 2) throw new Error('Migration history incomplete');
  db.close();
`;

const result = spawnSync(process.execPath, ['-e', checkScript], {
  cwd: path.join(__dirname, '..'),
  env: {
    ...process.env,
    DB_PATH: dbPath,
    NODE_ENV: 'test',
  },
  encoding: 'utf8',
});

fs.rmSync(tempDir, { recursive: true, force: true });
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

console.log('Migration smoke checks passed.');
