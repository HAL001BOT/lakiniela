const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const dbPath = path.join(__dirname, 'data', 'lakiniela.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
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
  home_logo TEXT,
  away_logo TEXT,
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

CREATE TABLE IF NOT EXISTS pool_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pool_id INTEGER NOT NULL,
  match_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(pool_id, match_id),
  FOREIGN KEY(pool_id) REFERENCES pools(id),
  FOREIGN KEY(match_id) REFERENCES matches(id)
);
`);

try { db.exec('ALTER TABLE matches ADD COLUMN home_logo TEXT'); } catch {}
try { db.exec('ALTER TABLE matches ADD COLUMN away_logo TEXT'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN username TEXT'); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'"); } catch {}
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)'); } catch {}

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

// ensure one admin exists and can log in with known bootstrap password
const bootstrapAdminPassword = process.env.ADMIN_BOOTSTRAP_PASSWORD || '123456';
const adminHash = bcrypt.hashSync(bootstrapAdminPassword, 10);
const adminUser = db.prepare("SELECT id FROM users WHERE username = 'admin' LIMIT 1").get();
if (!adminUser) {
  db.prepare("INSERT INTO users (name, username, email, password_hash, role) VALUES (?, 'admin', ?, ?, 'admin')")
    .run('Admin', 'admin@local.lakiniela', adminHash);
} else {
  db.prepare("UPDATE users SET role = 'admin', password_hash = ? WHERE id = ?").run(adminHash, adminUser.id);
}

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
