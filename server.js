const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cron = require('node-cron');
const db = require('./db');
const { recalcPointsForMatch, syncLigaMxScores } = require('./services/updater');

const app = express();
const PORT = process.env.PORT || 3090;
app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'lakiniela-secret',
    resave: false,
    saveUninitialized: false,
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function auth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function code() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

function consumePendingInvite(req, res) {
  const inviteCode = String(req.session.pendingInviteCode || '').trim().toUpperCase();
  if (!inviteCode || !req.session.user) return false;

  const pool = db.prepare('SELECT * FROM pools WHERE code = ?').get(inviteCode);
  delete req.session.pendingInviteCode;
  if (!pool) return false;

  db.prepare('INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(pool.id, req.session.user.id);
  res.redirect(`/pools/${pool.id}`);
  return true;
}

function formatCentral(iso) {
  const dt = new Date(iso);
  if (!Number.isFinite(dt.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Chicago',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  }).format(dt) + ' CT';
}

function poolStandings(poolId) {
  return db.prepare(`
    SELECT u.id, u.name, COALESCE(SUM(p.points),0) points, COUNT(p.id) picks
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    LEFT JOIN predictions p ON p.pool_id = pm.pool_id AND p.user_id = pm.user_id
    WHERE pm.pool_id = ?
    GROUP BY u.id
    ORDER BY points DESC, picks DESC, u.name ASC
  `).all(poolId);
}

function inferJornadaFromAnchor(matches) {
  // Anchor requested by product: current visible matchday is Jornada 9.
  const anchorJornada = 9;
  const anchorDate = new Date('2026-03-03T00:00:00-06:00').getTime();
  const firstKick = Math.min(...matches.map((m) => new Date(m.kickoff_at).getTime()).filter(Number.isFinite));
  if (!Number.isFinite(firstKick) || !Number.isFinite(anchorDate)) return anchorJornada;
  const weeks = Math.round((firstKick - anchorDate) / (7 * 24 * 60 * 60 * 1000));
  return Math.max(1, anchorJornada + weeks);
}

function getUpcomingUniqueScheduledMatches() {
  // ESPN scoreboard doesn't reliably expose jornada/week for Liga MX in this feed.
  // So we infer a gameweek by grouping chronological matches where teams don't repeat.
  const all = db.prepare(`
    SELECT *
    FROM matches
    WHERE external_id LIKE 'espn:%'
      AND kickoff_at >= datetime('now', '-21 days')
      AND kickoff_at <= datetime('now', '+21 days')
    ORDER BY kickoff_at ASC
  `).all();

  const rounds = [];
  let current = [];
  let usedTeams = new Set();

  for (const m of all) {
    const home = String(m.home_team || '').toLowerCase();
    const away = String(m.away_team || '').toLowerCase();
    if (!home || !away) continue;

    const repeats = usedTeams.has(home) || usedTeams.has(away);
    const fullRound = current.length >= 9; // Liga MX usually 9 matches / jornada

    if ((repeats || fullRound) && current.length) {
      rounds.push(current);
      current = [];
      usedTeams = new Set();
    }

    current.push(m);
    usedTeams.add(home);
    usedTeams.add(away);
  }
  if (current.length) rounds.push(current);

  if (!rounds.length) return { matches: [], jornadaNumber: 9 };

  const now = Date.now();

  let selected = null;

  // pick current jornada first (has live, or in-progress schedule window)
  const withLive = rounds.find((r) => r.some((m) => m.status === 'live'));
  if (withLive) selected = withLive;

  // otherwise pick the nearest upcoming jornada
  if (!selected) {
    const upcomingIndex = rounds.findIndex((r) => r.some((m) => new Date(m.kickoff_at).getTime() >= now));
    if (upcomingIndex >= 0) {
      const r = rounds[upcomingIndex];
      selected = r;
    }
  }

  // fallback: latest known jornada
  if (!selected) selected = rounds[rounds.length - 1];

  const explicitMatchday = selected
    .map((m) => Number(m.matchday))
    .filter((n) => Number.isInteger(n) && n > 0)
    .sort((a, b) => b - a)[0];

  const jornadaNumber = explicitMatchday || inferJornadaFromAnchor(selected);
  return { matches: selected, jornadaNumber };
}

function lockPoolMatches(poolId, matches) {
  const insert = db.prepare('INSERT OR IGNORE INTO pool_matches (pool_id, match_id) VALUES (?, ?)');
  for (const m of matches || []) {
    if (!m?.id) continue;
    insert.run(poolId, m.id);
  }
}

function getPoolMatches(poolId) {
  return db.prepare(`
    SELECT m.*
    FROM pool_matches pm
    JOIN matches m ON m.id = pm.match_id
    WHERE pm.pool_id = ?
    ORDER BY m.kickoff_at ASC
  `).all(poolId);
}

function shouldRunFrequentSyncNow() {
  const live = db.prepare(`
    SELECT COUNT(*) c
    FROM matches
    WHERE external_id LIKE 'espn:%' AND status = 'live'
  `).get().c;
  if (live > 0) return true;

  const upcoming = db.prepare(`
    SELECT kickoff_at
    FROM matches
    WHERE external_id LIKE 'espn:%'
      AND status = 'scheduled'
      AND home_score IS NULL
      AND away_score IS NULL
  `).all();

  const now = Date.now();
  const preWindowMs = 15 * 60 * 1000;   // start syncing 15 min before kickoff
  const gameWindowMs = 2.5 * 60 * 60 * 1000; // keep syncing for ~150 min after kickoff

  return upcoming.some((m) => {
    const kickoff = new Date(m.kickoff_at).getTime();
    return Number.isFinite(kickoff) && now >= (kickoff - preWindowMs) && now <= (kickoff + gameWindowMs);
  });
}

app.get('/', (req, res) => (req.session.user ? res.redirect('/dashboard') : res.redirect('/login')));

app.get('/register', (_req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.render('register', { error: 'Fill all fields.' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name.trim(), email.trim().toLowerCase(), hash);
    req.session.user = { id: info.lastInsertRowid, name: name.trim(), email: email.trim().toLowerCase() };
    if (consumePendingInvite(req, res)) return;
    res.redirect('/dashboard');
  } catch {
    res.render('register', { error: 'Email already in use.' });
  }
});

app.get('/login', (_req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((req.body.email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password_hash)) return res.render('login', { error: 'Invalid credentials.' });
  req.session.user = { id: user.id, name: user.name, email: user.email };
  if (consumePendingInvite(req, res)) return;
  res.redirect('/dashboard');
});

app.post('/logout', auth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/dashboard', auth, (req, res) => {
  const pools = db.prepare(`
    SELECT p.*, (SELECT COUNT(*) FROM pool_members pm WHERE pm.pool_id = p.id) members
    FROM pools p
    JOIN pool_members pm ON pm.pool_id = p.id
    WHERE pm.user_id = ?
    ORDER BY p.created_at DESC
  `).all(req.session.user.id);

  const matchdayView = getUpcomingUniqueScheduledMatches();
  const nextMatches = matchdayView.matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  res.render('dashboard', { pools, nextMatches, jornadaNumber: matchdayView.jornadaNumber });
});

app.post('/pools/create', auth, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.redirect('/dashboard');
  const poolCode = code();
  const snapshotMatches = getUpcomingUniqueScheduledMatches().matches;

  const tx = db.transaction(() => {
    const info = db.prepare('INSERT INTO pools (name, code, owner_id) VALUES (?, ?, ?)').run(name, poolCode, req.session.user.id);
    db.prepare('INSERT INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, req.session.user.id);
    lockPoolMatches(info.lastInsertRowid, snapshotMatches);
  });
  tx();
  res.redirect('/dashboard');
});

app.post('/pools/join', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE code = ?').get(String(req.body.code || '').trim().toUpperCase());
  if (!pool) return res.redirect('/dashboard');
  db.prepare('INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(pool.id, req.session.user.id);
  res.redirect(`/pools/${pool.id}`);
});

app.get(['/invite/:code', '/join/:code'], (req, res) => {
  const inviteCode = String(req.params.code || '').trim().toUpperCase();
  const pool = db.prepare('SELECT * FROM pools WHERE code = ?').get(inviteCode);
  if (!pool) return res.status(404).send('Invite link not valid.');

  if (!req.session.user) {
    req.session.pendingInviteCode = inviteCode;
    return res.redirect('/login');
  }

  db.prepare('INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(pool.id, req.session.user.id);
  return res.redirect(`/pools/${pool.id}`);
});

app.get('/pools/:id', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const isMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!isMember) return res.status(403).send('Join this pool first.');

  let matches = getPoolMatches(pool.id);
  if (!matches.length) {
    // Backfill old pools created before match-locking feature
    const snapshotMatches = getUpcomingUniqueScheduledMatches().matches;
    lockPoolMatches(pool.id, snapshotMatches);
    matches = getPoolMatches(pool.id);
  }

  matches = matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  const preds = db.prepare('SELECT * FROM predictions WHERE pool_id = ? AND user_id = ?').all(pool.id, req.session.user.id);
  const predByMatch = new Map(preds.map((p) => [p.match_id, p]));
  const standings = poolStandings(pool.id);
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const inviteLink = `${proto}://${req.get('host')}/invite/${pool.code}`;

  res.render('pool', { pool, matches, predByMatch, standings, nowMs: Date.now(), inviteLink });
});

app.post('/pools/:id/predictions/:matchId', auth, (req, res) => {
  const poolId = Number(req.params.id);
  const matchId = Number(req.params.matchId);
  const predHome = Number(req.body.pred_home);
  const predAway = Number(req.body.pred_away);

  if (!Number.isInteger(predHome) || !Number.isInteger(predAway) || predHome < 0 || predAway < 0) {
    return res.status(400).json({ ok: false, error: 'Invalid score.' });
  }

  const member = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(poolId, req.session.user.id);
  const poolMatch = db.prepare('SELECT 1 FROM pool_matches WHERE pool_id = ? AND match_id = ?').get(poolId, matchId);
  const match = db.prepare('SELECT * FROM matches WHERE id = ?').get(matchId);
  if (!member || !poolMatch || !match) return res.status(403).json({ ok: false, error: 'Match is not part of this pool.' });

  const kickoffMs = new Date(match.kickoff_at).getTime();
  const lockMs = kickoffMs - (15 * 60 * 1000);
  if (!Number.isFinite(kickoffMs) || Date.now() >= lockMs) {
    return res.status(403).json({ ok: false, error: 'Predictions are locked 15 minutes before kickoff.' });
  }

  db.prepare(`
    INSERT INTO predictions (pool_id, user_id, match_id, pred_home, pred_away)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(pool_id, user_id, match_id)
    DO UPDATE SET pred_home = excluded.pred_home, pred_away = excluded.pred_away, updated_at = CURRENT_TIMESTAMP
  `).run(poolId, req.session.user.id, matchId, predHome, predAway);

  if (match.status === 'finished') recalcPointsForMatch(matchId);

  res.json({ ok: true });
});

// admin endpoint for manual final score entry
app.post('/admin/matches/:id/final', (req, res) => {
  if (req.headers['x-admin-key'] !== (process.env.ADMIN_KEY || 'dev-admin')) return res.status(401).json({ ok: false });
  const home = Number(req.body.home_score);
  const away = Number(req.body.away_score);
  db.prepare("UPDATE matches SET home_score = ?, away_score = ?, status = 'finished' WHERE id = ?").run(home, away, req.params.id);
  recalcPointsForMatch(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/admin/sync', async (req, res) => {
  if (req.headers['x-admin-key'] !== (process.env.ADMIN_KEY || 'dev-admin')) return res.status(401).json({ ok: false });
  try {
    const result = await syncLigaMxScores();
    return res.json(result);
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

cron.schedule('*/5 * * * *', async () => {
  try {
    if (!shouldRunFrequentSyncNow()) return;
    const result = await syncLigaMxScores();
    console.log('Auto-sync (5m):', result);
  } catch (e) {
    console.error('Score sync failed:', e.message);
  }
});

(async () => {
  try {
    const result = await syncLigaMxScores();
    console.log('Startup sync:', result);
  } catch (e) {
    console.warn('Startup sync skipped:', e.message);
  }
})();

app.listen(PORT, () => console.log(`LaKiniela running on http://localhost:${PORT}`));
