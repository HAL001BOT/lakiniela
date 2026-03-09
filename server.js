const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cron = require('node-cron');
const helmet = require('helmet');
const db = require('./db');
const { recalcPointsForMatch, syncLigaMxScores } = require('./services/updater');

const app = express();
const PORT = process.env.PORT || 3090;
const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);

const sessionSecret = process.env.SESSION_SECRET;
const adminKey = process.env.ADMIN_KEY;
if (isProd && (!sessionSecret || sessionSecret.length < 24)) {
  throw new Error('SESSION_SECRET is required (min 24 chars) in production.');
}
if (isProd && (!adminKey || adminKey.length < 16)) {
  throw new Error('ADMIN_KEY is required (min 16 chars) in production.');
}

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);
app.use(
  session({
    secret: sessionSecret || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.user = req.session.user || null;
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

function createIpRateLimiter({ windowMs, max, message }) {
  const hits = new Map();
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const row = hits.get(ip);
    if (!row || now > row.resetAt) {
      hits.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }
    row.count += 1;
    if (row.count > max) return res.status(429).send(message || 'Too many requests');
    return next();
  };
}

const loginLimiter = createIpRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, message: 'Too many login attempts. Try again soon.' });
const adminLimiter = createIpRateLimiter({ windowMs: 60 * 1000, max: 120, message: 'Too many admin requests.' });

function csrfPostGuard(req, res, next) {
  if (req.method !== 'POST') return next();
  const path = req.path || '';
  // API-key protected admin endpoints are allowed without session CSRF token.
  if (path.startsWith('/admin/sync') || path.startsWith('/admin/matches/')) return next();

  const providedToken = req.body?._csrf || req.get('x-csrf-token');
  const expectedToken = req.session?.csrfToken;
  if (!expectedToken || !providedToken || providedToken !== expectedToken) {
    return res.status(403).send('Blocked by CSRF protection.');
  }
  return next();
}

app.use(csrfPostGuard);

function auth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function admin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Admin only');
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
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) return res.render('register', { error: 'Fill all fields.' });
  try {
    const uname = String(username).trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(uname)) return res.render('register', { error: 'Username must be 3-24 chars (letters, numbers, underscore).' });
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
      .run(name.trim(), uname, email.trim().toLowerCase(), hash, 'user');
    req.session.user = { id: info.lastInsertRowid, name: name.trim(), username: uname, email: email.trim().toLowerCase(), role: 'user' };
    if (consumePendingInvite(req, res)) return;
    res.redirect('/dashboard');
  } catch {
    res.render('register', { error: 'Username or email already in use.' });
  }
});

app.get('/login', (_req, res) => res.render('login', { error: null }));
app.post('/login', loginLimiter, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get((req.body.username || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password_hash)) return res.render('login', { error: 'Invalid credentials.' });
  req.session.user = { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role || 'user' };
  if (consumePendingInvite(req, res)) return;
  res.redirect('/dashboard');
});

app.post('/logout', auth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/account/password', auth, (req, res) => {
  res.render('change-password', { error: null, ok: false });
});

app.post('/account/password', auth, (req, res) => {
  const current = String(req.body.current_password || '');
  const nextPw = String(req.body.new_password || '');
  const confirm = String(req.body.confirm_password || '');

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!user || !bcrypt.compareSync(current, user.password_hash)) {
    return res.status(400).render('change-password', { error: 'Current password is incorrect.', ok: false });
  }
  if (nextPw.length < 8) {
    return res.status(400).render('change-password', { error: 'New password must be at least 8 characters.', ok: false });
  }
  if (nextPw !== confirm) {
    return res.status(400).render('change-password', { error: 'New passwords do not match.', ok: false });
  }

  const hash = bcrypt.hashSync(nextPw, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  return res.render('change-password', { error: null, ok: true });
});

app.get('/dashboard', auth, (req, res) => {
  const poolsRaw = db.prepare(`
    SELECT p.*, (SELECT COUNT(*) FROM pool_members pm WHERE pm.pool_id = p.id) members
    FROM pools p
    JOIN pool_members pm ON pm.pool_id = p.id
    WHERE pm.user_id = ?
    ORDER BY p.created_at DESC
  `).all(req.session.user.id);

  const winnerStmt = db.prepare(`
    SELECT u.name, COALESCE(SUM(pr.points), 0) AS points, COUNT(pr.id) AS picks
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    LEFT JOIN predictions pr ON pr.pool_id = pm.pool_id AND pr.user_id = pm.user_id
    WHERE pm.pool_id = ?
    GROUP BY u.id, u.name
    ORDER BY points DESC, picks DESC, u.name ASC
    LIMIT 1
  `);

  const pools = poolsRaw.map((p) => {
    const matchStats = db.prepare(`
      SELECT COUNT(*) AS total,
             SUM(CASE WHEN m.status = 'finished' THEN 1 ELSE 0 END) AS finished
      FROM pool_matches pm
      JOIN matches m ON m.id = pm.match_id
      WHERE pm.pool_id = ?
    `).get(p.id);

    const totalMatches = Number(matchStats?.total || 0);
    const finishedMatches = Number(matchStats?.finished || 0);
    const poolFinished = totalMatches > 0 && finishedMatches === totalMatches;
    const winner = poolFinished ? winnerStmt.get(p.id) : null;

    return {
      ...p,
      pool_finished: poolFinished,
      winner_name: winner?.name || null,
    };
  });

  const pointsDashboard = db.prepare(`
    SELECT u.id, u.name, COALESCE(SUM(pr.points), 0) AS points
    FROM pool_members mine
    JOIN pool_members pm ON pm.pool_id = mine.pool_id
    JOIN users u ON u.id = pm.user_id
    LEFT JOIN predictions pr ON pr.pool_id = pm.pool_id AND pr.user_id = pm.user_id
    WHERE mine.user_id = ?
    GROUP BY u.id, u.name
    ORDER BY points DESC, u.name ASC
  `).all(req.session.user.id);

  const matchdayView = getUpcomingUniqueScheduledMatches();
  const nextMatches = matchdayView.matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  res.render('dashboard', {
    pools,
    pointsDashboard,
    nextMatches,
    jornadaNumber: matchdayView.jornadaNumber,
    isAdmin: req.session.user.role === 'admin',
  });
});

app.use('/admin', adminLimiter);

app.get('/admin/users', admin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.name, u.username, u.email, u.role, u.created_at,
           (SELECT COUNT(*) FROM pool_members pm WHERE pm.user_id = u.id) pool_count
    FROM users u
    ORDER BY u.created_at DESC
  `).all();

  const memberships = db.prepare(`
    SELECT pm.user_id, pm.pool_id, p.name AS pool_name, p.code AS pool_code
    FROM pool_members pm
    JOIN pools p ON p.id = pm.pool_id
    ORDER BY p.created_at DESC
  `).all();

  const poolsByUser = new Map();
  memberships.forEach((m) => {
    if (!poolsByUser.has(m.user_id)) poolsByUser.set(m.user_id, []);
    poolsByUser.get(m.user_id).push(m);
  });

  res.render('admin-users', { users, me: req.session.user, poolsByUser });
});

app.post('/admin/users/:id/role', admin, (req, res) => {
  const id = Number(req.params.id);
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  if (!Number.isInteger(id)) return res.redirect('/admin/users');
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  if (req.session.user.id === id) req.session.user.role = role;
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/delete', admin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id === req.session.user.id) return res.redirect('/admin/users');

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM predictions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM pool_members WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM pools WHERE owner_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  tx();
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/reset-password', admin, (req, res) => {
  const id = Number(req.params.id);
  const newPassword = String(req.body.new_password || '');
  if (!Number.isInteger(id) || newPassword.length < 8) return res.redirect('/admin/users');
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
  res.redirect('/admin/users');
});

app.post('/admin/pools/:poolId/users/:userId/remove', admin, (req, res) => {
  const poolId = Number(req.params.poolId);
  const userId = Number(req.params.userId);
  if (!Number.isInteger(poolId) || !Number.isInteger(userId)) return res.redirect('/admin/users');

  db.prepare('DELETE FROM predictions WHERE pool_id = ? AND user_id = ?').run(poolId, userId);
  db.prepare('DELETE FROM pool_members WHERE pool_id = ? AND user_id = ?').run(poolId, userId);
  res.redirect('/admin/users');
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
    const proto = req.get('x-forwarded-proto') || req.protocol;
    const baseUrl = `${proto}://${req.get('host')}`;
    const inviteUrl = `${baseUrl}/invite/${inviteCode}`;
    const ogImage = `${baseUrl}/img/logo.png`;
    return res.render('invite-public', { pool, inviteUrl, ogImage });
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
  const poolFinished = matches.length > 0 && matches.every((m) => m.status === 'finished');
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const inviteLink = `${proto}://${req.get('host')}/invite/${pool.code}`;

  res.render('pool', { pool, matches, predByMatch, standings, poolFinished, nowMs: Date.now(), inviteLink });
});

app.get('/pools/:id/users/:userId/picks', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const viewerMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!viewerMember) return res.status(403).send('Join this pool first.');

  const targetUserId = Number(req.params.userId);
  if (!Number.isInteger(targetUserId)) return res.status(400).send('Invalid user');

  const targetMember = db.prepare('SELECT u.id, u.name FROM pool_members pm JOIN users u ON u.id = pm.user_id WHERE pm.pool_id = ? AND pm.user_id = ?').get(pool.id, targetUserId);
  if (!targetMember) return res.status(404).send('User is not in this pool.');

  let matches = getPoolMatches(pool.id);
  if (!matches.length) {
    const snapshotMatches = getUpcomingUniqueScheduledMatches().matches;
    lockPoolMatches(pool.id, snapshotMatches);
    matches = getPoolMatches(pool.id);
  }

  const picks = db.prepare('SELECT * FROM predictions WHERE pool_id = ? AND user_id = ?').all(pool.id, targetUserId);
  const pickByMatch = new Map(picks.map((p) => [p.match_id, p]));

  const rows = matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
    pick: pickByMatch.get(m.id) || null,
  }));

  res.render('pool-user-picks', { pool, targetMember, rows });
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
  const expectedAdminKey = adminKey || 'dev-admin';
  if (req.headers['x-admin-key'] !== expectedAdminKey) return res.status(401).json({ ok: false });
  const home = Number(req.body.home_score);
  const away = Number(req.body.away_score);
  db.prepare("UPDATE matches SET home_score = ?, away_score = ?, status = 'finished' WHERE id = ?").run(home, away, req.params.id);
  recalcPointsForMatch(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/admin/sync', async (req, res) => {
  const expectedAdminKey = adminKey || 'dev-admin';
  if (req.headers['x-admin-key'] !== expectedAdminKey) return res.status(401).json({ ok: false });
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
