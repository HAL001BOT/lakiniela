const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cron = require('node-cron');
const db = require('./db');
const { recalcPointsForMatch, syncLigaMxScores } = require('./services/updater');

const app = express();
const PORT = process.env.PORT || 3090;

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

app.get('/', (req, res) => (req.session.user ? res.redirect('/dashboard') : res.redirect('/login')));

app.get('/register', (_req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.render('register', { error: 'Fill all fields.' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name.trim(), email.trim().toLowerCase(), hash);
    req.session.user = { id: info.lastInsertRowid, name: name.trim(), email: email.trim().toLowerCase() };
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

  const nextMatches = db.prepare("SELECT * FROM matches WHERE status = 'scheduled' ORDER BY kickoff_at ASC LIMIT 6").all();
  res.render('dashboard', { pools, nextMatches });
});

app.post('/pools/create', auth, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.redirect('/dashboard');
  const poolCode = code();
  const tx = db.transaction(() => {
    const info = db.prepare('INSERT INTO pools (name, code, owner_id) VALUES (?, ?, ?)').run(name, poolCode, req.session.user.id);
    db.prepare('INSERT INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, req.session.user.id);
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

app.get('/pools/:id', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const isMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!isMember) return res.status(403).send('Join this pool first.');

  const matches = db.prepare('SELECT * FROM matches ORDER BY kickoff_at ASC').all();
  const preds = db.prepare('SELECT * FROM predictions WHERE pool_id = ? AND user_id = ?').all(pool.id, req.session.user.id);
  const predByMatch = new Map(preds.map((p) => [p.match_id, p]));
  const standings = poolStandings(pool.id);

  res.render('pool', { pool, matches, predByMatch, standings });
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
  const match = db.prepare('SELECT * FROM matches WHERE id = ?').get(matchId);
  if (!member || !match) return res.status(403).json({ ok: false });

  db.prepare(`
    INSERT INTO predictions (pool_id, user_id, match_id, pred_home, pred_away)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(pool_id, user_id, match_id)
    DO UPDATE SET pred_home = excluded.pred_home, pred_away = excluded.pred_away, updated_at = CURRENT_TIMESTAMP
  `).run(poolId, req.session.user.id, matchId, predHome, predAway);

  if (match.status === 'finished') recalcPointsForMatch(matchId);

  res.json({ ok: true });
});

// lightweight admin endpoint for manual score entry (until API key is configured)
app.post('/admin/matches/:id/final', (req, res) => {
  if (req.headers['x-admin-key'] !== (process.env.ADMIN_KEY || 'dev-admin')) return res.status(401).json({ ok: false });
  const home = Number(req.body.home_score);
  const away = Number(req.body.away_score);
  db.prepare("UPDATE matches SET home_score = ?, away_score = ?, status = 'finished' WHERE id = ?").run(home, away, req.params.id);
  recalcPointsForMatch(Number(req.params.id));
  res.json({ ok: true });
});

cron.schedule('*/20 * * * *', async () => {
  try {
    await syncLigaMxScores();
  } catch (e) {
    console.error('Score sync failed:', e.message);
  }
});

app.listen(PORT, () => console.log(`LaKiniela running on http://localhost:${PORT}`));
