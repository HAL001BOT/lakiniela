const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lakiniela-http-'));
process.env.DB_PATH = path.join(tempDir, 'test.db');
process.env.SESSION_SECRET = 'test-session-secret-at-least-24-characters';
process.env.ADMIN_KEY = 'test-admin-key-at-least-16-characters';
process.env.NODE_ENV = 'test';

const db = require('../db');
const { app, reconcileLigaMxPools, runFullSync } = require('../server');

function csrfFrom(response) {
  const match = response.text.match(/name=['"]_csrf['"] value=['"]([^'"]+)['"]/)
    || response.text.match(/const csrfToken = "([^"]+)"/);
  if (!match) throw new Error('CSRF token not found');
  return match[1];
}

async function register(agent, { name, username, email }) {
  const page = await agent.get('/register').expect(200);
  const oldSession = db.prepare('SELECT sid FROM sessions_store ORDER BY updated_at DESC LIMIT 1').get();
  const response = await agent.post('/register')
    .type('form')
    .send({
      _csrf: csrfFrom(page),
      name,
      username,
      email,
      password: 'correct-horse-battery-staple',
    })
    .expect(302);
  const newSession = db.prepare('SELECT sid FROM sessions_store ORDER BY updated_at DESC LIMIT 1').get();
  if (!oldSession || !newSession || oldSession.sid === newSession.sid) {
    throw new Error('Session id was not regenerated after registration');
  }
}

async function login(agent, username) {
  const page = await agent.get('/login').expect(200);
  const oldSession = db.prepare('SELECT sid FROM sessions_store ORDER BY updated_at DESC LIMIT 1').get();
  await agent.post('/login')
    .type('form')
    .send({
      _csrf: csrfFrom(page),
      username,
      password: 'correct-horse-battery-staple',
    })
    .expect(302);
  const newSession = db.prepare('SELECT sid FROM sessions_store ORDER BY updated_at DESC LIMIT 1').get();
  if (!oldSession || !newSession || oldSession.sid === newSession.sid) {
    throw new Error('Session id was not regenerated after login');
  }
}

async function main() {
  const owner = request.agent(app);
  await owner.post('/register').type('form').send({
    name: 'No CSRF',
    username: 'no_csrf',
    email: 'no-csrf@example.com',
    password: 'correct-horse-battery-staple',
  }).expect(403);

  await register(owner, {
    name: 'Owner',
    username: 'owner_user',
    email: 'owner@example.com',
  });
  await owner.get('/admin/users').expect(200);

  const kickoff = new Date(Date.now() + (24 * 60 * 60 * 1000)).toISOString();
  const match = db.prepare(`
    INSERT INTO matches (external_id, league, season, season_key, matchday, home_team, away_team, kickoff_at, status)
    VALUES (?, 'Liga MX', '2026', '2026:torneo-apertura', 7, 'Home', 'Away', ?, 'scheduled')
  `).run('espn:http-smoke-1', kickoff);

  const dashboard = await owner.get('/dashboard').expect(200);
  const maliciousPoolName = '</script><script>globalThis.xss=1</script>` ${alert(1)}';
  await owner.post('/pools/create')
    .type('form')
    .send({
      _csrf: csrfFrom(dashboard),
      name: maliciousPoolName,
      competition_type: 'liga_mx',
    })
    .expect(302);

  const pool = db.prepare('SELECT * FROM pools WHERE name = ?').get(maliciousPoolName);
  if (!pool) throw new Error('Pool was not created');
  const poolPage = await owner.get(`/pools/${pool.id}`).expect(200);
  if (poolPage.text.includes('</script><script>globalThis.xss')) {
    throw new Error('Stored XSS payload was emitted into executable HTML');
  }
  if (!poolPage.text.includes('\\u003c/script>')) {
    throw new Error('Stored XSS payload was not safely serialized');
  }

  const outsider = request.agent(app);
  await register(outsider, {
    name: 'Outsider',
    username: 'outsider_user',
    email: 'outsider@example.com',
  });
  await outsider.get(`/pools/${pool.id}`).expect(403);
  await outsider.get('/admin/users').expect(403);

  const refreshedPoolPage = await owner.get(`/pools/${pool.id}`).expect(200);
  await owner.post(`/pools/${pool.id}/predictions/${match.lastInsertRowid}`)
    .set('x-csrf-token', csrfFrom(refreshedPoolPage))
    .send({ pred_home: 2, pred_away: 1 })
    .expect(200);

  const secondMatch = db.prepare(`
    INSERT INTO matches (external_id, league, season, season_key, matchday, home_team, away_team, kickoff_at, status)
    VALUES (?, 'Liga MX', '2026', '2026:torneo-apertura', 7, 'Second Home', 'Second Away', ?, 'scheduled')
  `).run('espn:http-smoke-2', kickoff);
  const otherSeasonMatch = db.prepare(`
    INSERT INTO matches (external_id, league, season, season_key, matchday, home_team, away_team, kickoff_at, status)
    VALUES (?, 'Liga MX', '2026', '2026:torneo-clausura', 7, 'Wrong Home', 'Wrong Away', ?, 'scheduled')
  `).run('espn:http-smoke-other-season', kickoff);
  const reconciliation = reconcileLigaMxPools();
  if (reconciliation.matchesAdded !== 1) {
    throw new Error('Pool reconciliation did not append the missing match');
  }
  if (!db.prepare('SELECT 1 FROM predictions WHERE pool_id = ? AND match_id = ?').get(pool.id, match.lastInsertRowid)) {
    throw new Error('Pool reconciliation deleted an existing prediction');
  }
  if (!db.prepare('SELECT 1 FROM pool_matches WHERE pool_id = ? AND match_id = ?').get(pool.id, secondMatch.lastInsertRowid)) {
    throw new Error('Pool reconciliation did not preserve the matchday');
  }
  if (db.prepare('SELECT 1 FROM pool_matches WHERE pool_id = ? AND match_id = ?').get(pool.id, otherSeasonMatch.lastInsertRowid)) {
    throw new Error('Pool reconciliation mixed seasons with the same matchday');
  }

  const batchPoolPage = await owner.get(`/pools/${pool.id}`).expect(200);
  if (!batchPoolPage.text.includes('Guardar todos') || !batchPoolPage.text.includes('CLASIFICACIÓN DE JORNADA')) {
    throw new Error('Matchday prediction and standings UI is missing');
  }
  await owner.post(`/pools/${pool.id}/predictions`)
    .set('x-csrf-token', csrfFrom(batchPoolPage))
    .send({
      predictions: [
        { match_id: match.lastInsertRowid, pred_home: 2, pred_away: 1 },
        { match_id: secondMatch.lastInsertRowid, pred_home: 0, pred_away: 0 },
      ],
    })
    .expect(200);
  const batchSaved = db.prepare('SELECT pred_home, pred_away FROM predictions WHERE pool_id = ? AND match_id = ?')
    .get(pool.id, secondMatch.lastInsertRowid);
  if (batchSaved?.pred_home !== 0 || batchSaved?.pred_away !== 0) {
    throw new Error('Batch prediction save did not persist every match');
  }

  db.prepare('UPDATE matches SET kickoff_at = ? WHERE id = ?')
    .run(new Date(Date.now() + (5 * 60 * 1000)).toISOString(), match.lastInsertRowid);
  const lockedPoolPage = await owner.get(`/pools/${pool.id}`).expect(200);
  await owner.post(`/pools/${pool.id}/predictions/${match.lastInsertRowid}`)
    .set('x-csrf-token', csrfFrom(lockedPoolPage))
    .send({ pred_home: 3, pred_away: 1 })
    .expect(403);

  const saved = db.prepare('SELECT pred_home, pred_away FROM predictions WHERE pool_id = ? AND match_id = ?')
    .get(pool.id, match.lastInsertRowid);
  if (saved?.pred_home !== 2 || saved?.pred_away !== 1) {
    throw new Error('Locked prediction overwrote the saved pick');
  }
  await owner.post(`/pools/${pool.id}/predictions`)
    .set('x-csrf-token', csrfFrom(lockedPoolPage))
    .send({
      predictions: [
        { match_id: match.lastInsertRowid, pred_home: 3, pred_away: 1 },
        { match_id: secondMatch.lastInsertRowid, pred_home: 4, pred_away: 2 },
      ],
    })
    .expect(403);
  const atomicSaved = db.prepare('SELECT pred_home, pred_away FROM predictions WHERE pool_id = ? AND match_id = ?')
    .get(pool.id, secondMatch.lastInsertRowid);
  if (atomicSaved?.pred_home !== 0 || atomicSaved?.pred_away !== 0) {
    throw new Error('Rejected batch partially overwrote an unlocked prediction');
  }

  const ownerDashboard = await owner.get('/dashboard').expect(200);
  if (!ownerDashboard.text.includes('TU JORNADA') || !ownerDashboard.text.includes('Mis quinielas')) {
    throw new Error('Action-oriented dashboard UI is missing');
  }
  await owner.post('/logout')
    .type('form')
    .send({ _csrf: csrfFrom(ownerDashboard) })
    .expect(302);
  await login(owner, 'owner_user');
  await owner.get('/admin/users').expect(200);

  const adminPage = await owner.get('/admin/users').expect(200);
  const ownerUser = db.prepare("SELECT id FROM users WHERE username = 'owner_user'").get();
  await owner.post(`/admin/users/${ownerUser.id}/role`)
    .type('form')
    .send({ _csrf: csrfFrom(adminPage), role: 'user' })
    .expect(409);

  const outsiderUser = db.prepare("SELECT id FROM users WHERE username = 'outsider_user'").get();
  db.prepare("UPDATE users SET role = 'admin', session_version = session_version + 1 WHERE id = ?").run(outsiderUser.id);
  await login(outsider, 'outsider_user');
  await outsider.get('/admin/users').expect(200);

  const adminPageForRole = await owner.get('/admin/users').expect(200);
  await owner.post(`/admin/users/${outsiderUser.id}/role`)
    .type('form')
    .send({ _csrf: csrfFrom(adminPageForRole), role: 'user' })
    .expect(302);
  await outsider.get('/admin/users').expect(302).expect('location', '/login');

  const adminPageForReset = await owner.get('/admin/users').expect(200);
  await owner.post(`/admin/users/${outsiderUser.id}/reset-password`)
    .type('form')
    .send({ _csrf: csrfFrom(adminPageForReset), new_password: 'new-secure-password' })
    .expect(302);
  await outsider.get('/dashboard').expect(302).expect('location', '/login');

  const partialSync = await runFullSync('test', {
    ligaMx: async () => ({ ok: true, updated: 0 }),
    champions: async () => { throw new Error('champions unavailable'); },
    worldCup: async () => ({ ok: true, updated: 0 }),
  });
  if (partialSync.ok || partialSync.errors.length !== 1 || !partialSync.ligaMx || !partialSync.worldCup) {
    throw new Error('Partial sync failures must preserve successful competition results');
  }

  console.log('HTTP smoke checks passed.');
}

main()
  .then(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
    process.exit(1);
  });
