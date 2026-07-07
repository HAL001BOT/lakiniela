const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cron = require('node-cron');
const helmet = require('helmet');
const { z } = require('zod');
const db = require('./db');
const { recalcPointsForMatch, syncLigaMxScores, syncChampionsLeagueScores, syncWorldCupScores } = require('./services/updater');
const { predictionStatus, groupPredictionMatches } = require('./services/predictions-dashboard');

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

const adminAllowlist = new Set(
  String(process.env.ADMIN_ALLOWLIST || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
);

class SqliteSessionStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare('SELECT sess, expires_at FROM sessions_store WHERE sid = ?').get(sid);
      if (!row) return cb(null, null);
      if (row.expires_at <= Date.now()) {
        db.prepare('DELETE FROM sessions_store WHERE sid = ?').run(sid);
        return cb(null, null);
      }
      return cb(null, JSON.parse(row.sess));
    } catch (err) {
      return cb(err);
    }
  }

  set(sid, sess, cb) {
    try {
      const expiresAt = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + (7 * 24 * 60 * 60 * 1000);
      db.prepare(`
        INSERT INTO sessions_store (sid, sess, expires_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expires_at=excluded.expires_at, updated_at=excluded.updated_at
      `).run(sid, JSON.stringify(sess), expiresAt, Date.now());
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      db.prepare('DELETE FROM sessions_store WHERE sid = ?').run(sid);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  touch(sid, sess, cb) {
    try {
      const expiresAt = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + (7 * 24 * 60 * 60 * 1000);
      db.prepare('UPDATE sessions_store SET expires_at = ?, updated_at = ? WHERE sid = ?').run(expiresAt, Date.now(), sid);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }
}

const sessionStore = new SqliteSessionStore();

function logEvent(eventType, detail = {}, req = null, ok = true) {
  const payload = { ...detail };
  const actorUserId = req?.session?.user?.id || null;
  const ip = req?.ip || req?.socket?.remoteAddress || null;
  const path = req?.path || null;
  const method = req?.method || null;
  db.prepare(`INSERT INTO audit_events (event_type, actor_user_id, ip, path, method, ok, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(eventType, actorUserId, ip, path, method, ok ? 1 : 0, JSON.stringify(payload));
  console.log(JSON.stringify({ ts: new Date().toISOString(), eventType, actorUserId, ip, path, method, ok, ...payload }));
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
    store: sessionStore,
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

function createIpRateLimiter({ scope, windowMs, max, message }) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const row = db.prepare('SELECT count, reset_at FROM rate_limits WHERE scope = ? AND subject = ?').get(scope, ip);
    if (!row || now > row.reset_at) {
      db.prepare(`
        INSERT INTO rate_limits (scope, subject, count, reset_at)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(scope, subject) DO UPDATE SET count=1, reset_at=excluded.reset_at
      `).run(scope, ip, now + windowMs);
      return next();
    }

    const nextCount = Number(row.count || 0) + 1;
    db.prepare('UPDATE rate_limits SET count = ? WHERE scope = ? AND subject = ?').run(nextCount, scope, ip);
    if (nextCount > max) return res.status(429).send(message || 'Too many requests');
    return next();
  };
}

const loginLimiter = createIpRateLimiter({ scope: 'login', windowMs: 10 * 60 * 1000, max: 30, message: 'Too many login attempts. Try again soon.' });
const adminLimiter = createIpRateLimiter({ scope: 'admin', windowMs: 60 * 1000, max: 120, message: 'Too many admin requests.' });

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

const registerSchema = z.object({
  name: z.string().trim().min(1).max(80),
  username: z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,30}$/),
  email: z.string().trim().email().max(160),
  password: z.string().min(8).max(128),
});
const adminCreateUserSchema = registerSchema.extend({
  role: z.enum(['user', 'admin']).default('user'),
});
const loginSchema = z.object({ username: z.string().trim().min(1), password: z.string().min(1) });
const createPoolSchema = z.object({
  name: z.string().trim().min(1).max(80),
  competition_type: z.enum(['liga_mx', 'champions_league', 'world_cup_2026']).default('liga_mx'),
});
const joinPoolSchema = z.object({ code: z.string().trim().min(4).max(16) });
const predictionSchema = z.object({ pred_home: z.coerce.number().int().min(0).max(30), pred_away: z.coerce.number().int().min(0).max(30) });
const COMPETITIONS = {
  liga_mx: { key: 'liga_mx', label: 'Liga MX', leagueLabel: 'Liga MX', expectedMatches: 9, roundLabel: 'Jornada' },
  champions_league: { key: 'champions_league', label: 'Champions League', leagueLabel: 'UEFA Champions League', expectedMatches: 4, roundLabel: 'Round' },
  world_cup_2026: {
    key: 'world_cup_2026',
    label: 'FIFA World Cup 2026',
    leagueLabel: 'FIFA World Cup',
    expectedMatches: 72,
    roundLabel: 'Matches',
    startDate: '2026-06-11T00:00:00Z',
    endDate: '2026-07-20T00:00:00Z',
  },
};

function getCompetition(type) {
  return COMPETITIONS[type] || COMPETITIONS.liga_mx;
}

function competitionLabel(type) {
  return getCompetition(type).label;
}

function competitionLogo(type) {
  if (type === 'champions_league') return '/img/champions-league.png';
  if (type === 'world_cup_2026') return '/img/world-cup-2026.png?v=official-20260611';
  return '/img/logo.png';
}

function parseBody(schema, raw) {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) return null;
  return parsed.data;
}

function isAllowedAdminSource(req) {
  if (!adminAllowlist.size) return true;
  const ip = req.ip || req.socket?.remoteAddress || '';
  return adminAllowlist.has(ip);
}

function isAdminKeyValid(headerValue = '') {
  const expected = adminKey || 'dev-admin';
  const a = Buffer.from(String(headerValue));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
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

function matchHasStarted(match, nowMs = Date.now()) {
  if (!match) return false;
  if (match.status === 'live' || match.status === 'finished') return true;
  const kickoffMs = new Date(match.kickoff_at).getTime();
  return Number.isFinite(kickoffMs) && nowMs >= kickoffMs;
}

function poolStandings(poolId) {
  const rows = db.prepare(`
    SELECT
      u.id,
      u.name,
      COALESCE(SUM(p.points),0) points,
      COUNT(p.id) picks,
      SUM(CASE
        WHEN m.status = 'finished' AND m.home_score IS NOT NULL AND m.away_score IS NOT NULL THEN 1
        ELSE 0
      END) finished_picks,
      SUM(CASE
        WHEN m.status = 'finished'
          AND m.home_score IS NOT NULL
          AND m.away_score IS NOT NULL
          AND (
            (p.pred_home > p.pred_away AND m.home_score > m.away_score)
            OR (p.pred_home < p.pred_away AND m.home_score < m.away_score)
            OR (p.pred_home = p.pred_away AND m.home_score = m.away_score)
          )
        THEN 1
        ELSE 0
      END) correct_picks,
      SUM(CASE
        WHEN m.status = 'finished'
          AND m.home_score IS NOT NULL
          AND m.away_score IS NOT NULL
          AND p.pred_home = m.home_score
          AND p.pred_away = m.away_score
        THEN 1
        ELSE 0
      END) exact_picks
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    LEFT JOIN predictions p ON p.pool_id = pm.pool_id AND p.user_id = pm.user_id
    LEFT JOIN matches m ON m.id = p.match_id
    WHERE pm.pool_id = ?
    GROUP BY u.id
    ORDER BY points DESC, picks DESC, u.name ASC
  `).all(poolId);

  return rows.map((row) => {
    const finishedPicks = Number(row.finished_picks || 0);
    const correctPicks = Number(row.correct_picks || 0);
    const exactPicks = Number(row.exact_picks || 0);
    return {
      ...row,
      finished_picks: finishedPicks,
      correct_picks: correctPicks,
      exact_picks: exactPicks,
      accuracy_pct: finishedPicks ? Math.round((correctPicks / finishedPicks) * 100) : null,
      exact_pct: finishedPicks ? Math.round((exactPicks / finishedPicks) * 100) : null,
    };
  });
}

const CHART_COLORS = ['#4cc9ff', '#ffe58a', '#2fe2a8', '#ff7aa8', '#b794ff', '#ff9f43', '#7dd3fc', '#f87171'];

function poolPointsProgression(pool, matches, options = {}) {
  const members = db.prepare(`
    SELECT u.id, u.name
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    WHERE pm.pool_id = ?
    ORDER BY u.name ASC
  `).all(pool.id);

  if (!members.length || !matches.length) return { hasData: false, users: [], xTicks: [], yTicks: [] };

  const competition = getCompetition(pool.competition_type || 'liga_mx');
  const matchTimes = matches
    .map((m) => new Date(m.kickoff_at).getTime())
    .filter(Number.isFinite);
  const firstMatchMs = Math.min(...matchTimes);
  const startMs = options.startAtFirstMatch
    ? firstMatchMs
    : competition.startDate
    ? new Date(competition.startDate).getTime()
    : firstMatchMs;
  if (!Number.isFinite(startMs)) return { hasData: false, users: [], xTicks: [], yTicks: [] };

  const finishedMatchIds = matches
    .filter((m) => m.status === 'finished')
    .map((m) => m.id);
  if (!finishedMatchIds.length) return { hasData: false, users: [], xTicks: [], yTicks: [] };

  const matchDayById = new Map(matches.map((m) => {
    const kickoffMs = new Date(m.kickoff_at).getTime();
    const day = Number.isFinite(kickoffMs)
      ? Math.max(0, Math.floor((kickoffMs - startMs) / (24 * 60 * 60 * 1000)))
      : 0;
    return [m.id, day];
  }));

  const predictionRows = db.prepare(`
    SELECT user_id, match_id, points
    FROM predictions
    WHERE pool_id = ?
      AND match_id IN (${finishedMatchIds.map(() => '?').join(',')})
  `).all(pool.id, ...finishedMatchIds);

  const pointsByUserDay = new Map();
  for (const row of predictionRows) {
    const day = matchDayById.get(row.match_id);
    if (!Number.isInteger(day)) continue;
    const key = `${row.user_id}:${day}`;
    pointsByUserDay.set(key, (pointsByUserDay.get(key) || 0) + Number(row.points || 0));
  }

  const days = [...new Set([0, ...finishedMatchIds.map((id) => matchDayById.get(id)).filter(Number.isInteger)])].sort((a, b) => a - b);
  const users = members.map((member) => {
    let total = 0;
    const points = days.map((day) => {
      total += pointsByUserDay.get(`${member.id}:${day}`) || 0;
      return { day, value: total };
    });
    return {
      ...member,
      points,
      total,
    };
  })
    .sort((a, b) => b.total - a.total || a.name.localeCompare(b.name))
    .map((user, index) => ({
      ...user,
      color: CHART_COLORS[index % CHART_COLORS.length],
    }));

  const maxDay = Math.max(1, ...days);
  const maxPoints = Math.max(5, ...users.flatMap((user) => user.points.map((point) => point.value)));
  const xTicks = [...new Set([0, Math.floor(maxDay / 2), maxDay])].sort((a, b) => a - b);
  const yTicks = [...new Set([0, Math.ceil(maxPoints / 2), maxPoints])].sort((a, b) => a - b);

  return { hasData: true, users, xTicks, yTicks, maxDay, maxPoints };
}

function worldCupRoundMatches(matches, roundKey) {
  const round = buildWorldCupRounds(matches).find((candidate) => candidate.key === roundKey);
  return round ? round.matches : [];
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

function normalizeTeamName(name = '') {
  return String(name || '')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function hasWorldCupPlaceholderTeam(match) {
  const teamLine = `${match.home_team || ''} ${match.away_team || ''}`;
  return /\b(group|winner|runner-up|2nd place|third place|round of|quarterfinal|semifinal|match)\b/i.test(teamLine);
}

const WORLD_CUP_ROUNDS = [
  { key: 'group_stage', label: 'Fase de grupos', size: 72 },
  { key: 'round_of_32', label: 'Ronda de 32', size: 16 },
  { key: 'round_of_16', label: 'Octavos de final', size: 8 },
  { key: 'quarterfinals', label: 'Cuartos de final', size: 4 },
  { key: 'semifinals', label: 'Semifinales', size: 2 },
  { key: 'finals', label: 'Finales', size: 2 },
];

function buildWorldCupRounds(matches) {
  const ordered = [...(matches || [])].sort((a, b) => {
    const timeDiff = new Date(a.kickoff_at).getTime() - new Date(b.kickoff_at).getTime();
    return timeDiff || Number(a.id) - Number(b.id);
  });

  const rounds = [];
  let cursor = 0;
  for (const def of WORLD_CUP_ROUNDS) {
    const slice = ordered.slice(cursor, cursor + def.size);
    cursor += def.size;
    const decidedMatches = slice.filter((m) => !hasWorldCupPlaceholderTeam(m));
    if (decidedMatches.length) {
      rounds.push({ ...def, matches: decidedMatches });
    }
  }
  return rounds;
}

function matchWinner(match) {
  if (!match || match.status !== 'finished') return null;
  if (match.winner_side === 'home' || match.winner_side === 'away') return match.winner_side;
  const homeScore = Number(match.home_score);
  const awayScore = Number(match.away_score);
  if (!Number.isFinite(homeScore) || !Number.isFinite(awayScore) || homeScore === awayScore) return null;
  return homeScore > awayScore ? 'home' : 'away';
}

function teamInitials(name = '') {
  const compact = String(name || '')
    .replace(/\b(fc|cf|sc|club|de|the)\b/gi, ' ')
    .trim();
  const parts = compact.split(/\s+/).filter(Boolean);
  if (!parts.length) return 'TBD';
  if (parts.length === 1) return parts[0].slice(0, 3).toUpperCase();
  return parts.slice(0, 3).map((part) => part[0]).join('').toUpperCase();
}

const countryFlags = {
  algeria: '🇩🇿',
  argentina: '🇦🇷',
  australia: '🇦🇺',
  austria: '🇦🇹',
  belgium: '🇧🇪',
  bosnia: '🇧🇦',
  'bosnia and herzegovina': '🇧🇦',
  brazil: '🇧🇷',
  canada: '🇨🇦',
  'cape verde': '🇨🇻',
  colombia: '🇨🇴',
  congo: '🇨🇩',
  'dr congo': '🇨🇩',
  croatia: '🇭🇷',
  ecuador: '🇪🇨',
  egypt: '🇪🇬',
  england: '🏴',
  france: '🇫🇷',
  germany: '🇩🇪',
  ghana: '🇬🇭',
  ivory: '🇨🇮',
  "cote d'ivoire": '🇨🇮',
  japan: '🇯🇵',
  mexico: '🇲🇽',
  morocco: '🇲🇦',
  netherlands: '🇳🇱',
  norway: '🇳🇴',
  paraguay: '🇵🇾',
  portugal: '🇵🇹',
  senegal: '🇸🇳',
  south: '🇿🇦',
  'south africa': '🇿🇦',
  spain: '🇪🇸',
  sweden: '🇸🇪',
  switzerland: '🇨🇭',
  usa: '🇺🇸',
  'united states': '🇺🇸',
  uruguay: '🇺🇾',
};

function countryFlag(name = '') {
  const normalized = String(name || '').toLowerCase().replace(/[^a-z\s']/g, ' ').replace(/\s+/g, ' ').trim();
  if (!normalized) return '';
  if (countryFlags[normalized]) return countryFlags[normalized];
  const found = Object.entries(countryFlags)
    .find(([country]) => normalized.includes(country) || country.includes(normalized));
  return found ? found[1] : '';
}

const WORLD_CUP_ROUND_OF_32_VISUAL_ORDER = [
  ['Paraguay', 'Germany'],
  ['Brazil', 'Japan'],
  ['Ivory Coast', 'Norway'],
  ['Mexico', 'Ecuador'],
  ['England', 'Congo DR'],
  ['Argentina', 'Cape Verde'],
  ['Australia', 'Egypt'],
  ['Switzerland', 'Algeria'],
  ['Colombia', 'Ghana'],
  ['Senegal', 'Belgium'],
  ['Bosnia-Herzegovina', 'United States'],
  ['Austria', 'Spain'],
  ['Croatia', 'Portugal'],
  ['Morocco', 'Netherlands'],
  ['Canada', 'South Africa'],
  ['Sweden', 'France'],
];

const WORLD_CUP_TEAM_ALIASES = {
  'bosnia and herzegovina': 'bosnia herzegovina',
  'bosnia herzegovina': 'bosnia herzegovina',
  'congo dr': 'dr congo',
  'cote d ivoire': 'ivory coast',
  'cote divoire': 'ivory coast',
  'dr congo': 'dr congo',
  'turkiye': 'turkey',
  'turkey': 'turkey',
  'united states': 'usa',
  'united states of america': 'usa',
  usa: 'usa',
};

function worldCupTeamKey(name = '') {
  const normalized = normalizeTeamName(name);
  return WORLD_CUP_TEAM_ALIASES[normalized] || normalized;
}

function matchSideForTeam(match, teamName) {
  if (!match) return null;
  const key = worldCupTeamKey(teamName);
  if (worldCupTeamKey(match.home_team) === key) return 'home';
  if (worldCupTeamKey(match.away_team) === key) return 'away';
  return null;
}

function matchHasTeam(match, teamName) {
  return Boolean(matchSideForTeam(match, teamName));
}

function matchWinnerName(match) {
  const winnerSide = matchWinner(match);
  if (winnerSide === 'home') return match.home_team;
  if (winnerSide === 'away') return match.away_team;
  return '';
}

function teamFromMatchSlot(match, teamName, point, winnerSide) {
  const side = matchSideForTeam(match, teamName);
  const actualName = side === 'home' ? match.home_team : side === 'away' ? match.away_team : teamName;
  return {
    id: `${match?.id || `slot-${worldCupTeamKey(teamName)}`}-${side || worldCupTeamKey(teamName)}`,
    side: side || worldCupTeamKey(teamName),
    name: actualName || 'TBD',
    logo: side === 'home' ? match.home_logo : side === 'away' ? match.away_logo : '',
    flag: countryFlag(actualName || teamName),
    initials: teamInitials(actualName || teamName || 'TBD'),
    score: side === 'home' ? match.home_score : side === 'away' ? match.away_score : null,
    status: match?.status || 'scheduled',
    winner: Boolean(side && winnerSide === side),
    eliminated: Boolean(side && winnerSide && winnerSide !== side),
    x: point.x,
    y: point.y,
  };
}

function findWorldCupMatchByTeams(matches, teamA, teamB) {
  const keyA = worldCupTeamKey(teamA);
  const keyB = worldCupTeamKey(teamB);
  return matches.find((match) => {
    const home = worldCupTeamKey(match.home_team);
    const away = worldCupTeamKey(match.away_team);
    return (home === keyA && away === keyB) || (home === keyB && away === keyA);
  }) || null;
}

function orderedWorldCupRoundOf32Matches(matches) {
  const available = [...(matches || [])]
    .filter((match) => !hasWorldCupPlaceholderTeam(match))
    .sort((a, b) => {
      const timeDiff = new Date(a.kickoff_at).getTime() - new Date(b.kickoff_at).getTime();
      return timeDiff || Number(a.id) - Number(b.id);
    });

  return WORLD_CUP_ROUND_OF_32_VISUAL_ORDER.map(([teamA, teamB]) => findWorldCupMatchByTeams(available, teamA, teamB));
}

function buildWorldCupKnockoutCircle(matches) {
  const rounds = buildWorldCupRounds(matches).filter((round) => round.key !== 'group_stage');
  const roundsByKey = new Map(rounds.map((round) => [round.key, round]));
  const firstRound = roundsByKey.get('round_of_32') || rounds[0];
  const visualRoundOf32Matches = orderedWorldCupRoundOf32Matches(matches);
  const hasVisualRound = visualRoundOf32Matches.some(Boolean);
  if (!hasVisualRound && !firstRound?.matches?.length) return null;

  const size = 980;
  const center = size / 2;
  const outerRadius = 414;
  const roundSlots = [
    { key: 'round_of_32', label: 'Ronda de 16', count: 16, radius: 300 },
    { key: 'round_of_16', label: 'Cuartos', count: 8, radius: 218 },
    { key: 'quarterfinals', label: 'Semis', count: 4, radius: 142 },
    { key: 'semifinals', label: 'Final', count: 2, radius: 74 },
    { key: 'finals', label: 'Campeon', count: 1, radius: 0 },
  ];
  const totalOuterSlots = 32;
  const angleStep = 360 / totalOuterSlots;
  const startAngle = -90 - angleStep;
  const toPoint = (angle, radius) => {
    const radians = angle * Math.PI / 180;
    return {
      x: Number((center + Math.cos(radians) * radius).toFixed(2)),
      y: Number((center + Math.sin(radians) * radius).toFixed(2)),
    };
  };
  const slotPoint = (count, index, radius) => {
    if (count === 1) return { x: center, y: center, angle: -90 };
    const step = 360 / count;
    const angle = startAngle + (index * step) + (step / 2);
    return { ...toPoint(angle, radius), angle };
  };

  const outerTeams = [];
  const connectors = [];
  const roundOf32Matches = hasVisualRound
    ? visualRoundOf32Matches
    : firstRound.matches.slice(0, 16);
  for (let matchIndex = 0; matchIndex < 16; matchIndex += 1) {
    const match = roundOf32Matches[matchIndex] || null;
    const visualFixture = WORLD_CUP_ROUND_OF_32_VISUAL_ORDER[matchIndex] || [];
    const homeTeam = visualFixture[0] || match?.home_team || 'TBD';
    const awayTeam = visualFixture[1] || match?.away_team || 'TBD';
    const homeAngle = startAngle + (matchIndex * 2 * angleStep);
    const awayAngle = homeAngle + angleStep;
    const homePoint = toPoint(homeAngle, outerRadius);
    const awayPoint = toPoint(awayAngle, outerRadius);
    const winnerPoint = slotPoint(roundSlots[0].count, matchIndex, roundSlots[0].radius);
    const winnerSide = matchWinner(match);
    const homeVisualSide = matchSideForTeam(match, homeTeam);
    const awayVisualSide = matchSideForTeam(match, awayTeam);

    if (match) {
      connectors.push({
        x1: homePoint.x,
        y1: homePoint.y,
        x2: winnerPoint.x,
        y2: winnerPoint.y,
        active: Boolean(homeVisualSide && winnerSide === homeVisualSide),
      });
      connectors.push({
        x1: awayPoint.x,
        y1: awayPoint.y,
        x2: winnerPoint.x,
        y2: winnerPoint.y,
        active: Boolean(awayVisualSide && winnerSide === awayVisualSide),
      });
    }

    outerTeams.push(teamFromMatchSlot(match, homeTeam, homePoint, winnerSide));
    outerTeams.push(teamFromMatchSlot(match, awayTeam, awayPoint, winnerSide));
  }

  const winnerSlots = [];
  roundSlots.forEach((slotRound, roundIndex) => {
    const sourceMatches = slotRound.key === 'round_of_32'
      ? roundOf32Matches
      : (roundsByKey.get(slotRound.key)?.matches || []);
    for (let index = 0; index < slotRound.count; index += 1) {
      const match = sourceMatches[index] || null;
      const point = slotPoint(slotRound.count, index, slotRound.radius);
      const winnerSide = matchWinner(match);
      const winnerName = winnerSide === 'home' ? match.home_team : winnerSide === 'away' ? match.away_team : '';
      const winnerLogo = winnerSide === 'home' ? match.home_logo : winnerSide === 'away' ? match.away_logo : '';
      winnerSlots.push({
        id: `${slotRound.key}-${index}`,
        layer: roundIndex,
        round: slotRound.label,
        name: winnerName || 'TBD',
        logo: winnerLogo || '',
        initials: teamInitials(winnerName || 'TBD'),
        settled: Boolean(winnerSide),
        x: point.x,
        y: point.y,
      });
    }
  });

  const roundMatchesForSlot = (slotRound) => (
    slotRound.key === 'round_of_32'
      ? roundOf32Matches
      : (roundsByKey.get(slotRound.key)?.matches || [])
  );

  for (let layerIndex = 0; layerIndex < roundSlots.length - 1; layerIndex += 1) {
    const current = roundSlots[layerIndex];
    const next = roundSlots[layerIndex + 1];
    const currentMatches = roundMatchesForSlot(current);
    const nextMatches = roundMatchesForSlot(next);
    for (let index = 0; index < current.count; index += 1) {
      const sourceMatch = currentMatches[index] || null;
      const nextMatch = nextMatches[Math.floor(index / 2)] || null;
      const sourceWinnerName = matchWinnerName(sourceMatch);
      if (!sourceWinnerName || !matchHasTeam(nextMatch, sourceWinnerName)) continue;

      const from = slotPoint(current.count, index, current.radius);
      const to = slotPoint(next.count, Math.floor(index / 2), next.radius);
      connectors.push({
        x1: from.x,
        y1: from.y,
        x2: to.x,
        y2: to.y,
        active: matchWinnerName(nextMatch) === sourceWinnerName,
      });
    }
  }

  return {
    size,
    title: 'World Cup 2026 Knockout Phase',
    subtitle: 'Circle Draw',
    outerTeams,
    winnerSlots,
    connectors,
    rings: [outerRadius, ...roundSlots.map((slot) => slot.radius).filter((radius) => radius > 0)],
  };
}

function getActiveWorldCupRound(matches) {
  const rounds = buildWorldCupRounds(matches);
  if (!rounds.length) return { matches: [], roundNumber: 0, roundLabel: 'Matches' };

  const now = Date.now();
  const activeRound = rounds.find((round) => round.matches.some((m) => {
    const kickoffMs = new Date(m.kickoff_at).getTime();
    return m.status === 'live' || (Number.isFinite(kickoffMs) && kickoffMs >= now);
  }));

  const selected = activeRound || rounds[rounds.length - 1];
  return { matches: selected.matches, roundNumber: selected.matches.length, roundLabel: selected.label };
}

function deriveLigaMxMatchday(matches) {
  if (!matches.length) return null;

  const knownMatchdays = [
    {
      number: 13,
      fixtures: [
        'puebla|fc juarez',
        'necaxa|mazatlan fc',
        'tijuana|tigres uanl',
        'monterrey|atletico de san luis',
        'queretaro|toluca',
        'leon|atlas',
        'cruz azul|pachuca',
        'santos|america',
        'guadalajara|pumas unam',
        'queretaro|fc juarez',
      ],
    },
  ];

  const signatures = new Set(matches.map((m) => `${normalizeTeamName(m.home_team)}|${normalizeTeamName(m.away_team)}`));
  for (const candidate of knownMatchdays) {
    const overlap = [...signatures].filter((sig) => candidate.fixtures.includes(sig)).length;
    if (overlap >= Math.min(6, signatures.size)) return candidate.number;
  }

  return null;
}

function getUpcomingUniqueScheduledMatches(competitionType = 'liga_mx') {
  const competition = getCompetition(competitionType);
  const windowClause = competition.startDate && competition.endDate
    ? 'AND kickoff_at >= ? AND kickoff_at < ?'
    : "AND kickoff_at >= datetime('now', '-7 days') AND kickoff_at <= datetime('now', '+45 days')";
  const params = competition.startDate && competition.endDate
    ? [competition.leagueLabel, competition.startDate, competition.endDate]
    : [competition.leagueLabel];
  const all = db.prepare(`
    SELECT *
    FROM matches
    WHERE external_id LIKE 'espn:%'
      AND league = ?
      ${windowClause}
    ORDER BY kickoff_at ASC
  `).all(...params);

  if (!all.length) return { matches: [], roundNumber: competitionType === 'liga_mx' ? 9 : 1, roundLabel: competition.roundLabel };

  if (competitionType === 'world_cup_2026') {
    return getActiveWorldCupRound(all);
  }

  const now = Date.now();

  if (competitionType === 'liga_mx') {
    const chicagoDate = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Chicago',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    });
    const chicagoWeekday = new Intl.DateTimeFormat('en-US', {
      timeZone: 'America/Chicago',
      weekday: 'short',
    });
    const dateKey = (iso) => chicagoDate.format(new Date(iso));
    const weekdayKey = (iso) => chicagoWeekday.format(new Date(iso));
    const allowedDays = new Set(['Tue', 'Wed', 'Fri', 'Sat', 'Sun']);

    const weekendMatches = all.filter((m) => {
      const day = weekdayKey(m.kickoff_at);
      const kickoff = new Date(m.kickoff_at).getTime();
      return allowedDays.has(day) && Number.isFinite(kickoff);
    });

    const byDate = new Map();
    for (const match of weekendMatches) {
      const key = dateKey(match.kickoff_at);
      if (!byDate.has(key)) byDate.set(key, []);
      byDate.get(key).push(match);
    }

    const orderedDates = [...byDate.keys()].sort();
    let startIdx = orderedDates.findIndex((key) => {
      const dayMatches = byDate.get(key) || [];
      return dayMatches.some((m) => new Date(m.kickoff_at).getTime() >= now - (12 * 60 * 60 * 1000));
    });
    if (startIdx < 0) startIdx = Math.max(0, orderedDates.length - 3);

    const selected = [];
    for (let i = startIdx; i < orderedDates.length; i += 1) {
      selected.push(...(byDate.get(orderedDates[i]) || []));
      if (selected.length >= competition.expectedMatches || i >= startIdx + 4) break;
    }

    if (selected.length) {
      const explicitMatchday = selected
        .map((m) => Number(m.matchday))
        .filter((n) => Number.isInteger(n) && n > 0)
        .sort((a, b) => b - a)[0];

      const derivedLigaMxMatchday = deriveLigaMxMatchday(selected);
      const roundNumber = explicitMatchday || derivedLigaMxMatchday || inferJornadaFromAnchor(selected);
      return { matches: selected, roundNumber, roundLabel: competition.roundLabel };
    }
  }

  const buildRounds = (list) => {
    const out = [];
    let current = [];
    let usedTeams = new Set();

    for (const m of list) {
      const home = String(m.home_team || '').toLowerCase();
      const away = String(m.away_team || '').toLowerCase();
      if (!home || !away) continue;

      const repeats = usedTeams.has(home) || usedTeams.has(away);
      const fullRound = current.length >= competition.expectedMatches;

      if ((repeats || fullRound) && current.length) {
        out.push(current);
        current = [];
        usedTeams = new Set();
      }

      current.push(m);
      usedTeams.add(home);
      usedTeams.add(away);
    }
    if (current.length) out.push(current);
    return out;
  };

  const rounds = buildRounds(all);
  if (!rounds.length) return { matches: [], roundNumber: competitionType === 'liga_mx' ? 9 : 1, roundLabel: competition.roundLabel };

  let selected = null;

  const withLive = rounds.find((r) => r.some((m) => {
    if (m.status !== 'live') return false;
    const t = new Date(m.kickoff_at).getTime();
    return Number.isFinite(t) && Math.abs(now - t) <= (8 * 60 * 60 * 1000);
  }));
  if (withLive) selected = withLive;

  if (!selected) {
    const upcomingIndex = rounds.findIndex((r) => r.some((m) => new Date(m.kickoff_at).getTime() >= now));
    if (upcomingIndex >= 0) selected = rounds[upcomingIndex];
  }

  if (!selected) selected = rounds[rounds.length - 1];

  const explicitMatchday = selected
    .map((m) => Number(m.matchday))
    .filter((n) => Number.isInteger(n) && n > 0)
    .sort((a, b) => b - a)[0];

  const derivedLigaMxMatchday = competitionType === 'liga_mx' ? deriveLigaMxMatchday(selected) : null;
  const roundNumber = explicitMatchday || derivedLigaMxMatchday || (competitionType === 'liga_mx' ? inferJornadaFromAnchor(selected) : 1);
  return { matches: selected, roundNumber, roundLabel: competition.roundLabel };
}

function lockPoolMatches(poolId, matches) {
  const insert = db.prepare('INSERT OR IGNORE INTO pool_matches (pool_id, match_id) VALUES (?, ?)');
  for (const m of matches || []) {
    if (!m?.id) continue;
    insert.run(poolId, m.id);
  }
}

function cleanupPoolDuplicateMatches(poolId) {
  const rows = db.prepare(`
    SELECT pm.id AS pool_match_id, pm.match_id, m.*
    FROM pool_matches pm
    JOIN matches m ON m.id = pm.match_id
    WHERE pm.pool_id = ?
    ORDER BY LOWER(TRIM(m.home_team)) ASC, LOWER(TRIM(m.away_team)) ASC, m.kickoff_at ASC, m.id ASC, pm.id ASC
  `).all(poolId);

  const keepByKey = new Map();
  const deletePoolMatchIds = [];

  for (const row of rows) {
    const home = normalizeTeamName(row.home_team);
    const away = normalizeTeamName(row.away_team);
    const kickoffMs = new Date(row.kickoff_at).getTime();
    const roundedKickoff = Number.isFinite(kickoffMs)
      ? Math.floor(kickoffMs / (60 * 60 * 1000)) * (60 * 60 * 1000)
      : row.kickoff_at;
    const key = `${home}|${away}|${roundedKickoff}`;

    const existing = keepByKey.get(key);
    if (!existing) {
      keepByKey.set(key, row);
      continue;
    }

    const existingLive = existing.status === 'live' || existing.status === 'finished';
    const currentLive = row.status === 'live' || row.status === 'finished';
    const existingHasScore = existing.home_score !== null && existing.away_score !== null;
    const currentHasScore = row.home_score !== null && row.away_score !== null;

    let keepCurrent = false;
    if (!existingLive && currentLive) keepCurrent = true;
    else if (!existingHasScore && currentHasScore) keepCurrent = true;
    else if (row.id < existing.id) keepCurrent = true;

    if (keepCurrent) {
      deletePoolMatchIds.push(existing.pool_match_id);
      keepByKey.set(key, row);
    } else {
      deletePoolMatchIds.push(row.pool_match_id);
    }
  }

  if (deletePoolMatchIds.length) {
    const tx = db.transaction((ids) => {
      const del = db.prepare('DELETE FROM pool_matches WHERE id = ?');
      for (const id of ids) del.run(id);
    });
    tx(deletePoolMatchIds);
  }
}

function getPoolMatches(poolId) {
  cleanupPoolDuplicateMatches(poolId);
  const rows = db.prepare(`
    SELECT m.*
    FROM pool_matches pm
    JOIN matches m ON m.id = pm.match_id
    WHERE pm.pool_id = ?
    ORDER BY m.kickoff_at ASC, m.id ASC
  `).all(poolId);

  const out = [];
  const seen = new Set();
  for (const row of rows) {
    const kickoffMs = new Date(row.kickoff_at).getTime();
    const roundedKickoff = Number.isFinite(kickoffMs)
      ? Math.floor(kickoffMs / (60 * 60 * 1000)) * (60 * 60 * 1000)
      : row.kickoff_at;
    const key = `${normalizeTeamName(row.home_team)}|${normalizeTeamName(row.away_team)}|${roundedKickoff}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

function repairPoolMatches(poolId, competitionType = 'liga_mx') {
  const snapshotMatches = getUpcomingUniqueScheduledMatches(competitionType).matches || [];
  if (!snapshotMatches.length) return;

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM predictions WHERE pool_id = ?').run(poolId);
    db.prepare('DELETE FROM pool_matches WHERE pool_id = ?').run(poolId);
    lockPoolMatches(poolId, snapshotMatches);
  });

  tx();
}

function ensurePoolMatches(pool) {
  const competitionType = pool.competition_type || 'liga_mx';
  let matches = getPoolMatches(pool.id);

  if (!matches.length) {
    // Backfill old pools created before match-locking feature.
    const snapshotMatches = getUpcomingUniqueScheduledMatches(competitionType).matches;
    lockPoolMatches(pool.id, snapshotMatches);
    matches = getPoolMatches(pool.id);
  }

  if (competitionType === 'world_cup_2026') {
    // World Cup pools grow as each knockout round is decided. Keep prior picks
    // and append the active resolved round.
    const activeRoundMatches = getUpcomingUniqueScheduledMatches(competitionType).matches;
    lockPoolMatches(pool.id, activeRoundMatches);
    matches = getPoolMatches(pool.id);
  }

  const expectedMatches = getCompetition(competitionType).expectedMatches;
  if (competitionType === 'liga_mx' && matches.length !== expectedMatches) {
    repairPoolMatches(pool.id, competitionType);
    matches = getPoolMatches(pool.id);
  }

  return matches;
}

function appendActiveWorldCupRoundToPools(poolName = null) {
  const activeRoundMatches = getUpcomingUniqueScheduledMatches('world_cup_2026').matches;
  if (!activeRoundMatches.length) return { pools: 0, matchesAdded: 0, normalizedPools: 0 };

  const pools = poolName
    ? db.prepare('SELECT id, name, competition_type FROM pools WHERE lower(name) = lower(?)').all(poolName)
    : db.prepare(`
      SELECT id, name, competition_type
      FROM pools
      WHERE competition_type = 'world_cup_2026'
         OR lower(name) = 'mundial 2026'
    `).all();

  let matchesAdded = 0;
  let normalizedPools = 0;
  for (const pool of pools) {
    if (pool.competition_type !== 'world_cup_2026' && String(pool.name || '').toLowerCase() === 'mundial 2026') {
      db.prepare("UPDATE pools SET competition_type = 'world_cup_2026' WHERE id = ?").run(pool.id);
      normalizedPools += 1;
    }
    const before = db.prepare('SELECT COUNT(*) c FROM pool_matches WHERE pool_id = ?').get(pool.id).c;
    lockPoolMatches(pool.id, activeRoundMatches);
    const after = db.prepare('SELECT COUNT(*) c FROM pool_matches WHERE pool_id = ?').get(pool.id).c;
    matchesAdded += Math.max(0, Number(after) - Number(before));
  }

  return { pools: pools.length, matchesAdded, normalizedPools };
}

function applyMundial2026PickCorrections() {
  const pool = db.prepare("SELECT id, name FROM pools WHERE lower(name) = 'mundial 2026' LIMIT 1").get();
  if (!pool) return { applied: 0, missing: ['pool:mundial 2026'] };

  const findMatch = db.prepare(`
    SELECT m.*
    FROM pool_matches pm
    JOIN matches m ON m.id = pm.match_id
    WHERE pm.pool_id = ?
      AND lower(m.home_team) = lower(?)
      AND lower(m.away_team) = lower(?)
    ORDER BY datetime(m.kickoff_at) DESC
    LIMIT 1
  `);

  const matchCorrections = [
    {
      homeTeam: 'South Africa',
      awayTeam: 'Canada',
      picks: [
        { aliases: ['pablo'], predHome: 1, predAway: 1 },
        { aliases: ['admin'], predHome: 0, predAway: 2 },
        { aliases: ['joaquin', 'joaquín'], predHome: 1, predAway: 2 },
        { aliases: ['mudo'], predHome: 1, predAway: 2 },
      ],
    },
    {
      homeTeam: 'England',
      awayTeam: 'Congo DR',
      picks: [
        { aliases: ['metaai', 'metaAI', 'meta ai'], predHome: 4, predAway: 0 },
      ],
    },
  ];

  const missing = [];
  let applied = 0;
  const findMember = db.prepare(`
    SELECT u.id, u.name, u.username, u.email
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    WHERE pm.pool_id = ?
      AND (
        lower(u.username) = lower(?)
        OR lower(u.name) = lower(?)
        OR lower(substr(u.email, 1, instr(u.email, '@') - 1)) = lower(?)
      )
    LIMIT 1
  `);

  const upsert = db.prepare(`
    INSERT INTO predictions (pool_id, user_id, match_id, pred_home, pred_away)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(pool_id, user_id, match_id)
    DO UPDATE SET pred_home = excluded.pred_home, pred_away = excluded.pred_away, updated_at = CURRENT_TIMESTAMP
  `);

  const recalcMatchIds = new Set();
  for (const matchCorrection of matchCorrections) {
    const match = findMatch.get(pool.id, matchCorrection.homeTeam, matchCorrection.awayTeam);
    if (!match) {
      missing.push(`match:${matchCorrection.homeTeam} vs ${matchCorrection.awayTeam}`);
      continue;
    }

    for (const correction of matchCorrection.picks) {
      const member = correction.aliases
        .map((alias) => findMember.get(pool.id, alias, alias, alias))
        .find(Boolean);

      if (!member) {
        missing.push(`user:${correction.aliases[0]}`);
        continue;
      }

      upsert.run(pool.id, member.id, match.id, correction.predHome, correction.predAway);
      applied += 1;
    }

    if (match.status === 'finished') recalcMatchIds.add(match.id);
  }

  for (const matchId of recalcMatchIds) recalcPointsForMatch(matchId);
  return { applied, missing };
}

function removeMundial2026Members() {
  const pool = db.prepare("SELECT id, name FROM pools WHERE lower(name) = 'mundial 2026' LIMIT 1").get();
  if (!pool) return { removed: 0, missing: ['pool:mundial 2026'] };

  const targets = [
    { label: 'marco', aliases: ['marco'] },
    { label: 'richard hdz', aliases: ['richard hdz', 'richard_hdz', 'richardhdz'] },
  ];

  const findMember = db.prepare(`
    SELECT u.id, u.name, u.username, u.email
    FROM pool_members pm
    JOIN users u ON u.id = pm.user_id
    WHERE pm.pool_id = ?
      AND (
        lower(u.username) = lower(?)
        OR lower(u.name) = lower(?)
        OR lower(substr(u.email, 1, instr(u.email, '@') - 1)) = lower(?)
      )
    LIMIT 1
  `);

  const missing = [];
  let removed = 0;
  const tx = db.transaction(() => {
    for (const target of targets) {
      const member = target.aliases
        .map((alias) => findMember.get(pool.id, alias, alias, alias))
        .find(Boolean);

      if (!member) {
        missing.push(`user:${target.label}`);
        continue;
      }

      db.prepare('DELETE FROM predictions WHERE pool_id = ? AND user_id = ?').run(pool.id, member.id);
      const info = db.prepare('DELETE FROM pool_members WHERE pool_id = ? AND user_id = ?').run(pool.id, member.id);
      removed += Number(info.changes || 0);
    }
  });
  tx();

  return { removed, missing };
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
  const gameWindowMs = 2.5 * 60 * 60 * 1000; // only poll during the expected live match window

  return upcoming.some((m) => {
    const kickoff = new Date(m.kickoff_at).getTime();
    return Number.isFinite(kickoff) && now >= kickoff && now <= (kickoff + gameWindowMs);
  });
}

app.get('/', (req, res) => (req.session.user ? res.redirect('/dashboard') : res.redirect('/login')));

app.get('/register', (_req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
  const input = parseBody(registerSchema, req.body);
  if (!input) return res.render('register', { error: 'Invalid fields. Check username/email/password format.' });
  try {
    const hash = bcrypt.hashSync(input.password, 10);
    const info = db.prepare('INSERT INTO users (name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
      .run(input.name, input.username, input.email.toLowerCase(), hash, 'user');
    req.session.user = { id: info.lastInsertRowid, name: input.name, username: input.username, email: input.email.toLowerCase(), role: 'user' };
    logEvent('auth.register.success', { username: input.username }, req, true);
    if (consumePendingInvite(req, res)) return;
    res.redirect('/dashboard');
  } catch {
    logEvent('auth.register.failed', { username: input.username }, req, false);
    res.render('register', { error: 'Username or email already in use.' });
  }
});

app.get('/login', (_req, res) => res.render('login', { error: null }));
app.post('/login', loginLimiter, (req, res) => {
  const input = parseBody(loginSchema, req.body);
  if (!input) return res.render('login', { error: 'Invalid credentials.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(input.username.toLowerCase());
  if (!user || !bcrypt.compareSync(input.password, user.password_hash)) {
    logEvent('auth.login.failed', { username: input.username.toLowerCase() }, req, false);
    return res.render('login', { error: 'Invalid credentials.' });
  }
  req.session.user = { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role || 'user' };
  logEvent('auth.login.success', { username: user.username }, req, true);
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

  const ligaMxView = getUpcomingUniqueScheduledMatches('liga_mx');
  const championsView = getUpcomingUniqueScheduledMatches('champions_league');
  const worldCupView = getUpcomingUniqueScheduledMatches('world_cup_2026');
  const nextMatches = ligaMxView.matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  const championsMatches = championsView.matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  const worldCupMatches = worldCupView.matches.map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  res.render('dashboard', {
    pools,
    pointsDashboard,
    nextMatches,
    jornadaNumber: ligaMxView.roundNumber,
    championsMatches,
    championsRoundNumber: championsView.roundNumber,
    worldCupMatches,
    worldCupMatchCount: worldCupView.roundNumber,
    isAdmin: req.session.user.role === 'admin',
    competitionLabel,
    competitionLogo,
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

  const pools = db.prepare(`
    SELECT p.id, p.name, p.code, p.competition_type, p.created_at,
           owner.name AS owner_name,
           (SELECT COUNT(*) FROM pool_members pm WHERE pm.pool_id = p.id) AS members
    FROM pools p
    LEFT JOIN users owner ON owner.id = p.owner_id
    ORDER BY p.created_at DESC
  `).all();

  const poolsByUser = new Map();
  memberships.forEach((m) => {
    if (!poolsByUser.has(m.user_id)) poolsByUser.set(m.user_id, []);
    poolsByUser.get(m.user_id).push(m);
  });

  const errorMessages = {
    invalid: 'Invalid fields. Username must be 3-30 lowercase letters, numbers, or underscores. Password must be at least 8 characters.',
    duplicate: 'Username or email already in use.',
  };

  res.render('admin-users', {
    users,
    me: req.session.user,
    poolsByUser,
    pools,
    createdUser: typeof req.query.created === 'string' ? req.query.created : null,
    error: errorMessages[req.query.error] || null,
  });
});

app.post('/admin/users/create', admin, (req, res) => {
  const input = parseBody(adminCreateUserSchema, req.body);
  if (!input) return res.redirect('/admin/users?error=invalid');

  try {
    const hash = bcrypt.hashSync(input.password, 10);
    const info = db.prepare('INSERT INTO users (name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
      .run(input.name, input.username, input.email.toLowerCase(), hash, input.role);
    logEvent('admin.user.create', { targetUserId: info.lastInsertRowid, username: input.username, role: input.role }, req, true);
    res.redirect(`/admin/users?created=${encodeURIComponent(input.username)}`);
  } catch {
    logEvent('admin.user.create.failed', { username: input.username, role: input.role }, req, false);
    res.redirect('/admin/users?error=duplicate');
  }
});

app.post('/admin/users/:id/role', admin, (req, res) => {
  const id = Number(req.params.id);
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  if (!Number.isInteger(id)) return res.redirect('/admin/users');
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  if (req.session.user.id === id) req.session.user.role = role;
  logEvent('admin.user.role', { targetUserId: id, role }, req, true);
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/delete', admin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id === req.session.user.id) return res.redirect('/admin/users');

  const tx = db.transaction(() => {
    const ownedPoolIds = db.prepare('SELECT id FROM pools WHERE owner_id = ?').all(id).map((row) => row.id);
    for (const poolId of ownedPoolIds) {
      db.prepare('DELETE FROM predictions WHERE pool_id = ?').run(poolId);
      db.prepare('DELETE FROM pool_matches WHERE pool_id = ?').run(poolId);
      db.prepare('DELETE FROM pool_members WHERE pool_id = ?').run(poolId);
      db.prepare('DELETE FROM pools WHERE id = ?').run(poolId);
    }

    db.prepare('DELETE FROM predictions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM pool_members WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  tx();
  logEvent('admin.user.delete', { targetUserId: id }, req, true);
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/reset-password', admin, (req, res) => {
  const id = Number(req.params.id);
  const newPassword = String(req.body.new_password || '');
  if (!Number.isInteger(id) || newPassword.length < 8) return res.redirect('/admin/users');
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
  logEvent('admin.user.reset_password', { targetUserId: id }, req, true);
  res.redirect('/admin/users');
});

app.post('/admin/pools/:poolId/users/:userId/remove', admin, (req, res) => {
  const poolId = Number(req.params.poolId);
  const userId = Number(req.params.userId);
  if (!Number.isInteger(poolId) || !Number.isInteger(userId)) return res.redirect('/admin/users');

  db.prepare('DELETE FROM predictions WHERE pool_id = ? AND user_id = ?').run(poolId, userId);
  db.prepare('DELETE FROM pool_members WHERE pool_id = ? AND user_id = ?').run(poolId, userId);
  logEvent('admin.pool.remove_member', { poolId, userId }, req, true);
  res.redirect('/admin/users');
});

app.post('/admin/pools/:poolId/delete', admin, (req, res) => {
  const poolId = Number(req.params.poolId);
  if (!Number.isInteger(poolId)) return res.redirect('/admin/users');

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM predictions WHERE pool_id = ?').run(poolId);
    db.prepare('DELETE FROM pool_matches WHERE pool_id = ?').run(poolId);
    db.prepare('DELETE FROM pool_members WHERE pool_id = ?').run(poolId);
    db.prepare('DELETE FROM pools WHERE id = ?').run(poolId);
  });
  tx();
  logEvent('admin.pool.delete', { poolId }, req, true);
  res.redirect('/admin/users');
});

app.post('/pools/create', auth, (req, res) => {
  const input = parseBody(createPoolSchema, req.body);
  if (!input) return res.redirect('/dashboard');
  const poolCode = code();
  const competitionType = input.competition_type || 'liga_mx';
  const snapshotMatches = getUpcomingUniqueScheduledMatches(competitionType).matches;

  const tx = db.transaction(() => {
    const info = db.prepare('INSERT INTO pools (name, code, owner_id, competition_type) VALUES (?, ?, ?, ?)').run(input.name, poolCode, req.session.user.id, competitionType);
    db.prepare('INSERT INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, req.session.user.id);
    lockPoolMatches(info.lastInsertRowid, snapshotMatches);
  });
  tx();
  logEvent('pool.create', { poolName: input.name, poolCode, competitionType }, req, true);
  res.redirect('/dashboard');
});

app.post('/pools/join', auth, (req, res) => {
  const input = parseBody(joinPoolSchema, req.body);
  if (!input) return res.redirect('/dashboard');
  const pool = db.prepare('SELECT * FROM pools WHERE code = ?').get(input.code.trim().toUpperCase());
  if (!pool) return res.redirect('/dashboard');
  db.prepare('INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(pool.id, req.session.user.id);
  logEvent('pool.join', { poolId: pool.id, poolCode: pool.code }, req, true);
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
    const logoPath = competitionLogo(pool.competition_type);
    const ogImage = `${baseUrl}${logoPath}`;
    return res.render('invite-public', { pool, inviteUrl, ogImage, logoPath });
  }

  db.prepare('INSERT OR IGNORE INTO pool_members (pool_id, user_id) VALUES (?, ?)').run(pool.id, req.session.user.id);
  return res.redirect(`/pools/${pool.id}`);
});

app.get('/pools/:id', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const isMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!isMember) return res.status(403).send('Join this pool first.');

  const matches = ensurePoolMatches(pool);

  const nowMs = Date.now();
  const poolFinished = matches.length > 0 && matches.every((m) => m.status === 'finished');
  const canViewOthersPicks = matches.some((m) => matchHasStarted(m, nowMs));
  const visibleMatches = matches.filter((m) => !matchHasStarted(m, nowMs)).map((m) => ({
    ...m,
    kickoff_local: formatCentral(m.kickoff_at),
  }));
  const preds = db.prepare('SELECT * FROM predictions WHERE pool_id = ? AND user_id = ?').all(pool.id, req.session.user.id);
  const predByMatch = new Map(preds.map((p) => [p.match_id, p]));
  const standings = poolStandings(pool.id);
  const pointsProgression = poolPointsProgression(pool, matches);
  const roundOf32Matches = pool.competition_type === 'world_cup_2026'
    ? worldCupRoundMatches(matches, 'round_of_32')
    : [];
  const roundOf32PointsProgression = roundOf32Matches.length
    ? poolPointsProgression(pool, roundOf32Matches, { startAtFirstMatch: true })
    : null;
  const knockoutCircle = buildWorldCupKnockoutCircle(matches);
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const inviteLink = `${proto}://${req.get('host')}/invite/${pool.code}`;

  res.render('pool', { pool, matches: visibleMatches, predByMatch, standings, pointsProgression, roundOf32PointsProgression, knockoutCircle, poolFinished, canViewOthersPicks, nowMs, inviteLink, competitionLogo });
});

app.get('/pools/:id/pronosticos', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const viewerMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!viewerMember) return res.status(403).send('Join this pool first.');

  const matches = ensurePoolMatches(pool);

  const nowMs = Date.now();
  if (!matches.some((match) => matchHasStarted(match, nowMs))) {
    return res.redirect(`/pools/${pool.id}`);
  }

  const rounds = groupPredictionMatches(matches, pool.competition_type || 'liga_mx');
  const requestedRound = String(req.query.round || '');
  const selectedRound = rounds.find((round) => round.key === requestedRound) || rounds[0] || {
    key: '1',
    label: 'Jornada 1',
    matches: [],
  };
  const selectedMatchIds = selectedRound.matches.map((match) => match.id);

  const standings = poolStandings(pool.id);
  const predictions = selectedMatchIds.length
    ? db.prepare(`
      SELECT *
      FROM predictions
      WHERE pool_id = ?
        AND match_id IN (${selectedMatchIds.map(() => '?').join(',')})
    `).all(pool.id, ...selectedMatchIds)
    : [];
  const predictionByUserMatch = new Map(
    predictions.map((prediction) => [`${prediction.user_id}:${prediction.match_id}`, prediction])
  );

  const rows = standings.map((member) => ({
    ...member,
    predictions: selectedRound.matches.map((match) => {
      const revealPrediction = matchHasStarted(match, nowMs);
      const prediction = predictionByUserMatch.get(`${member.id}:${match.id}`) || null;
      return {
        prediction: revealPrediction ? prediction : null,
        hidden: !revealPrediction,
        status: predictionStatus(prediction, match),
      };
    }),
  }));

  const roundMatches = selectedRound.matches.map((match) => ({
    ...match,
    kickoff_local: formatCentral(match.kickoff_at),
  }));

  res.render('predictions-dashboard', {
    pool,
    rounds,
    selectedRound,
    matches: roundMatches,
    rows,
    competitionLogo,
  });
});

app.get('/pools/:id/knockout', auth, (req, res) => {
  const pool = db.prepare('SELECT * FROM pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).send('Pool not found');

  const isMember = db.prepare('SELECT 1 FROM pool_members WHERE pool_id = ? AND user_id = ?').get(pool.id, req.session.user.id);
  if (!isMember) return res.status(403).send('Join this pool first.');
  if ((pool.competition_type || 'liga_mx') !== 'world_cup_2026') return res.redirect(`/pools/${pool.id}`);

  const matches = ensurePoolMatches(pool);
  const knockoutCircle = buildWorldCupKnockoutCircle(matches);
  if (!knockoutCircle) return res.redirect(`/pools/${pool.id}`);

  res.render('knockout', { pool, knockoutCircle, competitionLogo });
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

  const matches = ensurePoolMatches(pool);

  const nowMs = Date.now();
  if (targetUserId !== req.session.user.id && !matches.some((match) => matchHasStarted(match, nowMs))) {
    return res.redirect(`/pools/${pool.id}`);
  }

  const picks = db.prepare('SELECT * FROM predictions WHERE pool_id = ? AND user_id = ?').all(pool.id, targetUserId);
  const pickByMatch = new Map(picks.map((p) => [p.match_id, p]));

  const rows = matches
    .filter((m) => targetUserId === req.session.user.id || matchHasStarted(m, nowMs))
    .map((m) => ({
      ...m,
      kickoff_local: formatCentral(m.kickoff_at),
      pick: pickByMatch.get(m.id) || null,
    }));

  res.render('pool-user-picks', { pool, targetMember, rows, competitionLogo });
});

app.post('/pools/:id/predictions/:matchId', auth, (req, res) => {
  const poolId = Number(req.params.id);
  const matchId = Number(req.params.matchId);
  const input = parseBody(predictionSchema, req.body);
  if (!input) {
    return res.status(400).json({ ok: false, error: 'Invalid score.' });
  }
  const predHome = input.pred_home;
  const predAway = input.pred_away;

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
  if (!isAllowedAdminSource(req) || !isAdminKeyValid(req.headers['x-admin-key'])) {
    logEvent('admin.final_score.denied', { matchId: Number(req.params.id) }, req, false);
    return res.status(401).json({ ok: false });
  }
  const home = Number(req.body.home_score);
  const away = Number(req.body.away_score);
  if (!Number.isInteger(home) || !Number.isInteger(away) || home < 0 || away < 0) {
    return res.status(400).json({ ok: false, error: 'Invalid score.' });
  }
  const homePenalty = req.body.home_penalty_score === undefined || req.body.home_penalty_score === ''
    ? null
    : Number(req.body.home_penalty_score);
  const awayPenalty = req.body.away_penalty_score === undefined || req.body.away_penalty_score === ''
    ? null
    : Number(req.body.away_penalty_score);
  if (
    (homePenalty !== null && (!Number.isInteger(homePenalty) || homePenalty < 0))
    || (awayPenalty !== null && (!Number.isInteger(awayPenalty) || awayPenalty < 0))
  ) {
    return res.status(400).json({ ok: false, error: 'Invalid penalty score.' });
  }

  const requestedWinner = req.body.winner_side === 'home' || req.body.winner_side === 'away' ? req.body.winner_side : null;
  const winnerSide = home > away ? 'home' : away > home ? 'away' : requestedWinner;
  db.prepare(`
    UPDATE matches
    SET home_score = ?, away_score = ?, home_penalty_score = ?, away_penalty_score = ?, winner_side = ?, status = 'finished'
    WHERE id = ?
  `).run(home, away, homePenalty, awayPenalty, winnerSide, req.params.id);
  recalcPointsForMatch(Number(req.params.id));
  logEvent('admin.final_score.ok', { matchId: Number(req.params.id), home, away, homePenalty, awayPenalty, winnerSide }, req, true);
  res.json({ ok: true });
});

app.post('/admin/sync', async (req, res) => {
  if (!isAllowedAdminSource(req) || !isAdminKeyValid(req.headers['x-admin-key'])) {
    logEvent('admin.sync.denied', {}, req, false);
    return res.status(401).json({ ok: false });
  }
  try {
    const [ligaMx, champions, worldCup] = await Promise.all([syncLigaMxScores(), syncChampionsLeagueScores(), syncWorldCupScores()]);
    const worldCupPools = appendActiveWorldCupRoundToPools();
    const mundialCorrections = applyMundial2026PickCorrections();
    const mundialRemovedMembers = removeMundial2026Members();
    logEvent('admin.sync.ok', { ligaMxUpdated: ligaMx?.updated || 0, championsUpdated: champions?.updated || 0, worldCupUpdated: worldCup?.updated || 0, worldCupPools, mundialCorrections, mundialRemovedMembers }, req, true);
    return res.json({ ok: true, ligaMx, champions, worldCup, worldCupPools, mundialCorrections, mundialRemovedMembers });
  } catch (e) {
    logEvent('admin.sync.failed', { error: e.message }, req, false);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

cron.schedule('* * * * *', async () => {
  try {
    if (!shouldRunFrequentSyncNow()) return;
    const [ligaMx, champions, worldCup] = await Promise.all([syncLigaMxScores(), syncChampionsLeagueScores(), syncWorldCupScores()]);
    const worldCupPools = appendActiveWorldCupRoundToPools();
    const mundialCorrections = applyMundial2026PickCorrections();
    const mundialRemovedMembers = removeMundial2026Members();
    logEvent('sync.auto.ok', { ligaMxUpdated: ligaMx?.updated || 0, championsUpdated: champions?.updated || 0, worldCupUpdated: worldCup?.updated || 0, worldCupPools, mundialCorrections, mundialRemovedMembers }, null, true);
  } catch (e) {
    logEvent('sync.auto.failed', { error: e.message }, null, false);
  }
});

cron.schedule('*/15 * * * *', () => {
  const now = Date.now();
  db.prepare('DELETE FROM rate_limits WHERE reset_at < ?').run(now - 5 * 60 * 1000);
  db.prepare('DELETE FROM sessions_store WHERE expires_at < ?').run(now);
});

(async () => {
  try {
    const [ligaMx, champions, worldCup] = await Promise.all([syncLigaMxScores(), syncChampionsLeagueScores(), syncWorldCupScores()]);
    const worldCupPools = appendActiveWorldCupRoundToPools();
    const mundialCorrections = applyMundial2026PickCorrections();
    const mundialRemovedMembers = removeMundial2026Members();
    logEvent('sync.startup.ok', { ligaMxUpdated: ligaMx?.updated || 0, championsUpdated: champions?.updated || 0, worldCupUpdated: worldCup?.updated || 0, worldCupPools, mundialCorrections, mundialRemovedMembers }, null, true);
  } catch (e) {
    logEvent('sync.startup.failed', { error: e.message }, null, false);
  }
})();

app.listen(PORT, () => console.log(`LaKiniela running on http://localhost:${PORT}`));
