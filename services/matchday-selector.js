function kickoffMs(match) {
  return new Date(match?.kickoff_at).getTime();
}

function normalizedTeam(name) {
  return String(name || '').trim().toLowerCase();
}

function orderedMatches(matches) {
  return [...(matches || [])]
    .filter((match) => Number.isFinite(kickoffMs(match)))
    .sort((a, b) => kickoffMs(a) - kickoffMs(b) || Number(a.id) - Number(b.id));
}

function chooseActiveRound(rounds, nowMs) {
  const live = rounds.find((round) => round.matches.some((match) => match.status === 'live'));
  if (live) return live;

  const upcoming = rounds
    .map((round) => ({
      ...round,
      nextKickoff: Math.min(
        ...round.matches
          .map(kickoffMs)
          .filter((time) => Number.isFinite(time) && time >= nowMs)
      ),
    }))
    .filter((round) => Number.isFinite(round.nextKickoff))
    .sort((a, b) => a.nextKickoff - b.nextKickoff)[0];
  if (upcoming) return upcoming;

  return rounds[rounds.length - 1] || null;
}

function roundsFromMatchday(matches) {
  const grouped = new Map();
  for (const match of orderedMatches(matches)) {
    const matchday = Number(match.matchday);
    if (!Number.isInteger(matchday) || matchday < 1) continue;
    if (!grouped.has(matchday)) grouped.set(matchday, []);
    grouped.get(matchday).push(match);
  }

  return [...grouped.entries()]
    .sort(([a], [b]) => a - b)
    .map(([matchday, roundMatches]) => ({ matchday, matches: roundMatches, source: 'matchday' }));
}

function roundsFromSchedule(matches) {
  const rounds = [];
  let current = [];
  let usedTeams = new Set();
  let previousKickoff = null;
  const maxGapMs = 6 * 24 * 60 * 60 * 1000;

  for (const match of orderedMatches(matches)) {
    const home = normalizedTeam(match.home_team);
    const away = normalizedTeam(match.away_team);
    if (!home || !away) continue;

    const currentKickoff = kickoffMs(match);
    const repeatsTeam = usedTeams.has(home) || usedTeams.has(away);
    const largeGap = previousKickoff !== null && currentKickoff - previousKickoff > maxGapMs;
    if (current.length && (repeatsTeam || largeGap)) {
      rounds.push({ matchday: null, matches: current, source: 'schedule' });
      current = [];
      usedTeams = new Set();
    }

    current.push(match);
    usedTeams.add(home);
    usedTeams.add(away);
    previousKickoff = currentKickoff;
  }

  if (current.length) rounds.push({ matchday: null, matches: current, source: 'schedule' });
  return rounds;
}

function selectActiveMatchday(matches, { nowMs = Date.now() } = {}) {
  const ordered = orderedMatches(matches);
  if (!ordered.length) return { matches: [], matchday: null, source: 'none' };

  const explicitRounds = roundsFromMatchday(ordered);
  const rounds = explicitRounds.length
    ? explicitRounds
    : roundsFromSchedule(ordered);

  return chooseActiveRound(rounds, nowMs) || { matches: [], matchday: null, source: 'none' };
}

module.exports = {
  roundsFromMatchday,
  roundsFromSchedule,
  selectActiveMatchday,
};
