function kickoffMs(match) {
  return new Date(match?.kickoff_at).getTime();
}

function normalizedTeam(name) {
  return String(name || '').trim().toLowerCase();
}

function homeTeam(match) {
  return match?.home_team || match?.home;
}

function awayTeam(match) {
  return match?.away_team || match?.away;
}

function matchKey(match) {
  return match?.id ?? match?.externalId;
}

function seasonKey(match) {
  return String(match?.season_key || match?.seasonKey || match?.season || 'unknown');
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
    const key = `${seasonKey(match)}:${matchday}`;
    if (!grouped.has(key)) grouped.set(key, { matchday, seasonKey: seasonKey(match), matches: [] });
    grouped.get(key).matches.push(match);
  }

  return [...grouped.values()]
    .sort((a, b) => kickoffMs(a.matches[0]) - kickoffMs(b.matches[0]))
    .map((round) => ({ ...round, source: 'matchday' }));
}

function attachUnassignedMatches(rounds, matches) {
  const assignedIds = new Set(rounds.flatMap((round) => round.matches.map(matchKey)));
  const maxDistanceMs = 6 * 24 * 60 * 60 * 1000;

  for (const match of orderedMatches(matches).filter((candidate) => !assignedIds.has(matchKey(candidate)))) {
    const home = normalizedTeam(homeTeam(match));
    const away = normalizedTeam(awayTeam(match));
    const time = kickoffMs(match);
    const candidates = rounds
      .map((round) => {
        const times = round.matches.map(kickoffMs).filter(Number.isFinite);
        const first = Math.min(...times);
        const last = Math.max(...times);
        const distance = time < first ? first - time : time > last ? time - last : 0;
        const teams = new Set(round.matches.flatMap((item) => [
          normalizedTeam(homeTeam(item)),
          normalizedTeam(awayTeam(item)),
        ]));
        return { round, distance, repeatsTeam: teams.has(home) || teams.has(away) };
      })
      .filter((candidate) => !candidate.repeatsTeam && candidate.distance <= maxDistanceMs)
      .sort((a, b) => a.distance - b.distance);

    if (candidates[0]) {
      candidates[0].round.matches.push({
        ...match,
        matchday: candidates[0].round.matchday,
        inferred_matchday: true,
      });
    }
  }

  for (const round of rounds) round.matches = orderedMatches(round.matches);
  return rounds;
}

function inferMissingMatchdays(matches) {
  const ordered = orderedMatches(matches);
  const explicitRounds = roundsFromMatchday(ordered);
  const rounds = explicitRounds.length
    ? attachUnassignedMatches(explicitRounds, ordered)
    : roundsFromSchedule(ordered).map((round, index) => ({
      ...round,
      matchday: index + 1,
      matches: round.matches.map((match) => ({
        ...match,
        matchday: index + 1,
        inferred_matchday: true,
      })),
    }));
  const inferredById = new Map(
    rounds
      .flatMap((round) => round.matches)
      .filter((match) => match.inferred_matchday)
      .map((match) => [matchKey(match), match.matchday])
  );
  return (matches || []).map((match) => {
    const inferred = inferredById.get(matchKey(match));
    return inferred ? { ...match, matchday: inferred, inferredMatchday: true } : match;
  });
}

function roundsFromSchedule(matches) {
  const rounds = [];
  let current = [];
  let usedTeams = new Set();
  let previousKickoff = null;
  const maxGapMs = 6 * 24 * 60 * 60 * 1000;

  for (const match of orderedMatches(matches)) {
    const home = normalizedTeam(homeTeam(match));
    const away = normalizedTeam(awayTeam(match));
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

  const explicitRounds = attachUnassignedMatches(roundsFromMatchday(ordered), ordered);
  const rounds = explicitRounds.length
    ? explicitRounds
    : roundsFromSchedule(ordered);

  return chooseActiveRound(rounds, nowMs) || { matches: [], matchday: null, source: 'none' };
}

module.exports = {
  roundsFromMatchday,
  roundsFromSchedule,
  attachUnassignedMatches,
  inferMissingMatchdays,
  selectActiveMatchday,
};
