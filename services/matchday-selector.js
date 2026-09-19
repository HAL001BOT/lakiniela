function kickoffMs(match) {
  // Database rows use snake_case while the ESPN updater normalizes fixtures
  // with camelCase before persisting them. Support both shapes so missing ESPN
  // week metadata can be inferred during the sync itself.
  return new Date(match?.kickoff_at || match?.kickoffAt).getTime();
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

function espnEventNumber(match) {
  const externalId = String(match?.external_id || match?.externalId || '');
  const parsed = externalId.match(/^espn:(?:[^:]+:)*(\d+)$/);
  return parsed ? Number(parsed[1]) : null;
}

function roundInferenceOrder(matches) {
  const ordered = orderedMatches(matches);
  const withEventNumbers = ordered.map((match) => ({ match, eventNumber: espnEventNumber(match) }));
  if (withEventNumbers.length < 2 || withEventNumbers.some(({ eventNumber }) => !Number.isSafeInteger(eventNumber))) {
    return { matches: ordered, source: 'kickoff' };
  }

  // ESPN no longer includes week.number in its Liga MX scoreboard payload.
  // Event ids are assigned in fixture-list order and remain stable when a game
  // is postponed, so use their prevailing direction to recover the original
  // round order instead of treating the rescheduled kickoff as a new jornada.
  const kickoffAverage = withEventNumbers.reduce((sum, item) => sum + kickoffMs(item.match), 0) / withEventNumbers.length;
  const eventAverage = withEventNumbers.reduce((sum, item) => sum + item.eventNumber, 0) / withEventNumbers.length;
  const covariance = withEventNumbers.reduce((sum, item) => (
    sum + ((kickoffMs(item.match) - kickoffAverage) * (item.eventNumber - eventAverage))
  ), 0);
  const direction = covariance < 0 ? -1 : 1;

  const sourceOrdered = withEventNumbers
    .sort((a, b) => direction * (a.eventNumber - b.eventNumber))
    .map(({ match }) => match);
  let rotationIndex = 0;
  let largestBackwardGap = 6 * 24 * 60 * 60 * 1000;
  for (let index = 1; index < sourceOrdered.length; index += 1) {
    const backwardGap = kickoffMs(sourceOrdered[index - 1]) - kickoffMs(sourceOrdered[index]);
    if (backwardGap > largestBackwardGap) {
      largestBackwardGap = backwardGap;
      rotationIndex = index;
    }
  }
  const earliestKickoff = Math.min(...sourceOrdered.map(kickoffMs));
  const sourceStartsAfterOpener = kickoffMs(sourceOrdered[0]) - earliestKickoff > (6 * 24 * 60 * 60 * 1000);
  if (!sourceStartsAfterOpener) rotationIndex = 0;

  return {
    // ESPN sometimes allocates the final round after the rest of the season,
    // which wraps its ids ahead of round one. Rotate at the largest backwards
    // schedule jump so that round numbering still starts with the opener.
    matches: rotationIndex
      ? [...sourceOrdered.slice(rotationIndex), ...sourceOrdered.slice(0, rotationIndex)]
      : sourceOrdered,
    source: 'espn-event-order',
  };
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
  let rounds;
  if (explicitRounds.length) {
    rounds = attachUnassignedMatches(explicitRounds, ordered);
  } else {
    const bySeason = new Map();
    for (const match of ordered) {
      const key = seasonKey(match);
      if (!bySeason.has(key)) bySeason.set(key, []);
      bySeason.get(key).push(match);
    }
    rounds = [...bySeason.values()].flatMap((seasonMatches) => (
      roundsFromSchedule(seasonMatches).map((round, index) => ({
        ...round,
        matchday: index + 1,
        matches: round.matches.map((match) => ({
          ...match,
          matchday: index + 1,
          inferred_matchday: true,
        })),
      }))
    ));
  }
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
  const inferenceOrder = roundInferenceOrder(matches);

  for (const match of inferenceOrder.matches) {
    const home = normalizedTeam(homeTeam(match));
    const away = normalizedTeam(awayTeam(match));
    if (!home || !away) continue;

    const currentKickoff = kickoffMs(match);
    const repeatsTeam = usedTeams.has(home) || usedTeams.has(away);
    const largeGap = inferenceOrder.source === 'kickoff'
      && previousKickoff !== null
      && currentKickoff - previousKickoff > maxGapMs;
    if (current.length && (repeatsTeam || largeGap)) {
      rounds.push({ matchday: null, matches: orderedMatches(current), source: inferenceOrder.source });
      current = [];
      usedTeams = new Set();
    }

    current.push(match);
    usedTeams.add(home);
    usedTeams.add(away);
    previousKickoff = currentKickoff;
  }

  if (current.length) rounds.push({ matchday: null, matches: orderedMatches(current), source: inferenceOrder.source });
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
