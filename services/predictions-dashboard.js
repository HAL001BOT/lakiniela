function predictionStatus(prediction, match) {
  if (!prediction) return 'empty';
  if (!match || match.status !== 'finished' || match.home_score === null || match.away_score === null) {
    return 'pending';
  }

  if (
    Number(prediction.pred_home) === Number(match.home_score)
    && Number(prediction.pred_away) === Number(match.away_score)
  ) {
    return 'exact';
  }

  const predictedResult = Math.sign(Number(prediction.pred_home) - Number(prediction.pred_away));
  const actualResult = Math.sign(Number(match.home_score) - Number(match.away_score));
  return predictedResult === actualResult ? 'result' : 'miss';
}

function groupPredictionMatches(matches, competitionType) {
  const ordered = [...(matches || [])].sort((a, b) => {
    const timeDiff = new Date(a.kickoff_at).getTime() - new Date(b.kickoff_at).getTime();
    return timeDiff || Number(a.id) - Number(b.id);
  });

  if (competitionType === 'world_cup_2026') {
    const groups = [];
    const addGroup = (key, label, roundMatches) => {
      if (!roundMatches.length) return;
      groups.push({ key, label, matches: roundMatches });
    };

    const knockoutRounds = [
      ['round_of_32', 'Ronda de 32', 16, '2026-06-28T19:00:00Z'],
      ['round_of_16', 'Octavos de final', 8, '2026-07-04T17:00:00Z'],
      ['quarterfinals', 'Cuartos de final', 4, '2026-07-09T20:00:00Z'],
      ['semifinals', 'Semifinales', 2, '2026-07-14T19:00:00Z'],
      ['finals', 'Finales', 2, '2026-07-18T21:00:00Z'],
    ];

    const firstKickoff = ordered.length ? new Date(ordered[0].kickoff_at).getTime() : NaN;
    const firstKnockoutIndex = knockoutRounds.findLastIndex((round) => (
      Number.isFinite(firstKickoff) && firstKickoff >= new Date(round[3]).getTime()
    ));

    if (firstKnockoutIndex >= 0) {
      let knockoutCursor = 0;
      for (const [key, label, size] of knockoutRounds.slice(firstKnockoutIndex)) {
        addGroup(key, label, ordered.slice(knockoutCursor, knockoutCursor + size));
        knockoutCursor += size;
      }
      return groups;
    }

    for (let i = 0; i < Math.min(ordered.length, 72); i += 24) {
      addGroup(`group_${(i / 24) + 1}`, `Fase de grupos - ${(i / 24) + 1}`, ordered.slice(i, i + 24));
    }

    let cursor = 72;
    for (const [key, label, size] of knockoutRounds) {
      addGroup(key, label, ordered.slice(cursor, cursor + size));
      cursor += size;
    }

    if (groups.length) return groups;
  }

  const matchdays = new Map();
  for (const match of ordered) {
    const matchday = Number(match.matchday);
    if (!Number.isInteger(matchday) || matchday < 1) continue;
    if (!matchdays.has(matchday)) matchdays.set(matchday, []);
    matchdays.get(matchday).push(match);
  }

  if (matchdays.size && [...matchdays.values()].reduce((total, round) => total + round.length, 0) === ordered.length) {
    return [...matchdays.entries()]
      .sort(([a], [b]) => a - b)
      .map(([number, roundMatches]) => ({
        key: String(number),
        label: `Jornada ${number}`,
        matches: roundMatches,
      }));
  }

  return [{
    key: '1',
    label: competitionType === 'champions_league' ? 'Ronda 1' : 'Jornada 1',
    matches: ordered,
  }];
}

module.exports = {
  predictionStatus,
  groupPredictionMatches,
};
