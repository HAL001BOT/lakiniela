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

  if (competitionType === 'world_cup_2026' && ordered.length > 24) {
    const groupStage = ordered.slice(0, 72);
    const groups = [];
    for (let i = 0; i < groupStage.length; i += 24) {
      groups.push({
        key: String(groups.length + 1),
        label: `Fase de grupos - ${groups.length + 1}`,
        matches: groupStage.slice(i, i + 24),
      });
    }
    return groups;
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
