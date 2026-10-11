const assert=require('node:assert/strict');const {rankStandings}=require('../services/ranking');
const base={finished_picks:6,points:8,exact_picks:1,correct_picks:2};
let rows=rankStandings([{...base,id:2,name:'Zoe'},{...base,id:1,name:'Admin'},{...base,id:3,name:'Third',points:3,exact_picks:0,correct_picks:1},{id:4,name:'Absent',finished_picks:0}]);
assert.deepEqual(rows.map(r=>r.rank),[1,1,3,null]);assert.equal(rows.filter(r=>r.leader).length,2);assert.ok(rows[0].tied&&rows[1].tied);assert.equal(rows[3].leader,false);
rows=rankStandings([{...base,id:1,name:'A',points:15,exact_picks:0,correct_picks:5},{...base,id:2,name:'Z',points:15,exact_picks:3,correct_picks:3}]);assert.equal(rows[0].id,2);assert.equal(rows[1].rank,2);
rows=rankStandings([{...base,points:0,correct_picks:0,exact_picks:0},{...base,points:0,correct_picks:0,exact_picks:0}]);assert.ok(rows.every(r=>r.rank===1&&r.tied&&!r.leader));
rows=rankStandings([{...base,id:1,name:'High percentage',accuracy_pct:100,points:5,exact_picks:1,correct_picks:1,finished_picks:1},{...base,id:2,name:'More points',accuracy_pct:33}]);assert.equal(rows[0].id,2);
console.log('Ranking regression passed: shared places/crowns, sporting tiebreaks, no percentage/name preference, no zero-point awards or unplayed ranks.');
