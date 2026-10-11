// One published sporting order for tables and awards. Names only stabilize display.
function comparePerformance(a, b, scoreKey = 'points') {
  return Number(b[scoreKey] || 0) - Number(a[scoreKey] || 0)
    || Number(b.exact_picks || 0) - Number(a.exact_picks || 0)
    || Number(b.correct_picks || 0) - Number(a.correct_picks || 0);
}
function rankStandings(rows, scoreKey = 'points') {
  const sorted = [...rows].sort((a,b) => Number(Boolean(b.finished_picks)) - Number(Boolean(a.finished_picks))
    || comparePerformance(a,b,scoreKey) || String(a.name || '').localeCompare(String(b.name || ''),'es') || Number(a.id)-Number(b.id));
  let previous, rank=0;
  const ranked=sorted.map((row,index)=>{
    if(!Number(row.finished_picks))return {...row,rank:null,tied:false,leader:false};
    if(!previous || comparePerformance(previous,row,scoreKey)!==0)rank=index+1;
    previous=row;return {...row,rank};
  });
  const sizes=new Map();for(const row of ranked)if(row.rank)sizes.set(row.rank,(sizes.get(row.rank)||0)+1);
  return ranked.map(row=>({...row,tied:row.rank!==null&&sizes.get(row.rank)>1,leader:row.rank===1&&Number(row[scoreKey])>0}));
}
module.exports={comparePerformance,rankStandings};
