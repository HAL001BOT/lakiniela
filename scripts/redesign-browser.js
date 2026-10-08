// Isolated, repeatable browser regression. Never opens the production database.
const fs=require('fs'),os=require('os'),path=require('path'),assert=require('node:assert/strict');
const {chromium}=require('@playwright/test');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'kiniela-ui-'));
process.env.DB_PATH=path.join(dir,'test.db');process.env.NODE_ENV='test';process.env.SESSION_SECRET='browser-regression-secret-123456';
const db=require('../db');const {app}=require('../server');
(async()=>{const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
const browser=await chromium.launch({headless:true,...(fs.existsSync('/usr/bin/chromium')?{executablePath:'/usr/bin/chromium'}:{}),args:['--no-sandbox']});
try{const page=await browser.newPage({viewport:{width:1440,height:1100}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
const base=`http://127.0.0.1:${server.address().port}`;
await page.goto(base+'/register');await page.locator('[name=name]').fill('Carlos');await page.locator('[name=username]').fill('reviewer');await page.locator('[name=email]').fill('review@example.com');await page.locator('[name=password]').fill('test-password-1234');await page.locator('button[type=submit],form button').first().click();await page.waitForURL('**/dashboard');
const owner=db.prepare('SELECT id FROM users WHERE username=?').get('reviewer').id;
const pool=Number(db.prepare("INSERT INTO pools(name,code,owner_id,competition_type,current_matchday,current_season_key) VALUES('Los Invencibles','DEMO01',?,'liga_mx',12,'2026:torneo-apertura')").run(owner).lastInsertRowid);
db.prepare('INSERT INTO pool_members(pool_id,user_id) VALUES(?,?)').run(pool,owner);
for(const [i,home,away] of [[1,'América','Chivas'],[2,'Tigres','Monterrey'],[3,'Pumas','Cruz Azul']]){const id=Number(db.prepare("INSERT INTO matches(external_id,league,season,season_key,matchday,home_team,away_team,kickoff_at,status) VALUES(?,'Liga MX','2026','2026:torneo-apertura',12,?,?,?,'scheduled')").run('demo-'+i,home,away,new Date(Date.now()+86400000+i*3600000).toISOString()).lastInsertRowid);db.prepare('INSERT INTO pool_matches(pool_id,match_id) VALUES(?,?)').run(pool,id)}
await page.goto(base+`/pools/${pool}`);const rows=page.locator('.prediction');assert.equal(await rows.count(),3);
await rows.nth(0).locator('.ph').fill('2');await rows.nth(0).locator('.pa').fill('1');await page.locator('#save-all').click();await page.getByText('Pronósticos guardados ✓',{exact:true}).waitFor();assert.equal(db.prepare('SELECT count(*) n FROM predictions').get().n,1);
await page.reload();assert.equal(await rows.nth(0).locator('.ph').inputValue(),'2');assert.equal(await rows.nth(1).locator('.ph').inputValue(),'');
await rows.nth(1).locator('.ph').fill('3');assert.equal(await page.locator('#save-all').isDisabled(),true);await rows.nth(1).locator('.pa').fill('0');assert.equal(await page.locator('#save-all').isEnabled(),true);
// Finish saving to avoid a beforeunload prompt while checking the routes.
await page.locator('#save-all').click();await page.getByText('Pronósticos guardados ✓',{exact:true}).waitFor();
const artifacts=process.env.UI_SCREENSHOTS; if(artifacts){fs.mkdirSync(artifacts,{recursive:true});await page.screenshot({path:path.join(artifacts,'desktop.png'),fullPage:true})}
for(const width of [390,768,1440]){await page.setViewportSize({width,height:900});for(const route of ['/dashboard',`/pools/${pool}`,`/pools/${pool}/pronosticos`,'/account/password','/admin/users']){await page.goto(base+route);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`Overflow ${width} ${route}`)} }
await page.setViewportSize({width:390,height:844});await page.goto(base+`/pools/${pool}`);assert.equal(await page.locator('#standings-card').isVisible(),false);await page.locator('[data-pool-tab=standings-card]').click();assert.equal(await page.locator('#standings-card').isVisible(),true);assert.equal(await page.locator('#predicciones').isVisible(),false);await page.locator('[data-pool-tab=predicciones]').click();assert.equal(await page.locator('#predicciones').isVisible(),true);
if(artifacts)await page.screenshot({path:path.join(artifacts,'mobile.png'),fullPage:true});
await page.locator('[data-pool-tab=standings-card]').click();await page.getByRole('button',{name:'Jornada',exact:true}).click();assert.equal(await page.locator('.matchday-leaderboard').isVisible(),true);await page.getByRole('button',{name:'General',exact:true}).click();assert.equal(await page.locator('.standings').isVisible(),true);
await page.locator('[data-pool-tab=predicciones]').click();
await page.locator('.prediction').nth(2).locator('.ph').fill('1');await page.locator('.prediction').nth(2).locator('.pa').fill('0');
await page.evaluate(()=>{document.querySelectorAll('.prediction')[2].dataset.lock=String(Date.now()-1);updateDeadlines()});assert.equal(await page.locator('.prediction').nth(2).locator('.ph').isDisabled(),true);assert.equal(await page.locator('#save-all').isDisabled(),true);
assert.deepEqual(errors,[]);console.log('Browser PASS: partial-round save, persisted scores, incomplete pairs, mobile tabs, five routes at 390/768/1440px, no JS errors.');
}finally{await browser.close();await new Promise(r=>server.close(r));db.close();fs.rmSync(dir,{recursive:true,force:true})}})().catch(e=>{console.error(e);process.exitCode=1});
