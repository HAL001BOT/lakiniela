// Test with an isolated database; never reads family/user production data.
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('node:assert/strict');
const { chromium } = require('@playwright/test');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kiniela-shader-'));
process.env.DB_PATH = path.join(dir, 'test.db');
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'shader-browser-test-only-secret';
const db = require('../db');
const { app } = require('../server');
(async () => {
  const server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const browser = await chromium.launch({executablePath:'/usr/bin/chromium', args:['--no-sandbox','--use-angle=swiftshader','--enable-unsafe-swiftshader']});
  try {
    const page = await browser.newPage({ viewport: {width:390,height:844} });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(base+'/register');
    for (const [name, value] of Object.entries({name:'Admin',username:'shader',email:'shader@example.com',password:'test-password-1234'})) await page.locator(`[name=${name}]`).fill(value);
    await page.locator('form button').first().click(); await page.waitForURL('**/dashboard');
    const owner = db.prepare('SELECT id FROM users WHERE username=?').get('shader').id;
    const pool = db.prepare("INSERT INTO pools(name,code,owner_id) VALUES('Demo','SHADER',?)").run(owner).lastInsertRowid;
    db.prepare('INSERT INTO pool_members(pool_id,user_id) VALUES(?,?)').run(pool,owner);
    await page.goto(base+'/dashboard');
    await page.locator('.action-shader canvas').waitFor();
    await page.evaluate(()=>document.documentElement.dataset.theme='dark');
    await page.waitForTimeout(600);
    const card = page.locator('.next-action-card');
    assert.match(await card.innerText(), /Tus pronósticos están al día/);
    const before = await card.boundingBox();
    const image1 = await card.screenshot();
    await page.waitForTimeout(500);
    const image2 = await card.screenshot();
    assert.ok(!image1.equals(image2), 'Shader must actually animate');
    await page.locator('.action-shader').evaluate(el=>el.style.display='none');
    assert.deepEqual(await card.boundingBox(), before, 'Background must not change layout');
    await page.locator('.action-shader').evaluate(el=>el.style.display='');
    for (const theme of ['light','dark']) {
      await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth), false);
      await card.screenshot({path:`/tmp/lakiniela-shader-${theme}.png`});
    }
    await page.emulateMedia({reducedMotion:'reduce'}); await page.waitForTimeout(400);
    const still1 = await card.screenshot(); await page.waitForTimeout(400);
    assert.ok(still1.equals(await card.screenshot()), 'Reduced motion must stop animation');
    await page.setViewportSize({width:1440,height:1000});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    await page.goto(base+'/account/profile'); assert.equal(await page.locator('.action-shader').count(),0);
    assert.deepEqual(errors,[]);
    console.log('PASS: actual animation, unchanged geometry, light/dark, mobile/desktop, reduced motion, dashboard-only, no JS errors.');
  } finally { await browser.close(); await new Promise(r=>server.close(r)); db.close(); fs.rmSync(dir,{recursive:true,force:true}); }
})().catch(e=>{console.error(e);process.exitCode=1});
