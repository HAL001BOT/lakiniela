const fs=require('fs'),os=require('os'),path=require('path'),assert=require('node:assert/strict');
const request=require('supertest'),sharp=require('sharp');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'kiniela-profile-'));process.env.DB_PATH=path.join(dir,'test.db');process.env.NODE_ENV='test';process.env.SESSION_SECRET='profile-test-secret-123456789';
const db=require('../db');const {app}=require('../server');
const csrf=res=>res.text.match(/name=['"]_csrf['"] value=['"]([^'"]+)['"]/)[1];
(async()=>{try{
const owner=request.agent(app),other=request.agent(app);
for(const [agent,name] of [[owner,'photo_owner'],[other,'photo_other']]){const page=await agent.get('/register');await agent.post('/register').type('form').send({_csrf:csrf(page),name,username:name,email:name+'@example.com',password:'test-password-1234'}).expect(302)}
const profile=await owner.get('/account/profile').expect(200);const token=csrf(profile);const ownerId=db.prepare('SELECT id FROM users WHERE username=?').get('photo_owner').id,otherId=db.prepare('SELECT id FROM users WHERE username=?').get('photo_other').id;
await request(app).get(`/users/${ownerId}/avatar`).expect(302);
await owner.get(`/users/${ownerId}/avatar`).expect('Content-Type',/image\/svg/).expect(200);
const input=await sharp({create:{width:600,height:300,channels:3,background:'#4169ff'}}).png().toBuffer();
await owner.post('/account/avatar').set('Content-Type','image/png').send(input).expect(403);
await owner.post('/account/avatar?user_id='+otherId).set('x-csrf-token',token).set('Content-Type','image/png').send(input).expect(200);
const row=db.prepare('SELECT * FROM user_avatars WHERE user_id=?').get(ownerId);assert.ok(row);assert.equal(db.prepare('SELECT count(*) n FROM user_avatars WHERE user_id=?').get(otherId).n,0);
const info=await sharp(row.image).metadata();assert.equal(info.width,256);assert.equal(info.height,256);assert.equal(info.format,'webp');assert.equal(info.exif,undefined);
await other.get(`/users/${ownerId}/avatar`).expect('Content-Type',/image\/webp/).expect(200);
await owner.post('/account/avatar').set('x-csrf-token',token).set('Content-Type','image/png').send(Buffer.from('<svg><script>alert(1)</script></svg>')).expect(400);
assert.equal(db.prepare('SELECT version FROM user_avatars WHERE user_id=?').get(ownerId).version,row.version);
await owner.post('/account/avatar').set('x-csrf-token',token).set('Content-Type','image/png').send(Buffer.alloc(5*1024*1024+1)).expect(413);
// Each account only changes its own photo. Removing another user's query id is ignored.
const otherProfile=await other.get('/account/profile');await other.post('/account/avatar/remove?user_id='+ownerId).set('x-csrf-token',csrf(otherProfile)).expect(200);assert.ok(db.prepare('SELECT 1 FROM user_avatars WHERE user_id=?').get(ownerId));
await owner.post('/account/avatar/remove').set('x-csrf-token',token).expect(200);assert.equal(db.prepare('SELECT count(*) n FROM user_avatars').get().n,0);
await owner.get(`/users/${ownerId}/avatar`).expect('Content-Type',/image\/svg/).expect(200);
console.log('Profile tests passed: upload, normalized image, privacy/auth, CSRF, invalid and oversized images, ownership, removal.');
}finally{db.close();fs.rmSync(dir,{recursive:true,force:true})}})().catch(e=>{console.error(e);process.exitCode=1});
