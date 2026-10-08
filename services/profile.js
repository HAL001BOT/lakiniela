const express = require('express');
const sharp = require('sharp');
const crypto = require('crypto');
const fallback = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256"><rect width="256" height="256" rx="128" fill="#253657"/><circle cx="128" cy="94" r="40" fill="#c4d7ff"/><path d="M52 224v-22a76 66 0 0 1 152 0v22" fill="#c4d7ff"/></svg>');
module.exports = function profileRoutes(db, auth) {
  const router = express.Router();
  router.get('/account/profile', auth, (req,res) => {
    const hasPhoto = !!db.prepare('SELECT 1 FROM user_avatars WHERE user_id=?').get(req.session.user.id);
    res.render('profile',{hasPhoto});
  });
  router.get('/users/:id/avatar', auth, (req,res) => {
    const id=Number(req.params.id);
    if(!Number.isSafeInteger(id)||id<=0||!db.prepare('SELECT 1 FROM users WHERE id=?').get(id)) return res.sendStatus(404);
    const avatar=db.prepare('SELECT image,version FROM user_avatars WHERE user_id=?').get(id);
    res.set('Cache-Control','private, no-cache');
    res.set('ETag','"'+(avatar?avatar.version:'default-avatar-v1')+'"');
    res.type(avatar?'image/webp':'image/svg+xml');
    return res.send(avatar?avatar.image:fallback);
  });
  router.post('/account/avatar', auth, express.raw({type:['image/jpeg','image/png','image/webp','image/avif'],limit:'5mb'}), async (req,res) => {
    if(!Buffer.isBuffer(req.body)||!req.body.length) return res.status(400).json({error:'Selecciona una imagen JPG, PNG, WebP o AVIF.'});
    let image;
    try {
      const input=sharp(req.body,{limitInputPixels:25000000,failOn:'warning',animated:false});
      const metadata=await input.metadata();
      if(!['jpeg','png','webp','avif','heif'].includes(metadata.format)) throw new Error('Unsupported format');
      // Decode and re-encode: correct orientation, crop square and discard metadata.
      image=await input.rotate().resize(256,256,{fit:'cover',position:'centre'}).webp({quality:82}).toBuffer();
    } catch(_) {return res.status(400).json({error:'No se pudo leer la imagen. Usa JPG, PNG, WebP o AVIF de hasta 5 MB y 25 megapíxeles.'});}
    const version=crypto.randomUUID();
    db.prepare('INSERT INTO user_avatars(user_id,image,version) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET image=excluded.image,version=excluded.version').run(req.session.user.id,image,version);
    res.json({ok:true,version});
  });
  router.post('/account/avatar/remove',auth,(req,res)=>{
    db.prepare('DELETE FROM user_avatars WHERE user_id=?').run(req.session.user.id);
    res.json({ok:true});
  });
  router.use((error,req,res,next)=>{
    if(error.type==='entity.too.large') return res.status(413).json({error:'La imagen supera el límite de 5 MB.'});
    next(error);
  });
  return router;
};
