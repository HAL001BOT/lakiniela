(() => {
  const form=document.getElementById('avatar-form');if(!form)return;
  const file=document.getElementById('avatar-file'),save=document.getElementById('avatar-save'),remove=document.getElementById('avatar-remove'),status=document.getElementById('avatar-status'),photo=document.getElementById('profile-avatar');
  const headers={'x-csrf-token':form.querySelector('[name=_csrf]').value};
  let busy=false;
  const controls=value=>{busy=value;file.disabled=save.disabled=remove.disabled=value};
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;const selected=file.files[0];if(!selected)return;
    if(selected.size>5*1024*1024){status.textContent='La imagen supera el límite de 5 MB.';return;}
    if(!['image/jpeg','image/png','image/webp','image/avif'].includes(selected.type)){status.textContent='Selecciona una imagen JPG, PNG, WebP o AVIF.';return;}
    controls(true);status.textContent='Guardando foto…';
    try{const response=await fetch('/account/avatar',{method:'POST',headers:{...headers,'Content-Type':selected.type},body:selected});const result=await response.json().catch(()=>({}));if(!response.ok||!result.ok)throw new Error(result.error||'No se pudo guardar la foto.');photo.src=`/users/${form.dataset.userId}/avatar?v=${encodeURIComponent(result.version)}`;file.value='';remove.hidden=false;status.textContent='Foto de perfil guardada.';}
    catch(error){status.textContent=error.message}finally{controls(false)}
  });
  remove.addEventListener('click',async()=>{
    if(busy||!confirm('¿Quitar tu foto de perfil?'))return;controls(true);status.textContent='Quitando foto…';
    try{const response=await fetch('/account/avatar/remove',{method:'POST',headers});const result=await response.json().catch(()=>({}));if(!response.ok||!result.ok)throw new Error('No se pudo quitar la foto.');photo.src=`/users/${form.dataset.userId}/avatar?v=${Date.now()}`;remove.hidden=true;status.textContent='Foto eliminada.';}
    catch(error){status.textContent=error.message}finally{controls(false)}
  });
})();
