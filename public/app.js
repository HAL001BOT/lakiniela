document.addEventListener('error', (event) => {
  const el = event.target;
  if (el instanceof HTMLImageElement && el.classList.contains('hide-on-error')) {
    el.style.display = 'none';
  }
}, true);

document.addEventListener('submit', (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (!form.classList.contains('confirmable')) return;
  const message = form.getAttribute('data-confirm') || 'Are you sure?';
  if (!window.confirm(message)) event.preventDefault();
});

document.querySelectorAll('[data-auto-submit]').forEach((control) => {
  control.addEventListener('change', () => control.form?.requestSubmit());
});

// Real anchor links remain useful without JavaScript; enhance them into phone tabs.
if (document.body.classList.contains('pool-page')) {
  document.body.classList.add('js-tabs');
  const setPoolTab = () => {
    const table = location.hash === '#standings-card';
    document.body.classList.toggle('show-standings', table);
    document.querySelectorAll('[data-pool-tab]').forEach(link => {
      const active = (link.dataset.poolTab === 'standings-card') === table;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
  };
  window.addEventListener('hashchange', setPoolTab); setPoolTab();
}

if (document.querySelector('header.top') && !document.body.classList.contains('knockout-page')) {
  const rail = document.createElement('nav');
  rail.className = 'desktop-rail'; rail.setAttribute('aria-label', 'Navegación principal');
  const mark = document.createElement('img'); mark.src='/img/lakiniela-mark.png'; mark.alt='';
  const brand=document.createElement('a');brand.href='/dashboard';brand.className='rail-brand';brand.append(mark,document.createTextNode('LaKiniela'));rail.append(brand);
  const poolMatch = location.pathname.match(/^\/pools\/(\d+)/);
  const links=[['Inicio','/dashboard'],['Mis quinielas','/dashboard#quinielas']];
  if(poolMatch) links.push(['Pronósticos',`/pools/${poolMatch[1]}#predicciones`],['Clasificación',`/pools/${poolMatch[1]}#standings-card`]);
  links.push(['Perfil','/account/password']);
  links.forEach(([label,href])=>{const a=document.createElement('a');a.href=href;a.textContent=label;rail.append(a)});
  document.body.prepend(rail);document.body.classList.add('with-rail');
}
// Cached/empty image failures can occur before the delegated error listener loads.
document.querySelectorAll('img.hide-on-error').forEach(img => {
  if (!img.getAttribute('src') || (img.complete && img.naturalWidth === 0)) img.style.display='none';
});

const rankingCard = document.getElementById('standings-card');
if(rankingCard?.querySelector('.matchday-leaderboard')) {
  const controls=document.createElement('div');controls.className='ranking-tabs';controls.setAttribute('aria-label','Alcance de clasificación');
  const general=rankingCard.querySelector('.standings'),columns=rankingCard.querySelector('.standings-columns'),round=rankingCard.querySelector('.matchday-leaderboard');
  ['General','Jornada'].forEach((label,index)=>{
    const button=document.createElement('button');button.type='button';button.textContent=label;button.setAttribute('aria-pressed',String(index===0));
    button.addEventListener('click',()=>{general.hidden=columns.hidden=index===1;round.hidden=index===0;controls.querySelectorAll('button').forEach(b=>b.setAttribute('aria-pressed',String(b===button)))});controls.append(button);
  });
  rankingCard.querySelector('.standings-head').after(controls);round.hidden=true;
}
