(() => {
  const key = 'lakiniela-theme';
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference;
  try { preference = localStorage.getItem(key); } catch (_) { /* Storage can be blocked. */ }
  let explicit = preference === 'light' || preference === 'dark';
  const apply = theme => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    const button = document.getElementById('theme-toggle');
    if (button) {
      button.setAttribute('aria-pressed', String(theme === 'dark'));
      button.textContent = theme === 'dark' ? '☀ Modo claro' : '☾ Modo oscuro';
      button.title = theme === 'dark' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro';
    }
  };
  apply(explicit ? preference : system.matches ? 'dark' : 'light');
  system.addEventListener('change', e => { if (!explicit) apply(e.matches ? 'dark' : 'light'); });
  window.addEventListener('storage', e => {
    if (e.key !== key && e.key !== null) return;
    explicit = e.newValue === 'light' || e.newValue === 'dark';
    apply(explicit ? e.newValue : system.matches ? 'dark' : 'light');
  });
  document.addEventListener('DOMContentLoaded', () => {
    const button = document.createElement('button');
    button.type = 'button'; button.id = 'theme-toggle'; button.className = 'theme-toggle';
    button.addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      explicit = true; apply(next);
      try { localStorage.setItem(key, next); } catch (_) { /* Still works for this page. */ }
    });
    const header = document.querySelector('header.top');
    if (header) header.append(button);
    else { button.classList.add('theme-floating'); document.body.append(button); }
    apply(document.documentElement.dataset.theme);
  });
})();
