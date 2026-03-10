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
