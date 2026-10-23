// App installation only: private pages and live scores are never cached.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      // LaKiniela continues to work normally if service workers are unavailable.
    });
  });
}
