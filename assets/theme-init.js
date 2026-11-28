// Applies the saved theme before first paint. Loaded as an external script so pages can
// use a strict Content-Security-Policy (script-src 'self').
try {
  if (localStorage.getItem('st-gravity-theme') === 'light') {
    document.body.classList.remove('g-root_theme_dark');
    document.body.classList.add('g-root_theme_light');
  }
} catch (_) { /* storage unavailable: keep the dark default */ }
