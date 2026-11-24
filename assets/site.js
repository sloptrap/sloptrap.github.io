(function () {
  const STORAGE_KEY = 'st-gravity-theme';

  function applyTheme(theme) {
    const body = document.body;
    if (!body) return;
    body.classList.remove('g-root_theme_dark', 'g-root_theme_light');
    body.classList.add(theme === 'light' ? 'g-root_theme_light' : 'g-root_theme_dark');
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      const isLight = theme === 'light';
      btn.setAttribute('title', isLight ? 'Switch to dark theme' : 'Switch to light theme');
      btn.setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
      btn.innerHTML = isLight
        ? '<svg class="icon-14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13.5 9.8A5.8 5.8 0 0 1 6.2 2.5a5.8 5.8 0 1 0 7.3 7.3Z"/></svg>'
        : '<svg class="icon-14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="3.2"/><path d="M8 1.5v1.8M8 12.7v1.8M1.5 8h1.8M12.7 8h1.8M3.4 3.4l1.3 1.3M11.3 11.3l1.3 1.3M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3"/></svg>';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const saved = localStorage.getItem(STORAGE_KEY) || 'dark';
    applyTheme(saved);

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const next = document.body.classList.contains('g-root_theme_light') ? 'dark' : 'light';
        localStorage.setItem(STORAGE_KEY, next);
        applyTheme(next);
      });
    }

    // 1-click Copy buttons on <pre> blocks
    document.querySelectorAll('pre').forEach(pre => {
      const btn = document.createElement('button');
      btn.className = 'copy-code-btn';
      btn.type = 'button';
      btn.textContent = 'Copy';
      btn.addEventListener('click', () => {
        const code = pre.querySelector('code') ? pre.querySelector('code').innerText : pre.innerText;
        navigator.clipboard.writeText(code.trim()).then(() => {
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1400);
        });
      });
      pre.appendChild(btn);
    });

    // Segmented TUI view switcher on Overview page
    const shotImg = document.getElementById('tui-showcase-img');
    const shotCaption = document.getElementById('tui-showcase-caption');
    if (shotImg) {
      document.querySelectorAll('.shot-tab').forEach(tab => {
        tab.addEventListener('click', () => {
          document.querySelectorAll('.shot-tab').forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          shotImg.src = tab.dataset.src;
          shotImg.alt = tab.dataset.caption || '';
          if (shotCaption) {
            shotCaption.textContent = tab.dataset.caption || '';
          }
        });
      });
    }
  });
})();
