document.addEventListener('DOMContentLoaded', () => {
  // Attach 1-click Copy buttons to all <pre> blocks
  document.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-code-btn';
    btn.type = 'button';
    btn.textContent = 'Copy';
    btn.addEventListener('click', () => {
      const code = pre.querySelector('code') ? pre.querySelector('code').innerText : pre.innerText;
      navigator.clipboard.writeText(code.trim()).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1600);
      });
    });
    pre.appendChild(btn);
  });

  // Interactive TUI screenshot tabs on landing page
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
