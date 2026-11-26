// Home page leaderboard preview: top official rules per site. Untrusted feed strings are
// rendered with textContent only; links come from SlopTrapRegistryUI.bundleHref().
(function () {
  'use strict';
  const U = window.SlopTrapRegistryUI;
  const { el } = U;
  let stats;

  function message(text, danger) {
    const td = el('td', { text, css: danger ? 'color:var(--g-color-text-danger);' : '' });
    td.colSpan = 8;
    document.getElementById('home-lb-rows').replaceChildren(el('tr', {}, [td]));
  }

  async function loadHomeSite(rawSite) {
    const site = U.siteParam(rawSite);
    document.getElementById('home-full-lb-link').href = `./leaderboard/?site=${site}`;
    try {
      const r = await fetch(`./leaderboard/${site}/leaderboard.json`, { credentials: 'same-origin' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      if (stats === undefined) stats = await U.fetchStats();
      const entries = (Array.isArray(data.entries) ? data.entries : []).filter(e => U.tierOf(e) === 'official');
      U.applyStats(entries, stats);
      const winDays = (stats && stats.windowDays) || U.count(data.active_window_days) || 30;
      document.getElementById('home-active-col').textContent = `Active (${winDays}d)`;
      entries.forEach(e => { e.composite_score = U.composite(e); });
      entries.sort((a, b) => U.num(b.composite_score) - U.num(a.composite_score));
      const rows = entries.slice(0, 5).map((e, i) => {
        const href = U.bundleHref(e.local_bundle_path, './');
        return el('tr', {}, [
          el('td', { className: 'mono', css: 'color:var(--g-color-text-secondary);', text: String(i + 1) }),
          el('td', {}, [
            el('div', { className: 'rule-name' }, [U.str(e.name), ' ',
              el('span', { className: 'mono', css: 'color:var(--g-color-text-hint);font-weight:400;', text: `v${U.str(e.version)}` })]),
            el('div', { className: 'rule-desc', text: U.str(e.description) }),
          ]),
          el('td', {}, [U.tierBadge(U.tierOf(e)),
            el('div', { className: 'mono', css: 'font-size:11px;color:var(--g-color-text-hint);margin-top:3px;', text: U.str(e.author) })]),
          el('td', {}, [
            el('span', { className: `g-label g-label_theme_${U.bandTheme(e.band)}`, text: `Band ${U.str(e.band) || '—'}` }),
            el('span', { className: 'mono', css: 'margin-left:6px;', text: U.num(e.coarse_f1).toFixed(2) }),
          ]),
          el('td', { className: 'num mono', text: String(U.count(e.active_installs)) }),
          el('td', { className: 'num mono', text: String(Math.max(U.count(e.all_time_installs), U.count(e.active_installs))) }),
          el('td', { className: 'num mono', text: `${U.count(e.overhead)}/100` }),
          el('td', { className: 'num' }, href ? [el('a', { className: 'g-btn g-btn_view_outlined g-btn_size_s mono', href, text: '.strule' })] : []),
        ]);
      });
      if (rows.length) document.getElementById('home-lb-rows').replaceChildren(...rows);
      else message('No official rules published for this site yet.');
    } catch (_) {
      message('Failed to load site leaderboard', true);
    }
  }

  document.querySelectorAll('#home-site-tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#home-site-tabs button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      loadHomeSite(btn.dataset.site);
    });
  });

  loadHomeSite('youtube');
})();
