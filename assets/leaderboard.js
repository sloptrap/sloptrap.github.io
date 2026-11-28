// Leaderboard page (leaderboard/index.html). All feed strings are rendered with textContent;
// links come only from SlopTrapRegistryUI.githubHref()/bundleHref().
(function () {
  'use strict';
  const U = window.SlopTrapRegistryUI;
  const { el } = U;
  const params = new URLSearchParams(window.location.search);

  let docData = null;
  let liveStats = null;
  let currentSite = U.siteParam(params.get('site'));
  let currentSort = 'rank';
  let filterQuery = '';
  let includeCommunity = false;  // community rules are off by default
  let activeWindowDays = 30;

  const targetRule = (params.get('rule') || window.location.hash.replace(/^#rule-/, '')).trim().toLowerCase();

  function setText(id, text) {
    const n = document.getElementById(id);
    if (n) n.textContent = text;
  }

  function syncWindowLabels(days) {
    activeWindowDays = days;
    setText('window-desc', `rolling ${days}-day active window`);
    setText('stat-window', `${days} days`);
    setText('th-active', `Active (${days}d)`);
    setText('sort-active-btn', `Active (${days}d)`);
  }

  function message(text, danger) {
    const tbody = document.getElementById('rows');
    tbody.replaceChildren(el('tr', {}, [el('td', {
      text, css: `color:var(${danger ? '--g-color-text-danger' : '--g-color-text-secondary'});`,
    })]));
    tbody.firstChild.firstChild.colSpan = 10;
  }

  function overheadColor(oh) {
    if (oh <= 30) return 'var(--g-color-text-positive)';
    if (oh <= 60) return 'var(--g-color-text-warning)';
    return 'var(--g-color-text-danger)';
  }

  function provenanceCell(e, tier) {
    const key = U.str(e.author_public_key);
    const cell = el('td', {}, [
      el('div', {}, [U.tierBadge(tier)]),
      el('div', { className: 'mono', css: 'font-size:12px;margin-top:4px;', text: U.str(e.author) }),
      el('div', { className: 'mono', css: 'font-size:11px;color:var(--g-color-text-hint);', title: key,
        text: `${key.slice(0, 12)}…` }),
    ]);
    const prov = e.provenance && typeof e.provenance === 'object' ? e.provenance : {};
    const run = U.githubHref(prov.build_run_url);
    if (run) {
      const commit = U.str(prov.source_commit).slice(0, 7);
      cell.append(el('div', { css: 'font-size:11px;margin-top:2px;' }, [
        el('a', { href: run, external: true, className: 'mono', text: `build@${commit || 'run'}` }),
      ]));
    }
    return cell;
  }

  function metricsCell(e, tier) {
    if (tier !== 'official' || e.coarse_f1 === undefined) {
      return el('td', { css: 'color:var(--g-color-text-hint);font-size:12px;',
        text: tier === 'community' ? 'Holdout-checked by the pipeline (not published)' : '—' });
    }
    return el('td', {}, [
      el('div', { css: 'display:flex;align-items:center;gap:6px;' }, [
        el('span', { className: `g-label g-label_theme_${U.bandTheme(e.band)}`, text: `Band ${U.str(e.band)}` }),
        el('span', { className: 'mono', css: 'font-weight:600;', text: `F1 ${U.num(e.coarse_f1).toFixed(2)}` }),
      ]),
      el('div', { className: 'mono', css: 'font-size:11px;color:var(--g-color-text-secondary);margin-top:4px;',
        text: `P ${U.num(e.coarse_precision).toFixed(2)} · R ${U.num(e.coarse_recall).toFixed(2)} · Score ${U.num(e.composite_score).toFixed(1)}` }),
    ]);
  }

  function row(e, idx) {
    const tier = U.tierOf(e);
    const rid = U.str(e.rule_id);
    const oh = Math.max(1, Math.min(100, U.count(e.overhead)));
    const inputs = (Array.isArray(e.inputs) ? e.inputs : []).map(i =>
      el('span', { className: 'g-label g-label_theme_normal mono', text: U.str(i) }));
    const tagLabels = {
      'creative-content': 'Creative Content', 'creative-animation': 'AI Film & Animation', 'ai-assisted-creator': 'AI-Assisted Creator',
      'slop-documentary': 'Slop Documentary', 'slop-info-channel': 'Slop Info Channel', 'slop-news-chyron': 'Slop News / Chyron',
      'slop-hijacked-necro': 'Hijacked / Necro Account', 'slop-clone-farm': 'Clone Farm', 'slop-clip-mill': 'TTS Clip Mill',
      'slop-image-mill': 'Synthetic Image Mill', 'slop-funnel-spam': 'Spam / Affiliate Funnel',
      'slop-deceptive-fake': 'Deceptive Synthetic', 'slop-general': 'AI Slop',
    };
    const classification = e.classification === 'creative_ai' ? 'creative_ai' : 'slop';
    const channelTag = U.str(e.channel_tag || (classification === 'creative_ai' ? 'creative-content' : 'slop-general'));
    inputs.unshift(el('span', {
      className: `g-label g-label_theme_${classification === 'creative_ai' ? 'positive' : 'danger'}`,
      text: `${classification === 'creative_ai' ? 'AI' : 'Slop'} · ${tagLabels[channelTag] || channelTag}`,
      title: `${classification} · ${channelTag}`,
    }));

    const issue = U.githubHref(e.issue_url);
    const likes = String(U.count(e.likes));
    const upvote = issue
      ? el('a', { className: 'g-btn g-btn_view_outlined g-btn_size_s tabular', href: issue, external: true,
          title: 'Upvote on GitHub', text: `▲ ${likes}` })
      : el('span', { className: 'mono', text: likes });

    const links = el('div', { css: 'display:flex;gap:6px;justify-content:flex-end;' });
    const bundle = U.bundleHref(e.local_bundle_path, '../');
    if (bundle) links.append(el('a', { className: 'g-btn g-btn_view_action g-btn_size_s mono', href: bundle, text: '.strule' }));
    const repo = U.githubHref(e.repo_url);
    if (repo) links.append(el('a', { className: 'g-btn g-btn_view_flat g-btn_size_s', href: repo, external: true, text: 'Repo' }));
    const sha = U.str(e.bundle_sha256);

    const tr = el('tr', { id: `rule-${rid}` }, [
      el('td', { className: 'mono', css: 'color:var(--g-color-text-secondary);', text: String(idx + 1) }),
      el('td', {}, [
        el('div', { className: 'rule-name' }, [U.str(e.name), ' ',
          el('span', { className: 'mono', css: 'color:var(--g-color-text-hint);font-weight:400;', text: `v${U.str(e.version)}` })]),
        el('div', { className: 'rule-desc', text: U.str(e.description) }),
        el('div', { className: 'tag-row' }, inputs),
      ]),
      provenanceCell(e, tier),
      metricsCell(e, tier),
      el('td', { className: 'num mono', title: `Unique installs active in last ${activeWindowDays} days` },
        [el('strong', { text: String(U.count(e.active_installs)) })]),
      el('td', { className: 'num mono', title: 'Cumulative unique installs',
        text: String(Math.max(U.count(e.all_time_installs), U.count(e.active_installs))) }),
      el('td', { className: 'num mono', title: 'GitHub Release .strule downloads', text: String(U.count(e.downloads_total)) }),
      el('td', { className: 'num' }, [upvote]),
      el('td', { className: 'num' }, [
        el('div', { className: 'mono', text: `${oh}/100` }),
        el('div', { className: 'meter' }, [el('div', { className: 'meter__fill',
          css: `width:${Math.max(5, oh)}%;background:${overheadColor(oh)};` })]),
      ]),
      el('td', { className: 'num' }, [links,
        el('div', { className: 'mono', css: 'font-size:11px;color:var(--g-color-text-hint);margin-top:4px;', title: sha,
          text: `sha256:${sha.slice(0, 10)}` })]),
    ]);
    if (tier === 'community') tr.classList.add('row-community');
    if (targetRule && rid.toLowerCase() === targetRule) {
      tr.style.cssText = 'background:rgba(255,190,92,0.12);outline:1px solid var(--g-color-line-brand);';
    }
    return tr;
  }

  function currentEntries() {
    if (!docData) return [];
    const all = Array.isArray(docData.entries) ? docData.entries : [];
    return all.filter(e => U.tierOf(e) === 'official' || (includeCommunity && U.tierOf(e) === 'community'));
  }

  function render() {
    const q = filterQuery.trim().toLowerCase();
    const list = currentEntries().filter(e => {
      if (!q) return true;
      const hay = [e.name, e.rule_id, e.description, e.author, e.classification, e.channel_tag,
        U.tierOf(e), ...(Array.isArray(e.inputs) ? e.inputs : [])]
        .map(U.str).join(' ').toLowerCase();
      return hay.includes(q);
    });
    const by = {
      active: (a, b) => U.count(b.active_installs) - U.count(a.active_installs),
      alltime: (a, b) => U.count(b.all_time_installs) - U.count(a.all_time_installs),
      likes: (a, b) => U.count(b.likes) - U.count(a.likes),
      downloads: (a, b) => U.count(b.downloads_total) - U.count(a.downloads_total),
      f1: (a, b) => U.num(b.coarse_f1) - U.num(a.coarse_f1),
      overhead: (a, b) => U.count(a.overhead) - U.count(b.overhead),
      rank: () => 0,
    }[currentSort] || (() => 0);
    list.sort((a, b) => by(a, b) || U.num(b.composite_score) - U.num(a.composite_score));

    if (list.length === 0) {
      message('No matching rules for this filter.');
      return;
    }
    document.getElementById('rows').replaceChildren(...list.map(row));
  }

  async function loadSite(site, pushUrl) {
    currentSite = U.siteParam(site);
    document.querySelectorAll('#site-switcher button').forEach(b => {
      b.classList.toggle('active', b.dataset.site === currentSite);
    });
    if (pushUrl) {
      const u = new URL(window.location.href);
      u.searchParams.set('site', currentSite);
      history.replaceState(null, '', u);
    }
    const feedRel = `./${currentSite}/leaderboard.json`;
    const rawLink = document.getElementById('raw-feed-link');
    rawLink.href = feedRel;
    rawLink.textContent = `${currentSite}/leaderboard.json`;
    try {
      const r = await fetch(feedRel, { credentials: 'same-origin' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      docData = await r.json();
      const disp = U.SITE_NAMES[currentSite];
      setText('lb-heading', `${disp} Rule Leaderboard`);
      setText('stat-site', disp);
      const all = Array.isArray(docData.entries) ? docData.entries : [];
      const off = all.filter(e => U.tierOf(e) === 'official').length;
      const com = all.filter(e => U.tierOf(e) === 'community').length;
      setText('stat-rules', `${off} official · ${com} community`);
      setText('stat-epoch', `${U.count(docData.corpus_count)} holdout · ${U.str(docData.epoch_id)}`);
      const wd = U.count(docData.active_window_days);
      if (wd > 0) syncWindowLabels(wd);
      render();
      if (targetRule) document.getElementById(`rule-${targetRule}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (!liveStats) liveStats = await U.fetchStats();
      if (liveStats) {
        if (liveStats.windowDays) syncWindowLabels(liveStats.windowDays);
        const all = Array.isArray(docData.entries) ? docData.entries : [];
        U.applyStats(all, liveStats);
        for (const e of all) e.composite_score = U.composite(e);
        render();
      }
    } catch (err) {
      message(`Failed to load ${feedRel}: ${err && err.message ? err.message : err}`, true);
    }
  }

  document.querySelectorAll('#site-switcher button').forEach(btn => {
    btn.addEventListener('click', () => loadSite(btn.dataset.site, true));
  });
  document.querySelectorAll('.sort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSort = btn.dataset.sort;
      render();
    });
  });
  document.getElementById('rule-filter').addEventListener('input', ev => {
    filterQuery = ev.target.value || '';
    render();
  });
  const chk = document.getElementById('community-chk');
  chk.checked = false;
  chk.addEventListener('change', ev => {
    includeCommunity = ev.target.checked;
    document.getElementById('community-note').hidden = !includeCommunity;
    render();
  });
  document.getElementById('copy-feed-btn').addEventListener('click', ev => {
    const b = ev.currentTarget;
    const feedUrl = new URL(`./${currentSite}/leaderboard.json`, window.location.href).href;
    navigator.clipboard.writeText(feedUrl).then(() => {
      const prev = b.textContent;
      b.textContent = 'Copied URL';
      setTimeout(() => { b.textContent = prev; }, 1400);
    });
  });

  loadSite(currentSite, false);
})();
