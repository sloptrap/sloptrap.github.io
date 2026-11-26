// Shared, injection-safe helpers for pages that render registry data (leaderboard feeds).
//
// Every string from a feed is untrusted (community rules are written by anonymous authors):
// text is only ever set with textContent, and links are only created from values that pass
// githubHref() (https://github.com/... only) or bundleHref() (a local bundles/ path).
(function () {
  'use strict';

  const SITES = ['youtube', 'tiktok', 'pinterest'];
  const SITE_NAMES = { youtube: 'YouTube', tiktok: 'TikTok', pinterest: 'Pinterest' };
  const WORKER = 'https://sloptrap-worker.fablestre.am';
  const RULE_ID_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/;
  const LOCAL_BUNDLE_RE = /^bundles\/(community\/)?[a-z0-9][a-z0-9_-]{1,63}\.strule$/;

  function githubHref(u) {
    if (typeof u !== 'string' || u === '') return null;
    let x;
    try { x = new URL(u); } catch (_) { return null; }
    if (x.protocol !== 'https:' || x.hostname !== 'github.com' || x.port || x.username || x.password) return null;
    return x.href;
  }

  function bundleHref(path, rootPrefix) {
    return typeof path === 'string' && LOCAL_BUNDLE_RE.test(path) ? rootPrefix + path : null;
  }

  function num(v, d) {
    const n = typeof v === 'number' ? v : Number.NaN;
    return Number.isFinite(n) ? n : (d === undefined ? 0 : d);
  }

  function count(v) {
    return Math.max(0, Math.trunc(num(v)));
  }

  function str(v) {
    return typeof v === 'string' ? v : '';
  }

  // The tier is computed by the site's audit from the signing key. Anything else in the
  // feed (a "verified" flag, provenance fields) is never used to label a rule.
  function tierOf(e) {
    const t = e && e.verification_tier;
    return t === 'official' || t === 'community' ? t : 'unverified';
  }

  function el(tag, opts, children) {
    const n = document.createElement(tag);
    const o = opts || {};
    if (o.className) n.className = o.className;
    if (o.text !== undefined) n.textContent = String(o.text);
    if (o.title) n.title = String(o.title);
    if (o.css) n.style.cssText = o.css;
    if (o.id) n.id = o.id;
    if (o.href) {
      n.href = o.href;  // callers pass only githubHref()/bundleHref() results or constants
      if (o.external) { n.target = '_blank'; n.rel = 'noopener noreferrer'; }
    }
    for (const c of children || []) {
      if (c == null) continue;
      n.append(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return n;
  }

  function tierBadge(tier) {
    if (tier === 'official') {
      return el('span', { className: 'g-label g-label_theme_positive', text: 'Official',
        title: 'Signed by the pinned SlopTrap official maintainer key' });
    }
    if (tier === 'community') {
      return el('span', { className: 'g-label g-label_theme_warning', text: 'Community',
        title: 'Anonymous submission compiled and signed by the community pipeline after automated checks. Not reviewed or endorsed by maintainers.' });
    }
    return el('span', { className: 'g-label g-label_theme_danger', text: 'Unverified' });
  }

  function bandTheme(b) {
    if (b === 'S') return 'positive';
    if (b === 'A') return 'info';
    if (b === 'B') return 'warning';
    return 'normal';
  }

  // Same formula as scripts/sync_registry.py composite().
  function composite(e) {
    const f1 = Math.max(0, Math.min(1, num(e.coarse_f1)));
    const rep = Math.max(0, Math.min(100, num(e.author_reputation, 50)));
    const oh = Math.max(1, Math.min(100, num(e.overhead, 50)));
    const act = count(e.active_installs);
    const allT = Math.max(count(e.all_time_installs), act);
    const likes = count(e.likes), stars = count(e.stars);
    const dv = count(e.downloads_version), dt = count(e.downloads_total);
    const qGate = Math.max(0, Math.min(1, (f1 - 0.5) / 0.5));
    const eff = (101 - oh) / 100;
    const pop = 1.40 * Math.log1p(act) + 0.45 * Math.log1p(allT) + 1.35 * Math.log1p(likes + stars * 0.75) +
      0.55 * Math.log1p(dv * 0.70 + dt * 0.30);
    return Math.round(1000 * (0.62 * f1 + 0.10 * eff + 0.08 * rep / 100 + 0.20 * qGate * Math.tanh(pop / 6.5))) / 10;
  }

  // Live install counts from the Worker: numbers only, keyed by valid rule ids.
  async function fetchStats() {
    try {
      const r = await fetch(WORKER + '/api/v1/rules/stats', { credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (!r.ok) return null;
      const st = await r.json();
      const clean = m => {
        const out = new Map();
        if (m && typeof m === 'object') {
          for (const [k, v] of Object.entries(m)) {
            if (RULE_ID_RE.test(k) && Number.isFinite(v) && v >= 0) out.set(k, Math.trunc(v));
          }
        }
        return out;
      };
      const wd = Number.isInteger(st.window_days) && st.window_days > 0 && st.window_days <= 365 ? st.window_days : null;
      return { windowDays: wd, active: clean(st.active_installs), allTime: clean(st.all_time_installs) };
    } catch (_) {
      return null;
    }
  }

  function applyStats(entries, stats) {
    if (!stats) return;
    for (const e of entries) {
      if (stats.active.has(e.rule_id)) e.active_installs = stats.active.get(e.rule_id);
      const at = stats.allTime.has(e.rule_id) ? stats.allTime.get(e.rule_id) : count(e.all_time_installs);
      e.all_time_installs = Math.max(at, count(e.active_installs));
    }
  }

  function siteParam(raw) {
    const s = String(raw || '').toLowerCase();
    return SITES.includes(s) ? s : 'youtube';
  }

  window.SlopTrapRegistryUI = {
    SITES, SITE_NAMES, RULE_ID_RE, githubHref, bundleHref, num, count, str, tierOf, el, tierBadge,
    bandTheme, composite, fetchStats, applyStats, siteParam,
  };
})();
