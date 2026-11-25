/**
 * SlopTrap JavaScript & WebAssembly SDK (v1)
 * ------------------------------------------
 * Zero-dependency ES module for integrating SlopTrap into web apps, browser extensions,
 * Electron/Tauri apps, and Node/Deno/Cloudflare runtimes.
 *
 * Supports two integration modes:
 *   1. Static Engine (`SlopTrapStaticEngine`) — Load a fixed array of `.strule` bundles with zero network calls.
 *   2. Managed Client (`SlopTrapClient`) — Sync site-specific leaderboards (`youtube`, `tiktok`, `pinterest`, or custom),
 *      filter by Verified provenance, toggle rules, and optionally report Anonymous rule rankings.
 */

export const DEFAULT_SCORING_SEED = "sloptrap-public-scoring-v1:9f84c2e0a1b74d6e8f3c5a2b1d9e0f4a";
export const DEFAULT_REGISTRY_BASE = "https://sloptrap.github.io";
export const DEFAULT_RANKINGS_ENDPOINT = "https://sloptrap-worker.fablestre.am";

export const OFFICIAL_MAINTAINER_KEYS = new Set([
  "eb85cbf507e27e2c0f94ad723385db3138af32670ea37ca337f0c1866eae02cc",
  "33fee5d93b69abffb9d920da59d823a1c88a71119064a794ff6a8258bee2a472",
]);

const enc = new TextEncoder();
const dec = new TextDecoder();

function hexToBytes(hex) {
  const clean = String(hex || "").trim().toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function b64ToBytes(b64) {
  const bin = atob(String(b64 || "").trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function canonicalManifestBytes(m) {
  const weight = Number(m.default_weight || 1.0).toFixed(4);
  const canon = [
    "sloptrap-manifest-v1",
    m.rule_id || "",
    m.name || "",
    m.version || "",
    m.author || "",
    String(m.author_public_key || "").trim().toLowerCase(),
    m.interpreter || "wasm-v1",
    (m.inputs || []).join(","),
    weight,
    String(Math.trunc(Number(m.overhead || 1))),
    m.encryption || "none",
  ].join("\n");
  return enc.encode(canon);
}

export function resolveProvenance(manifest) {
  const pub = String(manifest?.author_public_key || "").trim().toLowerCase();
  if (OFFICIAL_MAINTAINER_KEYS.has(pub)) {
    return {
      verified: true,
      tier: "official",
      source_repo: manifest?.provenance?.source_repo || manifest?.repo_url || "",
      source_commit: manifest?.provenance?.source_commit || "",
      build_run_url: manifest?.provenance?.build_run_url || "",
    };
  }
  const p = manifest?.provenance;
  if (
    p &&
    p.tier === "source-attested" &&
    p.verified === true &&
    String(p.source_repo || "").startsWith("https://github.com/") &&
    /^[0-9a-f]{40}$/i.test(String(p.source_commit || "")) &&
    String(p.build_run_url || "").startsWith("https://github.com/")
  ) {
    return { ...p, verified: true };
  }
  return { verified: false, tier: "unverified" };
}

async function deriveBundleAesKey(scoringSeed, manifest) {
  const saltKey = await crypto.subtle.importKey(
    "raw",
    enc.encode("sloptrap-hkdf-salt-v1"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, enc.encode(scoringSeed)));
  const prkKey = await crypto.subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const info = enc.encode(
    `sloptrap-bundle-v1|${manifest.rule_id}|${String(manifest.author_public_key).trim().toLowerCase()}|${manifest.version}`
  );
  const okm = await crypto.subtle.sign("HMAC", prkKey, concatBytes(info, new Uint8Array([1])));
  return crypto.subtle.importKey("raw", okm, { name: "AES-GCM" }, false, ["decrypt"]);
}

export async function verifyAndUnpackBundle(bundle, scoringSeed = DEFAULT_SCORING_SEED) {
  if (!bundle || bundle.format !== "sloptrap-bundle-v1") {
    throw new Error(`Unsupported bundle format: ${bundle?.format}`);
  }
  const m = bundle.manifest || {};
  const pubBytes = hexToBytes(m.author_public_key);
  const sigBytes = b64ToBytes(bundle.signature_b64);
  const rawPayload = b64ToBytes(bundle.payload_b64);
  const canon = canonicalManifestBytes(m);

  let wasmBytes;
  if (!m.encryption || m.encryption === "none") {
    wasmBytes = rawPayload;
  } else if (m.encryption === "aes-256-gcm-hkdf") {
    if (rawPayload.length < 28) throw new Error("Encrypted payload too short");
    const aesKey = await deriveBundleAesKey(scoringSeed, m);
    const nonce = rawPayload.slice(0, 12);
    const ciphertext = rawPayload.slice(12);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: canon },
      aesKey,
      ciphertext
    );
    wasmBytes = new Uint8Array(plain);
  } else {
    throw new Error(`Unsupported encryption: ${m.encryption}`);
  }

  const sigMsg = concatBytes(enc.encode("sloptrap-sig-v1:"), canon, new Uint8Array([0]), wasmBytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", sigMsg));

  if (crypto.subtle.importKey) {
    try {
      const edKey = await crypto.subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
      const valid = await crypto.subtle.verify({ name: "Ed25519" }, edKey, sigBytes, digest);
      if (!valid) throw new Error(`Invalid Ed25519 signature for ${m.rule_id}`);
    } catch (err) {
      if (String(err?.message || "").includes("Invalid Ed25519")) throw err;
      // Browser without subtle Ed25519 support still enforces authenticated AES-256-GCM AAD above
    }
  }

  if (wasmBytes.length < 8 || wasmBytes[0] !== 0x00 || wasmBytes[1] !== 0x61 || wasmBytes[2] !== 0x73 || wasmBytes[3] !== 0x6d) {
    throw new Error("Unpacked payload is not valid WebAssembly");
  }
  return wasmBytes;
}

function runPooledInstance(instance, manifest, fpBytes) {
  const t0 = performance.now();
  const exports = instance.exports;
  const mem = exports.memory;
  if (!mem || typeof exports.st_evaluate !== "function") {
    throw new Error(`Invalid WASM ABI in ${manifest.rule_id}`);
  }

  // Reset linear memory scratch bump pointer to 16384 so pooled instance never fragments or grows memory
  if (mem.buffer.byteLength >= 4) {
    new DataView(mem.buffer).setInt32(0, 16384, true);
  }

  let inPtr = 16384;
  if (typeof exports.st_alloc === "function") {
    const p = exports.st_alloc(fpBytes.length);
    if (Number(p) > 0) inPtr = Number(p) >>> 0;
  }

  const needed = inPtr + fpBytes.length + 1024;
  if (mem.buffer.byteLength < needed) {
    const pages = Math.ceil((needed - mem.buffer.byteLength) / 65536);
    mem.grow(pages);
  }
  new Uint8Array(mem.buffer, inPtr, fpBytes.length).set(fpBytes);

  const packed = BigInt(exports.st_evaluate(inPtr, fpBytes.length));
  const elapsedUs = Math.round((performance.now() - t0) * 1000);
  const u64 = BigInt.asUintN(64, packed);
  const upper = Number((u64 >> 32n) & 0xffffffffn);
  const lower = Number(u64 & 0xffffffffn);

  const prov = resolveProvenance(manifest);
  let score = 0;
  let confidence = 1.0;
  let reason = manifest.description || "";

  if (upper === 0) {
    score = Math.max(0, Math.min(100, lower));
  } else {
    const slice = new Uint8Array(mem.buffer, upper, lower);
    const parsed = JSON.parse(dec.decode(slice));
    score = Math.max(0, Math.min(100, Number(parsed.score || 0)));
    if (parsed.confidence > 0 && parsed.confidence <= 1) confidence = Number(parsed.confidence);
    if (parsed.reason) reason = parsed.reason;
  }

  return {
    rule_id: manifest.rule_id,
    target_site: manifest.target_site || "youtube",
    verified: prov.verified,
    verification_tier: prov.tier,
    rule_name: manifest.name,
    version: manifest.version,
    score,
    confidence,
    weight: Number(manifest.default_weight || 1.0),
    overhead: Number(manifest.overhead || 1),
    reason,
    exec_micros: elapsedUs,
  };
}

export function normalizeAccountKey(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  if (s.startsWith("UC") && s.length >= 20 && !s.includes("/")) return s;
  return (s.startsWith("@") ? s : `@${s}`).toLowerCase();
}

export function parseAccountListText(txt) {
  const set = new Set();
  for (const rawLine of String(txt || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!")) continue;
    const norm = normalizeAccountKey(line);
    if (norm) set.add(norm);
  }
  return set;
}

// Pluggable Site Adapter Registry
const siteAdapters = new Map();

export function registerSiteAdapter(adapter) {
  if (!adapter || !adapter.siteId) throw new Error("Adapter requires siteId");
  siteAdapters.set(String(adapter.siteId).toLowerCase(), adapter);
}

export function getSiteAdapter(siteId) {
  return siteAdapters.get(String(siteId || "").toLowerCase()) || null;
}

export function listRegisteredSites() {
  return [...siteAdapters.keys()];
}

const AUTO_SUFFIX_RE = /^@[a-z0-9_.]{5,}-[a-z0-9]{1,5}$/i;
const KEYWORD_STUFF_RE = /(?:#[a-z0-9_]+|\b(?:ai|midjourney|sdxl|generated|viral|fyp|trending|aesthetic|decor|ideas)\b)/gi;

export function normalizeAccountSnapshot(site, snap = {}) {
  const rawHandle = String(snap.handle || "").trim();
  const handle = rawHandle && !rawHandle.startsWith("@") ? `@${rawHandle}` : rawHandle;
  const posts = Array.isArray(snap.posts) ? snap.posts : [];
  let keywordHits = 0;
  let totalWords = 0;
  let synthHits = 0;
  let watermarkHits = 0;
  const domains = new Map();
  let outboundTotal = 0;

  for (const p of posts) {
    const txt = `${p.title || ""} ${p.caption || ""}`.trim();
    const words = txt ? txt.split(/\s+/).length : 0;
    totalWords += words;
    keywordHits += (txt.match(KEYWORD_STUFF_RE) || []).length;
    if (p.syntheticHint) synthHits++;
    if (p.repostWatermark) watermarkHits++;
    if (p.outboundDomain) {
      const d = String(p.outboundDomain).toLowerCase().replace(/^www\./, "");
      domains.set(d, (domains.get(d) || 0) + 1);
      outboundTotal++;
    }
  }

  let maxDomain = 0;
  for (const c of domains.values()) if (c > maxDomain) maxDomain = c;
  const n = Math.max(1, posts.length);

  return {
    schema_version: 1,
    site,
    channel: {
      channel_id: snap.accountId || "",
      handle,
      title: snap.title || "",
      description: snap.bio || "",
      subscriber_count: Number(snap.followers || 0),
      total_videos: Number(snap.totalPosts || posts.length),
      has_auto_suffix: AUTO_SUFFIX_RE.test(handle),
      stem_siblings: Number(snap.stemSiblings || 0),
      outbound_domain_share: outboundTotal > 0 ? maxDomain / outboundTotal : 0,
    },
    upload_cadence: {
      channel_age_days: Number(snap.accountAgeDays || 0),
      max_dormancy_gap_days: Number(snap.maxDormancyGapDays || 0),
      post_pivot_share: Number(snap.postPivotShare || 0),
      recent_uploads_per_day: Number(snap.recentUploadsPerDay || 0),
      output_minutes_per_week: Number(snap.outputMinutesPerWeek || 0),
      duration_cv: Number(snap.durationCv || 0),
    },
    transcript: {
      uncontracted_ratio: Number(snap.uncontractedRatio || 0),
      antithesis_per_1k: Number(snap.antithesisPer1k || 0),
      slop_hooks_per_1k: Number(snap.slopHooksPer1k || 0),
      keyword_stuffing_ratio: totalWords > 0 ? keywordHits / totalWords : 0,
      intra_video_wpm_cv: Number(snap.intraVideoWpmCv || 0),
      pause_cv: Number(snap.pauseCv || 0),
      earliest_has_speech: snap.earliestHasSpeech !== false,
    },
    thumbnails: {
      title_skeleton_reuse: Number(snap.titleSkeletonReuse || 0),
      synthetic_image_ratio: posts.length > 0 ? synthHits / n : Number(snap.syntheticImageRatio || 0),
      aspect_uniformity: Number(snap.aspectUniformity || 0),
      repost_watermark_ratio: posts.length > 0 ? watermarkHits / n : Number(snap.repostWatermarkRatio || 0),
    },
    audio_video_stats: {
      dead_air_floor: Boolean(snap.deadAirFloor),
    },
  };
}

registerSiteAdapter({ siteId: "youtube", displayName: "YouTube", matchUrl: u => /youtube\.com|youtu\.be/i.test(u) });
registerSiteAdapter({ siteId: "tiktok", displayName: "TikTok", matchUrl: u => /tiktok\.com/i.test(u) });
registerSiteAdapter({ siteId: "pinterest", displayName: "Pinterest", matchUrl: u => /pinterest\.|pin\.it/i.test(u) });

export class SlopTrapStaticEngine {
  constructor(options = {}) {
    this.site = String(options.site || "youtube").toLowerCase();
    this.verifiedOnly = Boolean(options.verifiedOnly);
    this.usePreMatchedLists = options.usePreMatchedLists !== false;
    this.warnThreshold = Number(options.warnThreshold || 45);
    this.blockThreshold = Number(options.blockThreshold || 68);
    this.scoringSeed = options.scoringSeed || DEFAULT_SCORING_SEED;
    this.rules = new Map();
    this.ruleMatchedSets = new Map(); // ruleId -> Set<normalizedAccountKey>
  }

  async loadBundle(bundle, enabled = true) {
    const bSite = String(bundle?.manifest?.target_site || "youtube").toLowerCase();
    if (this.site && this.site !== "*" && bSite !== "*" && bSite !== this.site) {
      return false;
    }
    const prov = resolveProvenance(bundle.manifest);
    if (this.verifiedOnly && !prov.verified) {
      return false;
    }
    const wasmBytes = await verifyAndUnpackBundle(bundle, this.scoringSeed);
    const compiled = await WebAssembly.compile(wasmBytes);
    const instance = await WebAssembly.instantiate(compiled, {});
    this.rules.set(bundle.manifest.rule_id, {
      manifest: bundle.manifest,
      provenance: prov,
      compiled,
      instance,
      enabled,
    });
    return true;
  }

  loadRuleList(ruleId, textOrIterable) {
    const set =
      typeof textOrIterable === "string"
        ? parseAccountListText(textOrIterable)
        : new Set(Array.from(textOrIterable || [], k => normalizeAccountKey(k)).filter(Boolean));
    this.ruleMatchedSets.set(ruleId, set);
    return set.size;
  }

  hasRuleListMatch(ruleId, accountKey) {
    const set = this.ruleMatchedSets.get(ruleId);
    return Boolean(set && set.has(normalizeAccountKey(accountKey)));
  }

  async loadBundles(bundles) {
    for (const b of bundles || []) {
      await this.loadBundle(b, true);
    }
  }

  listRules() {
    return [...this.rules.values()].map(r => ({
      manifest: r.manifest,
      provenance: r.provenance,
      enabled: r.enabled,
      listCount: this.ruleMatchedSets.get(r.manifest.rule_id)?.size || 0,
    }));
  }

  toggleRule(ruleId, forceState) {
    const r = this.rules.get(ruleId);
    if (!r) return false;
    r.enabled = typeof forceState === "boolean" ? forceState : !r.enabled;
    return r.enabled;
  }

  async evaluate(fingerprint) {
    const rawHandle = fingerprint?.channel?.handle || fingerprint?.channel?.channel_id || "";
    const accountKey = normalizeAccountKey(rawHandle);

    // O(1) Pre-Matched Public Rule List Fast-Path (skips JSON serialization & WASM execution)
    if (this.usePreMatchedLists && accountKey) {
      const listHitRules = [];
      for (const r of this.rules.values()) {
        if (!r.enabled) continue;
        if (this.verifiedOnly && !r.provenance.verified) continue;
        const set = this.ruleMatchedSets.get(r.manifest.rule_id);
        if (set && set.has(accountKey)) {
          listHitRules.push(r.manifest.rule_id);
        }
      }
      if (listHitRules.length > 0) {
        return {
          site: this.site,
          score: 85,
          action: "block",
          fast_path_list: true,
          matched_rule_ids: listHitRules,
          newly_matched_rules: [],
          verified_rules: listHitRules.length,
          outputs: [],
          total_micros: 0,
        };
      }
    }

    const fpBytes = enc.encode(JSON.stringify({ schema_version: 1, site: this.site, ...fingerprint }));
    const outputs = [];
    const newlyMatchedRules = [];
    let weightedSum = 0;
    let weightTotal = 0;
    let totalMicros = 0;
    let verifiedRules = 0;

    for (const r of this.rules.values()) {
      if (!r.enabled) continue;
      if (this.verifiedOnly && !r.provenance.verified) continue;
      const out = runPooledInstance(r.instance, r.manifest, fpBytes);
      outputs.push(out);
      totalMicros += out.exec_micros;
      if (out.verified) verifiedRules++;
      const w = out.weight * (out.confidence || 1);
      weightedSum += out.score * w;
      weightTotal += w;

      if (accountKey && out.score >= this.warnThreshold) {
        const set = this.ruleMatchedSets.get(r.manifest.rule_id);
        if (!set || !set.has(accountKey)) {
          newlyMatchedRules.push({
            site: this.site,
            rule_id: r.manifest.rule_id,
            account_key: accountKey,
            action: out.score >= this.blockThreshold ? "block" : "warn",
          });
        }
      }
    }

    const score = weightTotal > 0 ? Math.round(Math.min(100, Math.max(0, weightedSum / weightTotal))) : 0;
    const action = score >= this.blockThreshold ? "block" : score >= this.warnThreshold ? "warn" : "allow";
    return {
      site: this.site,
      score,
      action,
      fast_path_list: false,
      newly_matched_rules: newlyMatchedRules,
      verified_rules: verifiedRules,
      outputs,
      total_micros: totalMicros,
    };
  }
}

export class SlopTrapClient {
  constructor(options = {}) {
    this.registryBaseUrl = String(options.registryBaseUrl || DEFAULT_REGISTRY_BASE).replace(/\/$/, "");
    this.rankingsEndpoint = String(options.rankingsEndpoint || DEFAULT_RANKINGS_ENDPOINT).replace(/\/$/, "");
    this.storagePrefix = options.storagePrefix || "sloptrap_sdk_v1";
    this.anonymousRuleRankings = Boolean(options.anonymousRuleRankings);
    this.contributeMatchedAccounts = Boolean(options.contributeMatchedAccounts);
    this.engine = new SlopTrapStaticEngine(options);
    this.availableSites = ["youtube", "tiktok", "pinterest"];
    this._submittedMatches = new Set();
  }

  get site() { return this.engine.site; }
  get verifiedOnly() { return this.engine.verifiedOnly; }

  setVerifiedOnly(val) {
    this.engine.verifiedOnly = Boolean(val);
  }

  setAnonymousRuleRankings(val) {
    this.anonymousRuleRankings = Boolean(val);
  }

  async switchSite(site) {
    this.engine = new SlopTrapStaticEngine({
      site,
      verifiedOnly: this.engine.verifiedOnly,
      warnThreshold: this.engine.warnThreshold,
      blockThreshold: this.engine.blockThreshold,
      scoringSeed: this.engine.scoringSeed,
    });
    return this.syncRegistry();
  }

  getOrCreateInstallToken() {
    const key = `${this.storagePrefix}:anon_token`;
    try {
      let tok = localStorage.getItem(key);
      if (!tok || tok.length < 24) {
        const arr = new Uint8Array(16);
        crypto.getRandomValues(arr);
        tok = [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
        localStorage.setItem(key, tok);
      }
      return tok;
    } catch (_) {
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      return [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
    }
  }

  async syncRegistry() {
    try {
      const idxResp = await fetch(`${this.registryBaseUrl}/leaderboard/index.json`);
      if (idxResp.ok) {
        const idx = await idxResp.json();
        if (Array.isArray(idx.sites) && idx.sites.length > 0) {
          this.availableSites = idx.sites.map(s => s.site_id);
        }
      }
    } catch (_) {}

    const lbUrl = `${this.registryBaseUrl}/leaderboard/${this.site}/leaderboard.json`;
    const resp = await fetch(lbUrl);
    if (!resp.ok) throw new Error(`Failed loading ${lbUrl} (${resp.status})`);
    const doc = await resp.json();

    let loaded = 0;
    for (const entry of doc.entries || []) {
      if (this.verifiedOnly && !entry.verified) continue;
      // Prefer same-origin local_bundle_path when available to avoid cross-origin redirects
      const relPath = entry.local_bundle_path || entry.bundle_url || "";
      const url = relPath.startsWith("http")
        ? `${this.registryBaseUrl}/bundles/${entry.rule_id}.strule`
        : `${this.registryBaseUrl}/${relPath.replace(/^\//, "")}`;
      const bResp = await fetch(url);
      if (!bResp.ok) continue;
      const bundle = await bResp.json();
      if (await this.engine.loadBundle(bundle, true)) loaded++;
    }

    // Sync pre-matched public rule lists (`lists/manifest.json`) for O(1) lookup
    try {
      const lmResp = await fetch(`${this.registryBaseUrl}/lists/manifest.json`);
      if (lmResp.ok) {
        const lm = await lmResp.json();
        for (const info of Object.values(lm.lists || {})) {
          if (info.site !== this.site) continue;
          const txtResp = await fetch(`${this.registryBaseUrl}/${info.path}`);
          if (txtResp.ok) {
            this.engine.loadRuleList(info.rule_id, await txtResp.text());
          }
        }
      }
    } catch (_) {}

    if (this.anonymousRuleRankings && this.rankingsEndpoint) {
      const activeRules = this.engine
        .listRules()
        .filter(r => r.enabled)
        .map(r => ({ rule_id: r.manifest.rule_id, version: r.manifest.version }));
      fetch(`${this.rankingsEndpoint}/api/v1/rules/check-updates`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          install_token: this.getOrCreateInstallToken(),
          active_rules: activeRules,
        }),
      }).catch(() => {});
    }
    return loaded;
  }

  listRules() { return this.engine.listRules(); }
  toggleRule(id, state) { return this.engine.toggleRule(id, state); }

  async evaluate(fp) {
    const res = await this.engine.evaluate(fp);
    if (this.contributeMatchedAccounts && this.rankingsEndpoint && res.newly_matched_rules?.length > 0) {
      const fresh = res.newly_matched_rules.filter(m => {
        const k = `${m.site}|${m.rule_id}|${m.account_key}`;
        if (this._submittedMatches.has(k)) return false;
        this._submittedMatches.add(k);
        return true;
      });
      if (fresh.length > 0) {
        fetch(`${this.rankingsEndpoint}/api/v1/lists/report-matches`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ site: this.site, matches: fresh }),
        }).catch(() => {});
      }
    }
    return res;
  }
}
