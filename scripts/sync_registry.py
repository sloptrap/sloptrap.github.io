#!/usr/bin/env python3
"""Sync the public registry from the Worker and GitHub, fail closed.

Run by .github/workflows/sync-leaderboard.yml as `python3 -I scripts/sync_registry.py`.

* Official bundles (bundles/*.strule) are audited first. If any fails, nothing is written:
  official rule ids are the allowlist for everything else.
* Community bundles: GET /api/v1/rules/community-bundles?since=<unix>, paged. Each bundle is
  verified with strule_v2 and fully audited, must be tier community (computed from the key),
  is written to bundles/community/<rule_id>.strule, and must not collide with an official id.
* Pre-matched lists: GET /api/v1/lists/entries?since=<unix>, paged from 0 every run, and the
  list files are rebuilt from that data only (no merge with older, unvalidated entries).
  Every row is re-validated: site, official rule id for that site, account key format.
* Leaderboards are regenerated from the audited bundles. `verification_tier` and `verified`
  come from the audit (the signing key), never from remote data or manifest fields.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_bundles as audit  # noqa: E402
import strule_v2  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENDPOINT = "https://sloptrap-worker.fablestre.am"
REGISTRY_REPO = "sloptrap/sloptrap.github.io"
SITES = ("youtube", "tiktok", "pinterest")
SITE_NAMES = {"youtube": "YouTube", "tiktok": "TikTok", "pinterest": "Pinterest"}
ACCOUNT_KEY_RE = re.compile(r"^@[A-Za-z0-9._-]{3,100}$|^UC[A-Za-z0-9_-]{22}$")
RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_PAGES = 200
MAX_COMMUNITY_BUNDLES = 1000
MAX_LIST_ENTRIES_PER_RULE = 100_000
MAX_COUNT = 1_000_000_000
USER_AGENT = "sloptrap-registry-sync/2"
UNIX_TS_MAX = 4_102_444_800  # 2100-01-01


class SyncError(RuntimeError):
    pass


# ---------------------------------------------------------------------------- http
def endpoint_from_env() -> str:
    ep = os.environ.get("SLOPTRAP_WORKER_URL", DEFAULT_ENDPOINT).rstrip("/")
    u = urllib.parse.urlsplit(ep)
    if u.scheme != "https" or not u.hostname or u.path or u.query or u.username:
        raise SyncError(f"SLOPTRAP_WORKER_URL must be a bare https origin, got {ep!r}")
    return ep


def http_get_json(url: str, headers: dict | None = None, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                               **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - https URLs built here
        raw = r.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SyncError(f"response from {url} is larger than {MAX_RESPONSE_BYTES} bytes")
    return audit.strict_json_loads(raw)


def _ts(v) -> int | None:
    if type(v) is int and 0 <= v <= UNIX_TS_MAX:
        return v
    return None


def fetch_paged(get, path: str, rows_key: str, ts_key: str, row_key) -> list[dict]:
    """Page through `path?since=` from 0 until a page adds nothing new.

    Works whether the Worker treats `since` as inclusive or exclusive: when a page has no
    row at exactly `since` (exclusive, or a gap), the boundary second is read again with
    `since-1` so rows cut off at a page boundary are not lost. Duplicates are dropped.
    (More rows in one second than a page holds cannot be paged past with a timestamp
    cursor; the Worker's page size must stay above its per-second insert rate.)"""
    seen: set = set()
    rows: list[dict] = []

    def take(since: int) -> tuple[int, int, bool]:
        doc = get(f"{path}?since={since}")
        if not isinstance(doc, dict) or doc.get("ok") is not True or not isinstance(doc.get(rows_key), list):
            raise SyncError(f"{path}: unexpected response shape")
        new, max_ts, boundary = 0, since, False
        for r in doc[rows_key]:
            ts = _ts(r.get(ts_key)) if isinstance(r, dict) else None
            if ts is None:
                continue
            max_ts = max(max_ts, ts)
            boundary = boundary or ts == since
            k = row_key(r)
            if k in seen:
                continue
            seen.add(k)
            rows.append(r)
            new += 1
        return new, max_ts, boundary

    since = 0
    for _ in range(MAX_PAGES):
        new, max_ts, boundary = take(since)
        if since > 0 and not boundary:
            n2, m2, _b = take(since - 1)
            new, max_ts = new + n2, max(max_ts, m2)
        if new == 0:
            return rows
        since = max_ts
    raise SyncError(f"{path}: more than {MAX_PAGES} pages")


# -------------------------------------------------------------------- official rules
def audit_official(root: Path) -> list[audit.AuditResult]:
    paths = sorted(p for p in (root / "bundles").glob("*.strule") if p.is_file())
    if not paths:
        raise SyncError("no official bundles in bundles/")
    ok, failed = audit.audit_paths(paths, root, execute=True)
    if failed:
        for rel, err in failed:
            print(f"official bundle FAILED audit: {rel}: {err}", file=sys.stderr)
        raise SyncError(f"{len(failed)} official bundle(s) failed the audit; refusing to sync")
    return ok


# ------------------------------------------------------------------ community bundles
def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def select_community(rows: list[dict], official_ids: set[str], existing: dict[str, audit.AuditResult]
                     ) -> tuple[dict[str, tuple[bytes, audit.AuditResult]], list[str]]:
    """Validate and audit remote community rows. Returns ({rule_id: (bytes, result)}, rejections)."""
    chosen: dict[str, tuple[bytes, audit.AuditResult]] = {}
    rejected: list[str] = []
    for row in rows:
        rid = row.get("rule_id")
        try:
            if not isinstance(rid, str) or not RULE_ID_RE.fullmatch(rid) or not rid.startswith(strule_v2.COMMUNITY_PREFIX):
                raise SyncError(f"bad community rule_id {rid!r}")
            if rid in official_ids or rid[len(strule_v2.COMMUNITY_PREFIX):] in official_ids:
                raise SyncError(f"{rid}: collides with an official rule id")
            bundle = row.get("bundle")
            if isinstance(bundle, str):
                if len(bundle.encode("utf-8")) > audit.MAX_BUNDLE_BYTES:
                    raise SyncError(f"{rid}: bundle too large")
                bundle = audit.strict_json_loads(bundle)
            if not isinstance(bundle, dict):
                raise SyncError(f"{rid}: bundle must be a JSON object")
            raw = (json.dumps(bundle, ensure_ascii=True, indent=2) + "\n").encode("ascii")
            res = audit.audit_bundle(raw, expected_rule_id=rid, required_tier="community", execute=True,
                                     label=f"bundles/community/{rid}.strule")
            if row.get("version") != res.version:
                raise SyncError(f"{rid}: row version {row.get('version')!r} != manifest {res.version!r}")
            prev = chosen.get(rid)
            if prev and _vtuple(prev[1].version) >= _vtuple(res.version):
                continue
            old = existing.get(rid)
            if old and _vtuple(old.version) > _vtuple(res.version):
                raise SyncError(f"{rid}: refusing rollback from v{old.version} to v{res.version}")
            chosen[rid] = (raw, res)
        except Exception as e:  # noqa: BLE001 - one bad remote bundle never stops the others
            rejected.append(f"{rid!r}: {type(e).__name__}: {e}")
    if len(chosen) > MAX_COMMUNITY_BUNDLES:
        raise SyncError(f"more than {MAX_COMMUNITY_BUNDLES} community bundles")
    return chosen, rejected


def sync_community(root: Path, get, official_ids: set[str]) -> list[audit.AuditResult]:
    cdir = root / "bundles" / "community"
    cdir.mkdir(parents=True, exist_ok=True)
    existing_paths = sorted(cdir.glob("*.strule"))
    ok_existing, bad_existing = audit.audit_paths(existing_paths, root, execute=True)
    for rel, err in bad_existing:  # remote-sourced data: drop anything that no longer passes
        print(f"removing community bundle that fails the audit: {rel}: {err}", file=sys.stderr)
        (root / rel).unlink(missing_ok=True)
    existing = {r.rule_id: r for r in ok_existing}
    try:
        rows = fetch_paged(get, "/api/v1/rules/community-bundles", "bundles", "accepted_at",
                           lambda r: (r.get("rule_id"), r.get("version")))
    except Exception as e:  # noqa: BLE001
        print(f"community bundle fetch failed, keeping existing files: {e}", file=sys.stderr)
        return [r for r in ok_existing if r.rule_id not in official_ids]
    chosen, rejected = select_community(rows, official_ids, existing)
    for msg in rejected:
        print(f"community bundle rejected: {msg}", file=sys.stderr)
    for rid, (raw, _res) in chosen.items():
        target = cdir / f"{rid}.strule"
        if not target.exists() or target.read_bytes() != raw:
            target.write_bytes(raw)
    keep = set(chosen) | {rid for rid in existing if rid not in chosen and any(
        str(r.get("rule_id")) == rid for r in rows)}
    for p in cdir.glob("*.strule"):  # the Worker is the source of truth for the community registry
        if p.stem not in keep:
            print(f"removing community bundle no longer published: {p.name}")
            p.unlink()
    out = {rid: res for rid, (_raw, res) in chosen.items()}
    for rid, res in existing.items():
        if rid in keep and rid not in out:
            out[rid] = res
    return [out[k] for k in sorted(out)]


# ------------------------------------------------------------------------------ lists
def normalize_account_key(site: str, key) -> str | None:
    if not isinstance(key, str):
        return None
    key = key.strip()
    if not ACCOUNT_KEY_RE.fullmatch(key):
        return None
    if key.startswith("UC"):
        return key if site == "youtube" else None
    return key.lower()


def build_lists(rows: list[dict], official_sites: dict[str, str]) -> tuple[dict[tuple[str, str], set[str]], int]:
    """official_sites maps official rule_id -> target_site. Returns ({(site, rule): keys}, rejected)."""
    out: dict[tuple[str, str], set[str]] = {}
    for rid, tsite in official_sites.items():
        for s in (SITES if tsite == "*" else (tsite,)):
            out[(s, rid)] = set()
    rejected = 0
    for row in rows:
        site, rid = row.get("site"), row.get("rule_id")
        key = normalize_account_key(site, row.get("account_key")) if site in SITES else None
        if key is None or not isinstance(rid, str) or (site, rid) not in out:
            rejected += 1
            continue
        if len(out[(site, rid)]) >= MAX_LIST_ENTRIES_PER_RULE:
            rejected += 1
            continue
        out[(site, rid)].add(key)
    return out, rejected


def write_lists(root: Path, lists: dict[tuple[str, str], set[str]], names: dict[str, str], now_iso: str) -> None:
    ldir = root / "lists"
    manifest = {"schema_version": 1, "generated_at": now_iso, "lists": {}}
    wanted = set()
    for (site, rid) in sorted(lists):
        keys = sorted(lists[(site, rid)])
        path = ldir / site / f"{rid}.txt"
        wanted.add(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = "\n".join(["! SlopTrap Public Rule Matched Accounts",
                          f"! Rule: {rid} ({names.get(rid, rid)})",
                          f"! Site: {site}",
                          f"! Entries: {len(keys)}", *keys]) + "\n"
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        manifest["lists"][f"{site}/{rid}"] = {
            "site": site, "rule_id": rid, "path": f"lists/{site}/{rid}.txt", "count": len(keys),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    for p in ldir.glob("*/*.txt"):  # lists for unknown sites or non-official rules are removed
        if p not in wanted:
            print(f"removing list for a non-official rule or unknown site: {p.relative_to(root)}")
            p.unlink()
    (ldir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


# ------------------------------------------------------------------------ leaderboards
def _count(v) -> int | None:
    if type(v) is int and 0 <= v <= MAX_COUNT:
        return v
    return None


def fetch_stats(get) -> tuple[int | None, dict, dict]:
    try:
        st = get("/api/v1/rules/stats")
    except Exception as e:  # noqa: BLE001
        print(f"Worker stats warning: {e}", file=sys.stderr)
        return None, {}, {}
    if not isinstance(st, dict):
        return None, {}, {}
    wd = st.get("window_days")
    wd = wd if type(wd) is int and 1 <= wd <= 365 else None

    def clean(m):
        return {k: c for k, v in (m.items() if isinstance(m, dict) else []) if
                isinstance(k, str) and RULE_ID_RE.fullmatch(k) and (c := _count(v)) is not None}
    return wd, clean(st.get("active_installs")), clean(st.get("all_time_installs"))


def fetch_github(repo: str, token: str) -> tuple[dict, dict, dict]:
    """Upvotes from maintainer-opened `leaderboard-rule` issues, and release download counts."""
    hdr = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    likes: dict[str, tuple[int, int, str]] = {}
    issue_re = re.compile(rf"^https://github\.com/{re.escape(repo)}/issues/\d+$")
    try:
        issues = http_get_json(f"https://api.github.com/repos/{repo}/issues?labels=leaderboard-rule&state=open&per_page=100", hdr)
        for iss in issues if isinstance(issues, list) else []:
            if not isinstance(iss, dict) or iss.get("pull_request"):
                continue
            if iss.get("author_association") not in ("OWNER", "MEMBER", "COLLABORATOR"):
                continue
            m = re.search(r"\[rule:([a-z0-9][a-z0-9_-]{1,63})\]", str(iss.get("title", "")))
            url, num = iss.get("html_url"), iss.get("number")
            if not m or not isinstance(url, str) or not issue_re.fullmatch(url) or type(num) is not int:
                continue
            rx = iss.get("reactions") if isinstance(iss.get("reactions"), dict) else {}
            n = (_count(rx.get("+1")) or 0) + (_count(rx.get("heart")) or 0)
            rid = m.group(1)
            if rid not in likes or num < likes[rid][1]:
                likes[rid] = (n, num, url)
    except Exception as e:  # noqa: BLE001
        print(f"Issues warning: {e}", file=sys.stderr)
    dl_total: dict[str, int] = {}
    dl_ver: dict[tuple[str, str], int] = {}
    try:
        rels = http_get_json(f"https://api.github.com/repos/{repo}/releases?per_page=100", hdr)
        for rel in rels if isinstance(rels, list) else []:
            if not isinstance(rel, dict) or rel.get("draft"):
                continue
            tag = str(rel.get("tag_name") or "")
            for a in rel.get("assets") or []:
                name = str(a.get("name") or "") if isinstance(a, dict) else ""
                cnt = _count(a.get("download_count")) if isinstance(a, dict) else None
                if not name.endswith(".strule") or cnt is None or not RULE_ID_RE.fullmatch(name[:-7]):
                    continue
                rid = name[:-7]
                dl_total[rid] = dl_total.get(rid, 0) + cnt
                dl_ver[(rid, tag)] = cnt
    except Exception as e:  # noqa: BLE001
        print(f"Releases warning: {e}", file=sys.stderr)
    return likes, dl_total, dl_ver


def composite(e: dict) -> float:
    """Same formula as leaderboard/leaderboard.js computeComposite()."""
    def num(k, d=0.0):
        v = e.get(k)
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else d
    f1 = max(0.0, min(1.0, num("coarse_f1")))
    rep = max(0.0, min(100.0, num("author_reputation", 50.0)))
    oh = max(1.0, min(100.0, num("overhead", 50.0)))
    act = num("active_installs")
    allt = max(num("all_time_installs"), act)
    likes, stars = num("likes"), num("stars")
    dv, dt = num("downloads_version"), num("downloads_total")
    q_gate = max(0.0, min(1.0, (f1 - 0.5) / 0.5))
    eff = (101 - oh) / 100.0
    pop = (1.40 * math.log1p(act) + 0.45 * math.log1p(allt) + 1.35 * math.log1p(likes + stars * 0.75)
           + 0.55 * math.log1p(dv * 0.70 + dt * 0.30))
    return round(1000 * (0.62 * f1 + 0.10 * eff + 0.08 * rep / 100 + 0.20 * q_gate * math.tanh(pop / 6.5))) / 10


METRIC_KEYS = ("band", "coarse_f1", "coarse_precision", "coarse_recall", "author_reputation", "stars")


def make_entry(res: audit.AuditResult, local_path: str, prev: dict, today: str, stats, gh) -> dict:
    m = res.manifest
    rid = res.rule_id
    _wd, active, alltime = stats
    likes, dl_total, dl_ver = gh
    e = {
        "rank": 0,
        "rule_id": rid,
        "target_site": m["target_site"],
        "verification_tier": res.tier,          # computed from the signing key by the audit
        "verified": res.tier == "official",     # never read from remote data
        "name": m["name"],
        "description": m["description"],
        "version": m["version"],
        "author": m["author"],
        "author_public_key": m["author_public_key"],
        "repo_url": m["repo_url"],
        "provenance": dict(m["provenance"]),
        "inputs": list(m["inputs"]),
        "overhead": m["overhead"],
        "weight_milli": m["weight_milli"],
    }
    if res.tier == "official":  # holdout metrics are maintained by maintainers for official rules
        for k in METRIC_KEYS:
            if k in prev:
                e[k] = prev[k]
    for k in ("likes", "active_installs", "all_time_installs", "downloads_total", "downloads_version"):
        e[k] = _count(prev.get(k)) or 0
    if rid in active:
        e["active_installs"] = active[rid]
    e["all_time_installs"] = max(alltime.get(rid, e["all_time_installs"]), e["active_installs"])
    if rid in likes:
        e["likes"], e["issue_number"], e["issue_url"] = likes[rid]
    if rid in dl_total:
        e["downloads_total"] = dl_total[rid]
    if (rid, f"rule-{rid}-v{res.version}") in dl_ver:
        e["downloads_version"] = dl_ver[(rid, f"rule-{rid}-v{res.version}")]
    e["composite_score"] = composite(e)
    e["bundle_url"] = local_path
    e["local_bundle_path"] = local_path
    e["bundle_sha256"] = res.sha256
    e["updated_at"] = prev.get("updated_at") if prev.get("bundle_sha256") == res.sha256 and isinstance(
        prev.get("updated_at"), str) else today
    return e


def _load(path: Path) -> dict:
    try:
        d = audit.strict_json_loads(path.read_bytes())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def write_leaderboards(root: Path, official: list[audit.AuditResult], community: list[audit.AuditResult],
                       stats, gh, now_iso: str, endpoint: str) -> None:
    today = now_iso[:10]
    window = stats[0]
    idx_path = root / "leaderboard" / "index.json"
    idx = _load(idx_path)
    idx_sites = []
    for site in SITES:
        path = root / "leaderboard" / site / "leaderboard.json"
        old = _load(path)
        prev = {e.get("rule_id"): e for key in ("entries", "community_entries")
                for e in (old.get(key) or []) if isinstance(e, dict)}
        doc = {k: old[k] for k in ("epoch_id", "corpus_count", "corpus_hashes") if k in old}
        doc = {
            "schema_version": 2,
            "target_site": site,
            "site_display_name": SITE_NAMES[site],
            "registry_repo": REGISTRY_REPO,
            "rankings_endpoint": endpoint,
            "active_window_days": window or old.get("active_window_days") or 30,
            "generated_at": now_iso,
            **doc,
        }
        for key, results, base in (("entries", official, "bundles"), ("community_entries", community, "bundles/community")):
            rows = [make_entry(r, f"{base}/{r.rule_id}.strule", prev.get(r.rule_id) or {}, today, stats, gh)
                    for r in results if r.target_site in (site, "*")]
            rows.sort(key=lambda e: (-e["composite_score"], -e["active_installs"], e["overhead"], e["rule_id"]))
            for i, e in enumerate(rows, 1):
                e["rank"] = i
            doc[key] = rows
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        path.write_text(encoded, encoding="utf-8")
        if site == "youtube":
            (root / "leaderboard.json").write_text(encoded, encoding="utf-8")
            (root / "leaderboard" / "leaderboard.json").write_text(encoded, encoding="utf-8")
        idx_sites.append({
            "site_id": site, "display_name": SITE_NAMES[site], "feed_path": f"leaderboard/{site}/leaderboard.json",
            "rule_count": len(doc["entries"]), "official_count": len(doc["entries"]),
            "community_count": len(doc["community_entries"]), "corpus_count": doc.get("corpus_count", 0)})
    idx = {"schema_version": 2, "default_site": "youtube", "registry_repo": REGISTRY_REPO,
           "rankings_endpoint": endpoint, "active_window_days": window or idx.get("active_window_days") or 30,
           "generated_at": now_iso, "sites": idx_sites}
    idx_path.write_text(json.dumps(idx, indent=2) + "\n", encoding="utf-8")


# ------------------------------------------------------------------------------- main
def run(root: Path, get, gh_fetch, endpoint: str, now_iso: str) -> int:
    official = audit_official(root)
    official_ids = {r.rule_id for r in official}
    community = sync_community(root, get, official_ids)

    try:
        rows = fetch_paged(get, "/api/v1/lists/entries", "entries", "first_seen",
                           lambda r: (r.get("site"), r.get("rule_id"), r.get("account_key")))
    except Exception as e:  # noqa: BLE001
        print(f"list fetch failed, keeping existing list files: {e}", file=sys.stderr)
        rows = None
    if rows is not None:
        lists, rejected = build_lists(rows, {r.rule_id: r.target_site for r in official})
        if rejected:
            print(f"rejected {rejected} list row(s) (unknown site, non-official rule, or bad account key)")
        write_lists(root, lists, {r.rule_id: r.manifest["name"] for r in official}, now_iso)

    write_leaderboards(root, official, community, fetch_stats(get), gh_fetch(), now_iso, endpoint)
    print(f"synced {len(official)} official and {len(community)} community rule(s)")
    return 0


def main() -> int:
    if audit.wasmtime is None:
        print("wasmtime is required (pip install --require-hashes -r .github/requirements-ci.txt)", file=sys.stderr)
        return 1
    try:
        endpoint = endpoint_from_env()
        repo = os.environ.get("GITHUB_REPOSITORY", REGISTRY_REPO)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise SyncError("bad GITHUB_REPOSITORY")
        token = os.environ.get("GH_TOKEN", "")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return run(REPO_ROOT, lambda p: http_get_json(endpoint + p), lambda: fetch_github(repo, token),
                   endpoint, now_iso)
    except SyncError as e:
        print(f"SYNC FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
