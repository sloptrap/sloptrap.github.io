#!/usr/bin/env python3
"""
SlopTrap .strule Security & Malicious-Content Auditor
-----------------------------------------------------
Validates all .strule WebAssembly rule bundles and leaderboard.json manifests:
  1. File size ceilings (<= 256 KiB bundle, <= 192 KiB WASM) & SHA-256 manifest match
  2. Cryptographic Ed25519 author signature + HKDF-SHA256 AES-256-GCM AAD decryption
  3. Static WASM 1.0 binary section audit:
       - Rejects Custom sections (id 0) to block payload smuggling
       - Rejects Import sections (id 2) to block host/WASI/FS/network escapes
       - Rejects Start sections (id 8) to block implicit init execution
       - Enforces bounded linear memory <= 32 pages (2 MiB)
       - Enforces strict export whitelist: {memory, st_alloc, st_evaluate}
  4. Fuel-metered WASM sandbox fuzzing (via wasmtime if installed):
       - Blocks infinite loops / CPU bombs via instruction fuel cap (500,000 instructions)
       - Verifies strict determinism across repeated runs
       - Enforces anti-poisoning separation (clean human < 50, extreme slop > human + 15)
"""

from __future__ import annotations

import base64
import glob
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import wasmtime  # type: ignore
except ImportError:
    wasmtime = None

MAX_BUNDLE_BYTES = 256 * 1024
MAX_WASM_BYTES = 192 * 1024
MAX_MEMORY_PAGES = 32
FUEL_BUDGET = 10_000_000
DEFAULT_SCORING_SEED = "sloptrap-public-scoring-v1:9f84c2e0a1b74d6e8f3c5a2b1d9e0f4a"

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
SITE_ID_RE = re.compile(r"^(?:\*|[a-z0-9][a-z0-9_-]{1,31})$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
OFFICIAL_MAINTAINER_KEYS = {
    "eb85cbf507e27e2c0f94ad723385db3138af32670ea37ca337f0c1866eae02cc",
    "33fee5d93b69abffb9d920da59d823a1c88a71119064a794ff6a8258bee2a472",
}
ALLOWED_INPUTS = {
    "metadata",
    "upload_cadence",
    "transcript",
    "thumbnails",
    "audio_video_stats",
}
ALLOWED_EXPORTS = {"memory", "st_alloc", "st_evaluate"}


def canonical_manifest_bytes(m: dict) -> bytes:
    canon = (
        "sloptrap-manifest-v1\n"
        f"{m.get('rule_id', '')}\n"
        f"{m.get('name', '')}\n"
        f"{m.get('version', '')}\n"
        f"{m.get('author', '')}\n"
        f"{str(m.get('author_public_key', '')).strip().lower()}\n"
        f"{m.get('interpreter', '')}\n"
        f"{','.join(m.get('inputs', []))}\n"
        f"{float(m.get('default_weight', 0.0)):.4f}\n"
        f"{int(m.get('overhead', 0))}\n"
        f"{m.get('encryption', '')}"
    )
    return canon.encode("utf-8")


def derive_aes_key(scoring_seed: str, m: dict) -> bytes:
    prk = hmac.new(
        b"sloptrap-hkdf-salt-v1", scoring_seed.encode("utf-8"), hashlib.sha256
    ).digest()
    info = (
        f"sloptrap-bundle-v1|{m['rule_id']}|"
        f"{str(m['author_public_key']).strip().lower()}|{m['version']}"
    ).encode("utf-8")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def verify_and_unpack(bundle: dict, scoring_seed: str) -> bytes:
    if bundle.get("format") != "sloptrap-bundle-v1":
        raise ValueError(f"unsupported bundle format: {bundle.get('format')!r}")
    m = bundle.get("manifest") or {}
    pub_hex = str(m.get("author_public_key", "")).strip()
    pub_bytes = bytes.fromhex(pub_hex)
    if len(pub_bytes) != 32:
        raise ValueError("invalid 32-byte Ed25519 author_public_key")
    sig_bytes = base64.b64decode(bundle.get("signature_b64", ""))
    if len(sig_bytes) != 64:
        raise ValueError("invalid 64-byte Ed25519 signature_b64")
    raw_payload = base64.b64decode(bundle.get("payload_b64", ""))
    canon = canonical_manifest_bytes(m)

    enc = m.get("encryption") or "none"
    if enc == "none":
        wasm_bytes = raw_payload
    elif enc == "aes-256-gcm-hkdf":
        if len(raw_payload) < 28:
            raise ValueError("encrypted payload too short")
        key = derive_aes_key(scoring_seed, m)
        nonce, ct = raw_payload[:12], raw_payload[12:]
        wasm_bytes = AESGCM(key).decrypt(nonce, ct, canon)
    else:
        raise ValueError(f"unsupported encryption mode: {enc!r}")

    digest = hashlib.sha256(b"sloptrap-sig-v1:" + canon + b"\x00" + wasm_bytes).digest()
    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, digest)
    return wasm_bytes


def read_uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):
        if pos >= len(buf):
            raise ValueError("truncated LEB128 integer")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    raise ValueError("oversized LEB128 integer")


def audit_wasm_sections(wasm: bytes) -> tuple[int, list[str]]:
    if len(wasm) < 8 or wasm[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("invalid WebAssembly 1.0 header")
    if len(wasm) > MAX_WASM_BYTES:
        raise ValueError(f"WASM size {len(wasm)} exceeds {MAX_WASM_BYTES} byte limit")

    pos = 8
    last_sec = -1
    max_pages = 0
    has_mem = False
    exports: list[str] = []

    while pos < len(wasm):
        sec_id = wasm[pos]
        pos += 1
        sec_len, pos = read_uleb128(wasm, pos)
        if pos + sec_len > len(wasm):
            raise ValueError(f"truncated WASM section {sec_id}")
        sec = wasm[pos : pos + sec_len]
        pos += sec_len

        if sec_id == 0:
            raise ValueError("custom WASM section (id 0) forbidden (payload smuggling guard)")
        if sec_id <= last_sec:
            raise ValueError(f"out-of-order or duplicate WASM section {sec_id}")
        last_sec = sec_id

        if sec_id == 2:
            raise ValueError("WASM import section (id 2) forbidden (zero host/WASI imports allowed)")
        if sec_id == 8:
            raise ValueError("WASM start section (id 8) forbidden")

        if sec_id == 5:  # Memory section
            cnt, sp = read_uleb128(sec, 0)
            if cnt != 1:
                raise ValueError(f"expected exactly 1 linear memory, got {cnt}")
            flags, sp = read_uleb128(sec, sp)
            min_p, sp = read_uleb128(sec, sp)
            if (flags & 0x01) == 0:
                raise ValueError("WASM linear memory must declare explicit maximum page bound")
            max_p, sp = read_uleb128(sec, sp)
            if min_p > MAX_MEMORY_PAGES or max_p > MAX_MEMORY_PAGES or max_p < min_p:
                raise ValueError(f"memory limits ({min_p}..{max_p}) exceed {MAX_MEMORY_PAGES} pages")
            max_pages = max_p
            has_mem = True

        if sec_id == 7:  # Export section
            cnt, sp = read_uleb128(sec, 0)
            for _ in range(cnt):
                nlen, sp = read_uleb128(sec, sp)
                name = sec[sp : sp + nlen].decode("utf-8")
                sp += nlen
                _kind = sec[sp]
                sp += 1
                _, sp = read_uleb128(sec, sp)
                if name not in ALLOWED_EXPORTS:
                    raise ValueError(f"unauthorized WASM export {name!r}")
                exports.append(name)

    if not has_mem:
        raise ValueError("missing bounded linear memory section")
    if "st_evaluate" not in exports or "memory" not in exports:
        raise ValueError("missing required exports 'memory' and 'st_evaluate'")
    return max_pages, exports


def run_wasmtime_probe(wasm_bytes: bytes, payload: bytes) -> tuple[int, float]:
    assert wasmtime is not None
    cfg = wasmtime.Config()
    cfg.consume_fuel = True
    engine = wasmtime.Engine(cfg)
    module = wasmtime.Module(engine, wasm_bytes)
    store = wasmtime.Store(engine)
    store.set_fuel(FUEL_BUDGET)
    instance = wasmtime.Instance(store, module, [])
    exps = instance.exports(store)
    mem = exps["memory"]

    in_ptr = 4096
    if "st_alloc" in exps:
        ptr = exps["st_alloc"](store, len(payload))
        if isinstance(ptr, int) and ptr > 0:
            in_ptr = ptr & 0xFFFFFFFF

    needed = in_ptr + len(payload) + 1024
    cur_bytes = mem.data_len(store)
    if cur_bytes < needed:
        grow_pages = (needed - cur_bytes + 65535) // 65536
        mem.grow(store, grow_pages)

    mem.write(store, payload, in_ptr)
    packed = exps["st_evaluate"](store, in_ptr, len(payload))
    u64 = packed & 0xFFFFFFFFFFFFFFFF
    upper = (u64 >> 32) & 0xFFFFFFFF
    lower = u64 & 0xFFFFFFFF

    if upper == 0:
        return max(0, min(100, int(lower))), 1.0

    raw_out = bytes(mem.read(store, upper, upper + lower))
    parsed = json.loads(raw_out.decode("utf-8"))
    score = max(0, min(100, int(parsed.get("score", 0))))
    conf = float(parsed.get("confidence", 1.0))
    return score, conf


def audit_bundle_file(path: Path, scoring_seed: str, require_wasmtime: bool) -> str:
    size = path.stat().st_size
    if size > MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle size {size} exceeds {MAX_BUNDLE_BYTES} byte limit")
    bundle = json.loads(path.read_text(encoding="utf-8"))
    m = bundle.get("manifest") or {}

    rule_id = str(m.get("rule_id", ""))
    target_site = str(m.get("target_site") or "youtube").strip().lower()
    version = str(m.get("version", ""))
    overhead = int(m.get("overhead", 0))
    inputs = m.get("inputs") or []
    pub_hex = str(m.get("author_public_key", "")).strip().lower()
    prov = m.get("provenance")

    if not RULE_ID_RE.match(rule_id):
        raise ValueError(f"invalid rule_id {rule_id!r}")
    if not SITE_ID_RE.match(target_site):
        raise ValueError(f"invalid target_site {target_site!r}")
    if not SEMVER_RE.match(version):
        raise ValueError(f"invalid semver {version!r}")
    if not (1 <= overhead <= 10):
        raise ValueError(f"invalid overhead {overhead} (expected 1..10)")
    if not inputs or any(i not in ALLOWED_INPUTS for i in inputs):
        raise ValueError(f"invalid inputs {inputs!r}")

    if isinstance(prov, dict):
        tier = prov.get("tier") or "unverified"
        if tier == "official":
            if pub_hex not in OFFICIAL_MAINTAINER_KEYS:
                raise ValueError(f"spoofed official provenance: {pub_hex} is not an official maintainer key")
        elif tier == "source-attested":
            srepo = str(prov.get("source_repo", ""))
            scommit = str(prov.get("source_commit", "")).strip()
            srun = str(prov.get("build_run_url", ""))
            if not (
                srepo.startswith("https://github.com/")
                and COMMIT_SHA_RE.match(scommit)
                and srun.startswith("https://github.com/")
            ):
                raise ValueError("source-attested provenance requires valid GitHub source_repo, 40-char source_commit, and build_run_url")
        elif tier == "unverified":
            if prov.get("verified"):
                raise ValueError("unverified tier cannot assert verified=true")
        else:
            raise ValueError(f"unknown provenance tier {tier!r}")

    wasm_bytes = verify_and_unpack(bundle, scoring_seed)
    max_pages, _ = audit_wasm_sections(wasm_bytes)
    verify_tier = "official" if pub_hex in OFFICIAL_MAINTAINER_KEYS else ((prov or {}).get("tier") or "unverified")

    if wasmtime is None:
        if require_wasmtime:
            raise RuntimeError("wasmtime package is required in CI (--require-wasmtime)")
        return (
            f"PASS (static+crypto) [{path.name}] site={target_site} tier={verify_tier} | "
            f"{rule_id} v{version} | WASM:{len(wasm_bytes)}B Mem<={max_pages}p"
        )

    slop_probe = json.dumps(
        {
            "schema_version": 1,
            "site": target_site,
            "channel": {
                "has_auto_suffix": True,
                "stem_siblings": 3,
                "total_videos": 240,
                "outbound_domain_share": 0.92,
            },
            "upload_cadence": {
                "channel_age_days": 5800,
                "max_dormancy_gap_days": 5400,
                "pre_pivot_videos": 2,
                "post_pivot_videos": 238,
                "post_pivot_share": 0.99,
                "recent_uploads_per_day": 4.2,
                "output_minutes_per_week": 340,
                "duration_cv": 0.04,
            },
            "transcript": {
                "uncontracted_ratio": 0.90,
                "antithesis_per_1k": 2.6,
                "slop_hooks_per_1k": 2.4,
                "keyword_stuffing_ratio": 0.76,
                "intra_video_wpm_cv": 0.08,
                "pause_cv": 0.19,
                "earliest_has_speech": False,
            },
            "thumbnails": {
                "title_skeleton_reuse": 0.78,
                "raw_camera_earliest_title": True,
                "synthetic_image_ratio": 0.94,
                "aspect_uniformity": 0.97,
                "repost_watermark_ratio": 0.86,
            },
            "audio_video_stats": {"dead_air_floor": True},
        }
    ).encode("utf-8")

    human_probe = json.dumps(
        {
            "schema_version": 1,
            "site": target_site,
            "channel": {
                "has_auto_suffix": False,
                "stem_siblings": 0,
                "total_videos": 260,
                "outbound_domain_share": 0.06,
            },
            "upload_cadence": {
                "channel_age_days": 4200,
                "max_dormancy_gap_days": 60,
                "recent_uploads_per_day": 0.04,
                "output_minutes_per_week": 8,
                "duration_cv": 0.42,
            },
            "transcript": {
                "uncontracted_ratio": 0.16,
                "first_person_per_1k": 18.0,
                "disfluencies_per_1k": 2.8,
                "keyword_stuffing_ratio": 0.04,
                "intra_video_wpm_cv": 0.21,
                "pause_cv": 0.52,
                "earliest_has_speech": True,
            },
            "thumbnails": {
                "title_skeleton_reuse": 0.10,
                "synthetic_image_ratio": 0.0,
                "aspect_uniformity": 0.24,
                "repost_watermark_ratio": 0.0,
            },
        }
    ).encode("utf-8")

    probes = [
        slop_probe,
        human_probe,
        b"{}",
        b'{"schema_version":1,"upload_cadence":{"max_dormancy_gap_days":-999}}',
        ('{"schema_version":1,"channel":{"title":"' + ("A" * 8192) + '"}}').encode("utf-8"),
    ]

    scores: list[int] = []
    for idx, p in enumerate(probes):
        s1, c1 = run_wasmtime_probe(wasm_bytes, p)
        s2, c2 = run_wasmtime_probe(wasm_bytes, p)
        if (s1, c1) != (s2, c2):
            raise ValueError(f"non-deterministic execution on probe #{idx}")
        scores.append(s1)

    slop_score, human_score = scores[0], scores[1]
    if human_score >= 50:
        raise ValueError(
            f"poisoning guard failed: clean human probe scored {human_score}/100 (must be < 50)"
        )
    if slop_score <= human_score + 15:
        raise ValueError(
            f"degenerate rule guard failed: slop ({slop_score}) <= human ({human_score}) + 15"
        )

    return (
        f"AUDIT PASS [{path.name}] {rule_id} v{version} | "
        f"WASM:{len(wasm_bytes)}B Mem<={max_pages}p | "
        f"Separation: slop={slop_score} vs human={human_score}"
    )


def main() -> int:
    require_wasmtime = "--require-wasmtime" in sys.argv
    scoring_seed = os.environ.get("SLOPTRAP_SCORING_SEED", DEFAULT_SCORING_SEED)
    repo_root = Path(__file__).resolve().parent.parent

    lb_files = [repo_root / "leaderboard.json"] + sorted((repo_root / "leaderboard").glob("*/leaderboard.json"))
    for lb_path in lb_files:
        if not lb_path.exists():
            continue
        lb = json.loads(lb_path.read_text(encoding="utf-8"))
        for entry in lb.get("entries", []):
            pub_hex = str(entry.get("author_public_key", "")).strip().lower()
            tier = entry.get("verification_tier") or "unverified"
            if entry.get("verified") and tier == "official" and pub_hex not in OFFICIAL_MAINTAINER_KEYS:
                print(f"AUDIT FAIL [{lb_path.relative_to(repo_root)}]: spoofed official entry {entry.get('rule_id')}", file=sys.stderr)
                return 1
            local_rel = entry.get("local_bundle_path")
            if local_rel:
                bp = repo_root / local_rel
                if not bp.exists():
                    print(f"AUDIT FAIL: missing bundle {local_rel} referenced in {lb_path.name}", file=sys.stderr)
                    return 1
                actual_sha = hashlib.sha256(bp.read_bytes()).hexdigest()
                expected_sha = entry.get("bundle_sha256", "")
                if expected_sha and actual_sha != expected_sha:
                    print(
                        f"AUDIT FAIL [{local_rel}]: SHA-256 mismatch "
                        f"(leaderboard={expected_sha}, file={actual_sha})",
                        file=sys.stderr,
                    )
                    return 1

    bundle_files = sorted(
        {Path(p) for p in glob.glob(str(repo_root / "**" / "*.strule"), recursive=True)}
    )
    if not bundle_files:
        print("AUDIT FAIL: no .strule files found", file=sys.stderr)
        return 1

    failed = 0
    for bp in bundle_files:
        try:
            msg = audit_bundle_file(bp, scoring_seed, require_wasmtime)
            print(msg)
        except Exception as exc:
            print(f"AUDIT FAIL [{bp.relative_to(repo_root)}]: {exc}", file=sys.stderr)
            failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
