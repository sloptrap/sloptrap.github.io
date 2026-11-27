"""SlopTrap .strule v2 reference implementation (manifest canon, signing, verification,
canonical fingerprint). See SPEC-v2.md. Pure stdlib + `cryptography`."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from decimal import Decimal

FORMAT = "sloptrap-bundle-v2"
OFFICIAL_KEYS = frozenset({"0540a396ece8ab0f9670a25e03b02e345450a1373b86a7d400dcad79ceec5cc1"})
COMMUNITY_KEYS = frozenset({"34c3c2ee0d51ae18fbf669dc441a51faa06bbfcbf5efa6adf73702d644c5c69e"})
LIST_SIGNING_PUBLIC_KEY = "303607bb2fc5bdebbb50021d3480d59da127d5c40122785ff4b6e228be54b3e1"
LIST_SIGNING_KEYS = frozenset({LIST_SIGNING_PUBLIC_KEY})
COMMUNITY_PREFIX = "community-"
MAX_BUNDLE_BYTES = 512 * 1024
MAX_WASM_BYTES = 256 * 1024
INPUTS = ("metadata", "upload_cadence", "transcript", "thumbnails", "audio_video_stats")
SITES = ("youtube", "tiktok", "pinterest", "*")

_RE = {
    "rule_id": re.compile(r"[a-z0-9][a-z0-9_-]{1,63}"),
    "version": re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}"),
    "author": re.compile(r"@?[A-Za-z0-9_.-]{1,63}"),
    "key": re.compile(r"[0-9a-f]{64}"),
    "repo": re.compile(r"https://github\.com/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?"),
    "commit": re.compile(r"[0-9a-f]{40}"),
    "run": re.compile(r"https://github\.com/[A-Za-z0-9_./-]{1,200}"),
    "uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
}
MANIFEST_KEYS = frozenset({"rule_id", "name", "version", "author", "author_public_key", "target_site",
                           "description", "repo_url", "interpreter", "inputs", "weight_milli",
                           "overhead", "provenance"})
PROVENANCE_KEYS = frozenset({"source_repo", "source_commit", "build_run_url", "submission_id"})


class BundleError(ValueError):
    pass


def _clean_str(s, field, lo, hi):
    if not isinstance(s, str):
        raise BundleError(f"{field}: must be a string")
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o == 0x7F or o in (0x2028, 0x2029) or 0xD800 <= o <= 0xDFFF:
            raise BundleError(f"{field}: forbidden character U+{o:04X}")
    if not (lo <= len(s) <= hi):
        raise BundleError(f"{field}: length must be {lo}..{hi} code points")
    return s


def _int(v, field, lo, hi):
    if type(v) is not int:  # rejects bool and float
        raise BundleError(f"{field}: must be an integer")
    if not (lo <= v <= hi):
        raise BundleError(f"{field}: must be {lo}..{hi}")
    return v


def _match(v, field, rx, allow_empty=False):
    _clean_str(v, field, 0, 400)
    if allow_empty and v == "":
        return v
    if not rx.fullmatch(v):
        raise BundleError(f"{field}: invalid format")
    return v


def validate_manifest(m) -> dict:
    if not isinstance(m, dict) or set(m.keys()) != MANIFEST_KEYS:
        raise BundleError(f"manifest: keys must be exactly {sorted(MANIFEST_KEYS)}")
    _match(m["rule_id"], "rule_id", _RE["rule_id"])
    _clean_str(m["name"], "name", 1, 80)
    _match(m["version"], "version", _RE["version"])
    _match(m["author"], "author", _RE["author"])
    _match(m["author_public_key"], "author_public_key", _RE["key"])
    if m["target_site"] not in SITES:
        raise BundleError("target_site: invalid")
    _clean_str(m["description"], "description", 0, 500)
    _match(m["repo_url"], "repo_url", _RE["repo"], allow_empty=True)
    if m["interpreter"] != "wasm-v1":
        raise BundleError("interpreter: must be wasm-v1")
    inp = m["inputs"]
    if not isinstance(inp, list) or len(inp) > 5 or len(set(inp)) != len(inp) or any(i not in INPUTS for i in inp):
        raise BundleError("inputs: invalid")
    _int(m["weight_milli"], "weight_milli", 1, 10000)
    _int(m["overhead"], "overhead", 1, 100)
    p = m["provenance"]
    if not isinstance(p, dict) or set(p.keys()) != PROVENANCE_KEYS:
        raise BundleError("provenance: keys must be exactly source_repo, source_commit, build_run_url, submission_id")
    _match(p["source_repo"], "provenance.source_repo", _RE["repo"], allow_empty=True)
    _match(p["source_commit"], "provenance.source_commit", _RE["commit"], allow_empty=True)
    _match(p["build_run_url"], "provenance.build_run_url", _RE["run"], allow_empty=True)
    _match(p["submission_id"], "provenance.submission_id", _RE["uuid"], allow_empty=True)
    return m


def _c(v) -> str:
    if isinstance(v, dict):
        return "{" + ",".join(_c(k) + ":" + _c(v[k]) for k in sorted(v.keys())) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_c(x) for x in v) + "]"
    if isinstance(v, bool):
        raise BundleError("canon: booleans not allowed in manifest")
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise BundleError(f"canon: unsupported type {type(v).__name__}")


def canonical_manifest_bytes(m) -> bytes:
    validate_manifest(m)
    return ("sloptrap-manifest-v2\n" + _c(m)).encode("utf-8")


def signing_digest(m, wasm: bytes) -> bytes:
    return hashlib.sha256(b"sloptrap-sig-v2\n" + canonical_manifest_bytes(m) + b"\n" + hashlib.sha256(wasm).digest()).digest()


def tier_for_key(pub_hex: str) -> str:
    if pub_hex in OFFICIAL_KEYS:
        return "official"
    if pub_hex in COMMUNITY_KEYS:
        return "community"
    return "unverified"


def sign_bundle(manifest: dict, wasm: bytes, seed_hex: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser

    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise BundleError("seed must be 32 bytes hex")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    if manifest.get("author_public_key") != pub:
        raise BundleError("manifest.author_public_key does not match signing seed")
    if len(wasm) > MAX_WASM_BYTES or wasm[:4] != b"\0asm":
        raise BundleError("payload must be a wasm module <= 256 KiB")
    sig = sk.sign(signing_digest(manifest, wasm))
    return {"format": FORMAT, "manifest": manifest,
            "payload_b64": base64.b64encode(wasm).decode(), "signature_b64": base64.b64encode(sig).decode()}


def _b64(s, field):
    if not isinstance(s, str):
        raise BundleError(f"{field}: must be base64 string")
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:  # noqa: BLE001
        raise BundleError(f"{field}: invalid base64") from e


def verify_bundle(bundle) -> tuple[dict, bytes, str]:
    """Returns (manifest, wasm, tier). Raises BundleError on any problem (fail closed)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(bundle, dict) or set(bundle.keys()) != {"format", "manifest", "payload_b64", "signature_b64"}:
        raise BundleError("bundle: keys must be exactly format, manifest, payload_b64, signature_b64")
    if bundle["format"] != FORMAT:
        raise BundleError(f"bundle: unsupported format {bundle['format']!r}")
    m = validate_manifest(bundle["manifest"])
    wasm = _b64(bundle["payload_b64"], "payload_b64")
    sig = _b64(bundle["signature_b64"], "signature_b64")
    pub = bytes.fromhex(m["author_public_key"])
    if len(pub) != 32 or len(sig) != 64:
        raise BundleError("bundle: bad key or signature length")
    if len(wasm) > MAX_WASM_BYTES or wasm[:4] != b"\0asm":
        raise BundleError("bundle: payload is not a wasm module <= 256 KiB")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, signing_digest(m, wasm))
    except InvalidSignature as e:
        raise BundleError(f"bundle: invalid signature for {m['rule_id']}") from e
    except Exception as e:  # noqa: BLE001
        raise BundleError(f"bundle: signature verification failed: {e}") from e
    tier = tier_for_key(m["author_public_key"])
    is_comm_id = m["rule_id"].startswith(COMMUNITY_PREFIX)
    if (tier == "community") != is_comm_id:
        raise BundleError("bundle: community rule ids must start with 'community-' and only community bundles may use it")
    return m, wasm, tier


# ---------------------------------------------------------------- signed list manifests (M4, V3-M2, V3-L1)
LIST_SITES = frozenset({"youtube", "tiktok", "pinterest"})
_ISO_Z_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
LIST_YT_CHANNEL_ID_RE = re.compile(r"^UC[0-9A-Za-z_-]{22}$")
LIST_HANDLE_RE = re.compile(r"^@[a-z0-9._-]{2,64}$")
DEFAULT_MAX_LIST_MANIFEST_AGE_SECONDS = 14 * 86400


def normalize_list_account_key(site: str, raw) -> str | None:
    """Canonical account-key validator shared with the Worker (V3-M2)."""
    if site not in LIST_SITES or not isinstance(raw, str):
        return None
    s = raw.strip()
    if site == "youtube" and LIST_YT_CHANNEL_ID_RE.fullmatch(s):
        return s
    h = s.lower()
    return h if LIST_HANDLE_RE.fullmatch(h) else None


def parse_list_generated_at(generated_at: str) -> int:
    from datetime import datetime, timezone

    if not isinstance(generated_at, str) or not _ISO_Z_RE.fullmatch(generated_at):
        raise BundleError("list manifest: invalid generated_at")
    try:
        dt = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise BundleError(f"list manifest: invalid generated_at {generated_at!r}") from e
    return int(dt.timestamp())


def canonical_list_manifest_bytes(generated_at: str, lists_obj: dict) -> bytes:
    parse_list_generated_at(generated_at)
    if not isinstance(lists_obj, dict):
        raise BundleError("list manifest: lists must be an object")
    lines = []
    for k in sorted(lists_obj.keys()):
        it = lists_obj[k]
        if not isinstance(it, dict):
            raise BundleError(f"list manifest: {k!r} must be an object")
        site = it.get("site")
        rid = it.get("rule_id")
        path = it.get("path")
        cnt = it.get("count")
        sha = it.get("sha256")
        if site not in LIST_SITES:
            raise BundleError(f"list manifest: invalid site {site!r}")
        _match(rid, "list.rule_id", _RE["rule_id"])
        if k != f"{site}/{rid}" or path != f"lists/{site}/{rid}.txt":
            raise BundleError(f"list manifest: mismatched key or path for {k!r}")
        _int(cnt, "list.count", 0, 1_000_000_000)
        _match(sha, "list.sha256", _RE["key"])
        lines.append(f"{site}\t{rid}\t{path}\t{cnt}\t{sha}")
    return ("sloptrap-list-manifest-v2\n" + generated_at + "\n" + "\n".join(lines)).encode("utf-8")


def sign_list_manifest(manifest_doc: dict, seed_hex: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser

    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise BundleError("list seed must be 32 bytes hex")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    if pub not in LIST_SIGNING_KEYS:
        raise BundleError("list signing seed does not match LIST_SIGNING_KEYS")
    gen = manifest_doc.get("generated_at")
    lists_in = manifest_doc.get("lists")
    msg = canonical_list_manifest_bytes(gen, lists_in)
    out_lists = {}
    for k in sorted(lists_in.keys()):
        it = dict(lists_in[k])
        item_msg = (
            f"sloptrap-list-item-v2\n{it['site']}\t{it['rule_id']}\t{it['path']}\t{it['count']}\t{it['sha256']}\t{gen}"
        ).encode("utf-8")
        it["signature_b64"] = base64.b64encode(sk.sign(item_msg)).decode("ascii")
        out_lists[k] = it
    return {
        "schema_version": 2,
        "generated_at": gen,
        "public_key": pub,
        "signature_b64": base64.b64encode(sk.sign(msg)).decode("ascii"),
        "lists": out_lists,
    }


def verify_list_manifest(
    manifest_doc: dict,
    *,
    now_sec: int | None = None,
    max_age_seconds: int = DEFAULT_MAX_LIST_MANIFEST_AGE_SECONDS,
    min_generated_at: int = 0,
) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(manifest_doc, dict) or manifest_doc.get("schema_version") != 2:
        raise BundleError("list manifest: unsupported schema_version")
    pub_hex = manifest_doc.get("public_key")
    if not isinstance(pub_hex, str) or pub_hex not in LIST_SIGNING_KEYS:
        raise BundleError("list manifest: untrusted or missing public_key")
    sig = _b64(manifest_doc.get("signature_b64"), "list manifest signature_b64")
    if len(sig) != 64:
        raise BundleError("list manifest: signature must be 64 bytes")
    gen = manifest_doc.get("generated_at")
    gen_ts = parse_list_generated_at(gen)
    lists_obj = manifest_doc.get("lists")
    msg = canonical_list_manifest_bytes(gen, lists_obj)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(sig, msg)
    except InvalidSignature as e:
        raise BundleError("list manifest: invalid Ed25519 signature") from e
    if min_generated_at > 0 and gen_ts < min_generated_at:
        raise BundleError(f"list manifest: rollback rejected ({gen_ts} < {min_generated_at})")
    if now_sec is not None:
        if max_age_seconds > 0 and (now_sec - gen_ts) > max_age_seconds:
            raise BundleError(f"list manifest: stale manifest rejected (age {now_sec - gen_ts}s > {max_age_seconds}s)")
        if gen_ts > now_sec + 3600:
            raise BundleError("list manifest: future-dated manifest rejected")
    for k, it in lists_obj.items():
        if "signature_b64" in it:
            isig = _b64(it.get("signature_b64"), f"{k}.signature_b64")
            if len(isig) != 64:
                raise BundleError(f"list manifest: {k} signature must be 64 bytes")
            imsg = (
                f"sloptrap-list-item-v2\n{it['site']}\t{it['rule_id']}\t{it['path']}\t{it['count']}\t{it['sha256']}\t{gen}"
            ).encode("utf-8")
            try:
                pub.verify(isig, imsg)
            except InvalidSignature as e:
                raise BundleError(f"list manifest: invalid item signature for {k}") from e
    return manifest_doc


# ---------------------------------------------------------------- canonical fingerprint
_S, _I, _F, _B = "s", "i", "f", "b"
FP_SCHEMA = [
    ("schema_version", _I), ("site", _S),
    ("channel", [("channel_id", _S), ("handle", _S), ("title", _S), ("description", _S),
                 ("subscriber_count", _I), ("total_videos", _I), ("has_auto_suffix", _B),
                 ("stem_siblings", _I), ("outbound_domain_share", _F)]),
    ("upload_cadence", [("channel_age_days", _F), ("max_dormancy_gap_days", _F), ("pre_pivot_videos", _I),
                        ("post_pivot_videos", _I), ("post_pivot_share", _F), ("recent_uploads_per_day", _F),
                        ("output_minutes_per_week", _F), ("avg_duration_sec", _F), ("duration_cv", _F),
                        ("schedule_hour_stddev", _F)]),
    ("transcript", [("videos_sampled", _I), ("total_words", _I), ("uncontracted_ratio", _F),
                    ("first_person_per_1k", _F), ("disfluencies_per_1k", _F), ("antithesis_per_1k", _F),
                    ("slop_hooks_per_1k", _F), ("llm_lexicon_per_1k", _F), ("keyword_stuffing_ratio", _F),
                    ("mean_wpm", _F), ("cross_video_wpm_stddev", _F), ("intra_video_wpm_cv", _F),
                    ("pause_cv", _F), ("earliest_has_speech", _B)]),
    ("thumbnails", [("title_skeleton_reuse", _F), ("raw_camera_earliest_title", _B),
                    ("synthetic_image_ratio", _F), ("aspect_uniformity", _F), ("repost_watermark_ratio", _F)]),
    ("audio_video_stats", [("earliest_vertical", _B), ("earliest_max_dim", _I), ("recent_widescreen_hd_ratio", _F),
                           ("altered_content_flag", _B), ("dead_air_floor", _B), ("loudness_range_lu", _F),
                           ("silence_cv", _F)]),
    ("sample_text", _S),
]
STR_CAPS = {"handle": 100, "channel_id": 100, "title": 200, "description": 2000, "site": 32, "sample_text": 4000}
TRUE_DEFAULTS = {"earliest_has_speech"}
MAX_SAFE = 9007199254740991


def norm_str(v, key) -> str:
    if v is None:
        v = ""
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    v = str(v)
    out = []
    for ch in v:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            out.append("�")
        elif o < 0x20 or o == 0x7F or o in (0x2028, 0x2029):
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)[: STR_CAPS.get(key, 4000)]


def _num(v) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def norm_int(v) -> int:
    f = _num(v)
    i = int(f)  # trunc toward zero
    return max(0, min(MAX_SAFE, i))


def norm_float(v) -> float:
    f = _num(v)
    f = math.floor(f * 1e6 + 0.5) / 1e6
    f = max(-1e12, min(1e12, f))
    return 0.0 if f == 0 else f


def fmt_float(f: float) -> str:
    if f == int(f):
        return str(int(f))
    s = format(Decimal(repr(f)), "f")
    return s


def _esc(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def canonical_fingerprint_bytes(fp: dict, site: str = "youtube") -> bytes:
    def emit(schema, src, top=False):
        parts = []
        for key, t in schema:
            v = src.get(key) if isinstance(src, dict) else None
            if isinstance(t, list):
                parts.append(_esc(key) + ":" + emit(t, v if isinstance(v, dict) else {}))
                continue
            if top and key == "schema_version":
                enc = "1"
            elif t == _S:
                if top and key == "site" and (v is None or v == ""):
                    v = site
                enc = _esc(norm_str(v, key))
            elif t == _I:
                enc = str(norm_int(v))
            elif t == _F:
                enc = fmt_float(norm_float(v))
            else:
                enc = "true" if (bool(v) if v is not None else key in TRUE_DEFAULTS) else "false"
            parts.append(_esc(key) + ":" + enc)
        return "{" + ",".join(parts) + "}"

    return emit(FP_SCHEMA, fp or {}, top=True).encode("utf-8")


if __name__ == "__main__":  # tiny CLI: verify bundles
    import sys

    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            if len(raw) > MAX_BUNDLE_BYTES:
                raise BundleError("bundle too large")
            man, _w, tr = verify_bundle(json.loads(raw))
            print(f"OK   {path}: {man['rule_id']} v{man['version']} tier={tr}")
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {path}: {exc}")
            sys.exit(1)
