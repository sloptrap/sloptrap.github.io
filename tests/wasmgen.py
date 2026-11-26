"""Tiny wasm assembler and bundle helpers for the audit tests."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import strule_v2  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TEST_SEED = "01" * 32          # vectors' test key (tier unverified unless patched)
OFFICIAL_TEST_SEED = "02" * 32  # patched into OFFICIAL_KEYS by tests
COMMUNITY_TEST_SEED = "03" * 32  # patched into COMMUNITY_KEYS by tests


def pubkey(seed_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def uleb(v: int) -> list[int]:
    out = []
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return out


def sleb(v: int) -> list[int]:
    out = []
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not b & 0x40) or (v == -1 and b & 0x40):
            out.append(b)
            return out
        out.append(b | 0x80)


def vec(items: list[list[int]]) -> list[int]:
    return uleb(len(items)) + [x for it in items for x in it]


def name(s: str) -> list[int]:
    b = s.encode()
    return uleb(len(b)) + list(b)


def sec(sid: int, body: list[int]) -> list[int]:
    return [sid] + uleb(len(body)) + body


EVAL_T = [0x60, 2, 0x7F, 0x7F, 1, 0x7E]   # (i32,i32)->i64
ALLOC_T = [0x60, 1, 0x7F, 1, 0x7F]       # (i32)->i32


def module(body=(0x42, 0x2A), *, locals_=(), mem=(1, 1, 2), types=None, funcs=None, extra_bodies=(),
           exports=None, globals_=None, data=None, sections_before=(), sections_after_types=(),
           sections_tail=(), datacount=None, alloc_body=None) -> bytes:
    """A module with st_evaluate = `body`. mem = (flags, min[, max]) or None."""
    out = [0x00, 0x61, 0x73, 0x6D, 1, 0, 0, 0]
    for s in sections_before:
        out += s
    ty = types if types is not None else [EVAL_T, ALLOC_T]
    out += sec(1, vec(ty))
    for s in sections_after_types:
        out += s
    fn = funcs if funcs is not None else ([[0]] + ([[1]] if alloc_body is not None else []) + [[0] for _ in extra_bodies])
    out += sec(3, vec(fn))
    if mem is not None:
        flags = mem[0]
        m = [flags] + uleb(mem[1]) + (uleb(mem[2]) if flags & 1 else [])
        out += sec(5, vec([m]))
    if globals_ is not None:
        out += sec(6, globals_)
    exps = exports if exports is not None else (
        [name("memory") + [2, 0], name("st_evaluate") + [0, 0]] + ([name("st_alloc") + [0, 1]] if alloc_body is not None else []))
    out += sec(7, vec(exps))
    if datacount is not None:
        out += sec(12, uleb(datacount))

    def fb(code, loc):
        b = vec([list(x) for x in loc]) + list(code) + [0x0B]
        return uleb(len(b)) + b
    bodies = [fb(body, locals_)]
    if alloc_body is not None:
        bodies.append(fb(alloc_body, ()))
    bodies += [fb(b, ()) for b in extra_bodies]
    out += sec(10, uleb(len(bodies)) + [x for b in bodies for x in b])
    if data is not None:
        out += sec(11, data)
    for s in sections_tail:
        out += s
    return bytes(out)


def ret_i64(v: int) -> list[int]:
    return [0x42] + sleb(v if v < (1 << 63) else v - (1 << 64))


def json_output_module(text: str, off: int = 256) -> bytes:
    b = text.encode()
    seg = vec([[0x00, 0x41] + sleb(off) + [0x0B] + uleb(len(b)) + list(b)])
    return module(body=ret_i64((off << 32) | len(b)), data=seg)


def manifest(rule_id: str, pub: str, **over) -> dict:
    m = {"rule_id": rule_id, "name": f"Test {rule_id}", "version": "1.0.0", "author": "@tester",
         "author_public_key": pub, "target_site": "youtube", "description": "test rule", "repo_url": "",
         "interpreter": "wasm-v1", "inputs": ["metadata"], "weight_milli": 1000, "overhead": 5,
         "provenance": {"source_repo": "", "source_commit": "", "build_run_url": "", "submission_id": ""}}
    m.update(over)
    return m


def bundle(rule_id: str, wasm: bytes, seed: str = TEST_SEED, **over) -> dict:
    return strule_v2.sign_bundle(manifest(rule_id, pubkey(seed), **over), wasm, seed)


def bundle_bytes(rule_id: str, wasm: bytes, seed: str = TEST_SEED, **over) -> bytes:
    import json
    return (json.dumps(bundle(rule_id, wasm, seed, **over), indent=2) + "\n").encode()
