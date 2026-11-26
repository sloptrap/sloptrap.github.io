#!/usr/bin/env python3
"""SlopTrap `.strule` v2 bundle auditor (fail closed).

Every check here follows SPEC-v2 (`sloptrap-bundle-v2`); `strule_v2.py` is the shared
reference implementation and is used unchanged for parsing, canonical bytes, signature
verification and the canonical fingerprint.

For every bundle:

1. Size limits: bundle file <= 512 KiB, wasm payload <= 256 KiB.
2. Strict JSON (no duplicate keys, no NaN/Infinity), then `strule_v2.verify_bundle`:
   exact top-level keys, exact manifest schema, strict Ed25519 over the v2 digest.
   Any exception is a rejection. v1 bundles are rejected (v1 support is removed).
3. Trust tier computed from the signing key only (official / community / unverified),
   community `community-` prefix rule, rule_id == file name, and the tier the location
   requires (bundles/*.strule: official; bundles/community/*.strule: community).
4. SPEC section 3 static audit: full MVP decoder of every section and every function body,
   forbidden sections and opcodes, exactly one bounded memory (max <= 32 pages), counts,
   data segment bounds and the exact export set/signatures.
5. SPEC section 4 execution check with wasmtime (fuel 10,000,000 per call, 32-page store
   limit, a fresh instance per evaluation): every audit input must produce a valid output
   under the v2 output ABI, and repeated evaluations must agree.

The old fixed "slop"/"human" probe scores are printed as an informational smoke test only.
They are public, so a rule can recognise them (CRIT-02); they never decide pass or fail.
Behavioural acceptance of community rules happens in the private pipeline against a hidden
holdout corpus.

Exit status: 0 if every bundle passed, 1 if any failed, 2 on usage errors.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # run with `python3 -I`: no implicit path
import strule_v2  # noqa: E402
from strule_v2 import BundleError  # noqa: E402

try:  # wasmtime is pinned in .github/requirements-ci.txt
    import wasmtime  # type: ignore
except ImportError:  # pragma: no cover - depends on the environment
    wasmtime = None

REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_BUNDLE_BYTES = strule_v2.MAX_BUNDLE_BYTES
MAX_WASM_BYTES = strule_v2.MAX_WASM_BYTES
MAX_PAGES = 32
PAGE = 65536
MAX_FUNCS = 1024
MAX_GLOBALS = 64
MAX_DATA_SEGMENTS = 64
MAX_TYPES = 1024
MAX_LOCALS_PER_FUNC = 50_000
FUEL = 10_000_000
DEFAULT_INPUT_PTR = 16384
MAX_OUTPUT_LEN = 4096
MAX_REASON_CODEPOINTS = 300

I32, I64, F32, F64 = 0x7F, 0x7E, 0x7D, 0x7C
VALTYPES = {I32, I64, F32, F64}
# Binary-format section order. Datacount (12) sits between element (9) and code (10).
SECTION_ORDER = {1: 1, 3: 3, 5: 5, 6: 6, 7: 7, 12: 9.5, 10: 10, 11: 11}
FORBIDDEN_SECTIONS = {2: "import", 4: "table", 8: "start", 9: "element"}

# Opcode table. Values give the immediate layout.
_OPS: dict[int, str] = {
    0x00: "", 0x01: "", 0x02: "bt", 0x03: "bt", 0x04: "bt", 0x05: "else", 0x0B: "end",
    0x0C: "label", 0x0D: "label", 0x0E: "br_table", 0x0F: "", 0x10: "func",
    0x1A: "", 0x1B: "",
    0x20: "local", 0x21: "local", 0x22: "local", 0x23: "global", 0x24: "global",
    0x3F: "zero", 0x40: "zero",
    0x41: "i32", 0x42: "i64", 0x43: "f32", 0x44: "f64",
}
for _op in range(0x28, 0x3F):  # loads and stores
    _OPS[_op] = "memarg"
for _op in range(0x45, 0xBC):  # MVP numeric ops (0xBC-0xBF reinterpret are excluded)
    _OPS[_op] = ""
FORBIDDEN_OPCODES = {
    0x06: "try", 0x07: "catch", 0x08: "throw", 0x09: "rethrow", 0x18: "delegate", 0x19: "catch_all",
    0x11: "call_indirect", 0x12: "return_call", 0x13: "return_call_indirect", 0x1C: "typed select",
    0x25: "table.get", 0x26: "table.set",
    0xBC: "i32.reinterpret_f32", 0xBD: "i64.reinterpret_f64", 0xBE: "f32.reinterpret_i32",
    0xBF: "f64.reinterpret_i64",
    0xD0: "ref.null", 0xD1: "ref.is_null", 0xD2: "ref.func", 0xD3: "ref.as_non_null",
    0xD4: "br_on_null", 0xD5: "ref.eq", 0xD6: "br_on_non_null",
    0xFD: "SIMD prefix", 0xFE: "atomics prefix",
}
FC_ALLOWED = {0, 1, 2, 3, 4, 5, 6, 7, 10, 11}


class AuditError(ValueError):
    """The bundle or module failed the audit."""


# ------------------------------------------------------------------------- wasm reader
class _Reader:
    def __init__(self, buf: bytes, pos: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end

    def eof(self) -> bool:
        return self.pos >= self.end

    def byte(self) -> int:
        if self.pos >= self.end:
            raise AuditError("unexpected end of module")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise AuditError("unexpected end of module")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        result = shift = 0
        for i in range(5):
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                if i == 4 and b & 0x70:
                    raise AuditError("u32 LEB128 overflow")
                return result
            shift += 7
        raise AuditError("u32 LEB128 too long")

    def sleb(self, bits: int) -> int:
        result = shift = 0
        max_bytes = (bits + 6) // 7
        for _ in range(max_bytes):
            b = self.byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if b & 0x40:
                    result -= 1 << shift
                if not -(1 << (bits - 1)) <= result < (1 << (bits - 1)):
                    raise AuditError(f"s{bits} LEB128 overflow")
                return result
        raise AuditError(f"s{bits} LEB128 too long")

    def name(self) -> str:
        raw = self.bytes(self.u32())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise AuditError("invalid UTF-8 name") from e


@dataclass
class WasmInfo:
    size: int
    types: list[tuple[tuple[int, ...], tuple[int, ...]]] = field(default_factory=list)
    func_types: list[int] = field(default_factory=list)
    mem_min: int = 0
    mem_max: int = 0
    globals: list[tuple[int, bool]] = field(default_factory=list)
    exports: dict[str, tuple[int, int]] = field(default_factory=dict)
    data_segments: int = 0
    has_st_alloc: bool = False


def _valtype(r: _Reader) -> int:
    t = r.byte()
    if t not in VALTYPES:
        raise AuditError(f"unsupported value type 0x{t:02x}")
    return t


def _const_expr(r: _Reader, want: int | None) -> int | None:
    op = r.byte()
    if op == 0x41:
        val, typ = r.sleb(32), I32
    elif op == 0x42:
        val, typ = r.sleb(64), I64
    elif op == 0x43:
        r.bytes(4)
        val, typ = None, F32
    elif op == 0x44:
        r.bytes(8)
        val, typ = None, F64
    else:
        raise AuditError(f"constant expression may only be a single *.const (got 0x{op:02x})")
    if r.byte() != 0x0B:
        raise AuditError("constant expression must be one instruction followed by end")
    if want is not None and typ != want:
        raise AuditError("constant expression has the wrong type")
    return val


def _decode_body(r: _Reader, info: WasmInfo, n_params: int, fidx: int) -> None:
    n_locals = n_params
    for _ in range(r.u32()):
        n_locals += r.u32()
        if n_locals > MAX_LOCALS_PER_FUNC:
            raise AuditError(f"func {fidx}: too many locals")
        _valtype(r)
    depth = 0  # open blocks, not counting the function body
    kinds: list[int] = []
    while True:
        if r.eof():
            raise AuditError(f"func {fidx}: body ends without 'end'")
        op = r.byte()
        if op in FORBIDDEN_OPCODES:
            raise AuditError(f"func {fidx}: forbidden opcode 0x{op:02x} ({FORBIDDEN_OPCODES[op]})")
        if op == 0xFC:
            sub = r.u32()
            if sub not in FC_ALLOWED:
                raise AuditError(f"func {fidx}: forbidden opcode 0xfc {sub}")
            if sub == 10:
                if r.byte() != 0 or r.byte() != 0:
                    raise AuditError(f"func {fidx}: memory.copy must use memory 0")
            elif sub == 11:
                if r.byte() != 0:
                    raise AuditError(f"func {fidx}: memory.fill must use memory 0")
            continue
        imm = _OPS.get(op)
        if imm is None:
            raise AuditError(f"func {fidx}: unknown opcode 0x{op:02x}")
        if imm == "bt":
            bt = r.byte()
            if bt != 0x40 and bt not in VALTYPES:
                raise AuditError(f"func {fidx}: block type 0x{bt:02x} not allowed (multi-value/type-index)")
            depth += 1
            kinds.append(op)
        elif imm == "else":
            if not kinds or kinds[-1] != 0x04:
                raise AuditError(f"func {fidx}: 'else' outside 'if'")
            kinds[-1] = 0x05
        elif imm == "end":
            if depth == 0:
                if r.pos != r.end:
                    raise AuditError(f"func {fidx}: trailing bytes after final 'end'")
                return
            depth -= 1
            kinds.pop()
        elif imm == "label":
            if r.u32() > depth:
                raise AuditError(f"func {fidx}: branch depth out of range")
        elif imm == "br_table":
            n = r.u32()
            if n > 65536:
                raise AuditError(f"func {fidx}: br_table too large")
            for _ in range(n + 1):
                if r.u32() > depth:
                    raise AuditError(f"func {fidx}: branch depth out of range")
        elif imm == "func":
            if r.u32() >= len(info.func_types):
                raise AuditError(f"func {fidx}: call to unknown function")
        elif imm == "local":
            if r.u32() >= n_locals:
                raise AuditError(f"func {fidx}: local index out of range")
        elif imm == "global":
            gi = r.u32()
            if gi >= len(info.globals):
                raise AuditError(f"func {fidx}: global index out of range")
            if op == 0x24 and not info.globals[gi][1]:
                raise AuditError(f"func {fidx}: global.set on immutable global")
        elif imm == "zero":
            if r.byte() != 0:
                raise AuditError(f"func {fidx}: memory index must be 0")
        elif imm == "memarg":
            r.u32()
            r.u32()
        elif imm == "i32":
            r.sleb(32)
        elif imm == "i64":
            r.sleb(64)
        elif imm == "f32":
            r.bytes(4)
        elif imm == "f64":
            r.bytes(8)


def audit_wasm(wasm: bytes) -> WasmInfo:
    """SPEC section 3 static audit. Raises AuditError on the first violation."""
    if not isinstance(wasm, (bytes, bytearray)):
        raise AuditError("module must be bytes")
    wasm = bytes(wasm)
    if len(wasm) > MAX_WASM_BYTES:
        raise AuditError(f"module is {len(wasm)} bytes (limit {MAX_WASM_BYTES})")
    if wasm[:4] != b"\0asm" or wasm[4:8] != b"\x01\x00\x00\x00":
        raise AuditError("bad wasm header (need magic \\0asm, version 1)")
    info = WasmInfo(size=len(wasm))
    r = _Reader(wasm, 8)
    last_order = 0.0
    seen: set[int] = set()
    n_code = None
    datacount = None
    mem_count = 0
    while not r.eof():
        sid = r.byte()
        size = r.u32()
        start = r.pos
        if start + size > len(wasm):
            raise AuditError(f"section {sid} overruns the module")
        s = _Reader(wasm, start, start + size)
        if sid == 0:
            s.name()  # custom: name must decode; content ignored
            r.pos = start + size
            continue
        if sid in FORBIDDEN_SECTIONS:
            raise AuditError(f"forbidden section {sid} ({FORBIDDEN_SECTIONS[sid]})")
        if sid not in SECTION_ORDER:
            raise AuditError(f"unknown section id {sid}")
        if sid in seen:
            raise AuditError(f"duplicate section {sid}")
        if SECTION_ORDER[sid] <= last_order:
            raise AuditError(f"section {sid} out of order")
        seen.add(sid)
        last_order = SECTION_ORDER[sid]

        if sid == 1:
            n = s.u32()
            if n > MAX_TYPES:
                raise AuditError("too many types")
            for _ in range(n):
                if s.byte() != 0x60:
                    raise AuditError("type entry is not a function type")
                params = tuple(_valtype(s) for _ in range(s.u32()))
                nres = s.u32()
                if nres > 1:
                    raise AuditError("multi-value function results are not allowed")
                results = tuple(_valtype(s) for _ in range(nres))
                info.types.append((params, results))
        elif sid == 3:
            n = s.u32()
            if n > MAX_FUNCS:
                raise AuditError(f"{n} functions (limit {MAX_FUNCS})")
            for _ in range(n):
                ti = s.u32()
                if ti >= len(info.types):
                    raise AuditError("function refers to an unknown type")
                info.func_types.append(ti)
        elif sid == 5:
            mem_count = s.u32()
            if mem_count != 1:
                raise AuditError(f"module must declare exactly one memory (found {mem_count})")
            flags = s.byte()
            if flags != 0x01:
                raise AuditError("memory must declare a maximum and must not be shared or 64-bit")
            info.mem_min, info.mem_max = s.u32(), s.u32()
            if not (info.mem_min <= info.mem_max <= MAX_PAGES):
                raise AuditError(f"memory limits {info.mem_min}..{info.mem_max} pages (need min <= max <= {MAX_PAGES})")
        elif sid == 6:
            n = s.u32()
            if n > MAX_GLOBALS:
                raise AuditError(f"{n} globals (limit {MAX_GLOBALS})")
            for _ in range(n):
                t = _valtype(s)
                mut = s.byte()
                if mut not in (0, 1):
                    raise AuditError("bad global mutability flag")
                _const_expr(s, t)
                info.globals.append((t, mut == 1))
        elif sid == 7:
            for _ in range(s.u32()):
                nm = s.name()
                kind = s.byte()
                idx = s.u32()
                if nm in info.exports:
                    raise AuditError(f"duplicate export {nm!r}")
                info.exports[nm] = (kind, idx)
        elif sid == 12:
            datacount = s.u32()
        elif sid == 10:
            n_code = s.u32()
            if n_code != len(info.func_types):
                raise AuditError("code section count does not match function section")
            for i in range(n_code):
                bsize = s.u32()
                bstart = s.pos
                if bstart + bsize > s.end:
                    raise AuditError(f"func {i}: body overruns the code section")
                params = info.types[info.func_types[i]][0]
                _decode_body(_Reader(wasm, bstart, bstart + bsize), info, len(params), i)
                s.pos = bstart + bsize
        elif sid == 11:
            n = s.u32()
            if n > MAX_DATA_SEGMENTS:
                raise AuditError(f"{n} data segments (limit {MAX_DATA_SEGMENTS})")
            if datacount is not None and datacount != n:
                raise AuditError("datacount does not match the data section")
            info.data_segments = n
            for _ in range(n):
                flag = s.u32()
                if flag == 1:  # passive (memory.init is forbidden, so it is inert)
                    s.bytes(s.u32())
                    continue
                if flag == 2:
                    if s.u32() != 0:
                        raise AuditError("data segment targets a memory other than 0")
                elif flag != 0:
                    raise AuditError(f"bad data segment flag {flag}")
                if mem_count != 1:
                    raise AuditError("active data segment without a memory")
                off = _const_expr(s, I32) & 0xFFFFFFFF
                ln = s.u32()
                s.bytes(ln)
                if off + ln > info.mem_min * PAGE:
                    raise AuditError(f"data segment [{off}, {off + ln}) exceeds initial memory {info.mem_min * PAGE}")
        if s.pos != s.end:
            raise AuditError(f"section {sid} has trailing bytes")
        r.pos = start + size

    if mem_count != 1:
        raise AuditError("module must declare exactly one memory")
    if len(info.func_types) and n_code is None:
        raise AuditError("function section without code section")
    if datacount is not None and info.data_segments != datacount:
        raise AuditError("datacount does not match the data section")

    allowed = {"memory", "st_evaluate", "st_alloc"}
    extra = set(info.exports) - allowed
    if extra:
        raise AuditError(f"forbidden exports {sorted(extra)}")
    if info.exports.get("memory") != (2, 0):
        raise AuditError("must export memory 0 as 'memory'")
    _check_func_export(info, "st_evaluate", ((I32, I32), (I64,)), required=True)
    info.has_st_alloc = _check_func_export(info, "st_alloc", ((I32,), (I32,)), required=False)
    return info


def _check_func_export(info: WasmInfo, name: str, sig, required: bool) -> bool:
    ex = info.exports.get(name)
    if ex is None:
        if required:
            raise AuditError(f"missing export {name!r}")
        return False
    kind, idx = ex
    if kind != 0 or idx >= len(info.func_types):
        raise AuditError(f"export {name!r} must be a function")
    if info.types[info.func_types[idx]] != sig:
        raise AuditError(f"export {name!r} has the wrong signature")
    return True


# --------------------------------------------------------------------- execution (SPEC 4)
class RuleRunError(AuditError):
    """A rule error under SPEC section 4 (trap, fuel, bad output, OOB)."""


def _reject_constant(c):
    raise ValueError(f"non-finite JSON constant {c}")


def strict_json_loads(raw: bytes | str):
    """json.loads that rejects duplicate keys and NaN/Infinity."""
    def hook(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"duplicate JSON key {k!r}")
            out[k] = v
        return out

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=hook, parse_constant=_reject_constant)


def _finite_number(v) -> bool:
    if isinstance(v, bool):
        return False
    return isinstance(v, int) or (isinstance(v, float) and math.isfinite(v))


def parse_output(r: int, mem: bytes, description: str) -> dict:
    """Apply the SPEC section 4 output ABI to the raw i64 result."""
    u = r & 0xFFFFFFFFFFFFFFFF
    hi, lo = u >> 32, u & 0xFFFFFFFF
    if hi == 0:
        if lo > 100:
            raise RuleRunError(f"packed score {lo} > 100")
        return {"score": lo, "confidence": 1.0, "reason": description}
    if lo > MAX_OUTPUT_LEN or hi + lo > len(mem):
        raise RuleRunError(f"output [{hi}, {hi}+{lo}) out of bounds or longer than {MAX_OUTPUT_LEN}")
    try:
        obj = strict_json_loads(bytes(mem[hi:hi + lo]))
    except (UnicodeDecodeError, ValueError) as e:
        raise RuleRunError(f"output is not strict UTF-8 JSON: {e}") from e
    if not isinstance(obj, dict):
        raise RuleRunError("output JSON must be an object")
    score = obj.get("score")
    if not _finite_number(score) or score != int(score) or not 0 <= score <= 100:
        raise RuleRunError(f"score must be an integral number 0..100 (got {score!r})")
    conf = obj.get("confidence", 1.0)
    if not _finite_number(conf) or not 0 < conf <= 1:
        raise RuleRunError(f"confidence must be in (0, 1] (got {conf!r})")
    reason = obj.get("reason", description)
    if not isinstance(reason, str) or len(reason) > MAX_REASON_CODEPOINTS:
        raise RuleRunError("reason must be a string of at most 300 code points")
    return {"score": int(score), "confidence": float(conf), "reason": reason}


class Sandbox:
    """Compiled module cache; every evaluate() uses a fresh store and instance."""

    def __init__(self, wasm: bytes, info: WasmInfo):
        if wasmtime is None:
            raise AuditError("wasmtime is not installed")
        cfg = wasmtime.Config()
        cfg.consume_fuel = True
        for attr in ("wasm_threads", "wasm_reference_types", "wasm_simd", "wasm_multi_memory",
                     "wasm_memory64", "wasm_relaxed_simd", "wasm_tail_call", "wasm_gc",
                     "wasm_function_references", "wasm_exceptions"):
            if hasattr(cfg, attr):
                try:
                    setattr(cfg, attr, False)
                except Exception:  # noqa: BLE001 - optional hardening, the static audit is authoritative
                    pass
        self.engine = wasmtime.Engine(cfg)
        self.module = wasmtime.Module(self.engine, wasm)
        self.info = info

    def evaluate(self, payload: bytes, description: str = "") -> dict:
        store = wasmtime.Store(self.engine)
        store.set_limits(memory_size=MAX_PAGES * PAGE, table_elements=0, instances=1, tables=0, memories=1)
        store.set_fuel(FUEL)
        try:
            inst = wasmtime.Instance(store, self.module, [])
            ex = inst.exports(store)
            mem = ex["memory"]
            ptr = DEFAULT_INPUT_PTR
            if self.info.has_st_alloc:
                p = ex["st_alloc"](store, len(payload)) & 0xFFFFFFFF
                if p > 0:
                    ptr = p
            need = ptr + len(payload)
            have = mem.data_len(store)
            if need > have:
                pages = (need - have + PAGE - 1) // PAGE
                if have // PAGE + pages > self.info.mem_max:
                    raise RuleRunError("input does not fit within the memory maximum")
                mem.grow(store, pages)
            mem.write(store, payload, ptr)
            r = ex["st_evaluate"](store, ptr, len(payload))
            if not isinstance(r, int):
                raise RuleRunError("st_evaluate did not return an i64")
            data = mem.read(store, 0, mem.data_len(store))
        except RuleRunError:
            raise
        except Exception as e:  # noqa: BLE001 - traps, fuel exhaustion, limits: all rule errors
            msg = " ".join(str(e).split())
            if "fuel" in msg:
                msg = f"fuel budget of {FUEL} exhausted"
            raise RuleRunError(f"execution failed: {type(e).__name__}: {msg[:300]}") from e
        return parse_output(r, data, description)


def audit_inputs(site: str) -> list[tuple[str, bytes]]:
    """Fingerprints every rule must evaluate without a rule error. Public on purpose:
    these test robustness, not behaviour."""
    fp = strule_v2.canonical_fingerprint_bytes
    long_text = "A" * 4000
    return [
        ("empty", fp({}, site)),
        ("informational-slop", fp(SLOP_SMOKE, site)),
        ("informational-human", fp(HUMAN_SMOKE, site)),
        ("long-strings", fp({"channel": {"title": long_text, "description": long_text * 2,
                                        "handle": "@" + "x" * 200}, "sample_text": long_text}, site)),
        ("extreme-numbers", fp({"channel": {"subscriber_count": 9007199254740991, "total_videos": -5},
                                "upload_cadence": {"max_dormancy_gap_days": -1e15, "channel_age_days": 1e15}}, site)),
        ("quotes-and-unicode", fp({"channel": {"title": '"\\ é\U0001F389'}, "sample_text": "}{]["}, site)),
    ]


# Informational smoke fingerprints (the old public probes). Never a trust gate (CRIT-02).
SLOP_SMOKE = {
    "channel": {"has_auto_suffix": True, "stem_siblings": 3, "total_videos": 240, "outbound_domain_share": 0.92},
    "upload_cadence": {"channel_age_days": 5800, "max_dormancy_gap_days": 5400, "pre_pivot_videos": 2,
                       "post_pivot_videos": 238, "post_pivot_share": 0.99, "recent_uploads_per_day": 4.2,
                       "output_minutes_per_week": 340, "duration_cv": 0.04},
    "transcript": {"uncontracted_ratio": 0.90, "antithesis_per_1k": 2.6, "slop_hooks_per_1k": 2.4,
                   "keyword_stuffing_ratio": 0.76, "intra_video_wpm_cv": 0.08, "pause_cv": 0.19,
                   "earliest_has_speech": False},
    "thumbnails": {"title_skeleton_reuse": 0.78, "raw_camera_earliest_title": True, "synthetic_image_ratio": 0.94,
                   "aspect_uniformity": 0.97, "repost_watermark_ratio": 0.86},
    "audio_video_stats": {"dead_air_floor": True},
}
HUMAN_SMOKE = {
    "channel": {"has_auto_suffix": False, "stem_siblings": 0, "total_videos": 260, "outbound_domain_share": 0.06},
    "upload_cadence": {"channel_age_days": 4200, "max_dormancy_gap_days": 60, "recent_uploads_per_day": 0.04,
                       "output_minutes_per_week": 8, "duration_cv": 0.42},
    "transcript": {"uncontracted_ratio": 0.16, "first_person_per_1k": 18.0, "disfluencies_per_1k": 2.8,
                   "keyword_stuffing_ratio": 0.04, "intra_video_wpm_cv": 0.21, "pause_cv": 0.52,
                   "earliest_has_speech": True},
    "thumbnails": {"title_skeleton_reuse": 0.10, "synthetic_image_ratio": 0.0, "aspect_uniformity": 0.24,
                   "repost_watermark_ratio": 0.0},
}


def execution_check(wasm: bytes, info: WasmInfo, site: str, description: str) -> dict[str, int]:
    """SPEC section 4: run every audit input twice on fresh instances. Returns scores."""
    sb = Sandbox(wasm, info)
    scores: dict[str, int] = {}
    for label, payload in audit_inputs(site if site != "*" else "youtube"):
        a = sb.evaluate(payload, description)
        b = sb.evaluate(payload, description)
        if a != b:
            raise RuleRunError(f"non-deterministic output on input {label!r}")
        scores[label] = a["score"]
    return scores


# ---------------------------------------------------------------------- bundle audit
@dataclass
class AuditResult:
    path: str
    rule_id: str
    version: str
    tier: str
    target_site: str
    manifest: dict
    sha256: str
    wasm_bytes: int
    mem_max: int
    smoke: dict[str, int] | None


def load_bundle_bytes(raw: bytes) -> dict:
    if len(raw) > MAX_BUNDLE_BYTES:
        raise AuditError(f"bundle is {len(raw)} bytes (limit {MAX_BUNDLE_BYTES})")
    try:
        doc = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as e:
        raise AuditError(f"bundle is not strict UTF-8 JSON: {e}") from e
    if isinstance(doc, dict) and doc.get("format") == "sloptrap-bundle-v1":
        raise AuditError("legacy sloptrap-bundle-v1 bundle: v1 support is removed and its keys are revoked; "
                         "replace it with a maintainer-signed sloptrap-bundle-v2 bundle")
    return doc


def audit_bundle(raw: bytes, *, expected_rule_id: str | None = None, required_tier: str | None = None,
                 execute: bool = True, label: str = "<bundle>") -> AuditResult:
    """Full audit of one bundle's bytes. Raises AuditError/BundleError on any failure."""
    doc = load_bundle_bytes(raw)
    try:
        manifest, wasm, tier = strule_v2.verify_bundle(doc)
    except BundleError:
        raise
    except Exception as e:  # noqa: BLE001 - fail closed on anything unexpected
        raise AuditError(f"verification error: {type(e).__name__}: {e}") from e
    if tier != strule_v2.tier_for_key(manifest["author_public_key"]):
        raise AuditError("tier mismatch")  # defensive; tier is only ever derived from the key
    rid = manifest["rule_id"]
    if (tier == "community") != rid.startswith(strule_v2.COMMUNITY_PREFIX):
        raise AuditError("community prefix rule violated")
    if expected_rule_id is not None and rid != expected_rule_id:
        raise AuditError(f"rule_id {rid!r} does not match file name {expected_rule_id!r}")
    if tier == "unverified":
        raise AuditError(f"{rid}: signed by an unknown key {manifest['author_public_key'][:16]}...; "
                         "only official and community keys are accepted in the registry")
    if required_tier is not None and tier != required_tier:
        raise AuditError(f"{rid}: tier {tier!r} is not allowed here (need {required_tier!r})")
    w = manifest["weight_milli"]
    if type(w) is not int or not 1 <= w <= 10000:  # validated by strule_v2 too
        raise AuditError("weight_milli out of bounds")
    info = audit_wasm(wasm)
    smoke = None
    if execute:
        smoke = execution_check(wasm, info, manifest["target_site"], manifest["description"])
    return AuditResult(path=label, rule_id=rid, version=manifest["version"], tier=tier,
                       target_site=manifest["target_site"], manifest=manifest,
                       sha256=hashlib.sha256(raw).hexdigest(), wasm_bytes=len(wasm),
                       mem_max=info.mem_max, smoke=smoke)


def required_tier_for(path: Path, root: Path) -> str | None:
    rel = path.resolve().relative_to(root.resolve()).as_posix()
    if rel.startswith("bundles/community/"):
        return "community"
    if rel.startswith("bundles/"):
        return "official"
    return None


def discover_bundles(root: Path) -> list[Path]:
    out = []
    for base in ("bundles",):
        d = root / base
        if d.is_dir():
            out += sorted(p for p in d.rglob("*.strule") if p.is_file())
    return out


def audit_paths(paths: list[Path], root: Path, execute: bool) -> tuple[list[AuditResult], list[tuple[str, str]]]:
    ok: list[AuditResult] = []
    failed: list[tuple[str, str]] = []
    owners: dict[str, tuple[str, str]] = {}
    for p in paths:
        try:
            rel = p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = str(p)
        try:
            if p.is_symlink():
                raise AuditError("symlinked bundles are not allowed")
            if p.stat().st_size > MAX_BUNDLE_BYTES:
                raise AuditError(f"bundle is {p.stat().st_size} bytes (limit {MAX_BUNDLE_BYTES})")
            raw = p.read_bytes()
            res = audit_bundle(raw, expected_rule_id=p.stem, required_tier=required_tier_for(p, root),
                               execute=execute, label=rel)
            prev = owners.get(res.rule_id)
            if prev and prev[0] != res.manifest["author_public_key"]:
                raise AuditError(f"rule_id {res.rule_id!r} collides with {prev[1]} (different key)")
            owners.setdefault(res.rule_id, (res.manifest["author_public_key"], rel))
            ok.append(res)
        except Exception as e:  # noqa: BLE001 - report and continue; any failure fails the run
            failed.append((rel, f"{type(e).__name__}: {e}"))
    return ok, failed


def check_leaderboards(root: Path, results: list[AuditResult]) -> list[str]:
    """Leaderboard JSON must agree with the audited bundles; tiers are never self-declared."""
    by_path = {r.path: r for r in results}
    errs: list[str] = []
    files = [root / "leaderboard.json"] + sorted((root / "leaderboard").glob("*/leaderboard.json"))
    files.append(root / "leaderboard" / "leaderboard.json")
    for lb_path in files:
        if not lb_path.exists():
            continue
        rel = lb_path.relative_to(root).as_posix()
        try:
            lb = strict_json_loads(lb_path.read_bytes())
        except Exception as e:  # noqa: BLE001
            errs.append(f"{rel}: invalid JSON: {e}")
            continue
        if "community_entries" in lb:
            errs.append(f"{rel}: community rules belong in 'entries' (the SDK reads only 'entries')")
        for e in lb.get("entries") or []:
            rid = e.get("rule_id")
            local = e.get("local_bundle_path") or ""
            res = by_path.get(local)
            want = f"bundles/community/{rid}.strule" if str(rid).startswith("community-") else f"bundles/{rid}.strule"
            if res is None or local != want:
                errs.append(f"{rel}: entry {rid!r} has no audited bundle at {want!r}")
                continue
            if res.rule_id != rid:
                errs.append(f"{rel}: {rid!r} does not match its bundle")
            if "bundle_url" in e:
                errs.append(f"{rel}: {rid!r} has a bundle_url; bundles are served from local_bundle_path only")
            if e.get("verification_tier") != res.tier or bool(e.get("verified")) != (res.tier == "official"):
                errs.append(f"{rel}: {rid!r} declares a tier/verified flag that the key does not give")
            if e.get("author_public_key") != res.manifest["author_public_key"]:
                errs.append(f"{rel}: {rid!r} author_public_key differs from the bundle")
            if e.get("bundle_sha256") and e["bundle_sha256"] != res.sha256:
                errs.append(f"{rel}: {rid!r} bundle_sha256 mismatch")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", type=Path, help="bundles to audit (default: everything under bundles/)")
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    ap.add_argument("--allow-empty", action="store_true", help="exit 0 when there are no bundles to audit")
    ap.add_argument("--static-only", action="store_true",
                    help="skip the wasmtime execution check (local use only; NOT a full audit)")
    ap.add_argument("--require-wasmtime", action="store_true", help="(default behaviour; kept for compatibility)")
    ap.add_argument("--skip-leaderboard", action="store_true", help="do not cross-check leaderboard JSON")
    ap.add_argument("--json", type=Path, help="write machine-readable results here")
    a = ap.parse_args(argv)

    root = a.root
    execute = not a.static_only
    if execute and wasmtime is None:
        print("AUDIT FAIL: wasmtime is not installed; install .github/requirements-ci.txt "
              "(or pass --static-only for a partial local check)", file=sys.stderr)
        return 1
    paths = a.paths or discover_bundles(root)
    if not paths:
        if a.allow_empty:
            print("AUDIT OK: no .strule bundles found (--allow-empty)")
            return 0
        print("AUDIT FAIL: no .strule bundles found", file=sys.stderr)
        return 1

    ok, failed = audit_paths(paths, root, execute)
    for r in ok:
        smoke = ""
        if r.smoke:
            smoke = (f" | smoke (informational, not a gate): slop={r.smoke['informational-slop']}"
                     f" human={r.smoke['informational-human']}")
        print(f"AUDIT PASS [{r.path}] {r.rule_id} v{r.version} tier={r.tier} site={r.target_site} "
              f"wasm={r.wasm_bytes}B mem<={r.mem_max}p{'' if execute else ' (static only)'}{smoke}")
    for rel, err in failed:
        print(f"AUDIT FAIL [{rel}]: {err}", file=sys.stderr)
    lb_errs = [] if (a.skip_leaderboard or a.paths) else check_leaderboards(root, ok)
    for e in lb_errs:
        print(f"AUDIT FAIL [leaderboard] {e}", file=sys.stderr)

    legacy = sum(1 for _, e in failed if "sloptrap-bundle-v1" in e)
    if legacy:
        print(f"\n{legacy} legacy v1 bundle(s) found. v1 is no longer accepted; these fail until the "
              "maintainer replaces them with signed v2 bundles.", file=sys.stderr)
    if a.json:
        a.json.write_text(json.dumps({
            "passed": [{"path": r.path, "rule_id": r.rule_id, "version": r.version, "tier": r.tier,
                        "target_site": r.target_site, "sha256": r.sha256} for r in ok],
            "failed": [{"path": p, "error": e} for p, e in failed],
            "leaderboard_errors": lb_errs,
        }, indent=2) + "\n", encoding="utf-8")
    total_fail = len(failed) + len(lb_errs)
    print(f"\n{len(ok)} passed, {len(failed)} failed, {len(lb_errs)} leaderboard error(s)",
          file=sys.stderr if total_fail else sys.stdout)
    return 1 if total_fail else 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
