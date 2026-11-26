"""Audit tests: shared v2 vectors, the security-review wasm PoCs, and crafted modules.

Run: python3 -I -m unittest discover -s tests -t .
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wasmgen import (  # noqa: E402
    ALLOC_T, COMMUNITY_TEST_SEED, EVAL_T, FIXTURES, OFFICIAL_TEST_SEED, TEST_SEED, bundle, bundle_bytes,
    json_output_module, module, name, pubkey, ret_i64, sec, sleb, uleb, vec,
)

import audit_bundles as A  # noqa: E402
import strule_v2  # noqa: E402

VEC = FIXTURES / "vectors"
POCS = FIXTURES / "pocs"
HAVE_WASMTIME = A.wasmtime is not None
OFF_PUB = pubkey(OFFICIAL_TEST_SEED)
COM_PUB = pubkey(COMMUNITY_TEST_SEED)
LIST_PUB = pubkey(TEST_SEED)


def test_keys():
    """Patch the pinned key sets with test keys (the real seeds are never in CI)."""
    return mock.patch.multiple(
        strule_v2,
        OFFICIAL_KEYS=frozenset({OFF_PUB}),
        COMMUNITY_KEYS=frozenset({COM_PUB}),
        LIST_SIGNING_KEYS=frozenset({LIST_PUB}),
    )


def _fp_input(v):
    if isinstance(v, dict):
        if set(v) == {"$float"}:
            return float(v["$float"])
        return {k: _fp_input(x) for k, x in v.items()}
    return v


class VectorTests(unittest.TestCase):
    def setUp(self):
        self.mv = json.loads((VEC / "manifest_vectors.json").read_text(encoding="utf-8"))

    def test_valid_vector(self):
        v = self.mv["valid"]
        self.assertEqual(strule_v2.canonical_manifest_bytes(v["manifest"]).hex(), v["canon_hex"])
        wasm = bytes.fromhex(v["wasm_hex"])
        self.assertEqual(strule_v2.signing_digest(v["manifest"], wasm).hex(), v["digest_hex"])
        self.assertEqual(strule_v2.sign_bundle(v["manifest"], wasm, v["test_seed_hex"])["signature_b64"],
                         v["signature_b64"])
        m, w, tier = strule_v2.verify_bundle(v["bundle"])
        self.assertEqual((w, tier), (wasm, v["expected_tier"]))

    def test_valid_vector_is_still_rejected_by_the_registry_audit(self):
        raw = json.dumps(self.mv["valid"]["bundle"]).encode()
        with self.assertRaisesRegex(A.AuditError, "unknown key"):
            A.audit_bundle(raw, execute=False)

    def test_invalid_manifests(self):
        for case in self.mv["invalid_manifests"]:
            with self.subTest(case=case["case"]):
                with self.assertRaises(strule_v2.BundleError) as cm:
                    strule_v2.validate_manifest(case["manifest"])
                self.assertIn(case["error_contains"], str(cm.exception))

    def test_tampered_bundles(self):
        for case in self.mv["tampered_bundles"]:
            with self.subTest(case=case["case"]):
                with self.assertRaises((strule_v2.BundleError, A.AuditError)):
                    A.audit_bundle(json.dumps(case["bundle"]).encode(), execute=False)

    def test_fingerprint_vectors(self):
        fv = json.loads((VEC / "fingerprint_vectors.json").read_text(encoding="utf-8"))
        for case in fv["cases"]:
            with self.subTest(case=case["name"]):
                got = strule_v2.canonical_fingerprint_bytes(_fp_input(case["input"]), case["site"])
                self.assertEqual(got.decode("utf-8"), case["canonical"])

    def test_strule_v2_is_the_reference_copy(self):
        import hashlib
        ref = Path(A.__file__).with_name("strule_v2.py").read_bytes()
        # sha256 of the shared reference strule_v2.py (must stay byte-identical across repos)
        self.assertEqual(hashlib.sha256(ref).hexdigest(), "9b28ab139fc7d0b5090ed19292cd544a2c81a377fcc61c1e745d81d7e218baff")


class PocTests(unittest.TestCase):
    """Every PoC from the security review is rejected or contained."""

    def test_v1_poc_bundles_are_rejected_as_legacy(self):
        for p in sorted(POCS.glob("*.strule")):
            with self.subTest(poc=p.name):
                with self.assertRaisesRegex(A.AuditError, "sloptrap-bundle-v1"):
                    A.audit_bundle(p.read_bytes(), execute=False)

    STATIC_REJECT = {
        "p05-start-loop": "start",
        "p06-multi-memory": "exactly one memory",
        "p07-mem-unbounded-grow": "maximum",
        "p08-mem-max65536-grow": "<= 32",
        "p15-data-oob": "exceeds initial memory",
        "p16-mem-commit-1g": "maximum",
    }
    EXEC_REJECT = {
        "p01-loop-br": "fuel",
        "p02-loop-brif": "fuel",
        "p03-loop-brtable": "fuel",
        "p04-recursion": "execution failed",
        "p09-nan-score": "integral",
        "p10-oob-output-ptr": "out of bounds",
        "p11-float-score": "integral",
    }

    def test_static_rejections(self):
        for stem, msg in self.STATIC_REJECT.items():
            with self.subTest(poc=stem):
                with self.assertRaisesRegex(A.AuditError, msg):
                    A.audit_wasm((POCS / f"{stem}.wasm").read_bytes())

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_execution_rejections(self):
        for stem, msg in self.EXEC_REJECT.items():
            with self.subTest(poc=stem):
                wasm = (POCS / f"{stem}.wasm").read_bytes()
                info = A.audit_wasm(wasm)  # loops/recursion pass the static audit by design
                with self.assertRaisesRegex(A.RuleRunError, msg):
                    A.execution_check(wasm, info, "youtube", "poc")

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_full_bundle_audit_rejects_every_hostile_poc(self):
        with test_keys():
            for stem in sorted(set(self.STATIC_REJECT) | set(self.EXEC_REJECT)):
                with self.subTest(poc=stem):
                    rid = "community-" + stem
                    raw = bundle_bytes(rid, (POCS / f"{stem}.wasm").read_bytes(), COMMUNITY_TEST_SEED)
                    with self.assertRaises(A.AuditError):
                        A.audit_bundle(raw, expected_rule_id=rid, required_tier="community")

    def test_weight_and_overhead_pocs_cannot_be_expressed(self):
        # p12 default_weight 1e300, p13 0.03125, p14 overhead 3.5: v2 uses bounded integers.
        bad = [{"weight_milli": 10 ** 300}, {"weight_milli": 1e300}, {"weight_milli": 31.25},
               {"weight_milli": 0}, {"weight_milli": 10001}, {"weight_milli": True},
               {"overhead": 3.5}, {"overhead": 0}, {"overhead": 101}]
        good = bundle("community-p12", (POCS / "p12-weight-dominance.wasm").read_bytes(), TEST_SEED)
        for over in bad:
            with self.subTest(over=over):
                b = json.loads(json.dumps(good))
                b["manifest"].update(over)
                with self.assertRaises((strule_v2.BundleError, A.AuditError, ValueError)):
                    A.audit_bundle(json.dumps(b).encode(), execute=False)
                with self.assertRaises(strule_v2.BundleError):
                    strule_v2.validate_manifest(b["manifest"])

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_stateful_timebomb_is_contained_by_fresh_instances(self):
        wasm = (POCS / "p17-stateful-timebomb.wasm").read_bytes()
        info = A.audit_wasm(wasm)
        sb = A.Sandbox(wasm, info)
        short = b"{}"
        first = sb.evaluate(short)
        for _ in range(6):  # on a pooled instance the 3rd call would return 100
            self.assertEqual(sb.evaluate(short), first)
        self.assertEqual(first["score"], 0)

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_honest_poc_and_real_rule_pass(self):
        for path in (POCS / "p00-honest-100.wasm", FIXTURES / "clone-farm-sentinel.wasm"):
            with self.subTest(wasm=path.name):
                wasm = path.read_bytes()
                scores = A.execution_check(wasm, A.audit_wasm(wasm), "youtube", "d")
                self.assertTrue(all(0 <= s <= 100 for s in scores.values()))

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_public_probes_are_not_a_trust_gate(self):
        # CRIT-02: a rule that flags the public human probe (score 100 for everyone) passes the
        # robustness audit; behaviour is judged by the private hidden holdout, not here.
        with test_keys():
            raw = bundle_bytes("community-flag-all", module(body=ret_i64(100)), COMMUNITY_TEST_SEED)
            res = A.audit_bundle(raw, required_tier="community")
        self.assertEqual(res.smoke["informational-human"], 100)


class StaticAuditTests(unittest.TestCase):
    def check(self, wasm: bytes, msg: str):
        with self.assertRaisesRegex(A.AuditError, msg):
            A.audit_wasm(wasm)

    def test_minimal_module_passes(self):
        info = A.audit_wasm(module())
        self.assertEqual((info.mem_min, info.mem_max, info.has_st_alloc), (1, 2, False))

    def test_header(self):
        self.check(b"\0asm\x02\0\0\0", "header")
        self.check(b"\0wasm\x01\0\0", "header")
        self.check(b"\0asm\x01\0\0\0" + b"\0" * (A.MAX_WASM_BYTES), "limit")

    def test_forbidden_opcodes(self):
        cases = {
            "call_indirect": [0x41, 0, 0x11, 0, 0, 0x42, 0],
            "return_call": [0x12, 0],
            "typed select": [0x41, 0, 0x41, 0, 0x41, 0, 0x1C, 1, 0x7F, 0x1A, 0x42, 0],
            "table.get": [0x41, 0, 0x25, 0, 0x1A, 0x42, 0],
            "throw": [0x08, 0],
            "try": [0x06, 0x40, 0x0B, 0x42, 0],
            "ref.null": [0xD0, 0x70, 0x1A, 0x42, 0],
            "reinterpret": [0x43, 0, 0, 0, 0, 0xBC, 0x1A, 0x42, 0],
            "SIMD": [0xFD, 0x0C] + [0] * 16 + [0x1A, 0x42, 0],
            "atomics": [0x41, 0, 0xFE, 0x10, 2, 0, 0x1A, 0x42, 0],
            "0xfc 8": [0x41, 0, 0x41, 0, 0x41, 0, 0xFC, 8, 0, 0, 0x42, 0],
            "0xfc 12": [0xFC, 12, 0, 0, 0x42, 0],
        }
        for label, body in cases.items():
            with self.subTest(op=label):
                self.check(module(body=body), "forbidden opcode")

    def test_unknown_and_post_mvp_opcodes(self):
        for op in (0xC0, 0xC5, 0x27, 0x14, 0xFF):
            with self.subTest(op=hex(op)):
                self.check(module(body=[op, 0x42, 0]), "unknown opcode|forbidden")

    def test_allowed_prefix_ops(self):
        body = [0x41, 0, 0x41, 0, 0x41, 4, 0xFC, 10, 0, 0,       # memory.copy
                0x41, 0, 0x41, 0, 0x41, 4, 0xFC, 11, 0,          # memory.fill
                0x43, 0, 0, 0, 0, 0xFC, 0, 0x1A,                 # i32.trunc_sat_f32_s
                0x3F, 0, 0x40, 0, 0x1A,                          # memory.size / memory.grow
                0x03, 0x40, 0x0B, 0x02, 0x7E, 0x42, 0, 0x0B, 0x1A,  # loop, block (result i64)
                0x42, 1]
        A.audit_wasm(module(body=body))

    def test_block_types(self):
        self.check(module(body=[0x02, 0x00, 0x0B, 0x42, 0]), "block type")      # type index 0
        self.check(module(body=[0x02, 0x7B, 0x0B, 0x42, 0]), "block type")      # v128
        self.check(module(body=[0x02, 0x70, 0x0B, 0x42, 0]), "block type")      # funcref

    def test_body_structure(self):
        self.check(module(body=[0x05, 0x42, 0]), "else")
        self.check(module(body=[0x0C, 1, 0x42, 0]), "branch depth")
        self.check(module(body=[0x20, 5, 0x1A, 0x42, 0]), "local index")
        self.check(module(body=[0x10, 9, 0x42, 0]), "unknown function")
        self.check(module(body=[0x42, 0, 0x0B, 0x01]), "trailing bytes")  # code after final end
        self.check(module(body=[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]), "LEB128")

    def test_forbidden_sections(self):
        imp = sec(2, vec([name("env") + name("f") + [0x00, 0x00]]))
        self.check(module(sections_after_types=[imp]), "import")
        table = sec(4, vec([[0x70, 0x00, 0x01]]))
        self.check(module(sections_after_types=[table]), "table|order")
        elem = sec(9, vec([[0x00, 0x41, 0x00, 0x0B, 0x00]]))
        self.check(module(datacount=None, sections_tail=[elem]), "element|order")
        start = sec(8, uleb(0))
        self.check(module(sections_tail=[start]), "start|order")

    def test_section_order_and_duplicates(self):
        dup = sec(1, vec([EVAL_T]))
        self.check(module(sections_after_types=[dup]), "duplicate")
        late_types = sec(1, vec([EVAL_T]))
        m = module()
        self.check(m + bytes(late_types), "duplicate|order")
        self.check(m + bytes([13, 0]), "unknown section")
        self.check(m + bytes([11, 5, 0]), "overruns|trailing|end")

    def test_custom_sections_are_ignored(self):
        custom = sec(0, name("name") + [1, 2, 3])
        A.audit_wasm(module(sections_before=[custom]))

    def test_memory_rules(self):
        self.check(module(mem=None), "exactly one memory")
        self.check(module(mem=(0, 1)), "maximum")
        self.check(module(mem=(3, 1, 2)), "shared")
        self.check(module(mem=(1, 3, 2)), "min <= max")
        self.check(module(mem=(1, 1, 33)), "<= 32")
        A.audit_wasm(module(mem=(1, 0, 32)))

    def test_counts(self):
        many = [[0] for _ in range(1025)]
        self.check(module(funcs=many), "functions")
        g = vec([[0x7F, 0x00, 0x41, 0x00, 0x0B] for _ in range(65)])
        self.check(module(globals_=g), "globals")
        segs = vec([[0x00, 0x41, 0x00, 0x0B, 0x01, 0x00] for _ in range(65)])
        self.check(module(data=segs), "data segments")

    def test_global_and_data_init_exprs(self):
        g = vec([[0x7F, 0x00, 0x23, 0x00, 0x0B]])  # global.get as initializer
        self.check(module(globals_=g), "constant expression")
        seg = vec([[0x00, 0x42, 0x00, 0x0B, 0x01, 0x00]])  # i64 offset
        self.check(module(data=seg), "wrong type")
        seg = vec([[0x02, 0x01, 0x41, 0x00, 0x0B, 0x01, 0x00]])  # memory 1
        self.check(module(data=seg), "memory other than 0")
        seg = vec([[0x00, 0x41] + sleb(-1) + [0x0B, 0x01, 0x00]])  # offset 0xffffffff
        self.check(module(data=seg), "exceeds initial memory")
        self.check(module(datacount=2, data=vec([[0x01, 0x00]])), "datacount")
        A.audit_wasm(module(datacount=1, data=vec([[0x01, 0x01, 0x41]])))  # passive segment is inert

    def test_global_set_on_immutable(self):
        g = vec([[0x7F, 0x00, 0x41, 0x00, 0x0B]])
        self.check(module(globals_=g, body=[0x41, 1, 0x24, 0, 0x42, 0]), "immutable")

    def test_exports(self):
        base = [name("memory") + [2, 0], name("st_evaluate") + [0, 0]]
        self.check(module(exports=base + [name("other") + [0, 0]]), "forbidden exports")
        self.check(module(exports=[name("st_evaluate") + [0, 0]]), "memory")
        self.check(module(exports=[name("memory") + [2, 0]]), "st_evaluate")
        self.check(module(exports=base + [name("memory") + [2, 0]]), "duplicate export")
        self.check(module(types=[ALLOC_T, EVAL_T], funcs=[[0]], body=[0x41, 0]), "wrong signature")
        self.check(module(exports=[name("memory") + [2, 0], name("st_evaluate") + [3, 0]]), "must be a function")
        self.check(module(alloc_body=[0x42, 0], types=[EVAL_T, EVAL_T]), "st_alloc")
        info = A.audit_wasm(module(alloc_body=[0x41, 0]))
        self.assertTrue(info.has_st_alloc)

    def test_multi_value_types_rejected(self):
        multi = [0x60, 0, 2, 0x7F, 0x7F]
        self.check(module(types=[EVAL_T, multi], funcs=[[0]]), "multi-value")
        self.check(module(types=[EVAL_T, [0x60, 1, 0x7B, 0]], funcs=[[0]]), "value type")


@unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
class ExecutionTests(unittest.TestCase):
    def run_one(self, wasm: bytes, payload: bytes = b"{}") -> dict:
        return A.Sandbox(wasm, A.audit_wasm(wasm)).evaluate(payload, "desc")

    def test_packed_score(self):
        self.assertEqual(self.run_one(module(body=ret_i64(42))), {"score": 42, "confidence": 1.0, "reason": "desc"})
        with self.assertRaisesRegex(A.RuleRunError, "> 100"):
            self.run_one(module(body=ret_i64(101)))

    def test_json_output(self):
        out = self.run_one(json_output_module('{"score":42,"confidence":0.5,"reason":"r"}'))
        self.assertEqual(out, {"score": 42, "confidence": 0.5, "reason": "r"})
        self.assertEqual(self.run_one(json_output_module('{"score":7.0}'))["score"], 7)

    def test_bad_json_outputs(self):
        bad = ['{"score":"50"}', '{"score":true}', '{"score":-1}', '{"score":1e999}', '{"score":NaN}',
               '{"score":50,"score":0}', '[50]', '{"score":50,"confidence":0}', '{"score":50,"confidence":1.5}',
               '{"score":50,"reason":' + json.dumps("x" * 301) + '}', '{"score":50,"reason":5}', '{"score":',
               '{"confidence":1}']
        for text in bad:
            with self.subTest(out=text[:40]):
                with self.assertRaises(A.RuleRunError):
                    self.run_one(json_output_module(text))

    def test_output_too_long(self):
        with self.assertRaisesRegex(A.RuleRunError, "out of bounds|longer"):
            self.run_one(module(body=ret_i64((256 << 32) | 4097)))

    def test_trap_is_rule_error(self):
        with self.assertRaisesRegex(A.RuleRunError, "execution failed"):
            self.run_one(module(body=[0x00]))  # unreachable

    def test_input_written_at_st_alloc_pointer(self):
        # st_alloc returns 1024; st_evaluate returns the first input byte ('{' = 123 > 100 -> error) or
        # the byte at 1024 minus 100 when the input is there.
        alloc = [0x41] + sleb(1024)
        body = [0x41] + sleb(1024) + [0x2D, 0x00, 0x00] + [0x41] + sleb(100) + [0x6B, 0xAD]  # load8_u(1024) - 100
        out = self.run_one(module(alloc_body=alloc, body=body, locals_=()), b"{x")
        self.assertEqual(out["score"], 23)

    def test_input_beyond_memory_max_is_rule_error(self):
        wasm = module(mem=(1, 1, 1))
        with self.assertRaisesRegex(A.RuleRunError, "memory maximum"):
            self.run_one(wasm, b"x" * 70000)

    def test_memory_grow_beyond_max_fails_inside_sandbox(self):
        body = [0x41] + sleb(64) + [0x40, 0x00, 0x41, 0x7F, 0x46, 0xAD]  # (memory.grow 64) == -1 -> 1
        self.assertEqual(self.run_one(module(mem=(1, 1, 32), body=body))["score"], 1)


class BundleAuditTests(unittest.TestCase):
    wasm = module(body=ret_i64(10))

    def test_unverified_key_rejected(self):
        with self.assertRaisesRegex(A.AuditError, "unknown key"):
            A.audit_bundle(bundle_bytes("some-rule", self.wasm, TEST_SEED), execute=False)

    def test_tier_must_match_location(self):
        with test_keys():
            raw = bundle_bytes("community-x", self.wasm, COMMUNITY_TEST_SEED)
            with self.assertRaisesRegex(A.AuditError, "not allowed here"):
                A.audit_bundle(raw, required_tier="official", execute=False)
            raw = bundle_bytes("official-x", self.wasm, OFFICIAL_TEST_SEED)
            self.assertEqual(A.audit_bundle(raw, required_tier="official", execute=False).tier, "official")
            with self.assertRaisesRegex(A.AuditError, "not allowed here"):
                A.audit_bundle(raw, required_tier="community", execute=False)

    def test_community_prefix_rule(self):
        with test_keys():
            with self.assertRaisesRegex(strule_v2.BundleError, "community-"):
                A.audit_bundle(bundle_bytes("no-prefix", self.wasm, COMMUNITY_TEST_SEED), execute=False)
            with self.assertRaisesRegex(strule_v2.BundleError, "community-"):
                A.audit_bundle(bundle_bytes("community-fake", self.wasm, OFFICIAL_TEST_SEED), execute=False)

    def test_rule_id_must_match_file_name(self):
        with test_keys():
            raw = bundle_bytes("official-x", self.wasm, OFFICIAL_TEST_SEED)
            with self.assertRaisesRegex(A.AuditError, "file name"):
                A.audit_bundle(raw, expected_rule_id="official-y", execute=False)

    def test_size_limits(self):
        with self.assertRaisesRegex(A.AuditError, "limit"):
            A.audit_bundle(b" " * (A.MAX_BUNDLE_BYTES + 1), execute=False)

    def test_strict_json(self):
        with test_keys():
            b = bundle("official-x", self.wasm, OFFICIAL_TEST_SEED)
            raw = json.dumps(b)[:-1] + ', "format": "sloptrap-bundle-v2"}'
            with self.assertRaisesRegex(A.AuditError, "duplicate"):
                A.audit_bundle(raw.encode(), execute=False)

    def test_bad_signature_fails_closed(self):
        with test_keys():
            b = bundle("official-x", self.wasm, OFFICIAL_TEST_SEED)
            b["signature_b64"] = base64.b64encode(b"\0" * 64).decode()
            with self.assertRaises(strule_v2.BundleError):
                A.audit_bundle(json.dumps(b).encode(), execute=False)
            b["signature_b64"] = "!!"
            with self.assertRaises(strule_v2.BundleError):
                A.audit_bundle(json.dumps(b).encode(), execute=False)

    def test_static_audit_runs_on_verified_payload(self):
        with test_keys():
            raw = bundle_bytes("official-x", module(mem=(1, 1, 64)), OFFICIAL_TEST_SEED)
            with self.assertRaisesRegex(A.AuditError, "<= 32"):
                A.audit_bundle(raw, execute=False)

    @unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
    def test_cli_on_a_tree(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles" / "community").mkdir(parents=True)
            (root / "bundles" / "official-x.strule").write_bytes(bundle_bytes("official-x", self.wasm, OFFICIAL_TEST_SEED))
            (root / "bundles" / "community" / "community-y.strule").write_bytes(
                bundle_bytes("community-y", self.wasm, COMMUNITY_TEST_SEED))
            self.assertEqual(A.main(["--root", str(root)]), 0)
            # a community bundle in the official directory fails
            (root / "bundles" / "community-y.strule").write_bytes(
                bundle_bytes("community-y", self.wasm, COMMUNITY_TEST_SEED))
            self.assertEqual(A.main(["--root", str(root)]), 1)

    def test_cli_empty_tree(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(A.main(["--root", td, "--static-only"]), 1)
            self.assertEqual(A.main(["--root", td, "--static-only", "--allow-empty"]), 0)

    def test_leaderboard_cannot_self_declare_tier(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles").mkdir()
            (root / "leaderboard" / "youtube").mkdir(parents=True)
            raw = bundle_bytes("community-y", self.wasm, COMMUNITY_TEST_SEED)
            (root / "bundles" / "community").mkdir()
            (root / "bundles" / "community" / "community-y.strule").write_bytes(raw)
            ok, failed = A.audit_paths(A.discover_bundles(root), root, execute=False)
            self.assertEqual(failed, [])
            entry = {"rule_id": "community-y", "local_bundle_path": "bundles/community/community-y.strule",
                     "verification_tier": "official", "verified": True, "author_public_key": COM_PUB}
            (root / "leaderboard" / "youtube" / "leaderboard.json").write_text(
                json.dumps({"entries": [entry]}), encoding="utf-8")
            errs = A.check_leaderboards(root, ok)
            self.assertTrue(errs)


if __name__ == "__main__":
    unittest.main()
