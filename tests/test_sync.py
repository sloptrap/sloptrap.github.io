"""Registry sync tests (community bundles, pre-matched lists, leaderboard regeneration)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_audit import COM_PUB, HAVE_WASMTIME, OFF_PUB, test_keys  # noqa: E402
from wasmgen import (  # noqa: E402
    COMMUNITY_TEST_SEED, OFFICIAL_TEST_SEED, TEST_SEED, bundle, bundle_bytes, module, ret_i64,
)

import sync_registry as S  # noqa: E402

UC = "UC" + "a" * 22
WASM = module(body=ret_i64(10))


class FakeWorker:
    """Serves the Worker routes the sync uses. `inclusive` selects since semantics."""

    def __init__(self, bundles=(), entries=(), stats=None, page=2, inclusive=True):
        self.bundles, self.entries, self.stats = list(bundles), list(entries), stats
        self.page, self.inclusive, self.calls = page, inclusive, []

    def _page(self, rows, ts_key, since):
        rows = sorted(rows, key=lambda r: r[ts_key])
        sel = [r for r in rows if (r[ts_key] >= since if self.inclusive else r[ts_key] > since)]
        return sel[: self.page]

    def __call__(self, path):
        self.calls.append(path)
        route, _, q = path.partition("?")
        since = int(q.split("=", 1)[1]) if q else 0
        if route == "/api/v1/rules/community-bundles":
            return {"ok": True, "bundles": self._page(self.bundles, "accepted_at", since)}
        if route == "/api/v1/lists/entries":
            return {"ok": True, "entries": self._page(self.entries, "first_seen", since)}
        if route == "/api/v1/rules/stats":
            if self.stats is None:
                raise OSError("down")
            return self.stats
        raise AssertionError(path)


class PagingTests(unittest.TestCase):
    def test_paging_inclusive_and_exclusive(self):
        rows = [{"site": "youtube", "rule_id": "r", "account_key": f"@acct{i}", "first_seen": 100 + i // 2}
                for i in range(7)]
        for inclusive in (True, False):
            with self.subTest(inclusive=inclusive):
                w = FakeWorker(entries=rows, page=3, inclusive=inclusive)
                got = S.fetch_paged(w, "/api/v1/lists/entries", "entries", "first_seen",
                                    lambda r: (r["site"], r["rule_id"], r["account_key"]))
                self.assertEqual(len(got), 7)
                self.assertTrue(w.calls[0].endswith("since=0"))

    def test_bad_shape_raises(self):
        with self.assertRaises(S.SyncError):
            S.fetch_paged(lambda p: {"ok": False}, "/x", "entries", "first_seen", lambda r: r)
        with self.assertRaises(S.SyncError):
            S.fetch_paged(lambda p: {"ok": True, "entries": {}}, "/x", "entries", "first_seen", lambda r: r)


class ListTests(unittest.TestCase):
    rules = {"yt-rule": "youtube", "tt-rule": "tiktok", "any-rule": "*", "community-ok": "youtube"}

    def test_validation(self):
        rows = [
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "@Good.Handle", "count": 7},
            {"site": "youtube", "rule_id": "yt-rule", "account_key": UC, "count": 2},
            {"site": "youtube", "rule_id": "community-ok", "account_key": "@comm.hit", "count": 4},
            {"site": "tiktok", "rule_id": "tt-rule", "account_key": UC, "count": 1},            # UC ids are YouTube only
            {"site": "anything-site", "rule_id": "yt-rule", "account_key": "@abc", "count": 1},  # unknown site
            {"site": "youtube", "rule_id": "made-up-rule", "account_key": "@abc", "count": 1},   # unaudited rule
            {"site": "youtube", "rule_id": "community-unaudited", "account_key": "@abc", "count": 1},
            {"site": "youtube", "rule_id": "tt-rule", "account_key": "@abc", "count": 1},        # rule is for tiktok
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "@ab", "count": 1},         # too short
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "@a\nb\n! x", "count": 1},  # injection
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "UCshort", "count": 1},
            {"site": "youtube", "rule_id": "yt-rule", "account_key": 5, "count": 1},
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "@zero", "count": 0},       # zero count rejected
            {"site": "youtube", "rule_id": "yt-rule", "account_key": "@strcnt", "count": "3"},   # non-int count rejected
            {"site": "pinterest", "rule_id": "any-rule", "account_key": "@pinner", "count": 3},
        ]
        lists, rejected = S.build_lists(rows, self.rules)
        self.assertEqual(lists[("youtube", "yt-rule")], {"@good.handle": 7, UC: 2})
        self.assertEqual(lists[("youtube", "community-ok")], {"@comm.hit": 4})
        self.assertEqual(lists[("tiktok", "tt-rule")], {})
        self.assertEqual(lists[("pinterest", "any-rule")], {"@pinner": 3})
        self.assertEqual(rejected, 11)
        self.assertNotIn(("youtube", "made-up-rule"), lists)

    def test_write_lists_rebuilds_and_prunes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stale = root / "lists" / "youtube" / "made-up-rule.txt"
            stale.parent.mkdir(parents=True)
            stale.write_text("@victim\t1\n", encoding="utf-8")
            old = root / "lists" / "youtube" / "yt-rule.txt"
            old.write_text("! old\n@revoked-victim\t5\n", encoding="utf-8")
            S.write_lists(
                root,
                {
                    ("youtube", "yt-rule"): {"@a.b.c": 2, "@top.slop": 9},
                    ("youtube", "community-empty"): {},
                    ("youtube", "community-active"): {"@c.hit": 3},
                },
                {"yt-rule": "YT", "community-empty": "CE", "community-active": "CA"},
                "2026-01-01T00:00:00Z",
            )
            self.assertFalse(stale.exists())
            self.assertFalse((root / "lists" / "youtube" / "community-empty.txt").exists())
            self.assertTrue((root / "lists" / "youtube" / "community-active.txt").exists())
            text = old.read_text(encoding="utf-8")
            self.assertNotIn("victim", text)
            self.assertIn("@top.slop\t9\n@a.b.c\t2\n", text)
            man = json.loads((root / "lists" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(man["schema_version"], 2)
            self.assertEqual(man["lists"]["youtube/yt-rule"]["count"], 2)


@unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
class CommunityTests(unittest.TestCase):
    def row(self, rid, seed=COMMUNITY_TEST_SEED, version="1.0.0", ts=10, **over):
        return {"rule_id": rid, "version": version, "accepted_at": ts,
                "bundle": bundle(rid, WASM, seed, version=version, **over)}

    def test_select(self):
        with test_keys():
            rows = [
                self.row("community-good"),
                self.row("community-good", version="1.1.0", ts=11),
                self.row("community-unverified", seed=TEST_SEED),       # unknown key, also prefix rule
                {**self.row("community-mismatch"), "rule_id": "community-other"},
                {**self.row("community-ver"), "version": "9.9.9"},
                self.row("community-off-rule"),                          # shadows an official id
                {"rule_id": "community-bad", "version": "1.0.0", "accepted_at": 1, "bundle": "{not json"},
                {"rule_id": "../../etc", "version": "1.0.0", "accepted_at": 1, "bundle": {}},
                self.row("community-hostile", ts=12),
            ]
            rows[-1]["bundle"] = bundle("community-hostile", module(body=[0x03, 0x40, 0x0C, 0x00, 0x0B, 0x42, 0x00]),
                                        COMMUNITY_TEST_SEED)
            off = bundle("off-rule", WASM, OFFICIAL_TEST_SEED)
            rows.append({"rule_id": "off-rule", "version": "1.0.0", "accepted_at": 1, "bundle": off})
            chosen, rejected = S.select_community(rows, {"off-rule"}, {})
        self.assertEqual(sorted(chosen), ["community-good"])
        self.assertEqual(chosen["community-good"][1].version, "1.1.0")
        self.assertEqual(len(rejected), 8, rejected)

    def test_no_rollback(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles" / "community").mkdir(parents=True)
            p = root / "bundles" / "community" / "community-good.strule"
            p.write_bytes(bundle_bytes("community-good", WASM, COMMUNITY_TEST_SEED, version="2.0.0"))
            res = S.sync_community(root, FakeWorker(bundles=[self.row("community-good")]), set())
            self.assertEqual([r.version for r in res], ["2.0.0"])
            self.assertIn(b'"2.0.0"', p.read_bytes())


@unittest.skipUnless(HAVE_WASMTIME, "wasmtime not installed")
class EndToEndTests(unittest.TestCase):
    def test_run(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles").mkdir()
            (root / "bundles" / "yt-rule.strule").write_bytes(
                bundle_bytes("yt-rule", WASM, OFFICIAL_TEST_SEED, description="official yt"))
            (root / "leaderboard" / "youtube").mkdir(parents=True)
            prev = {"entries": [{"rule_id": "yt-rule", "band": "S", "coarse_f1": 0.9, "likes": 3},
                                {"rule_id": "gone-rule", "verified": True}],
                    "epoch_id": "E1", "corpus_count": 6}
            (root / "leaderboard" / "youtube" / "leaderboard.json").write_text(json.dumps(prev), encoding="utf-8")
            stale = root / "bundles" / "community" / "community-stale.strule"
            stale.parent.mkdir()
            stale.write_bytes(bundle_bytes("community-stale", WASM, COMMUNITY_TEST_SEED))
            worker = FakeWorker(
                bundles=[{"rule_id": "community-new", "version": "1.0.0", "accepted_at": 5,
                          "bundle": bundle("community-new", WASM, COMMUNITY_TEST_SEED, target_site="*"),
                          "verified": True, "tier": "official"},
                         {"rule_id": "community-evil", "version": "1.0.0", "accepted_at": 6,
                          "bundle": {**bundle("community-evil", WASM, COMMUNITY_TEST_SEED), "verified": True}}],  # extra key
                entries=[{"site": "youtube", "rule_id": "yt-rule", "account_key": "@Slop.Farm", "count": 6, "first_seen": 1},
                         {"site": "youtube", "rule_id": "community-new", "account_key": "@x.y.z", "count": 3, "first_seen": 2},
                         {"site": "youtube", "rule_id": "community-evil", "account_key": "@evil.hit", "count": 9, "first_seen": 3}],
                stats={"window_days": 30, "active_installs": {"yt-rule": 7, "community-new": "9"},
                       "all_time_installs": {"yt-rule": 5}})
            gh = lambda: ({"yt-rule": (4, 12, "https://github.com/sloptrap/sloptrap.github.io/issues/12")}, {}, {})  # noqa: E731
            self.assertEqual(S.run(root, worker, gh, "https://w.example", "2026-11-26T00:00:00Z"), 0)

            self.assertFalse(stale.exists())
            self.assertTrue((root / "bundles" / "community" / "community-new.strule").exists())
            self.assertFalse((root / "bundles" / "community" / "community-evil.strule").exists())
            for site in S.SITES:
                lb = json.loads((root / "leaderboard" / site / "leaderboard.json").read_text(encoding="utf-8"))
                self.assertNotIn("community_entries", lb)
                com = [e for e in lb["entries"] if e["rule_id"].startswith("community-")]
                self.assertEqual([e["rule_id"] for e in com], ["community-new"])
                self.assertTrue(all("bundle_url" not in e for e in lb["entries"]))
                ce = com[0]
                self.assertEqual((ce["verification_tier"], ce["verified"]), ("community", False))
                self.assertEqual(ce["active_installs"], 0)  # "9" is not an int
                self.assertNotIn("band", ce)
            yt = json.loads((root / "leaderboard" / "youtube" / "leaderboard.json").read_text(encoding="utf-8"))
            self.assertEqual([e["rule_id"] for e in yt["entries"]], ["yt-rule", "community-new"])
            e = yt["entries"][0]
            self.assertEqual((e["verification_tier"], e["verified"], e["band"], e["likes"]), ("official", True, "S", 4))
            self.assertEqual((e["active_installs"], e["all_time_installs"]), (7, 7))
            self.assertEqual(e["author_public_key"], OFF_PUB)
            self.assertEqual(yt["epoch_id"], "E1")
            self.assertEqual((root / "leaderboard.json").read_text(), (root / "leaderboard" / "leaderboard.json").read_text())
            lst = (root / "lists" / "youtube" / "yt-rule.txt").read_text(encoding="utf-8")
            self.assertIn("@slop.farm\t6", lst)
            clst = (root / "lists" / "youtube" / "community-new.txt").read_text(encoding="utf-8")
            self.assertIn("@x.y.z\t3", clst)
            self.assertFalse((root / "lists" / "youtube" / "community-evil.txt").exists())
            idx = json.loads((root / "leaderboard" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(idx["sites"][0]["community_count"], 1)

            # The audit agrees with the regenerated leaderboard.
            import audit_bundles as A
            self.assertEqual(A.main(["--root", str(root)]), 0)
            self.assertNotEqual(COM_PUB, OFF_PUB)

    def test_offline_regeneration_makes_no_requests(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles").mkdir()
            (root / "bundles" / "yt-rule.strule").write_bytes(bundle_bytes("yt-rule", WASM, OFFICIAL_TEST_SEED))
            (root / "leaderboard" / "youtube").mkdir(parents=True)
            (root / "leaderboard" / "youtube" / "leaderboard.json").write_text(json.dumps({"entries": [
                {"rule_id": "yt-rule", "active_installs": 3, "band": "A",
                 "bundle_url": "https://github.com/sloptrap/sloptrap.github.io/releases/download/x/yt-rule.strule"}]}))

            def no_net(*_a):
                raise AssertionError("network used in offline mode")
            self.assertEqual(S.run(root, no_net, no_net, "https://w.example", "2026-11-26T00:00:00Z", offline=True), 0)
            e = json.loads((root / "leaderboard" / "youtube" / "leaderboard.json").read_text())["entries"][0]
            self.assertEqual((e["active_installs"], e["band"], e["local_bundle_path"]), (3, "A", "bundles/yt-rule.strule"))
            self.assertNotIn("bundle_url", e)
            self.assertFalse((root / "lists").exists())

    def test_failing_official_bundle_aborts_without_writing(self):
        with test_keys(), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bundles").mkdir()
            (root / "bundles" / "yt-rule.strule").write_bytes(b'{"format":"sloptrap-bundle-v1"}')
            with self.assertRaises(S.SyncError):
                S.run(root, FakeWorker(), lambda: ({}, {}, {}), "https://w.example", "2026-11-26T00:00:00Z")
            self.assertFalse((root / "leaderboard").exists())
            self.assertFalse((root / "lists").exists())

    def test_endpoint_env(self):
        import os
        from unittest import mock
        for bad in ("http://x.example", "https://x.example/path", "file:///etc", "https://u@x.example"):
            with self.subTest(url=bad), mock.patch.dict(os.environ, {"SLOPTRAP_WORKER_URL": bad}):
                with self.assertRaises(S.SyncError):
                    S.endpoint_from_env()


if __name__ == "__main__":
    unittest.main()
