# SlopTrap GitHub Pages Site (`sloptrap-site`)

Documentation, the hosted Rule Studio build, the JS SDK, the rule leaderboards, signed rule
bundles and pre-matched account lists for **SlopTrap**, served at https://sloptrap.github.io.

## Pages & feeds

- [`index.html`](./index.html): overview and a preview of the top official rules per site
- [`docs/index.html`](./docs/index.html): Studio, SDK and integration documentation
- [`rules/index.html`](./rules/index.html): rule developer specification (canonical fingerprint,
  `wasm-v1` guest ABI, `sloptrap-bundle-v2` format and signature, trust tiers, audit rules)
- [`leaderboard/index.html`](./leaderboard/index.html): per-site leaderboards
  (`leaderboard/<site>/leaderboard.json`; `leaderboard.json` mirrors YouTube)
- [`bundles/*.strule`](./bundles/): official bundles; [`bundles/community/`](./bundles/community/):
  community bundles; [`lists/`](./lists/): pre-matched account lists for official rules

## Bundle format and trust tiers

Every client reads only **`sloptrap-bundle-v2`**. v1 support has been removed and the v1 keys
(`eb85cbf5…`, `33fee5d9…`) are revoked. The tier comes only from the signing key; fields inside
a bundle or a feed (such as `verified` or `provenance`) carry no trust.

| Tier | Key | Notes |
|---|---|---|
| Official | `0540a396ece8ab0f9670a25e03b02e345450a1373b86a7d400dcad79ceec5cc1` | Signed offline by a maintainer. The only tier shown as verified. |
| Community | `34c3c2ee0d51ae18fbf669dc441a51faa06bbfcbf5efa6adf73702d644c5c69e` | Anonymous submissions that passed the private pipeline. Ids start with `community-`. Not reviewed by maintainers; off by default in clients. |
| Unverified | any other key | Never published here; local import only. |

Bundles are **not encrypted**. The v1 "encryption" used a key derived from a public seed, so it
was only obfuscation; v2 carries the plain WASM module, and the Ed25519 signature covers the
whole manifest and the module hash.

## What this repository does (and does not do)

This repository **does not compile or sign rules and holds no secrets**. Anonymous submissions go
from Studio to the Worker, then to a private pipeline that compiles, audits (including a hidden
holdout corpus) and signs passing rules with the community key. Official bundles are signed
locally by a maintainer.

- `scripts/strule_v2.py`: the shared v2 reference implementation (byte-identical in every repo).
- `scripts/audit_bundles.py`: fail-closed audit of every bundle: v2 signature and schema, tier
  from the key, the `community-` id rule, the file name, the static WASM audit, and a sandboxed
  wasmtime run (fuel 10M, 32-page limit, fresh instance per call, output ABI checks). The old
  fixed probe scores are printed for information only and never decide pass or fail.
- `scripts/sync_registry.py` (run by `sync-leaderboard.yml` every 6 hours): pulls community
  bundles and list entries from the Worker, verifies and audits them, re-validates every list row,
  and regenerates the leaderboards.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary :all: -r .github/requirements-ci.txt
.venv/bin/python -I -m unittest discover -s tests      # vectors, PoCs, sync validation
.venv/bin/python -I scripts/audit_bundles.py           # audit bundles/ and the feeds
```

`audit_bundles.py` options: `--allow-empty` (no bundles is not an error), `--static-only`
(skip the wasmtime run; local use only), explicit bundle paths, `--json <file>`.
