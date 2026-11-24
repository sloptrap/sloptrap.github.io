# SlopTrap GitHub Pages Site (`sloptrap-site`)

Documentation, architecture guide, and live WASM `.strule` Leaderboard site for **SlopTrap**.

## Pages & Feeds

- [`index.html`](./index.html) — SlopTrap overview, interactive TUI screenshot showcase, 6-signal breakdown, and live top WASM rules preview
- [`docs/index.html`](./docs/index.html) — User & operator documentation (installation, TUI controls, headless CLI & autonomous crawler, AiSList auto-reporting, and HTTP API reference)
- [`rules/index.html`](./rules/index.html) — WASM rule developer specification (`ChannelFingerprint` v1 JSON schema, `wasm-v1` guest ABI, `.strule` Ed25519 + HKDF-AES-256-GCM cryptography, and anti-oracle leaderboard design)
- [`leaderboard/index.html`](./leaderboard/index.html) — Interactive WASM Rule Leaderboard with search, sorting, feed URL copy, and `.strule` bundle downloads
- [`leaderboard.json`](./leaderboard.json) & [`bundles/*.strule`](./bundles/) (also mirrored under `leaderboard/` for root or subpath hosting)

## Updating Leaderboard Bundles from `sloptrap`

```bash
cd ../sloptrap
./sloptrap rules build-defaults --out ../sloptrap-site
```
