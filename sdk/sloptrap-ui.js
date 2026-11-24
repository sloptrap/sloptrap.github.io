/**
 * <sloptrap-rules-panel> — Drop-in Gravity UI Web Component
 * ---------------------------------------------------------
 * Embed full SlopTrap rule management (pluggable target site selector, Verified badges,
 * per-rule toggles, Verified-only guard, and Anonymous rule rankings opt-in) into any
 * web application, browser extension options page, or Electron/Tauri view:
 *
 *   <script type="module" src="https://sloptrap.github.io/sdk/sloptrap-ui.js"></script>
 *   <sloptrap-rules-panel site="youtube" verified-only></sloptrap-rules-panel>
 */

import { SlopTrapClient } from "./sloptrap-sdk.js";

const TEMPLATE_CSS = `
  :host {
    display: block;
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 13px;
    line-height: 18px;
    color: var(--g-color-text-primary, rgba(255, 255, 255, 0.88));
  }
  .panel {
    border: 1px solid var(--g-color-line-generic, rgba(255, 255, 255, 0.15));
    border-radius: 8px;
    background: var(--g-color-base-background, rgb(34, 29, 34));
    overflow: hidden;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--g-color-line-generic, rgba(255, 255, 255, 0.15));
    background: var(--g-color-base-generic-ultralight, rgba(255, 255, 255, 0.03));
  }
  .title {
    font-weight: 600;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .seg {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border-radius: 6px;
    background: var(--g-color-base-generic, rgba(255, 255, 255, 0.1));
  }
  .seg button {
    border: 0;
    height: 26px;
    padding: 0 10px;
    border-radius: 5px;
    background: transparent;
    color: var(--g-color-text-secondary, rgba(255, 255, 255, 0.55));
    font-family: inherit;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    text-transform: capitalize;
  }
  .seg button.active {
    background: var(--g-color-base-float, rgb(52, 46, 52));
    color: var(--g-color-text-primary, rgba(255, 255, 255, 0.92));
  }
  .btn {
    height: 28px;
    padding: 0 11px;
    border-radius: 6px;
    border: 0;
    background: var(--g-color-base-brand, rgb(255, 190, 92));
    color: var(--g-color-text-brand-contrast, rgb(26, 22, 26));
    font-family: inherit;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }
  .opts {
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
    padding: 9px 16px;
    border-bottom: 1px solid var(--g-color-line-generic, rgba(255, 255, 255, 0.15));
    font-size: 12px;
    color: var(--g-color-text-secondary, rgba(255, 255, 255, 0.6));
  }
  .opts label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    user-select: none;
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
    padding: 11px 16px;
    border-bottom: 1px solid var(--g-color-line-generic, rgba(255, 255, 255, 0.12));
  }
  .row:last-child { border-bottom: 0; }
  .r-name { font-weight: 600; }
  .r-meta { font-family: monospace; font-size: 11px; opacity: 0.65; margin-left: 6px; }
  .r-desc { font-size: 12px; color: var(--g-color-text-secondary, rgba(255, 255, 255, 0.6)); margin-top: 2px; }
  .badge {
    display: inline-flex;
    align-items: center;
    height: 18px;
    padding: 0 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 500;
    margin-left: 6px;
  }
  .badge-ok {
    background: var(--g-color-base-positive-light, rgba(50, 186, 118, 0.18));
    color: var(--g-color-text-positive, rgb(50, 186, 118));
  }
  .badge-oh {
    background: var(--g-color-base-generic, rgba(255, 255, 255, 0.1));
    color: var(--g-color-text-complementary, rgba(255, 255, 255, 0.72));
    font-family: monospace;
  }
  .status {
    padding: 8px 16px;
    border-top: 1px solid var(--g-color-line-generic, rgba(255, 255, 255, 0.12));
    font-size: 11px;
    color: var(--g-color-text-hint, rgba(255, 255, 255, 0.45));
  }
`;

export class SlopTrapRulesPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this.client = null;
    this.statusText = "Initializing WASM sandbox…";
  }

  connectedCallback() {
    const initialSite = this.getAttribute("site") || "youtube";
    const verifiedOnly = this.hasAttribute("verified-only");
    const registryBaseUrl = this.getAttribute("registry-url") || undefined;

    this.client = new SlopTrapClient({
      site: initialSite,
      verifiedOnly,
      registryBaseUrl,
    });
    this.render();
    this.sync();
  }

  async sync() {
    try {
      this.statusText = `Syncing ${this.client.site} rules…`;
      this.render();
      await this.client.syncRegistry();
      const count = this.client.listRules().length;
      this.statusText = `${count} WebAssembly rule(s) active in browser sandbox for ${this.client.site}.`;
      this.dispatchEvent(new CustomEvent("sloptrap-ready", { detail: { client: this.client } }));
    } catch (err) {
      this.statusText = `Registry sync warning: ${err?.message || err}`;
    }
    this.render();
  }

  esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  render() {
    if (!this.client) return;
    const sites = this.client.availableSites || ["youtube", "tiktok", "pinterest"];
    const rules = this.client.listRules();

    this.shadowRoot.innerHTML = `
      <style>${TEMPLATE_CSS}</style>
      <div class="panel">
        <div class="head">
          <div class="title">
            <span>SlopTrap Rules</span>
            <div class="seg">
              ${sites.map(s => `<button type="button" data-site="${this.esc(s)}" class="${s === this.client.site ? "active" : ""}">${this.esc(s)}</button>`).join("")}
            </div>
          </div>
          <button class="btn" id="sync-btn" type="button">Check Updates</button>
        </div>
        <div class="opts">
          <label><input type="checkbox" id="opt-verified" ${this.client.verifiedOnly ? "checked" : ""}/> Verified rules only</label>
          <label><input type="checkbox" id="opt-anon" ${this.client.anonymousRuleRankings ? "checked" : ""}/> Anonymous rule rankings</label>
        </div>
        <div>
          ${
            rules.length === 0
              ? `<div class="row"><div class="r-desc">No rules loaded yet.</div></div>`
              : rules
                  .map(r => {
                    const m = r.manifest;
                    const p = r.provenance || {};
                    const vBadge = p.verified
                      ? `<span class="badge badge-ok" title="${p.tier === "official" ? "Signed by official SlopTrap maintainer key" : "Source-attested GitHub build"}">Verified · ${p.tier === "official" ? "Official" : "Source"}</span>`
                      : "";
                    return `
                      <div class="row">
                        <div>
                          <div>
                            <span class="r-name">${this.esc(m.name)}</span>
                            <span class="r-meta">v${this.esc(m.version)}</span>
                            ${vBadge}
                            <span class="badge badge-oh">OH ${m.overhead}/10</span>
                          </div>
                          <div class="r-desc">${this.esc(m.description)}</div>
                        </div>
                        <input type="checkbox" data-rule="${this.esc(m.rule_id)}" ${r.enabled ? "checked" : ""} aria-label="Toggle ${this.esc(m.name)}"/>
                      </div>
                    `;
                  })
                  .join("")
          }
        </div>
        <div class="status">${this.esc(this.statusText)}</div>
      </div>
    `;

    this.shadowRoot.querySelectorAll("button[data-site]").forEach(btn => {
      btn.addEventListener("click", async () => {
        await this.client.switchSite(btn.dataset.site);
        this.statusText = `Loaded ${this.client.listRules().length} rule(s) for ${this.client.site}.`;
        this.dispatchEvent(new CustomEvent("sloptrap-change", { detail: { site: this.client.site, client: this.client } }));
        this.render();
      });
    });

    this.shadowRoot.getElementById("sync-btn")?.addEventListener("click", () => this.sync());

    this.shadowRoot.getElementById("opt-verified")?.addEventListener("change", ev => {
      this.client.setVerifiedOnly(ev.target.checked);
      this.render();
    });

    this.shadowRoot.getElementById("opt-anon")?.addEventListener("change", ev => {
      this.client.setAnonymousRuleRankings(ev.target.checked);
    });

    this.shadowRoot.querySelectorAll("input[data-rule]").forEach(chk => {
      chk.addEventListener("change", ev => {
        this.client.toggleRule(chk.dataset.rule, ev.target.checked);
        this.dispatchEvent(new CustomEvent("sloptrap-change", { detail: { ruleId: chk.dataset.rule, enabled: ev.target.checked } }));
      });
    });
  }
}

if (!customElements.get("sloptrap-rules-panel")) {
  customElements.define("sloptrap-rules-panel", SlopTrapRulesPanel);
}
