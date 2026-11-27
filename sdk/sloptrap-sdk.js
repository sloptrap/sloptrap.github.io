/**
 * SlopTrap JavaScript & WebAssembly SDK — bundle format v2
 * --------------------------------------------------------
 * Zero-dependency ES module for browsers, MV3 service workers, Node 20+ and Deno.
 * This single file is shipped in the browser extension and published verbatim as the site SDK.
 *
 * Normative spec: SlopTrap `.strule` v2 (SPEC-v2.md). Summary of the guarantees:
 *   - Bundles are `sloptrap-bundle-v2`: a strictly validated manifest, a plain wasm payload and an
 *     Ed25519 signature over a canonical digest. v1 bundles and AES "encryption" are not supported.
 *   - Signature verification fails closed: malformed keys/signatures, any WebCrypto exception and
 *     missing Ed25519 support all reject the bundle.
 *   - Trust tiers come only from the pinned key sets below: official (the only "verified" tier),
 *     community (ids must start with `community-`, disabled unless enabled) and unverified
 *     (never loaded from the registry; only from an explicit local import).
 *   - Every module passes a static audit, is instrumented with a fuel counter (20,000,000 per
 *     call), and runs in a fresh instance per evaluation. Rule errors never abort the ensemble,
 *     and `evaluate()` never throws.
 *   - Rule input is the canonical fingerprint (`canonicalFingerprintBytes`), byte-identical to
 *     the Python reference and the Go runtime.
 */

export const SDK_VERSION = "2.0.0";
export const BUNDLE_FORMAT = "sloptrap-bundle-v2";
export const DEFAULT_REGISTRY_BASE = "https://sloptrap.github.io";
export const DEFAULT_RANKINGS_ENDPOINT = "https://sloptrap-worker.fablestre.am";

/** Pinned trust anchors (SPEC §1). Frozen arrays; the lookup sets are private to this module. */
export const OFFICIAL_KEYS = Object.freeze([
  "0540a396ece8ab0f9670a25e03b02e345450a1373b86a7d400dcad79ceec5cc1",
]);
export const COMMUNITY_KEYS = Object.freeze([
  "34c3c2ee0d51ae18fbf669dc441a51faa06bbfcbf5efa6adf73702d644c5c69e",
]);
export const LIST_SIGNING_KEYS = Object.freeze([
  "303607bb2fc5bdebbb50021d3480d59da127d5c40122785ff4b6e228be54b3e1",
]);
export const COMMUNITY_PREFIX = "community-";

export const MAX_BUNDLE_BYTES = 512 * 1024;
export const MAX_WASM_BYTES = 256 * 1024;
export const FUEL_BUDGET = 20_000_000;
export const DEFAULT_WARN_THRESHOLD = 45;
export const DEFAULT_BLOCK_THRESHOLD = 68;
export const DEFAULT_LIST_WARN_THRESHOLD = 2;
export const DEFAULT_LIST_BLOCK_THRESHOLD = 5;
export const DEFAULT_LIST_SATURATION_CAP = 25;
export const LIST_FAST_PATH_SCORE = 85;
export const LIST_FAST_PATH_WARN_SCORE = 56;
export const MAX_LIST_ENTRIES = 200_000;
export const MAX_LIST_BYTES = 8 * 1024 * 1024;

const PINNED_KEYRING = Object.freeze({
  official: new Set(OFFICIAL_KEYS),
  community: new Set(COMMUNITY_KEYS),
  listSigning: new Set(LIST_SIGNING_KEYS),
  test: false,
});

const enc = new TextEncoder();
const decFatal = new TextDecoder("utf-8", { fatal: true });

export class BundleError extends Error {
  constructor(message) {
    super(message);
    this.name = "BundleError";
  }
}

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isPlainObject = v => v !== null && typeof v === "object" && !Array.isArray(v);

// ---------------------------------------------------------------------------------------------
// §2 Manifest validation and canonical bytes
// ---------------------------------------------------------------------------------------------

export const RULE_ID_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const RE = {
  version: /^\d{1,4}\.\d{1,4}\.\d{1,4}$/,
  author: /^@?[A-Za-z0-9_.-]{1,63}$/,
  key: /^[0-9a-f]{64}$/,
  repo: /^https:\/\/github\.com\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)?$/,
  commit: /^[0-9a-f]{40}$/,
  run: /^https:\/\/github\.com\/[A-Za-z0-9_./-]{1,200}$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
};
export const INPUT_KINDS = Object.freeze(["metadata", "upload_cadence", "transcript", "thumbnails", "audio_video_stats"]);
export const TARGET_SITES = Object.freeze(["youtube", "tiktok", "pinterest", "*"]);
const MANIFEST_KEYS = ["rule_id", "name", "version", "author", "author_public_key", "target_site", "description",
  "repo_url", "interpreter", "inputs", "weight_milli", "overhead", "provenance"];
const PROVENANCE_KEYS = ["source_repo", "source_commit", "build_run_url", "submission_id"];

function sameKeySet(obj, keys) {
  const own = Object.keys(obj);
  if (own.length !== keys.length) return false;
  for (const k of keys) if (!hasOwn(obj, k)) return false;
  return true;
}

function cleanStr(s, field, lo, hi) {
  if (typeof s !== "string") throw new BundleError(`${field}: must be a string`);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) throw new BundleError(`${field}: forbidden character (lone surrogate)`);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new BundleError(`${field}: forbidden character (lone surrogate)`);
    } else if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029) {
      throw new BundleError(`${field}: forbidden character U+${c.toString(16).toUpperCase().padStart(4, "0")}`);
    }
    n++;
  }
  if (n < lo || n > hi) throw new BundleError(`${field}: length must be ${lo}..${hi} code points`);
  return s;
}

function checkInt(v, field, lo, hi) {
  if (typeof v !== "number" || !Number.isInteger(v)) throw new BundleError(`${field}: must be an integer`);
  if (v < lo || v > hi) throw new BundleError(`${field}: must be ${lo}..${hi}`);
  return v;
}

function checkMatch(v, field, rx, allowEmpty = false) {
  cleanStr(v, field, 0, 400);
  if (allowEmpty && v === "") return v;
  if (!rx.test(v)) throw new BundleError(`${field}: invalid format`);
  return v;
}

/** Throws BundleError unless `m` is a valid v2 manifest. Returns `m`. */
export function validateManifest(m) {
  if (!isPlainObject(m) || !sameKeySet(m, MANIFEST_KEYS)) {
    throw new BundleError(`manifest: keys must be exactly ${[...MANIFEST_KEYS].sort().join(", ")}`);
  }
  checkMatch(m.rule_id, "rule_id", RULE_ID_RE);
  cleanStr(m.name, "name", 1, 80);
  checkMatch(m.version, "version", RE.version);
  checkMatch(m.author, "author", RE.author);
  checkMatch(m.author_public_key, "author_public_key", RE.key);
  if (typeof m.target_site !== "string" || !TARGET_SITES.includes(m.target_site)) {
    throw new BundleError("target_site: invalid");
  }
  cleanStr(m.description, "description", 0, 500);
  checkMatch(m.repo_url, "repo_url", RE.repo, true);
  if (m.interpreter !== "wasm-v1") throw new BundleError("interpreter: must be wasm-v1");
  const inp = m.inputs;
  if (
    !Array.isArray(inp) ||
    inp.length > 5 ||
    new Set(inp).size !== inp.length ||
    inp.some(i => typeof i !== "string" || !INPUT_KINDS.includes(i))
  ) {
    throw new BundleError("inputs: invalid");
  }
  checkInt(m.weight_milli, "weight_milli", 1, 10000);
  checkInt(m.overhead, "overhead", 1, 100);
  const p = m.provenance;
  if (!isPlainObject(p) || !sameKeySet(p, PROVENANCE_KEYS)) {
    throw new BundleError("provenance: keys must be exactly source_repo, source_commit, build_run_url, submission_id");
  }
  checkMatch(p.source_repo, "provenance.source_repo", RE.repo, true);
  checkMatch(p.source_commit, "provenance.source_commit", RE.commit, true);
  checkMatch(p.build_run_url, "provenance.build_run_url", RE.run, true);
  checkMatch(p.submission_id, "provenance.submission_id", RE.uuid, true);
  return m;
}

const escJsonStr = s => '"' + s.replace(/[\\"]/g, c => "\\" + c) + '"';

function canonJSON(v) {
  if (Array.isArray(v)) return "[" + v.map(canonJSON).join(",") + "]";
  if (isPlainObject(v)) {
    return "{" + Object.keys(v).sort().map(k => escJsonStr(k) + ":" + canonJSON(v[k])).join(",") + "}";
  }
  if (typeof v === "string") return escJsonStr(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return String(v);
  throw new BundleError("canon: unsupported value type");
}

/** UTF-8("sloptrap-manifest-v2\n" + C(manifest)) — validates first. */
export function canonicalManifestBytes(m) {
  validateManifest(m);
  return enc.encode("sloptrap-manifest-v2\n" + canonJSON(m));
}

function subtleOrThrow() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new BundleError("WebCrypto is unavailable");
  return subtle;
}

async function sha256(bytes) {
  return new Uint8Array(await subtleOrThrow().digest("SHA-256", bytes));
}

export async function sha256HexBytes(input) {
  const bytes = typeof input === "string" ? enc.encode(input) : input;
  const digest = await sha256(bytes);
  let out = "";
  for (const b of digest) out += b.toString(16).padStart(2, "0");
  return out;
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** SHA256("sloptrap-sig-v2\n" || canon || "\n" || SHA256(wasm)) */
export async function signingDigest(manifest, wasm) {
  const canon = canonicalManifestBytes(manifest);
  const wasmHash = await sha256(wasm);
  return sha256(concatBytes(enc.encode("sloptrap-sig-v2\n"), canon, enc.encode("\n"), wasmHash));
}

function tierWith(keyring, pubHex) {
  if (keyring.official.has(pubHex)) return "official";
  if (keyring.community.has(pubHex)) return "community";
  return "unverified";
}

/** Tier for a public key under the pinned key sets: "official" | "community" | "unverified". */
export function tierForKey(pubHex) {
  return tierWith(PINNED_KEYRING, String(pubHex));
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function b64ToBytes(s, field) {
  if (typeof s !== "string" || !B64_RE.test(s)) throw new BundleError(`${field}: invalid base64`);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function ed25519Verify(pub, sig, msg) {
  // Fail closed: any exception, including "algorithm not supported", is a rejection.
  try {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle || typeof subtle.importKey !== "function" || typeof subtle.verify !== "function") return false;
    const key = await subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return (await subtle.verify({ name: "Ed25519" }, key, sig, msg)) === true;
  } catch {
    return false;
  }
}

/** Rejects JSON documents that contain any non-integer number token (`1.0`, `1e3`). */
function assertIntegerNumbersOnly(text) {
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inStr = false;
      continue;
    }
    if (c === 0x22) {
      inStr = true;
    } else if (c === 0x2d || (c >= 0x30 && c <= 0x39)) {
      let j = i;
      while (j < text.length && /[-+0-9.eE]/.test(text[j])) j++;
      if (/[.eE]/.test(text.slice(i, j))) {
        throw new BundleError("manifest: numbers must be JSON integers (floats are rejected)");
      }
      i = j - 1;
    }
  }
}

/**
 * Parses bundle JSON text (or UTF-8 bytes) with the v2 size limit and the integer-only rule.
 * Prefer this over JSON.parse: after JSON.parse, `1300.0` is indistinguishable from `1300`.
 */
export function parseBundleText(input) {
  let text = input;
  if (input instanceof ArrayBuffer) input = new Uint8Array(input);
  if (input instanceof Uint8Array) {
    if (input.length > MAX_BUNDLE_BYTES) throw new BundleError("bundle: larger than 512 KiB");
    try {
      text = decFatal.decode(input);
    } catch {
      throw new BundleError("bundle: not valid UTF-8");
    }
  }
  if (typeof text !== "string") throw new BundleError("bundle: expected JSON text");
  if (text.length > MAX_BUNDLE_BYTES || enc.encode(text).length > MAX_BUNDLE_BYTES) {
    throw new BundleError("bundle: larger than 512 KiB");
  }
  assertIntegerNumbersOnly(text);
  try {
    return JSON.parse(text);
  } catch {
    throw new BundleError("bundle: malformed JSON");
  }
}

function deepFreeze(o) {
  if (o && typeof o === "object") {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

async function verifyWith(keyring, bundleInput) {
  const bundle = typeof bundleInput === "string" || bundleInput instanceof Uint8Array || bundleInput instanceof ArrayBuffer
    ? parseBundleText(bundleInput)
    : bundleInput;
  if (!isPlainObject(bundle) || !sameKeySet(bundle, ["format", "manifest", "payload_b64", "signature_b64"])) {
    throw new BundleError("bundle: keys must be exactly format, manifest, payload_b64, signature_b64");
  }
  if (bundle.format !== BUNDLE_FORMAT) {
    throw new BundleError(`bundle: unsupported format ${JSON.stringify(String(bundle.format)).slice(0, 64)}`);
  }
  validateManifest(bundle.manifest);
  const m = deepFreeze(JSON.parse(JSON.stringify(bundle.manifest)));
  const wasm = b64ToBytes(bundle.payload_b64, "payload_b64");
  const sig = b64ToBytes(bundle.signature_b64, "signature_b64");
  const pub = hexToBytes(m.author_public_key);
  // Length checks happen before any crypto call.
  if (pub.length !== 32 || sig.length !== 64) throw new BundleError("bundle: bad key or signature length");
  if (wasm.length > MAX_WASM_BYTES || wasm.length < 8 || wasm[0] !== 0 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d) {
    throw new BundleError("bundle: payload is not a wasm module <= 256 KiB");
  }
  const digest = await signingDigest(m, wasm);
  if (!(await ed25519Verify(pub, sig, digest))) {
    throw new BundleError(`bundle: invalid signature for ${m.rule_id}`);
  }
  const tier = tierWith(keyring, m.author_public_key);
  if ((tier === "community") !== m.rule_id.startsWith(COMMUNITY_PREFIX)) {
    throw new BundleError("bundle: community rule ids must start with 'community-' and only community bundles may use it");
  }
  return { manifest: m, wasm, tier, verified: tier === "official" };
}

/**
 * Verifies a v2 bundle (object, JSON text or UTF-8 bytes) against the pinned keys.
 * Resolves to `{ manifest, wasm, tier, verified }`; rejects with BundleError on any problem.
 */
export function verifyBundle(bundle) {
  return verifyWith(PINNED_KEYRING, bundle);
}

/** Back-compat name: verifies a v2 bundle and returns the raw wasm bytes. */
export async function verifyAndUnpackBundle(bundle) {
  return (await verifyBundle(bundle)).wasm;
}

// ---------------------------------------------------------------------------------------------
// §3 Static WASM audit (full MVP opcode decoder) and §4 fuel instrumentation
// ---------------------------------------------------------------------------------------------

class Reader {
  constructor(bytes, pos = 0, end = bytes.length) {
    this.b = bytes;
    this.pos = pos;
    this.end = end;
  }
  u8() {
    if (this.pos >= this.end) throw new BundleError("audit: unexpected end of data");
    return this.b[this.pos++];
  }
  u32() {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i++) {
      const byte = this.u8();
      if (i === 4 && byte & 0xf0) throw new BundleError("audit: LEB128 u32 overflow");
      result += (byte & 0x7f) * 2 ** shift;
      if (!(byte & 0x80)) return result;
      shift += 7;
    }
    throw new BundleError("audit: LEB128 too long");
  }
  sleb(maxBytes) {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < maxBytes; i++) {
      const byte = this.u8();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if (!(byte & 0x80)) {
        if (byte & 0x40) result -= 1n << shift;
        return result;
      }
    }
    throw new BundleError("audit: signed LEB128 too long");
  }
  s32() {
    const v = this.sleb(5);
    if (v < -(2n ** 31n) || v >= 2n ** 31n) throw new BundleError("audit: i32 constant out of range");
    return Number(v);
  }
  s64() {
    this.sleb(10);
  }
  skip(n) {
    if (this.pos + n > this.end) throw new BundleError("audit: unexpected end of data");
    this.pos += n;
  }
  name() {
    const len = this.u32();
    const start = this.pos;
    this.skip(len);
    try {
      return decFatal.decode(this.b.subarray(start, start + len));
    } catch {
      throw new BundleError("audit: invalid UTF-8 name");
    }
  }
}

const VALTYPES = new Set([0x7f, 0x7e, 0x7d, 0x7c]);
const SECTION_RANK = new Map([[1, 1], [3, 2], [5, 3], [6, 4], [7, 5], [12, 6], [10, 7], [11, 8]]);
const MAX_PAGES = 32;
const MAX_FUNCS = 1024;
const MAX_GLOBALS = 64;
const MAX_DATA = 64;
const MAX_LOCALS = 50000;

const FORBIDDEN_OPS = new Map([
  [0x06, "try"], [0x07, "catch"], [0x08, "throw"], [0x09, "rethrow"], [0x18, "delegate"], [0x19, "catch_all"],
  [0x11, "call_indirect"], [0x12, "return_call"], [0x13, "return_call_indirect"], [0x1c, "typed select"],
  [0x25, "table.get"], [0x26, "table.set"], [0xbc, "i32.reinterpret_f32"], [0xbd, "i64.reinterpret_f64"],
  [0xbe, "f32.reinterpret_i32"], [0xbf, "f64.reinterpret_i64"], [0xfd, "SIMD prefix"], [0xfe, "atomics prefix"],
]);
for (let op = 0xd0; op <= 0xd6; op++) FORBIDDEN_OPS.set(op, "reference op");

function readBlockType(r) {
  const bt = r.u8();
  if (bt !== 0x40 && !VALTYPES.has(bt)) throw new BundleError("audit: only empty or single-value block types are allowed");
}

function readConstExprI32(r) {
  if (r.u8() !== 0x41) throw new BundleError("audit: data segment offset must be i32.const");
  const v = r.s32();
  if (r.u8() !== 0x0b) throw new BundleError("audit: data segment offset must be a single i32.const");
  return v >>> 0;
}

function readGlobalInit(r, valtype) {
  const op = r.u8();
  if (op === 0x41 && valtype === 0x7f) r.s32();
  else if (op === 0x42 && valtype === 0x7e) r.s64();
  else if (op === 0x43 && valtype === 0x7d) r.skip(4);
  else if (op === 0x44 && valtype === 0x7c) r.skip(8);
  else throw new BundleError("audit: global initializer must be a matching constant");
  if (r.u8() !== 0x0b) throw new BundleError("audit: global initializer must be a single constant");
}

function decodeFunctionBody(bytes, start, end, ctx, paramCount) {
  const r = new Reader(bytes, start, end);
  const groupCount = r.u32();
  let nLocals = paramCount;
  for (let g = 0; g < groupCount; g++) {
    const cnt = r.u32();
    const t = r.u8();
    if (!VALTYPES.has(t)) throw new BundleError("audit: invalid local type");
    nLocals += cnt;
    if (nLocals > MAX_LOCALS) throw new BundleError("audit: too many locals");
  }
  const localsEnd = r.pos;
  // Fuel frames: frame 0 is the function entry; one frame per loop. Each instruction is charged
  // to its innermost enclosing loop (or the function), giving a per-iteration upper bound.
  const frames = [{ insertAt: localsEnd, cost: 0 }];
  const frameStack = [0];
  const ctl = [];
  const bulk = [];
  for (;;) {
    const opPos = r.pos;
    const op = r.u8();
    frames[frameStack[frameStack.length - 1]].cost++;
    switch (op) {
      case 0x00: case 0x01: case 0x0f: case 0x1a: case 0x1b:
        break;
      case 0x02:
        readBlockType(r);
        ctl.push({ loop: false, isIf: false });
        break;
      case 0x04:
        readBlockType(r);
        ctl.push({ loop: false, isIf: true, sawElse: false });
        break;
      case 0x03:
        readBlockType(r);
        frames.push({ insertAt: r.pos, cost: 0 });
        frameStack.push(frames.length - 1);
        ctl.push({ loop: true, isIf: false });
        break;
      case 0x05: {
        const top = ctl[ctl.length - 1];
        if (!top || !top.isIf || top.sawElse) throw new BundleError("audit: misplaced else");
        top.sawElse = true;
        break;
      }
      case 0x0b:
        if (ctl.length === 0) {
          if (r.pos !== end) throw new BundleError("audit: trailing bytes after function end");
          return { localsEnd, groupCount, nLocals, frames, bulk };
        }
        if (ctl.pop().loop) frameStack.pop();
        break;
      case 0x0c: case 0x0d:
        if (r.u32() > ctl.length) throw new BundleError("audit: branch depth out of range");
        break;
      case 0x0e: {
        const n = r.u32();
        if (n > 65536) throw new BundleError("audit: br_table too large");
        for (let i = 0; i <= n; i++) if (r.u32() > ctl.length) throw new BundleError("audit: branch depth out of range");
        break;
      }
      case 0x10:
        if (r.u32() >= ctx.numFuncs) throw new BundleError("audit: call target out of range");
        break;
      case 0x20: case 0x21: case 0x22:
        if (r.u32() >= nLocals) throw new BundleError("audit: local index out of range");
        break;
      case 0x23: case 0x24:
        if (r.u32() >= ctx.numGlobals) throw new BundleError("audit: global index out of range");
        break;
      case 0x3f: case 0x40:
        if (r.u8() !== 0) throw new BundleError("audit: memory index must be 0");
        break;
      case 0x41: r.s32(); break;
      case 0x42: r.s64(); break;
      case 0x43: r.skip(4); break;
      case 0x44: r.skip(8); break;
      case 0xfc: {
        const sub = r.u32();
        if (sub <= 7) break;
        if (sub === 10) {
          if (r.u8() !== 0 || r.u8() !== 0) throw new BundleError("audit: memory index must be 0");
          bulk.push(opPos);
          break;
        }
        if (sub === 11) {
          if (r.u8() !== 0) throw new BundleError("audit: memory index must be 0");
          bulk.push(opPos);
          break;
        }
        throw new BundleError(`audit: forbidden opcode 0xFC ${sub}`);
      }
      default:
        if (op >= 0x28 && op <= 0x3e) {
          r.u32();
          r.u32();
          break;
        }
        if (op >= 0x45 && op <= 0xbb) break;
        if (FORBIDDEN_OPS.has(op)) throw new BundleError(`audit: forbidden opcode ${FORBIDDEN_OPS.get(op)} (0x${op.toString(16)})`);
        throw new BundleError(`audit: unknown opcode 0x${op.toString(16)}`);
    }
  }
}

function auditModule(wasm) {
  if (!(wasm instanceof Uint8Array)) throw new BundleError("audit: expected bytes");
  if (wasm.length > MAX_WASM_BYTES) throw new BundleError("audit: module larger than 256 KiB");
  if (wasm.length < 8 || wasm[0] !== 0 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d ||
      wasm[4] !== 1 || wasm[5] !== 0 || wasm[6] !== 0 || wasm[7] !== 0) {
    throw new BundleError("audit: bad wasm header");
  }
  const r = new Reader(wasm, 8);
  const sections = [];
  let lastRank = 0;
  while (r.pos < r.end) {
    const id = r.u8();
    const size = r.u32();
    const start = r.pos;
    r.skip(size);
    if (id === 0) continue;
    if (!SECTION_RANK.has(id)) {
      const names = { 2: "import", 4: "table", 8: "start", 9: "element" };
      throw new BundleError(`audit: forbidden section ${names[id] || id}`);
    }
    const rank = SECTION_RANK.get(id);
    if (rank <= lastRank) throw new BundleError(`audit: duplicate or out-of-order section ${id}`);
    lastRank = rank;
    sections.push({ id, start, end: start + size });
  }
  const sec = id => sections.find(s => s.id === id);
  const done = (sr, what) => {
    if (sr.pos !== sr.end) throw new BundleError(`audit: malformed ${what} section`);
  };

  // Types
  const types = [];
  if (sec(1)) {
    const s = sec(1);
    const sr = new Reader(wasm, s.start, s.end);
    const n = sr.u32();
    if (n > 4096) throw new BundleError("audit: too many types");
    for (let i = 0; i < n; i++) {
      if (sr.u8() !== 0x60) throw new BundleError("audit: invalid function type");
      const np = sr.u32();
      if (np > 1000) throw new BundleError("audit: too many params");
      const params = [];
      for (let j = 0; j < np; j++) {
        const t = sr.u8();
        if (!VALTYPES.has(t)) throw new BundleError("audit: invalid param type");
        params.push(t);
      }
      const nr = sr.u32();
      if (nr > 1) throw new BundleError("audit: multi-value results are not allowed");
      const results = [];
      for (let j = 0; j < nr; j++) {
        const t = sr.u8();
        if (!VALTYPES.has(t)) throw new BundleError("audit: invalid result type");
        results.push(t);
      }
      types.push({ params, results });
    }
    done(sr, "type");
  }

  // Functions
  const funcTypes = [];
  if (sec(3)) {
    const s = sec(3);
    const sr = new Reader(wasm, s.start, s.end);
    const n = sr.u32();
    if (n > MAX_FUNCS) throw new BundleError("audit: more than 1024 functions");
    for (let i = 0; i < n; i++) {
      const t = sr.u32();
      if (t >= types.length) throw new BundleError("audit: function type index out of range");
      funcTypes.push(t);
    }
    done(sr, "function");
  }

  // Memory
  let memMin = 0;
  {
    const s = sec(5);
    if (!s) throw new BundleError("audit: exactly one memory is required");
    const sr = new Reader(wasm, s.start, s.end);
    if (sr.u32() !== 1) throw new BundleError("audit: exactly one memory is required");
    const flags = sr.u8();
    if (flags !== 0x01) throw new BundleError("audit: memory must declare a maximum (and must not be shared/64-bit)");
    memMin = sr.u32();
    const memMax = sr.u32();
    if (memMin > memMax || memMax > MAX_PAGES) throw new BundleError("audit: memory limits must satisfy min <= max <= 32 pages");
    done(sr, "memory");
  }

  // Globals
  let numGlobals = 0;
  if (sec(6)) {
    const s = sec(6);
    const sr = new Reader(wasm, s.start, s.end);
    numGlobals = sr.u32();
    if (numGlobals > MAX_GLOBALS) throw new BundleError("audit: more than 64 globals");
    for (let i = 0; i < numGlobals; i++) {
      const t = sr.u8();
      if (!VALTYPES.has(t)) throw new BundleError("audit: invalid global type");
      const mut = sr.u8();
      if (mut > 1) throw new BundleError("audit: invalid global mutability");
      readGlobalInit(sr, t);
    }
    done(sr, "global");
  }

  // Exports
  {
    const s = sec(7);
    if (!s) throw new BundleError("audit: missing exports");
    const sr = new Reader(wasm, s.start, s.end);
    const n = sr.u32();
    const seen = new Set();
    for (let i = 0; i < n; i++) {
      const name = sr.name();
      const kind = sr.u8();
      const idx = sr.u32();
      if (seen.has(name)) throw new BundleError("audit: duplicate export");
      seen.add(name);
      const sig = k => {
        if (kind !== 0 || idx >= funcTypes.length) throw new BundleError(`audit: export ${name} must be a function`);
        const t = types[funcTypes[idx]];
        return `${t.params.join(",")}>${t.results.join(",")}`;
      };
      if (name === "memory") {
        if (kind !== 2 || idx !== 0) throw new BundleError("audit: export memory must be memory 0");
      } else if (name === "st_evaluate") {
        if (sig() !== "127,127>126") throw new BundleError("audit: st_evaluate must have type (i32,i32)->(i64)");
      } else if (name === "st_alloc") {
        if (sig() !== "127>127") throw new BundleError("audit: st_alloc must have type (i32)->(i32)");
      } else {
        throw new BundleError(`audit: export ${JSON.stringify(name).slice(0, 40)} is not allowed`);
      }
    }
    if (!seen.has("memory") || !seen.has("st_evaluate")) throw new BundleError("audit: exports memory and st_evaluate are required");
    done(sr, "export");
  }

  // Data
  let dataCount = 0;
  if (sec(11)) {
    const s = sec(11);
    const sr = new Reader(wasm, s.start, s.end);
    dataCount = sr.u32();
    if (dataCount > MAX_DATA) throw new BundleError("audit: more than 64 data segments");
    for (let i = 0; i < dataCount; i++) {
      const flags = sr.u32();
      let offset = null;
      if (flags === 0) offset = readConstExprI32(sr);
      else if (flags === 2) {
        if (sr.u32() !== 0) throw new BundleError("audit: data segment must target memory 0");
        offset = readConstExprI32(sr);
      } else if (flags !== 1) throw new BundleError("audit: invalid data segment flags");
      const len = sr.u32();
      sr.skip(len);
      if (offset !== null && offset + len > memMin * 65536) throw new BundleError("audit: data segment out of bounds");
    }
    done(sr, "data");
  }
  if (sec(12)) {
    const s = sec(12);
    const sr = new Reader(wasm, s.start, s.end);
    if (sr.u32() !== dataCount) throw new BundleError("audit: datacount mismatch");
    done(sr, "datacount");
  }

  // Code
  const bodies = [];
  {
    const s = sec(10);
    const n = s ? new Reader(wasm, s.start, s.end).u32() : 0;
    if (n !== funcTypes.length) throw new BundleError("audit: code/function count mismatch");
    if (s) {
      const sr = new Reader(wasm, s.start, s.end);
      sr.u32();
      const ctx = { numFuncs: funcTypes.length, numGlobals };
      for (let i = 0; i < n; i++) {
        const size = sr.u32();
        const start = sr.pos;
        sr.skip(size);
        const info = decodeFunctionBody(wasm, start, start + size, ctx, types[funcTypes[i]].params.length);
        bodies.push({ start, end: start + size, ...info });
      }
      done(sr, "code");
    }
  }
  return { sections, numGlobals, bodies };
}

/** SPEC §3 static audit. Never throws: `{ ok: true }` or `{ ok: false, error }`. */
export function auditWasm(bytes) {
  try {
    auditModule(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
}

const uleb = v => {
  const o = [];
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v) b |= 0x80;
    o.push(b);
  } while (v);
  return o;
};
const sleb32 = v => {
  const o = [];
  for (;;) {
    const b = v & 0x7f;
    v >>= 7;
    if ((v === 0 && !(b & 0x40)) || (v === -1 && b & 0x40)) {
      o.push(b);
      return o;
    }
    o.push(b | 0x80);
  }
};

/**
 * Audits a module and rewrites it with a fuel counter: one new mutable i32 global initialised to
 * `budget`, charged at every function entry and loop header with the static instruction count of
 * that block (plus n/64 for memory.copy/memory.fill), trapping when it goes negative.
 */
export function instrumentWasm(bytes, budget = FUEL_BUDGET) {
  const wasm = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const info = auditModule(wasm);
  const G = uleb(info.numGlobals);
  const charge = cost => [0x23, ...G, 0x41, ...sleb32(cost), 0x6b, 0x24, ...G, 0x23, ...G, 0x41, 0x00, 0x48, 0x04, 0x40, 0x00, 0x0b];
  const bulkCharge = L => [0x22, ...L, 0x23, ...G, 0x20, ...L, 0x41, 0x06, 0x76, 0x6b, 0x24, ...G,
    0x23, ...G, 0x41, 0x00, 0x48, 0x04, 0x40, 0x00, 0x0b];

  const out = [0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
  const pushSection = (id, payload) => {
    out.push(id, ...uleb(payload.length));
    for (let i = 0; i < payload.length; i++) out.push(payload[i]);
  };
  const newGlobal = [0x7f, 0x01, 0x41, ...sleb32(budget), 0x0b];
  let globalWritten = false;
  for (const s of info.sections) {
    if (!globalWritten && SECTION_RANK.get(s.id) > SECTION_RANK.get(6)) {
      pushSection(6, [...uleb(1), ...newGlobal]);
      globalWritten = true;
    }
    if (s.id === 6) {
      const sr = new Reader(wasm, s.start, s.end);
      const n = sr.u32();
      pushSection(6, [...uleb(n + 1), ...wasm.subarray(sr.pos, s.end), ...newGlobal]);
      globalWritten = true;
    } else if (s.id === 10) {
      const payload = [...uleb(info.bodies.length)];
      for (const b of info.bodies) {
        const inserts = b.frames.map((f, i) => ({ at: f.insertAt, order: i === 0 ? 0 : 1, code: charge(f.cost) }));
        let header;
        if (b.bulk.length > 0) {
          const L = uleb(b.nLocals);
          for (const at of b.bulk) inserts.push({ at, order: 2, code: bulkCharge(L) });
          const gr = new Reader(wasm, b.start, b.end);
          gr.u32();
          header = [...uleb(b.groupCount + 1), ...wasm.subarray(gr.pos, b.localsEnd), 0x01, 0x7f];
        } else {
          header = [...wasm.subarray(b.start, b.localsEnd)];
        }
        inserts.sort((a, c) => a.at - c.at || a.order - c.order);
        const body = header;
        let cursor = b.localsEnd;
        for (const ins of inserts) {
          for (let i = cursor; i < ins.at; i++) body.push(wasm[i]);
          cursor = ins.at;
          for (const x of ins.code) body.push(x);
        }
        for (let i = cursor; i < b.end; i++) body.push(wasm[i]);
        payload.push(...uleb(body.length));
        for (const x of body) payload.push(x);
      }
      pushSection(10, payload);
    } else {
      pushSection(s.id, wasm.subarray(s.start, s.end));
    }
  }
  if (!globalWritten) pushSection(6, [...uleb(1), ...newGlobal]);
  return new Uint8Array(out);
}

// ---------------------------------------------------------------------------------------------
// §5 Canonical fingerprint
// ---------------------------------------------------------------------------------------------

const S = "s", I = "i", F = "f", B = "b";
const FP_SCHEMA = [
  ["schema_version", I], ["site", S],
  ["channel", [["channel_id", S], ["handle", S], ["title", S], ["description", S], ["subscriber_count", I],
    ["total_videos", I], ["has_auto_suffix", B], ["stem_siblings", I], ["outbound_domain_share", F]]],
  ["upload_cadence", [["channel_age_days", F], ["max_dormancy_gap_days", F], ["pre_pivot_videos", I],
    ["post_pivot_videos", I], ["post_pivot_share", F], ["recent_uploads_per_day", F], ["output_minutes_per_week", F],
    ["avg_duration_sec", F], ["duration_cv", F], ["schedule_hour_stddev", F]]],
  ["transcript", [["videos_sampled", I], ["total_words", I], ["uncontracted_ratio", F], ["first_person_per_1k", F],
    ["disfluencies_per_1k", F], ["antithesis_per_1k", F], ["slop_hooks_per_1k", F], ["llm_lexicon_per_1k", F],
    ["keyword_stuffing_ratio", F], ["mean_wpm", F], ["cross_video_wpm_stddev", F], ["intra_video_wpm_cv", F],
    ["pause_cv", F], ["earliest_has_speech", B]]],
  ["thumbnails", [["title_skeleton_reuse", F], ["raw_camera_earliest_title", B], ["synthetic_image_ratio", F],
    ["aspect_uniformity", F], ["repost_watermark_ratio", F]]],
  ["audio_video_stats", [["earliest_vertical", B], ["earliest_max_dim", I], ["recent_widescreen_hd_ratio", F],
    ["altered_content_flag", B], ["dead_air_floor", B], ["loudness_range_lu", F], ["silence_cv", F]]],
  ["sample_text", S],
];
const STR_CAPS = { handle: 100, channel_id: 100, title: 200, description: 2000, site: 32, sample_text: 4000 };
const TRUE_DEFAULTS = new Set(["earliest_has_speech"]);
const MAX_SAFE = 9007199254740991;
const PY_FLOAT_RE = /^[+-]?(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?$/;

function normStr(v, key) {
  let s;
  if (v === null || v === undefined) s = "";
  else if (typeof v === "string") s = v;
  else if (typeof v === "boolean") s = v ? "True" : "False";
  else if (typeof v === "number" || typeof v === "bigint") s = String(v);
  else s = "";
  const cap = hasOwn(STR_CAPS, key) ? STR_CAPS[key] : 4000;
  let out = "";
  let n = 0;
  for (let i = 0; i < s.length && n < cap; i++, n++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s[i] + s[i + 1];
        i++;
        continue;
      }
    }
    if (c >= 0xd800 && c <= 0xdfff) out += "�";
    else if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029) out += " ";
    else out += s[i];
  }
  return out;
}

function pyNum(v) {
  let f = 0;
  if (typeof v === "boolean") f = v ? 1 : 0;
  else if (typeof v === "number") f = v;
  else if (typeof v === "bigint") f = Number(v);
  else if (typeof v === "string") {
    const t = v.trim();
    f = PY_FLOAT_RE.test(t) ? Number(t.replace(/_/g, "")) : 0;
  }
  return Number.isFinite(f) ? f : 0;
}

function normInt(v) {
  const i = Math.trunc(pyNum(v));
  return i <= 0 ? 0 : i > MAX_SAFE ? MAX_SAFE : i;
}

function normFloat(v) {
  let f = Math.floor(pyNum(v) * 1e6 + 0.5) / 1e6;
  if (!(f <= 1e12)) f = f !== f ? 0 : 1e12;
  if (f < -1e12) f = -1e12;
  return f === 0 ? 0 : f;
}

function pyTruthy(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string" || Array.isArray(v)) return v.length > 0;
  if (v && typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
}

function fmtFloat(f) {
  const s = String(f);
  if (!/[eE]/.test(s)) return s;
  return f.toFixed(6).replace(/\.?0+$/, "");
}

function normalizeTree(schema, src, site, top) {
  const out = {};
  for (const [key, t] of schema) {
    const v = isPlainObject(src) && hasOwn(src, key) ? src[key] : undefined;
    if (Array.isArray(t)) {
      out[key] = normalizeTree(t, isPlainObject(v) ? v : {}, site, false);
    } else if (top && key === "schema_version") {
      out[key] = 1;
    } else if (t === S) {
      out[key] = normStr(top && key === "site" && (v === null || v === undefined || v === "") ? site : v, key);
    } else if (t === I) {
      out[key] = normInt(v);
    } else if (t === F) {
      out[key] = normFloat(v);
    } else {
      out[key] = v === null || v === undefined ? TRUE_DEFAULTS.has(key) : pyTruthy(v);
    }
  }
  return out;
}

function serializeTree(schema, obj) {
  const parts = [];
  for (const [key, t] of schema) {
    const v = obj[key];
    let encv;
    if (Array.isArray(t)) encv = serializeTree(t, v);
    else if (t === S) encv = escJsonStr(v);
    else if (t === I) encv = String(v);
    else if (t === F) encv = fmtFloat(v);
    else encv = v ? "true" : "false";
    parts.push(escJsonStr(key) + ":" + encv);
  }
  return "{" + parts.join(",") + "}";
}

/** Returns a new fingerprint object with every SPEC §5 field, normalized, in canonical order. */
export function normalizeFingerprint(fp, site = "youtube") {
  return normalizeTree(FP_SCHEMA, isPlainObject(fp) ? fp : {}, site, true);
}

/** Canonical fingerprint JSON text (SPEC §5). */
export function canonicalFingerprintJSON(fp, site = "youtube") {
  return serializeTree(FP_SCHEMA, normalizeFingerprint(fp, site));
}

/** Canonical fingerprint bytes (SPEC §5) — the only rule input. */
export function canonicalFingerprintBytes(fp, site = "youtube") {
  return enc.encode(canonicalFingerprintJSON(fp, site));
}

// ---------------------------------------------------------------------------------------------
// Account keys, lists and site adapters
// ---------------------------------------------------------------------------------------------

export function normalizeAccountKey(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return "";
  if (s.startsWith("UC") && s.length >= 20 && !s.includes("/")) return s;
  return (s.startsWith("@") ? s : `@${s}`).toLowerCase();
}

/**
 * Parses v2 `<account_key>\t<count>` (or legacy bare `<account_key>`) list files into
 * `Map<normalizedAccountKey, count>`. Bare legacy entries default to count `1` (L8).
 */
export function parseAccountListCounts(txt) {
  const map = new Map();
  const text = String(txt ?? "");
  if (text.length > MAX_LIST_BYTES) return map;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const norm = normalizeAccountKey(parts[0]);
    if (!norm || norm.length > 101) continue;
    let cnt = 1;
    if (parts.length >= 2) {
      if (!/^\d{1,10}$/.test(parts[1])) continue;
      cnt = Number(parts[1]);
      if (!Number.isSafeInteger(cnt) || cnt < 1) continue;
    }
    const prev = map.get(norm) || 0;
    if (cnt > prev) map.set(norm, cnt);
    if (map.size >= MAX_LIST_ENTRIES) break;
  }
  return map;
}

const LIST_MANIFEST_SITES = new Set(["youtube", "tiktok", "pinterest"]);
const ISO_Z_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export const DEFAULT_MAX_LIST_MANIFEST_AGE_SECONDS = 14 * 86400;

export function parseListGeneratedAt(generatedAt) {
  if (typeof generatedAt !== "string" || !ISO_Z_RE.test(generatedAt)) {
    throw new BundleError("list manifest: invalid generated_at");
  }
  const ms = Date.parse(generatedAt);
  if (!Number.isFinite(ms)) {
    throw new BundleError("list manifest: invalid generated_at");
  }
  return Math.floor(ms / 1000);
}

export function canonicalListManifestBytes(generatedAt, listsObj) {
  parseListGeneratedAt(generatedAt);
  if (!isPlainObject(listsObj)) {
    throw new BundleError("list manifest: lists must be an object");
  }
  const keys = Object.keys(listsObj).sort();
  if (keys.length > 2000) throw new BundleError("list manifest: too many list entries");
  const lines = keys.map(k => {
    const it = listsObj[k];
    if (!isPlainObject(it)) throw new BundleError(`list manifest: ${k} must be an object`);
    const { site, rule_id: rid, path, count, sha256: sha } = it;
    if (typeof site !== "string" || !LIST_MANIFEST_SITES.has(site)) {
      throw new BundleError(`list manifest: invalid site ${String(site)}`);
    }
    if (typeof rid !== "string" || !RULE_ID_RE.test(rid)) {
      throw new BundleError(`list manifest: invalid rule_id ${String(rid)}`);
    }
    if (k !== `${site}/${rid}` || path !== `lists/${site}/${rid}.txt`) {
      throw new BundleError(`list manifest: mismatched key or path for ${k}`);
    }
    if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0 || count > 1_000_000_000) {
      throw new BundleError(`list manifest: invalid count for ${k}`);
    }
    if (typeof sha !== "string" || !RE.key.test(sha)) {
      throw new BundleError(`list manifest: invalid sha256 for ${k}`);
    }
    return `${site}\t${rid}\t${path}\t${count}\t${sha}`;
  });
  return enc.encode(`sloptrap-list-manifest-v2\n${generatedAt}\n${lines.join("\n")}`);
}

/**
 * Verifies the Ed25519 signature, freshness, and rollback monotonicity of `lists/manifest.json`
 * against pinned `LIST_SIGNING_KEYS` (M4, V3-L1). Fails closed on unsigned, tampered, stale, or rolled-back manifests.
 */
export async function verifyListManifest(manifestDoc, allowedKeys = PINNED_KEYRING.listSigning, opts = {}) {
  const doc = typeof manifestDoc === "string" ? JSON.parse(manifestDoc) : manifestDoc;
  if (!isPlainObject(doc) || doc.schema_version !== 2) {
    throw new BundleError("list manifest: unsupported schema_version");
  }
  const pubHex = doc.public_key;
  const keySet = allowedKeys instanceof Set ? allowedKeys : new Set(allowedKeys || LIST_SIGNING_KEYS);
  if (typeof pubHex !== "string" || !RE.key.test(pubHex) || !keySet.has(pubHex)) {
    throw new BundleError("list manifest: untrusted or missing public_key");
  }
  const sig = b64ToBytes(doc.signature_b64, "list manifest signature_b64");
  if (sig.length !== 64) throw new BundleError("list manifest: signature must be 64 bytes");
  const genSec = parseListGeneratedAt(doc.generated_at);
  const msg = canonicalListManifestBytes(doc.generated_at, doc.lists);
  const pub = hexToBytes(pubHex);
  if (!(await ed25519Verify(pub, sig, msg))) {
    throw new BundleError("list manifest: invalid Ed25519 signature");
  }
  const minGen = Number(opts?.minGeneratedAt || 0);
  if (minGen > 0 && genSec < minGen) {
    throw new BundleError(`list manifest: rollback rejected (${genSec} < ${minGen})`);
  }
  const nowSec = Number(opts?.nowSec || 0);
  const maxAge = opts?.maxAgeSeconds === undefined ? DEFAULT_MAX_LIST_MANIFEST_AGE_SECONDS : Number(opts.maxAgeSeconds);
  if (nowSec > 0) {
    if (maxAge > 0 && (nowSec - genSec) > maxAge) {
      throw new BundleError(`list manifest: stale manifest rejected (age ${nowSec - genSec}s > ${maxAge}s)`);
    }
    if (genSec > nowSec + 3600) {
      throw new BundleError("list manifest: future-dated manifest rejected");
    }
  }
  for (const [k, it] of Object.entries(doc.lists)) {
    if (it.signature_b64 !== undefined) {
      const isig = b64ToBytes(it.signature_b64, `${k}.signature_b64`);
      if (isig.length !== 64) throw new BundleError(`list manifest: ${k} signature must be 64 bytes`);
      const imsg = enc.encode(
        `sloptrap-list-item-v2\n${it.site}\t${it.rule_id}\t${it.path}\t${it.count}\t${it.sha256}\t${doc.generated_at}`
      );
      if (!(await ed25519Verify(pub, isig, imsg))) {
        throw new BundleError(`list manifest: invalid item signature for ${k}`);
      }
    }
  }
  return doc;
}

export function parseAccountListText(txt) {
  return new Set(parseAccountListCounts(txt).keys());
}

const siteAdapters = new Map();

export function registerSiteAdapter(adapter) {
  if (!adapter || !adapter.siteId) throw new Error("Adapter requires siteId");
  siteAdapters.set(String(adapter.siteId).toLowerCase(), adapter);
}

export function getSiteAdapter(siteId) {
  return siteAdapters.get(String(siteId || "").toLowerCase()) || null;
}

export function listRegisteredSites() {
  return [...siteAdapters.keys()];
}

registerSiteAdapter({ siteId: "youtube", displayName: "YouTube", matchUrl: u => /youtube\.com|youtu\.be/i.test(u) });
registerSiteAdapter({ siteId: "tiktok", displayName: "TikTok", matchUrl: u => /tiktok\.com/i.test(u) });
registerSiteAdapter({ siteId: "pinterest", displayName: "Pinterest", matchUrl: u => /pinterest\.|pin\.it/i.test(u) });

const AUTO_SUFFIX_RE = /^@[a-z0-9_.]{5,}-[a-z0-9]{1,5}$/i;
const KEYWORD_STUFF_RE = /(?:#[a-z0-9_]+|\b(?:ai|midjourney|sdxl|generated|viral|fyp|trending|aesthetic|decor|ideas)\b)/gi;
const num = v => (v === undefined || v === null || v === "" ? undefined : v);

/**
 * Maps a scraped account snapshot (camelCase, as produced by the extension's content adapters)
 * to the canonical fingerprint: every SPEC §5 field, normalized, in canonical order.
 */
export function normalizeAccountSnapshot(site, snap = {}) {
  const sn = isPlainObject(snap) ? snap : {};
  const rawHandle = String(sn.handle ?? "").trim();
  const handle = rawHandle && !rawHandle.startsWith("@") && !/^UC[\w-]{20,}$/.test(rawHandle) ? `@${rawHandle}` : rawHandle;
  const posts = Array.isArray(sn.posts) ? sn.posts.slice(0, 200) : [];
  let keywordHits = 0;
  let totalWords = 0;
  let synthHits = 0;
  let watermarkHits = 0;
  const domains = new Map();
  let outboundTotal = 0;
  const texts = [];
  for (const p of posts) {
    if (!isPlainObject(p)) continue;
    const txt = `${p.title ?? ""} ${p.caption ?? ""}`.trim().slice(0, 4000);
    if (txt) texts.push(txt);
    totalWords += txt ? txt.split(/\s+/).length : 0;
    keywordHits += (txt.match(KEYWORD_STUFF_RE) || []).length;
    if (p.syntheticHint) synthHits++;
    if (p.repostWatermark) watermarkHits++;
    if (p.outboundDomain) {
      const d = String(p.outboundDomain).toLowerCase().replace(/^www\./, "");
      domains.set(d, (domains.get(d) || 0) + 1);
      outboundTotal++;
    }
  }
  let maxDomain = 0;
  for (const c of domains.values()) if (c > maxDomain) maxDomain = c;
  const n = Math.max(1, posts.length);
  const sampleText = typeof sn.sampleText === "string"
    ? sn.sampleText
    : [sn.sampleTitle, ...texts].filter(x => typeof x === "string" && x).join(" | ");

  return normalizeFingerprint({
    schema_version: 1,
    site,
    channel: {
      channel_id: sn.accountId,
      handle,
      title: sn.title,
      description: sn.bio ?? sn.description,
      subscriber_count: sn.followers ?? sn.subscriberCount,
      total_videos: num(sn.totalPosts) ?? posts.length,
      has_auto_suffix: AUTO_SUFFIX_RE.test(handle),
      stem_siblings: sn.stemSiblings,
      outbound_domain_share: outboundTotal > 0 ? maxDomain / outboundTotal : 0,
    },
    upload_cadence: {
      channel_age_days: sn.accountAgeDays,
      max_dormancy_gap_days: sn.maxDormancyGapDays,
      pre_pivot_videos: sn.prePivotVideos,
      post_pivot_videos: sn.postPivotVideos,
      post_pivot_share: sn.postPivotShare,
      recent_uploads_per_day: sn.recentUploadsPerDay,
      output_minutes_per_week: sn.outputMinutesPerWeek,
      avg_duration_sec: sn.avgDurationSec,
      duration_cv: sn.durationCv,
      schedule_hour_stddev: sn.scheduleHourStddev,
    },
    transcript: {
      videos_sampled: sn.videosSampled,
      total_words: num(sn.totalWords) ?? totalWords,
      uncontracted_ratio: sn.uncontractedRatio,
      first_person_per_1k: sn.firstPersonPer1k,
      disfluencies_per_1k: sn.disfluenciesPer1k,
      antithesis_per_1k: sn.antithesisPer1k,
      slop_hooks_per_1k: sn.slopHooksPer1k,
      llm_lexicon_per_1k: sn.llmLexiconPer1k,
      keyword_stuffing_ratio: totalWords > 0 ? keywordHits / totalWords : sn.keywordStuffingRatio,
      mean_wpm: sn.meanWpm,
      cross_video_wpm_stddev: sn.crossVideoWpmStddev,
      intra_video_wpm_cv: sn.intraVideoWpmCv,
      pause_cv: sn.pauseCv,
      earliest_has_speech: sn.earliestHasSpeech !== false,
    },
    thumbnails: {
      title_skeleton_reuse: sn.titleSkeletonReuse,
      raw_camera_earliest_title: sn.rawCameraEarliestTitle === true,
      synthetic_image_ratio: posts.length > 0 ? synthHits / n : sn.syntheticImageRatio,
      aspect_uniformity: sn.aspectUniformity,
      repost_watermark_ratio: posts.length > 0 ? watermarkHits / n : sn.repostWatermarkRatio,
    },
    audio_video_stats: {
      earliest_vertical: sn.earliestVertical === true,
      earliest_max_dim: sn.earliestMaxDim,
      recent_widescreen_hd_ratio: sn.recentWidescreenHdRatio,
      altered_content_flag: sn.alteredContentFlag === true,
      dead_air_floor: Boolean(sn.deadAirFloor),
      loudness_range_lu: sn.loudnessRangeLu,
      silence_cv: sn.silenceCv,
    },
    sample_text: sampleText,
  }, site);
}

// ---------------------------------------------------------------------------------------------
// §4 Runtime
// ---------------------------------------------------------------------------------------------

const nowMs = () => (globalThis.performance?.now ? globalThis.performance.now() : Date.now());

function codePointLength(s) {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

async function runRule(rule, fpBytes) {
  const instance = await WebAssembly.instantiate(rule.module, {});
  const ex = instance.exports;
  const mem = ex.memory;
  if (!(mem instanceof WebAssembly.Memory) || typeof ex.st_evaluate !== "function") throw new Error("invalid ABI");
  let ptr = 16384;
  if (typeof ex.st_alloc === "function") {
    const p = Number(ex.st_alloc(fpBytes.length)) >>> 0;
    if (p > 0) ptr = p;
  }
  const need = ptr + fpBytes.length;
  const have = mem.buffer.byteLength;
  if (need > have) {
    try {
      mem.grow(Math.ceil((need - have) / 65536));
    } catch {
      throw new Error("input does not fit in memory");
    }
  }
  new Uint8Array(mem.buffer, ptr, fpBytes.length).set(fpBytes);
  const raw = ex.st_evaluate(ptr, fpBytes.length);
  if (typeof raw !== "bigint") throw new Error("st_evaluate must return i64");
  const r = BigInt.asUintN(64, raw);
  const hi = Number(r >> 32n);
  const lo = Number(r & 0xffffffffn);
  const m = rule.manifest;
  if (hi === 0) {
    if (lo > 100) throw new Error(`score ${lo} out of range`);
    return { score: lo, confidence: 1, reason: m.description };
  }
  if (lo > 4096 || hi + lo > mem.buffer.byteLength) throw new Error("output pointer/length out of bounds");
  let parsed;
  try {
    parsed = JSON.parse(decFatal.decode(new Uint8Array(mem.buffer, hi, lo)));
  } catch {
    throw new Error("output is not UTF-8 JSON");
  }
  if (!isPlainObject(parsed)) throw new Error("output must be a JSON object");
  const score = parsed.score;
  if (typeof score !== "number" || !Number.isInteger(score) || score < 0 || score > 100) {
    throw new Error("output score must be an integer 0..100");
  }
  let confidence = 1;
  if (hasOwn(parsed, "confidence")) {
    confidence = parsed.confidence;
    if (typeof confidence !== "number" || !(confidence > 0 && confidence <= 1)) throw new Error("output confidence must be in (0, 1]");
  }
  let reason = m.description;
  if (hasOwn(parsed, "reason")) {
    if (typeof parsed.reason !== "string" || codePointLength(parsed.reason) > 300) throw new Error("output reason must be a string <= 300 code points");
    reason = parsed.reason;
  }
  return { score, confidence, reason };
}

function clampThreshold(v, dflt) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 100 ? v : dflt;
}

function clampListThreshold(v, dflt, max = 100000) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? v : dflt;
}

/**
 * Static engine: load signed bundles, evaluate canonical fingerprints.
 *
 * Options: site ("youtube" | "tiktok" | "pinterest" | "*"), verifiedOnly (official rules only),
 * communityRules (default false; enables community-tier rules), usePreMatchedLists (default true),
 * warnThreshold (45), blockThreshold (68), listWarnThreshold (2), listBlockThreshold (5),
 * listSaturationCap (25), contributorMode (false).
 */
export class SlopTrapStaticEngine {
  constructor(options = {}) {
    this.site = String(options.site || "youtube").toLowerCase();
    this.verifiedOnly = Boolean(options.verifiedOnly);
    this.communityRules = options.communityRules === true;
    this.usePreMatchedLists = options.usePreMatchedLists !== false;
    this.contributorMode = options.contributorMode === true;
    this.warnThreshold = clampThreshold(options.warnThreshold, DEFAULT_WARN_THRESHOLD);
    this.blockThreshold = clampThreshold(options.blockThreshold, DEFAULT_BLOCK_THRESHOLD);
    if (this.warnThreshold > this.blockThreshold) {
      this.warnThreshold = DEFAULT_WARN_THRESHOLD;
      this.blockThreshold = DEFAULT_BLOCK_THRESHOLD;
    }
    this.listWarnThreshold = clampListThreshold(options.listWarnThreshold, DEFAULT_LIST_WARN_THRESHOLD);
    this.listBlockThreshold = clampListThreshold(options.listBlockThreshold, DEFAULT_LIST_BLOCK_THRESHOLD);
    this.listSaturationCap = Math.max(1, clampListThreshold(options.listSaturationCap, DEFAULT_LIST_SATURATION_CAP));
    let keyring = PINNED_KEYRING;
    if (options.testKeys !== undefined && keyring === PINNED_KEYRING) {
      throw new Error("testKeys is only accepted in test builds");
    }
    Object.defineProperty(this, "_keyring", { value: keyring, enumerable: false, writable: false });
    this.rules = new Map(); // rule_id -> rule record
    this.owners = new Map(); // rule_id -> author_public_key
    this.ruleMatchedCounts = new Map(); // rule_id -> Map<normalized account key, count>
  }

  setVerifiedOnly(v) {
    this.verifiedOnly = Boolean(v);
  }

  setCommunityRules(v) {
    this.communityRules = v === true;
  }

  setListThresholds({ warn, block } = {}) {
    if (warn !== undefined) this.listWarnThreshold = clampListThreshold(warn, this.listWarnThreshold);
    if (block !== undefined) this.listBlockThreshold = clampListThreshold(block, this.listBlockThreshold);
  }

  _isOfficialKey(pub) {
    return this._keyring.official.has(pub);
  }

  _isActive(r) {
    if (!r.enabled) return false;
    if (r.tier === "official") return true;
    if (this.verifiedOnly) return false;
    if (r.tier === "community") return this.communityRules;
    return r.localImport === true;
  }

  /**
   * Verifies, audits, instruments and compiles a bundle (object, JSON text or bytes).
   * `opts` may be a boolean (enabled) or `{ enabled = true, allowUnverified = false }`.
   * `allowUnverified` is for explicit local imports only; registry loaders must never set it.
   * Resolves `true` when loaded, `false` when skipped by policy (site, tier); rejects on any
   * verification, audit, ownership or compile error.
   */
  async loadBundle(bundle, opts = true) {
    const o = typeof opts === "boolean" ? { enabled: opts } : opts || {};
    const enabled = o.enabled !== false;
    const allowUnverified = o.allowUnverified === true;
    const v = await verifyWith(this._keyring, bundle);
    const m = v.manifest;
    if (this.site !== "*" && m.target_site !== "*" && m.target_site !== this.site) return false;
    if (v.tier === "community" && (this.verifiedOnly || !this.communityRules)) return false;
    if (v.tier === "unverified" && (this.verifiedOnly || !allowUnverified)) return false;
    const prevKey = this.owners.get(m.rule_id);
    if (prevKey !== undefined && prevKey !== m.author_public_key &&
        !(this._isOfficialKey(m.author_public_key) && !this._isOfficialKey(prevKey))) {
      throw new BundleError(`bundle: rule_id ${m.rule_id} is owned by another key`);
    }
    // A community id must not shadow an official one (community-<official id>), in either load order.
    if (v.tier === "community") {
      const shadowed = m.rule_id.slice(COMMUNITY_PREFIX.length);
      const owner = this.owners.get(shadowed);
      if (owner !== undefined && this._isOfficialKey(owner)) {
        throw new BundleError(`bundle: ${m.rule_id} shadows official rule ${shadowed}`);
      }
    }
    const instrumented = instrumentWasm(v.wasm);
    const module = await WebAssembly.compile(instrumented);
    this.rules.set(m.rule_id, {
      manifest: m,
      tier: v.tier,
      verified: v.verified,
      module,
      enabled,
      localImport: v.tier === "unverified",
    });
    this.owners.set(m.rule_id, m.author_public_key);
    if (v.tier === "official") {
      const shadow = COMMUNITY_PREFIX + m.rule_id;
      if (this.rules.get(shadow)?.tier === "community") this.unloadRule(shadow);
    }
    return true;
  }

  /** Loads many bundles; never throws. Returns `{ loaded, skipped, errors: [{ index, error }] }`. */
  async loadBundles(bundles, opts = true) {
    const res = { loaded: 0, skipped: 0, errors: [] };
    let i = 0;
    for (const b of bundles || []) {
      try {
        if (await this.loadBundle(b, opts)) res.loaded++;
        else res.skipped++;
      } catch (e) {
        res.errors.push({ index: i, error: String(e?.message || e) });
      }
      i++;
    }
    return res;
  }

  unloadRule(ruleId) {
    this.ruleMatchedCounts.delete(ruleId);
    return this.rules.delete(ruleId);
  }

  loadRuleList(ruleId, textOrIterable) {
    if (typeof ruleId !== "string" || !RULE_ID_RE.test(ruleId)) return 0;
    let map;
    if (typeof textOrIterable === "string") {
      map = parseAccountListCounts(textOrIterable);
    } else if (textOrIterable instanceof Map) {
      map = new Map();
      for (const [k, rawCnt] of textOrIterable.entries()) {
        const n = normalizeAccountKey(k);
        const cnt = Number(rawCnt);
        if (n && Number.isSafeInteger(cnt) && cnt >= 1) map.set(n, cnt);
        if (map.size >= MAX_LIST_ENTRIES) break;
      }
    } else {
      map = new Map();
      for (const item of textOrIterable || []) {
        const [rawKey, rawCnt] = Array.isArray(item) ? item : [item, 1];
        const n = normalizeAccountKey(rawKey);
        const cnt = Number(rawCnt);
        if (n && Number.isSafeInteger(cnt) && cnt >= 1) map.set(n, cnt);
        if (map.size >= MAX_LIST_ENTRIES) break;
      }
    }
    this.ruleMatchedCounts.set(ruleId, map);
    return map.size;
  }

  getRuleListCount(ruleId, accountKey) {
    const map = this.ruleMatchedCounts.get(ruleId);
    return map ? map.get(normalizeAccountKey(accountKey)) || 0 : 0;
  }

  hasRuleListMatch(ruleId, accountKey) {
    if (this.listBlockThreshold <= 0) return false;
    return this.getRuleListCount(ruleId, accountKey) >= this.listBlockThreshold;
  }

  listRules() {
    return [...this.rules.values()].map(r => ({
      manifest: r.manifest,
      tier: r.tier,
      verified: r.verified,
      provenance: { tier: r.tier, verified: r.verified },
      enabled: r.enabled,
      active: this._isActive(r),
      listCount: this.ruleMatchedCounts.get(r.manifest.rule_id)?.size || 0,
    }));
  }

  toggleRule(ruleId, forceState) {
    const r = this.rules.get(ruleId);
    if (!r) return false;
    r.enabled = typeof forceState === "boolean" ? forceState : !r.enabled;
    return r.enabled;
  }

  /** Evaluates a fingerprint. Never throws; rule failures are reported in `errors`. */
  async evaluate(fingerprint) {
    try {
      return await this._evaluate(fingerprint);
    } catch (e) {
      return {
        site: this.site, score: 0, action: "allow", fast_path_list: false, newly_matched_rules: [],
        verified_rules: 0, outputs: [], errors: [{ rule_id: "", error: String(e?.message || e) }], total_micros: 0,
      };
    }
  }

  async _evaluate(fingerprint) {
    const fp = normalizeFingerprint(fingerprint, this.site);
    const accountKey = normalizeAccountKey(fp.channel.handle || fp.channel.channel_id);
    const active = [...this.rules.values()].filter(r => this._isActive(r));

    let listVerdict = null;
    let allListRulesSaturated = true;
    if (this.usePreMatchedLists && accountKey) {
      const blockHits = [];
      const warnHits = [];
      let maxCount = 0;
      let verifiedHits = 0;
      for (const r of active) {
        if (r.tier !== "official" && r.tier !== "community") continue;
        const cnt = this.ruleMatchedCounts.get(r.manifest.rule_id)?.get(accountKey) || 0;
        if (cnt < this.listSaturationCap) allListRulesSaturated = false;
        if (cnt > maxCount) maxCount = cnt;
        if (this.listBlockThreshold > 0 && cnt >= this.listBlockThreshold) {
          blockHits.push(r.manifest.rule_id);
          if (r.verified) verifiedHits++;
        } else if (this.listWarnThreshold > 0 && cnt >= this.listWarnThreshold) {
          warnHits.push(r.manifest.rule_id);
          if (r.verified) verifiedHits++;
        }
      }
      if (blockHits.length > 0) {
        listVerdict = {
          site: this.site,
          score: LIST_FAST_PATH_SCORE,
          action: "block",
          fast_path_list: true,
          list_forced: true,
          max_list_count: maxCount,
          matched_rule_ids: blockHits,
          newly_matched_rules: [],
          verified_rules: verifiedHits,
          verified_blocking_rules: 0,
          outputs: [],
          errors: [],
          total_micros: 0,
        };
      } else if (warnHits.length > 0) {
        listVerdict = {
          site: this.site,
          score: LIST_FAST_PATH_WARN_SCORE,
          action: "warn",
          fast_path_list: true,
          list_forced: true,
          max_list_count: maxCount,
          matched_rule_ids: warnHits,
          newly_matched_rules: [],
          verified_rules: verifiedHits,
          verified_blocking_rules: 0,
          outputs: [],
          errors: [],
          total_micros: 0,
        };
      }
      if (listVerdict && (!this.contributorMode || allListRulesSaturated)) {
        return listVerdict;
      }
    }

    const fpBytes = enc.encode(serializeTree(FP_SCHEMA, fp));
    const outputs = [];
    const errors = [];
    const newly = [];
    let sumSW = 0;
    let sumW = 0;
    let totalMicros = 0;
    let verifiedRules = 0;
    let verifiedBlockingRules = 0;

    for (const r of active) {
      const m = r.manifest;
      const t0 = nowMs();
      let res;
      try {
        res = await runRule(r, fpBytes);
      } catch (e) {
        errors.push({ rule_id: m.rule_id, error: String(e?.message || e).slice(0, 200) });
        continue;
      }
      const execMicros = Math.round((nowMs() - t0) * 1000);
      totalMicros += execMicros;
      const w = (m.weight_milli / 1000) * res.confidence;
      sumSW += res.score * w;
      sumW += w;
      if (r.verified) {
        verifiedRules++;
        if (res.score >= this.blockThreshold) verifiedBlockingRules++;
      }
      outputs.push({
        rule_id: m.rule_id, rule_name: m.name, version: m.version, target_site: m.target_site,
        tier: r.tier, verified: r.verified, score: res.score, confidence: res.confidence,
        weight: m.weight_milli / 1000, weight_milli: m.weight_milli, overhead: m.overhead,
        reason: res.reason, exec_micros: execMicros,
      });
      if (accountKey && (r.tier === "official" || r.tier === "community") && res.score >= this.warnThreshold) {
        const existingCnt = this.ruleMatchedCounts.get(m.rule_id)?.get(accountKey) || 0;
        if (existingCnt < this.listSaturationCap) {
          newly.push({
            site: this.site,
            rule_id: m.rule_id,
            rule_version: m.version,
            account_key: accountKey,
            action: res.score >= this.blockThreshold ? "block" : "warn",
          });
        }
      }
    }

    let score = sumW > 0 ? Math.floor(sumSW / sumW + 0.5) : 0;
    if (!(score >= 0)) score = 0;
    if (score > 100) score = 100;
    let action = score >= this.blockThreshold ? "block" : score >= this.warnThreshold ? "warn" : "allow";
    let listForced = false;
    if (listVerdict) {
      if (listVerdict.action === "block" && action !== "block") {
        action = "block";
        score = Math.max(score, LIST_FAST_PATH_SCORE);
        listForced = true;
      } else if (listVerdict.action === "warn" && action === "allow") {
        action = "warn";
        score = Math.max(score, LIST_FAST_PATH_WARN_SCORE);
        listForced = true;
      }
    }
    return {
      site: this.site, score, action, fast_path_list: false, list_forced: listForced,
      ...(listVerdict ? { matched_rule_ids: listVerdict.matched_rule_ids, max_list_count: listVerdict.max_list_count } : {}),
      newly_matched_rules: newly,
      verified_rules: verifiedRules, verified_blocking_rules: verifiedBlockingRules,
      outputs, errors, total_micros: totalMicros,
    };
  }
}

// ---------------------------------------------------------------------------------------------
// Registry helpers and managed client
// ---------------------------------------------------------------------------------------------

/**
 * URL of a rule's bundle in the registry, or null. Official/unverified ids map to
 * `/bundles/<id>.strule`; community ids to `/bundles/community/<id>.strule` and only when
 * `communityRules` is true. Rule ids are validated before any URL is built.
 */
export function registryBundleUrl(registryBase, ruleId, { communityRules = false } = {}) {
  if (typeof ruleId !== "string" || !RULE_ID_RE.test(ruleId)) return null;
  const base = String(registryBase || DEFAULT_REGISTRY_BASE).replace(/\/+$/, "");
  if (ruleId.startsWith(COMMUNITY_PREFIX)) {
    return communityRules ? `${base}/bundles/community/${ruleId}.strule` : null;
  }
  return `${base}/bundles/${ruleId}.strule`;
}

const LIST_PATH_RE = /^lists\/[A-Za-z0-9_.\/-]{1,200}$/;

/** Validates a `lists/manifest.json` path (relative, no traversal). */
export function isSafeListPath(p) {
  return typeof p === "string" && LIST_PATH_RE.test(p) && !p.split("/").some(seg => seg === ".." || seg === ".");
}

async function fetchCapped(url, maxBytes, init) {
  const resp = await fetch(url, { redirect: "error", credentials: "omit", ...init });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const cl = Number(resp.headers?.get?.("content-length") || 0);
  if (cl > maxBytes) throw new Error("response too large");
  const text = await resp.text();
  if (text.length > maxBytes) throw new Error("response too large");
  return text;
}

const SITE_RE = /^[a-z0-9-]{1,32}$/;

export class SlopTrapClient {
  constructor(options = {}) {
    this.registryBaseUrl = String(options.registryBaseUrl || DEFAULT_REGISTRY_BASE).replace(/\/$/, "");
    this.rankingsEndpoint = String(options.rankingsEndpoint || DEFAULT_RANKINGS_ENDPOINT).replace(/\/$/, "");
    this.storagePrefix = options.storagePrefix || "sloptrap_sdk_v2";
    this.anonymousRuleRankings = Boolean(options.anonymousRuleRankings);
    this.contributeMatchedAccounts = Boolean(options.contributeMatchedAccounts);
    this.contributorToken = typeof options.contributorToken === "string" ? options.contributorToken.trim() : "";
    this._engineOptions = { ...options, contributorMode: Boolean(options.contributeMatchedAccounts && this.contributorToken) };
    this.engine = new SlopTrapStaticEngine(this._engineOptions);
    this.availableSites = ["youtube", "tiktok", "pinterest"];
    this.lastSyncErrors = [];
    this._submittedMatches = new Set();
    this._lastListGeneratedAt = 0;
  }

  get site() { return this.engine.site; }
  get verifiedOnly() { return this.engine.verifiedOnly; }
  get communityRules() { return this.engine.communityRules; }

  setVerifiedOnly(val) {
    this.engine.setVerifiedOnly(val);
  }

  /** Enabling takes effect for community bundles at the next `syncRegistry()`. */
  setCommunityRules(val) {
    this.engine.setCommunityRules(val);
  }

  setAnonymousRuleRankings(val) {
    this.anonymousRuleRankings = Boolean(val);
  }

  setContributorToken(tok) {
    this.contributorToken = typeof tok === "string" ? tok.trim() : "";
    this.engine.contributorMode = Boolean(this.contributeMatchedAccounts && this.contributorToken);
  }

  async switchSite(site) {
    this.engine = new SlopTrapStaticEngine({
      ...this._engineOptions,
      site,
      verifiedOnly: this.engine.verifiedOnly,
      communityRules: this.engine.communityRules,
      warnThreshold: this.engine.warnThreshold,
      blockThreshold: this.engine.blockThreshold,
      listWarnThreshold: this.engine.listWarnThreshold,
      listBlockThreshold: this.engine.listBlockThreshold,
      contributorMode: Boolean(this.contributeMatchedAccounts && this.contributorToken),
    });
    return this.syncRegistry();
  }

  getOrCreateInstallToken() {
    const key = `${this.storagePrefix}:anon_token`;
    const fresh = () => {
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      return [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
    };
    try {
      let tok = localStorage.getItem(key);
      if (!tok || !/^[0-9a-f]{32}$/.test(tok)) {
        tok = fresh();
        localStorage.setItem(key, tok);
      }
      return tok;
    } catch {
      return fresh();
    }
  }

  /** Loads the site's leaderboard rules and pre-matched lists. Resolves to the number loaded. */
  async syncRegistry() {
    const errors = [];
    try {
      const idx = JSON.parse(await fetchCapped(`${this.registryBaseUrl}/leaderboard/index.json`, 1 << 20));
      if (Array.isArray(idx?.sites) && idx.sites.length > 0) {
        const sites = idx.sites.map(s => s?.site_id).filter(s => typeof s === "string" && SITE_RE.test(s));
        if (sites.length > 0) this.availableSites = sites;
      }
    } catch {}

    if (!SITE_RE.test(this.site)) throw new Error("invalid site");
    const lbUrl = `${this.registryBaseUrl}/leaderboard/${this.site}/leaderboard.json`;
    const doc = JSON.parse(await fetchCapped(lbUrl, 4 << 20));
    const wantCommunity = this.engine.communityRules && !this.engine.verifiedOnly;
    let loaded = 0;
    const entries = Array.isArray(doc?.entries) ? doc.entries.slice(0, 1000) : [];
    for (const entry of entries) {
      // entry.verified, local_bundle_path and bundle_url are never trusted.
      const url = registryBundleUrl(this.registryBaseUrl, entry?.rule_id, { communityRules: wantCommunity });
      if (!url) continue;
      try {
        const text = await fetchCapped(url, MAX_BUNDLE_BYTES);
        if (await this.engine.loadBundle(text, true)) loaded++;
      } catch (e) {
        errors.push({ rule_id: entry.rule_id, error: String(e?.message || e) });
      }
    }

    try {
      const nowSec = Math.floor(Date.now() / 1000);
      const lm = await verifyListManifest(
        JSON.parse(await fetchCapped(`${this.registryBaseUrl}/lists/manifest.json`, 1 << 20)),
        this.engine._keyring.listSigning,
        { nowSec, maxAgeSeconds: DEFAULT_MAX_LIST_MANIFEST_AGE_SECONDS, minGeneratedAt: this._lastListGeneratedAt }
      );
      this._lastListGeneratedAt = parseListGeneratedAt(lm.generated_at);
      const lists = isPlainObject(lm?.lists) ? Object.values(lm.lists) : [];
      const seenRules = new Set();
      let totalBytes = 0;
      for (const info of lists) {
        if (!isPlainObject(info) || info.site !== this.site) continue;
        if (typeof info.rule_id !== "string" || !RULE_ID_RE.test(info.rule_id) || !isSafeListPath(info.path)) continue;
        const r = this.engine.rules.get(info.rule_id);
        if (!r || (r.tier !== "official" && r.tier !== "community")) continue;
        try {
          const txt = await fetchCapped(`${this.registryBaseUrl}/${info.path}`, MAX_LIST_BYTES);
          totalBytes += txt.length;
          if (totalBytes > 32 * 1024 * 1024) break;
          if ((await sha256HexBytes(txt)) !== info.sha256) continue;
          this.engine.loadRuleList(info.rule_id, txt);
          seenRules.add(info.rule_id);
        } catch {}
      }
      for (const rid of [...this.engine.ruleMatchedCounts.keys()]) {
        if (!seenRules.has(rid)) this.engine.loadRuleList(rid, "");
      }
    } catch {}

    if (this.anonymousRuleRankings && this.rankingsEndpoint) {
      const activeRules = this.engine.listRules()
        .filter(r => r.active)
        .map(r => ({ rule_id: r.manifest.rule_id, version: r.manifest.version }));
      fetch(`${this.rankingsEndpoint}/api/v1/rules/check-updates`, {
        method: "POST",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ install_token: this.getOrCreateInstallToken(), active_rules: activeRules }),
      }).catch(() => {});
    }
    this.lastSyncErrors = errors;
    return loaded;
  }

  listRules() { return this.engine.listRules(); }
  toggleRule(id, state) { return this.engine.toggleRule(id, state); }

  async evaluate(fp) {
    const res = await this.engine.evaluate(fp);
    if (this.contributeMatchedAccounts && this.contributorToken && this.rankingsEndpoint && res.newly_matched_rules?.length > 0) {
      const fresh = res.newly_matched_rules.filter(m => {
        if (m.action !== "block") return false;
        const k = `${m.site}|${m.rule_id}|${m.account_key}`;
        if (this._submittedMatches.has(k)) return false;
        this._submittedMatches.add(k);
        if (this._submittedMatches.size > 5000) this._submittedMatches.delete(this._submittedMatches.values().next().value);
        return true;
      });
      if (fresh.length > 0) {
        fetch(`${this.rankingsEndpoint}/api/v1/lists/report-matches`, {
          method: "POST",
          credentials: "omit",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.contributorToken}`,
          },
          body: JSON.stringify({ site: this.site, matches: fresh }),
        }).catch(() => {});
      }
    }
    return res;
  }
}
