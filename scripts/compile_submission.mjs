#!/usr/bin/env node

// scripts/compile_submission.ts
import fs from "node:fs";

// node_modules/@noble/ed25519/index.js
var ed25519_CURVE = {
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
  a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
  d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
  Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
  Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n
};
var { p: P, n: N, Gx, Gy, a: _a, d: _d } = ed25519_CURVE;
var h = 8n;
var L = 32;
var L2 = 64;
var err = (m = "") => {
  throw new Error(m);
};
var isBig = (n) => typeof n === "bigint";
var isStr = (s) => typeof s === "string";
var isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
var abytes = (a, l) => !isBytes(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
var u8n = (len) => new Uint8Array(len);
var u8fr = (buf) => Uint8Array.from(buf);
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
var _ch = (ch) => {
  if (ch >= C._0 && ch <= C._9)
    return ch - C._0;
  if (ch >= C.A && ch <= C.F)
    return ch - (C.A - 10);
  if (ch >= C.a && ch <= C.f)
    return ch - (C.a - 10);
  return;
};
var hexToBytes = (hex) => {
  const e = "hex invalid";
  if (!isStr(hex))
    return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = _ch(hex.charCodeAt(hi));
    const n2 = _ch(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0)
      return err(e);
    array[ai] = n1 * 16 + n2;
  }
  return array;
};
var toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
var cr = () => globalThis?.crypto;
var subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined");
var concatBytes = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var randomBytes = (len = L) => {
  const c = cr();
  return c.getRandomValues(u8n(len));
};
var big = BigInt;
var arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
var M = (a, b = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
var modN = (a) => M(a, N);
var invert = (num, md) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err("no inverse");
};
var callHash = (name) => {
  const fn = etc[name];
  if (typeof fn !== "function")
    err("hashes." + name + " not set");
  return fn;
};
var apoint = (p) => p instanceof Point ? p : err("Point expected");
var B256 = 2n ** 256n;
var Point = class _Point {
  static BASE;
  static ZERO;
  ex;
  ey;
  ez;
  et;
  constructor(ex, ey, ez, et) {
    const max = B256;
    this.ex = arange(ex, 0n, max);
    this.ey = arange(ey, 0n, max);
    this.ez = arange(ez, 1n, max);
    this.et = arange(et, 0n, max);
    Object.freeze(this);
  }
  static fromAffine(p) {
    return new _Point(p.x, p.y, 1n, M(p.x * p.y));
  }
  /** RFC8032 5.1.3: Uint8Array to Point. */
  static fromBytes(hex, zip215 = false) {
    const d = _d;
    const normed = u8fr(abytes(hex, L));
    const lastByte = hex[31];
    normed[31] = lastByte & ~128;
    const y = bytesToNumLE(normed);
    const max = zip215 ? B256 : P;
    arange(y, 0n, max);
    const y2 = M(y * y);
    const u = M(y2 - 1n);
    const v = M(d * y2 + 1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid)
      err("bad point: y not sqrt");
    const isXOdd = (x & 1n) === 1n;
    const isLastByteOdd = (lastByte & 128) !== 0;
    if (!zip215 && x === 0n && isLastByteOdd)
      err("bad point: x==0, isLastByteOdd");
    if (isLastByteOdd !== isXOdd)
      x = M(-x);
    return new _Point(x, y, 1n, M(x * y));
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity() {
    const a = _a;
    const d = _d;
    const p = this;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { ex: X, ey: Y, ez: Z, et: T } = p;
    const X2 = M(X * X);
    const Y2 = M(Y * Y);
    const Z2 = M(Z * Z);
    const Z4 = M(Z2 * Z2);
    const aX2 = M(X2 * a);
    const left = M(Z2 * M(aX2 + Y2));
    const right = M(Z4 + M(d * M(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = M(X * Y);
    const ZT = M(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return this;
  }
  /** Equality check: compare points P&Q. */
  equals(other) {
    const { ex: X1, ey: Y1, ez: Z1 } = this;
    const { ex: X2, ey: Y2, ez: Z2 } = apoint(other);
    const X1Z2 = M(X1 * Z2);
    const X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2);
    const Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0() {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate() {
    return new _Point(M(-this.ex), this.ey, this.ez, M(-this.et));
  }
  /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
  double() {
    const { ex: X1, ey: Y1, ez: Z1 } = this;
    const a = _a;
    const A = M(X1 * X1);
    const B = M(Y1 * Y1);
    const C2 = M(2n * M(Z1 * Z1));
    const D = M(a * A);
    const x1y1 = X1 + Y1;
    const E = M(M(x1y1 * x1y1) - A - B);
    const G2 = D + B;
    const F = G2 - C2;
    const H = D - B;
    const X3 = M(E * F);
    const Y3 = M(G2 * H);
    const T3 = M(E * H);
    const Z3 = M(F * G2);
    return new _Point(X3, Y3, Z3, T3);
  }
  /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
  add(other) {
    const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
    const { ex: X2, ey: Y2, ez: Z2, et: T2 } = apoint(other);
    const a = _a;
    const d = _d;
    const A = M(X1 * X2);
    const B = M(Y1 * Y2);
    const C2 = M(T1 * d * T2);
    const D = M(Z1 * Z2);
    const E = M((X1 + Y1) * (X2 + Y2) - A - B);
    const F = M(D - C2);
    const G2 = M(D + C2);
    const H = M(B - a * A);
    const X3 = M(E * F);
    const Y3 = M(G2 * H);
    const T3 = M(E * H);
    const Z3 = M(F * G2);
    return new _Point(X3, Y3, Z3, T3);
  }
  /**
   * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n scalar by which point is multiplied
   * @param safe safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n, safe = true) {
    if (!safe && (n === 0n || this.is0()))
      return I;
    arange(n, 1n, N);
    if (n === 1n)
      return this;
    if (this.equals(G))
      return wNAF(n).p;
    let p = I;
    let f = G;
    for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine() {
    const { ex: x, ey: y, ez: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 1n };
    const iz = invert(z, P);
    if (M(z * iz) !== 1n)
      err("invalid inverse");
    return { x: M(x * iz), y: M(y * iz) };
  }
  toBytes() {
    const { x, y } = this.assertValidity().toAffine();
    const b = numTo32bLE(y);
    b[31] |= x & 1n ? 128 : 0;
    return b;
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  // encode to hex string
  clearCofactor() {
    return this.multiply(big(h), false);
  }
  isSmallOrder() {
    return this.clearCofactor().is0();
  }
  isTorsionFree() {
    let p = this.multiply(N / 2n, false).double();
    if (N % 2n)
      p = p.add(this);
    return p.is0();
  }
  static fromHex(hex, zip215) {
    return _Point.fromBytes(toU8(hex), zip215);
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  toRawBytes() {
    return this.toBytes();
  }
};
var G = new Point(Gx, Gy, 1n, M(Gx * Gy));
var I = new Point(0n, 1n, 1n, 0n);
Point.BASE = G;
Point.ZERO = I;
var numTo32bLE = (num) => hexToBytes(padh(arange(num, 0n, B256), L2)).reverse();
var bytesToNumLE = (b) => big("0x" + bytesToHex(u8fr(abytes(b)).reverse()));
var pow2 = (x, power) => {
  let r = x;
  while (power-- > 0n) {
    r *= r;
    r %= P;
  }
  return r;
};
var pow_2_252_3 = (x) => {
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, 2n) * b2 % P;
  const b5 = pow2(b4, 1n) * x % P;
  const b10 = pow2(b5, 5n) * b5 % P;
  const b20 = pow2(b10, 10n) * b10 % P;
  const b40 = pow2(b20, 20n) * b20 % P;
  const b80 = pow2(b40, 40n) * b40 % P;
  const b160 = pow2(b80, 80n) * b80 % P;
  const b240 = pow2(b160, 80n) * b80 % P;
  const b250 = pow2(b240, 10n) * b10 % P;
  const pow_p_5_8 = pow2(b250, 2n) * x % P;
  return { pow_p_5_8, b2 };
};
var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
var uvRatio = (u, v) => {
  const v3 = M(v * v * v);
  const v7 = M(v3 * v3 * v);
  const pow = pow_2_252_3(u * v7).pow_p_5_8;
  let x = M(u * v3 * pow);
  const vx2 = M(v * x * x);
  const root1 = x;
  const root2 = M(x * RM1);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === M(-u);
  const noRoot = vx2 === M(-u * RM1);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if ((M(x) & 1n) === 1n)
    x = M(-x);
  return { isValid: useRoot1 || useRoot2, value: x };
};
var modL_LE = (hash) => modN(bytesToNumLE(hash));
var sha512a = (...m) => etc.sha512Async(...m);
var sha512s = (...m) => callHash("sha512Sync")(...m);
var hash2extK = (hashed) => {
  const head = hashed.slice(0, L);
  head[0] &= 248;
  head[31] &= 127;
  head[31] |= 64;
  const prefix = hashed.slice(L, L2);
  const scalar = modL_LE(head);
  const point = G.multiply(scalar);
  const pointBytes = point.toBytes();
  return { head, prefix, scalar, point, pointBytes };
};
var getExtendedPublicKeyAsync = (priv) => sha512a(toU8(priv, L)).then(hash2extK);
var getExtendedPublicKey = (priv) => hash2extK(sha512s(toU8(priv, L)));
var getPublicKeyAsync = (priv) => getExtendedPublicKeyAsync(priv).then((p) => p.pointBytes);
var hashFinishA = (res) => sha512a(res.hashable).then(res.finish);
var _sign = (e, rBytes, msg) => {
  const { pointBytes: P2, scalar: s } = e;
  const r = modL_LE(rBytes);
  const R = G.multiply(r).toBytes();
  const hashable = concatBytes(R, P2, msg);
  const finish = (hashed) => {
    const S = modN(r + modL_LE(hashed) * s);
    return abytes(concatBytes(R, numTo32bLE(S)), L2);
  };
  return { hashable, finish };
};
var signAsync = async (msg, privKey) => {
  const m = toU8(msg);
  const e = await getExtendedPublicKeyAsync(privKey);
  const rBytes = await sha512a(e.prefix, m);
  return hashFinishA(_sign(e, rBytes, m));
};
var veriOpts = { zip215: true };
var _verify = (sig, msg, pub, opts = veriOpts) => {
  sig = toU8(sig, L2);
  msg = toU8(msg);
  pub = toU8(pub, L);
  const { zip215 } = opts;
  let A;
  let R;
  let s;
  let SB;
  let hashable = Uint8Array.of();
  try {
    A = Point.fromHex(pub, zip215);
    R = Point.fromHex(sig.slice(0, L), zip215);
    s = bytesToNumLE(sig.slice(L, L2));
    SB = G.multiply(s, false);
    hashable = concatBytes(R.toBytes(), A.toBytes(), msg);
  } catch (error) {
  }
  const finish = (hashed) => {
    if (SB == null)
      return false;
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = modL_LE(hashed);
    const RkA = R.add(A.multiply(k, false));
    return RkA.add(SB.negate()).clearCofactor().is0();
  };
  return { hashable, finish };
};
var verifyAsync = async (s, m, p, opts = veriOpts) => hashFinishA(_verify(s, m, p, opts));
var etc = {
  sha512Async: async (...messages) => {
    const s = subtle();
    const m = concatBytes(...messages);
    return u8n(await s.digest("SHA-512", m.buffer));
  },
  sha512Sync: void 0,
  bytesToHex,
  hexToBytes,
  concatBytes,
  mod: M,
  invert,
  randomBytes
};
var utils = {
  getExtendedPublicKeyAsync,
  getExtendedPublicKey,
  randomPrivateKey: () => randomBytes(L),
  precompute: (w = 8, p = G) => {
    p.multiply(3n);
    w;
    return p;
  }
  // no-op
};
var W = 8;
var scalarBits = 256;
var pwindows = Math.ceil(scalarBits / W) + 1;
var pwindowSize = 2 ** (W - 1);
var precompute = () => {
  const points = [];
  let p = G;
  let b = p;
  for (let w = 0; w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var ctneg = (cnd, p) => {
  const n = p.negate();
  return cnd ? n : p;
};
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G;
  const pow_2_w = 2 ** W;
  const maxNum = pow_2_w;
  const mask = big(pow_2_w - 1);
  const shiftBy = big(W);
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off;
    const offP = off + Math.abs(wbits) - 1;
    const isEven = w % 2 !== 0;
    const isNeg = wbits < 0;
    if (wbits === 0) {
      f = f.add(ctneg(isEven, comp[offF]));
    } else {
      p = p.add(ctneg(isNeg, comp[offP]));
    }
  }
  return { p, f };
};

// src/lib/samples.ts
var COMMON_SIGNALS = [
  // Activity & Account (Universal across YouTube, TikTok, Pinterest, etc.)
  {
    field: "post.frequency",
    jsonKey: "recent_uploads_per_day",
    label: "Post frequency (posts per day)",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: ">=",
    defaultValue: 1,
    defaultRamp: 2,
    unit: "/ day",
    hint: "Average daily uploads, clips, or pins across any site."
  },
  {
    field: "post.weekly_minutes",
    jsonKey: "output_minutes_per_week",
    label: "Weekly content volume (minutes)",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: ">=",
    defaultValue: 60,
    defaultRamp: 180,
    unit: "min / wk",
    hint: "Total runtime minutes published per week."
  },
  {
    field: "post.duration_variance",
    jsonKey: "duration_cv",
    label: "Post length variation",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: "<=",
    defaultValue: 0.12,
    defaultRamp: 0.08,
    hint: "Very low variation means cookie-cutter templated lengths."
  },
  {
    field: "post.title_reuse",
    jsonKey: "title_skeleton_reuse",
    label: "Repeated title templates",
    group: "Activity & Account",
    category: "thumbnails",
    defaultOp: ">=",
    defaultValue: 0.35,
    defaultRamp: 0.45,
    hint: "Share of posts reusing the same title formula."
  },
  {
    field: "account.dormancy_days",
    jsonKey: "max_dormancy_gap_days",
    label: "Longest inactivity gap (days)",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: ">=",
    defaultValue: 540,
    defaultRamp: 1800,
    unit: "days",
    hint: "Multi-year silence before a sudden publishing flood (bought account)."
  },
  {
    field: "account.post_pivot_share",
    jsonKey: "post_pivot_share",
    label: "Share of posts after dormancy",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: ">=",
    defaultValue: 0.6,
    defaultRamp: 0.35,
    hint: "Fraction of total posts published after the inactivity gap."
  },
  {
    field: "account.recent_posts",
    jsonKey: "post_pivot_videos",
    label: "Posts published after dormancy",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: ">=",
    defaultValue: 12,
    defaultRamp: 80,
    unit: "posts",
    hint: "Count of posts uploaded after a long dormancy gap."
  },
  {
    field: "account.clone_siblings",
    jsonKey: "stem_siblings",
    label: "Matching clone handles",
    group: "Activity & Account",
    category: "metadata",
    defaultOp: ">=",
    defaultValue: 1,
    defaultRamp: 2,
    hint: "Known slop accounts sharing the same base handle stem."
  },
  {
    field: "account.auto_handle",
    jsonKey: "has_auto_suffix",
    label: "Auto-generated handle suffix",
    group: "Activity & Account",
    category: "metadata",
    defaultOp: "==",
    defaultValue: 1,
    defaultRamp: 0,
    isBoolean: true,
    hint: "Matches @BaseName-x8z or batch-generated handle endings."
  },
  {
    field: "account.silent_origin",
    jsonKey: "earliest_has_speech",
    label: "Earliest posts had no speech",
    group: "Activity & Account",
    category: "transcript",
    defaultOp: "<=",
    defaultValue: 0,
    defaultRamp: 0,
    isBoolean: true,
    invertBoolean: true,
    hint: "True when an account's oldest uploads were silent clips before pivoting."
  },
  {
    field: "account.camera_filename_origin",
    jsonKey: "raw_camera_earliest_title",
    label: "Earliest posts used camera filenames",
    group: "Activity & Account",
    category: "thumbnails",
    defaultOp: "==",
    defaultValue: 1,
    defaultRamp: 0,
    isBoolean: true,
    hint: "Oldest uploads named IMG_0421 / VID_ before modern rebrand."
  },
  // Text & Captions
  {
    field: "text.formal_prose",
    jsonKey: "uncontracted_ratio",
    label: "Formal uncontracted prose ratio",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: ">=",
    defaultValue: 0.36,
    defaultRamp: 0.44,
    hint: "LLM written style ('it is', 'do not') instead of natural speech."
  },
  {
    field: "text.antithesis_rate",
    jsonKey: "antithesis_per_1k",
    label: "LLM 'not X, it is Y' rate",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: ">=",
    defaultValue: 0.5,
    defaultRamp: 2.2,
    unit: "/ 1k words",
    hint: "Contrastive rhetorical phrasing typical of LLM scripts."
  },
  {
    field: "text.hook_rate",
    jsonKey: "slop_hooks_per_1k",
    label: "Sensational hook rate",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: ">=",
    defaultValue: 0.5,
    defaultRamp: 2,
    unit: "/ 1k words",
    hint: "Clickbait retention hooks per 1,000 words."
  },
  {
    field: "text.keyword_stuffing",
    jsonKey: "keyword_stuffing_ratio",
    label: "Hashtag & SEO keyword stuffing",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: ">=",
    defaultValue: 0.28,
    defaultRamp: 0.42,
    hint: "Density of SEO tags and AI hashtags in captions or descriptions."
  },
  {
    field: "text.phrases",
    jsonKey: "sample_text",
    label: "Text or caption contains phrase",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: "contains_any",
    defaultValue: 1,
    defaultRamp: 0,
    hint: "Matches any phrase in a comma-separated list or phrase token."
  },
  // Voice, Visuals & Links
  {
    field: "voice.pacing_variance",
    jsonKey: "intra_video_wpm_cv",
    label: "Speaking pace variation",
    group: "Voice, Visuals & Links",
    category: "transcript",
    defaultOp: "<=",
    defaultValue: 0.13,
    defaultRamp: 0.06,
    hint: "Low variation indicates flat, robotic TTS voiceovers."
  },
  {
    field: "voice.pause_variance",
    jsonKey: "pause_cv",
    label: "Sentence pause variation",
    group: "Voice, Visuals & Links",
    category: "transcript",
    defaultOp: "<=",
    defaultValue: 0.36,
    defaultRamp: 0.18,
    hint: "Low variation indicates stitched TTS sentence audio."
  },
  {
    field: "voice.dead_air",
    jsonKey: "dead_air_floor",
    label: "Digital dead-air silence (-65dBFS)",
    group: "Voice, Visuals & Links",
    category: "audio_video_stats",
    defaultOp: "==",
    defaultValue: 1,
    defaultRamp: 0,
    isBoolean: true,
    hint: "Pure zero-noise digital silence between TTS sentences."
  },
  {
    field: "media.synthetic_ratio",
    jsonKey: "synthetic_image_ratio",
    label: "AI-generated visual ratio",
    group: "Voice, Visuals & Links",
    category: "thumbnails",
    defaultOp: ">=",
    defaultValue: 0.3,
    defaultRamp: 0.5,
    hint: "Share of images/thumbnails showing diffusion or upscaler artifacts."
  },
  {
    field: "media.aspect_lock",
    jsonKey: "aspect_uniformity",
    label: "Batch aspect-ratio lock",
    group: "Voice, Visuals & Links",
    category: "thumbnails",
    defaultOp: ">=",
    defaultValue: 0.72,
    defaultRamp: 0.24,
    hint: "Uniform batch-generated image dimensions across posts."
  },
  {
    field: "media.repost_ratio",
    jsonKey: "repost_watermark_ratio",
    label: "Split-screen or repost ratio",
    group: "Voice, Visuals & Links",
    category: "thumbnails",
    defaultOp: ">=",
    defaultValue: 0.25,
    defaultRamp: 0.5,
    hint: "Cropped watermarks or split-screen gameplay Sludge ratios."
  },
  {
    field: "link.domain_concentration",
    jsonKey: "outbound_domain_share",
    label: "Links pointing to one domain",
    group: "Voice, Visuals & Links",
    category: "metadata",
    defaultOp: ">=",
    defaultValue: 0.55,
    defaultRamp: 0.35,
    hint: "Fraction of outbound links funneling to a single affiliate/ad domain."
  },
  {
    field: "post.schedule_regularity",
    jsonKey: "schedule_hour_stddev",
    label: "Cron upload regularity (hour stddev)",
    group: "Activity & Account",
    category: "upload_cadence",
    defaultOp: "<=",
    defaultValue: 1.5,
    defaultRamp: 1,
    unit: "hrs",
    hint: "Low hour-of-day variance typical of automated cron-scheduled uploaders."
  },
  {
    field: "text.llm_lexicon_rate",
    jsonKey: "llm_lexicon_per_1k",
    label: "LLM buzzword rate ('delve', 'tapestry')",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: ">=",
    defaultValue: 1.2,
    defaultRamp: 2.5,
    unit: "/ 1k words",
    hint: "Density of over-represented LLM vocabulary words per 1,000 spoken/written words."
  },
  {
    field: "text.first_person_rate",
    jsonKey: "first_person_per_1k",
    label: "First-person speech ('I', 'my', 'we')",
    group: "Text & Captions",
    category: "transcript",
    defaultOp: "<=",
    defaultValue: 2.5,
    defaultRamp: 2,
    unit: "/ 1k words",
    hint: "Omniscient faceless narration rarely uses natural first-person pronouns."
  },
  {
    field: "media.ai_disclosure",
    jsonKey: "altered_content_flag",
    label: "Self-declared AI/altered content flag",
    group: "Voice, Visuals & Links",
    category: "audio_video_stats",
    defaultOp: "==",
    defaultValue: 1,
    defaultRamp: 0,
    isBoolean: true,
    hint: "Platform metadata flag indicating synthetic or altered media."
  }
];
function findSignalMeta(fieldOrJsonKey) {
  return COMMON_SIGNALS.find(
    (s) => s.field === fieldOrJsonKey || s.jsonKey === fieldOrJsonKey
  );
}

// src/lib/compiler/wasmCompiler.ts
var enc = new TextEncoder();
function resolveNum(ref, tokens) {
  if (ref.token) {
    const found = tokens.find((t) => t.kind === "number" && t.name === ref.token);
    if (found && found.kind === "number") return found.value;
  }
  return Number(ref.literal || 0);
}
function resolvePhrases(ref, tokens) {
  if (ref.token) {
    const found = tokens.find((t) => t.kind === "phrases" && t.name === ref.token);
    if (found && found.kind === "phrases") {
      return found.values.map((s) => s.trim()).filter(Boolean);
    }
  }
  return (ref.literals || []).map((s) => s.trim()).filter(Boolean);
}
function inferRequiredInputs(project) {
  const set = /* @__PURE__ */ new Set(["metadata"]);
  for (const r of project.rules) {
    if (!r.enabled) continue;
    for (const c of r.conditions) {
      if (c.op === "contains_any" || c.op === "not_contains") {
        set.add("transcript");
        continue;
      }
      const meta = findSignalMeta(c.field);
      if (meta) set.add(meta.category);
    }
  }
  return [...set];
}
var ByteBuf = class {
  bytes = [];
  push(...vals) {
    for (const v of vals) this.bytes.push(v & 255);
  }
  pushBytes(arr) {
    for (const v of arr) this.bytes.push(v & 255);
  }
  uleb(val) {
    let v = val >>> 0;
    do {
      let byte = v & 127;
      v >>>= 7;
      if (v !== 0) byte |= 128;
      this.bytes.push(byte);
    } while (v !== 0);
  }
  sleb(val) {
    let v = Math.trunc(val);
    let more = true;
    while (more) {
      let byte = v & 127;
      v >>= 7;
      if (v === 0 && (byte & 64) === 0 || v === -1 && (byte & 64) !== 0) {
        more = false;
      } else {
        byte |= 128;
      }
      this.bytes.push(byte);
    }
  }
  f64Const(val) {
    this.bytes.push(68);
    const ab = new ArrayBuffer(8);
    new DataView(ab).setFloat64(0, val, true);
    this.pushBytes(new Uint8Array(ab));
  }
  toUint8Array() {
    return new Uint8Array(this.bytes);
  }
};
function writeSection(mod, secId, payload) {
  mod.push(secId);
  mod.uleb(payload.length);
  mod.pushBytes(payload);
}
function writeExport(sec, name, kind, idx) {
  const nb = enc.encode(name);
  sec.uleb(nb.length);
  sec.pushBytes(nb);
  sec.push(kind);
  sec.uleb(idx);
}
function writeFuncBody(codeSec, body) {
  codeSec.uleb(body.length);
  codeSec.pushBytes(body);
}
function buildFindJsonNumBody() {
  const b = new ByteBuf();
  b.uleb(2);
  b.uleb(6);
  b.push(127);
  b.uleb(2);
  b.push(124);
  b.push(32, 1, 32, 3, 73, 4, 64);
  b.f64Const(-1);
  b.push(15, 11);
  b.push(32, 1, 32, 3, 107, 33, 6);
  b.push(65, 0, 33, 4);
  b.push(65, 127, 33, 7);
  b.push(2, 64, 3, 64);
  b.push(32, 4, 32, 6, 75, 13, 1);
  b.push(65, 0, 33, 5);
  b.push(2, 64, 3, 64);
  b.push(32, 5, 32, 3, 79, 4, 64);
  b.push(32, 0, 32, 4, 106, 32, 3, 106, 33, 7);
  b.push(12, 4, 11);
  b.push(32, 0, 32, 4, 106, 32, 5, 106, 45, 0, 0);
  b.push(32, 2, 32, 5, 106, 45, 0, 0);
  b.push(71, 13, 1);
  b.push(32, 5, 65, 1, 106, 33, 5, 12, 0);
  b.push(11, 11);
  b.push(32, 4, 65, 1, 106, 33, 4, 12, 0);
  b.push(11, 11);
  b.push(32, 7, 65, 0, 72, 4, 64);
  b.f64Const(-1);
  b.push(15, 11);
  b.push(32, 0, 32, 1, 106, 33, 6);
  b.push(2, 64, 3, 64);
  b.push(32, 7, 32, 6, 79, 13, 1);
  b.push(32, 7, 45, 0, 0, 33, 8);
  b.push(32, 8, 65, 32, 75, 13, 1);
  b.push(32, 7, 65, 1, 106, 33, 7, 12, 0);
  b.push(11, 11);
  b.push(32, 7, 32, 6, 79, 4, 64);
  b.f64Const(-1);
  b.push(15, 11);
  b.push(32, 7, 45, 0, 0, 33, 8);
  b.push(32, 8, 65);
  b.sleb(116);
  b.push(70, 4, 64);
  b.f64Const(1);
  b.push(15, 11);
  b.push(32, 8, 65);
  b.sleb(102);
  b.push(70, 4, 64);
  b.f64Const(0);
  b.push(15, 11);
  b.push(65, 0, 33, 9);
  b.push(32, 8, 65, 45, 70, 4, 64);
  b.push(65, 1, 33, 9);
  b.push(32, 7, 65, 1, 106, 33, 7);
  b.push(11);
  b.f64Const(0);
  b.push(33, 10);
  b.push(2, 64, 3, 64);
  b.push(32, 7, 32, 6, 79, 13, 1);
  b.push(32, 7, 45, 0, 0, 33, 8);
  b.push(32, 8, 65, 48, 73, 13, 1);
  b.push(32, 8, 65, 57, 75, 13, 1);
  b.push(32, 10);
  b.f64Const(10);
  b.push(162);
  b.push(32, 8, 65, 48, 107, 183, 160, 33, 10);
  b.push(32, 7, 65, 1, 106, 33, 7, 12, 0);
  b.push(11, 11);
  b.push(32, 7, 32, 6, 73, 4, 64);
  b.push(32, 7, 45, 0, 0, 65, 46, 70, 4, 64);
  b.push(32, 7, 65, 1, 106, 33, 7);
  b.f64Const(0.1);
  b.push(33, 11);
  b.push(2, 64, 3, 64);
  b.push(32, 7, 32, 6, 79, 13, 1);
  b.push(32, 7, 45, 0, 0, 33, 8);
  b.push(32, 8, 65, 48, 73, 13, 1);
  b.push(32, 8, 65, 57, 75, 13, 1);
  b.push(32, 10);
  b.push(32, 8, 65, 48, 107, 183, 32, 11, 162, 160, 33, 10);
  b.push(32, 11);
  b.f64Const(0.1);
  b.push(162, 33, 11);
  b.push(32, 7, 65, 1, 106, 33, 7, 12, 0);
  b.push(11, 11, 11, 11);
  b.push(32, 9, 4, 64, 32, 10, 154, 33, 10, 11);
  b.push(32, 10, 11);
  return b.toUint8Array();
}
function buildContainsBytesCiBody() {
  const b = new ByteBuf();
  b.uleb(1);
  b.uleb(4);
  b.push(127);
  b.push(32, 3, 69, 32, 1, 32, 3, 73, 114, 4, 64);
  b.push(65, 0, 15, 11);
  b.push(32, 1, 32, 3, 107, 33, 6);
  b.push(65, 0, 33, 4);
  b.push(2, 64, 3, 64);
  b.push(32, 4, 32, 6, 75, 13, 1);
  b.push(65, 0, 33, 5);
  b.push(2, 64, 3, 64);
  b.push(32, 5, 32, 3, 79, 4, 64);
  b.push(65, 1, 15, 11);
  b.push(32, 0, 32, 4, 106, 32, 5, 106, 45, 0, 0, 33, 7);
  b.push(32, 7, 65);
  b.sleb(65);
  b.push(79, 32, 7, 65);
  b.sleb(90);
  b.push(77, 113, 4, 64);
  b.push(32, 7, 65, 32, 106, 33, 7, 11);
  b.push(32, 7);
  b.push(32, 2, 32, 5, 106, 45, 0, 0);
  b.push(71, 13, 1);
  b.push(32, 5, 65, 1, 106, 33, 5, 12, 0);
  b.push(11, 11);
  b.push(32, 4, 65, 1, 106, 33, 4, 12, 0);
  b.push(11, 11);
  b.push(65, 0, 11);
  return b.toUint8Array();
}
function buildAllocBody() {
  const b = new ByteBuf();
  b.uleb(0);
  b.push(65);
  b.sleb(16384);
  b.push(11);
  return b.toUint8Array();
}
function actionBaseScore(act) {
  switch (act) {
    case "block":
      return 85;
    case "hide":
      return 80;
    case "warn":
      return 56;
    case "dim":
      return 52;
    case "allow":
      return 0;
  }
}
function compileProjectToWasm(project) {
  const vars = project.variables.length > 0 ? project.variables : [{ name: "suspicion", initial: 0 }];
  const varIndex = /* @__PURE__ */ new Map();
  const varBaseLocal = 8;
  vars.forEach((v, i) => varIndex.set(v.name, varBaseLocal + i));
  const dataBase = 1024;
  const dataChunks = [];
  const allocData = (str) => {
    const raw = enc.encode(str);
    const offset = dataBase + dataChunks.length;
    for (const byte of raw) dataChunks.push(byte);
    return { offset, length: raw.length };
  };
  const keyCache = /* @__PURE__ */ new Map();
  const getKeySlice = (field) => {
    const meta = findSignalMeta(field);
    const jsonKey = meta ? meta.jsonKey : field;
    const pat = `"${jsonKey}":`;
    if (!keyCache.has(pat)) keyCache.set(pat, allocData(pat));
    return keyCache.get(pat);
  };
  const evalBuf = new ByteBuf();
  evalBuf.uleb(2);
  evalBuf.uleb(2);
  evalBuf.push(127);
  evalBuf.uleb(4 + vars.length);
  evalBuf.push(124);
  vars.forEach((v, i) => {
    evalBuf.f64Const(Number(v.initial || 0));
    evalBuf.push(33);
    evalBuf.uleb(varBaseLocal + i);
  });
  evalBuf.push(65, 0, 33, 2);
  evalBuf.f64Const(0);
  evalBuf.push(33, 4);
  for (const rule of project.rules) {
    if (!rule.enabled || rule.conditions.length === 0) continue;
    evalBuf.push(32, 2, 69, 4, 64);
    evalBuf.f64Const(rule.combinator === "any" ? 0 : 1);
    evalBuf.push(33, 6);
    for (const cond of rule.conditions) {
      evalBuf.f64Const(0);
      evalBuf.push(33, 7);
      if (cond.op === "contains_any" || cond.op === "not_contains") {
        const phrases = resolvePhrases(cond.phrases, project.tokens);
        if (phrases.length > 0) {
          evalBuf.push(65, 0, 33, 3);
          for (const ph of phrases) {
            const sl = allocData(ph.toLowerCase());
            evalBuf.push(32, 3, 32, 0, 32, 1, 65);
            evalBuf.sleb(sl.offset);
            evalBuf.push(65);
            evalBuf.sleb(sl.length);
            evalBuf.push(16, 1, 114, 33, 3);
          }
          if (cond.op === "not_contains") {
            evalBuf.push(32, 3, 69, 4, 64);
          } else {
            evalBuf.push(32, 3, 4, 64);
          }
          evalBuf.f64Const(1);
          evalBuf.push(33, 7, 11);
        } else if (cond.op === "not_contains") {
          evalBuf.f64Const(1);
          evalBuf.push(33, 7);
        }
      } else {
        const ks = getKeySlice(cond.field);
        evalBuf.push(32, 0, 32, 1, 65);
        evalBuf.sleb(ks.offset);
        evalBuf.push(65);
        evalBuf.sleb(ks.length);
        evalBuf.push(16, 0, 33, 5);
        const thresh = resolveNum(cond.value, project.tokens);
        const ramp = Math.max(0, Number(cond.ramp || 0));
        if (cond.op === "==") {
          evalBuf.push(32, 5);
          evalBuf.f64Const(0);
          evalBuf.push(102);
          evalBuf.push(32, 5);
          evalBuf.f64Const(thresh);
          evalBuf.push(161, 153);
          evalBuf.f64Const(1e-4);
          evalBuf.push(99, 113, 4, 64);
          evalBuf.f64Const(1);
          evalBuf.push(33, 7, 11);
        } else if (cond.op === ">=") {
          evalBuf.push(32, 5);
          evalBuf.f64Const(thresh);
          evalBuf.push(102, 4, 64);
          if (ramp <= 0) {
            evalBuf.f64Const(1);
            evalBuf.push(33, 7);
          } else {
            evalBuf.push(32, 5);
            evalBuf.f64Const(thresh);
            evalBuf.push(161);
            evalBuf.f64Const(ramp);
            evalBuf.push(163);
            evalBuf.f64Const(1);
            evalBuf.push(164);
            evalBuf.f64Const(0);
            evalBuf.push(165, 33, 7);
          }
          evalBuf.push(11);
        } else {
          const minFloor = thresh === 0 ? 0 : 1e-4;
          evalBuf.push(32, 5);
          evalBuf.f64Const(minFloor);
          evalBuf.push(102, 32, 5);
          evalBuf.f64Const(thresh);
          evalBuf.push(101, 113, 4, 64);
          if (ramp <= 0) {
            evalBuf.f64Const(1);
            evalBuf.push(33, 7);
          } else {
            evalBuf.f64Const(thresh);
            evalBuf.push(32, 5, 161);
            evalBuf.f64Const(ramp);
            evalBuf.push(163);
            evalBuf.f64Const(1);
            evalBuf.push(164);
            evalBuf.f64Const(0);
            evalBuf.push(165, 33, 7);
          }
          evalBuf.push(11);
        }
      }
      evalBuf.push(32, 6, 32, 7);
      evalBuf.push(rule.combinator === "any" ? 165 : 164);
      evalBuf.push(33, 6);
    }
    evalBuf.push(32, 6);
    evalBuf.f64Const(0);
    evalBuf.push(100, 4, 64);
    const targetVarIdx = varIndex.get(rule.action.variable || vars[0].name) ?? varBaseLocal;
    const amt = resolveNum(rule.action.amount, project.tokens);
    if (rule.action.kind === "add_var") {
      evalBuf.push(32);
      evalBuf.uleb(targetVarIdx);
      evalBuf.push(32, 6);
      evalBuf.f64Const(amt);
      evalBuf.push(162, 160, 33);
      evalBuf.uleb(targetVarIdx);
    } else if (rule.action.kind === "set_var") {
      evalBuf.f64Const(amt);
      evalBuf.push(33);
      evalBuf.uleb(targetVarIdx);
    } else {
      evalBuf.f64Const(actionBaseScore(rule.action.kind));
      evalBuf.push(33, 4);
      evalBuf.push(65, 1, 33, 2);
    }
    evalBuf.push(11, 11);
  }
  for (const dec of project.decisions) {
    if (dec.enabled === false || dec.checks.length === 0) continue;
    evalBuf.push(32, 2, 69, 4, 64);
    evalBuf.push(65, dec.combinator === "any" ? 0 : 1, 33, 3);
    for (const chk of dec.checks) {
      const vIdx = varIndex.get(chk.variable) ?? varBaseLocal;
      const tVal = resolveNum(chk.threshold, project.tokens);
      evalBuf.push(32, 3);
      evalBuf.push(32);
      evalBuf.uleb(vIdx);
      evalBuf.f64Const(tVal);
      evalBuf.push(chk.op === ">=" ? 102 : 101);
      evalBuf.push(dec.combinator === "any" ? 114 : 113);
      evalBuf.push(33, 3);
    }
    evalBuf.push(32, 3, 4, 64);
    if (dec.action === "block" || dec.action === "hide") {
      evalBuf.push(32);
      evalBuf.uleb(varBaseLocal);
      evalBuf.f64Const(actionBaseScore(dec.action));
      evalBuf.push(165);
      evalBuf.f64Const(100);
      evalBuf.push(164, 33, 4);
    } else if (dec.action === "warn" || dec.action === "dim") {
      evalBuf.push(32);
      evalBuf.uleb(varBaseLocal);
      evalBuf.f64Const(actionBaseScore(dec.action));
      evalBuf.push(165);
      evalBuf.f64Const(67);
      evalBuf.push(164, 33, 4);
    } else {
      evalBuf.f64Const(0);
      evalBuf.push(33, 4);
    }
    evalBuf.push(65, 1, 33, 2);
    evalBuf.push(11, 11);
  }
  evalBuf.push(32, 2, 69, 4, 64);
  evalBuf.push(32);
  evalBuf.uleb(varBaseLocal);
  evalBuf.f64Const(0.7);
  evalBuf.push(162);
  evalBuf.f64Const(44);
  evalBuf.push(164);
  evalBuf.f64Const(0);
  evalBuf.push(165, 33, 4);
  evalBuf.push(11);
  evalBuf.push(32, 4);
  evalBuf.f64Const(0.5);
  evalBuf.push(160);
  evalBuf.f64Const(0);
  evalBuf.push(165);
  evalBuf.f64Const(100);
  evalBuf.push(164);
  evalBuf.push(176, 11);
  const mod = new ByteBuf();
  mod.push(0, 97, 115, 109, 1, 0, 0, 0);
  const typeSec = new ByteBuf();
  typeSec.uleb(4);
  typeSec.push(96, 4, 127, 127, 127, 127, 1, 124);
  typeSec.push(96, 4, 127, 127, 127, 127, 1, 127);
  typeSec.push(96, 1, 127, 1, 127);
  typeSec.push(96, 2, 127, 127, 1, 126);
  writeSection(mod, 1, typeSec.toUint8Array());
  const funcSec = new ByteBuf();
  funcSec.uleb(4);
  funcSec.push(0, 1, 2, 3);
  writeSection(mod, 3, funcSec.toUint8Array());
  const memSec = new ByteBuf();
  memSec.uleb(1);
  memSec.push(1, 1, 16);
  writeSection(mod, 5, memSec.toUint8Array());
  const expSec = new ByteBuf();
  expSec.uleb(3);
  writeExport(expSec, "memory", 2, 0);
  writeExport(expSec, "st_alloc", 0, 2);
  writeExport(expSec, "st_evaluate", 0, 3);
  writeSection(mod, 7, expSec.toUint8Array());
  const codeSec = new ByteBuf();
  codeSec.uleb(4);
  writeFuncBody(codeSec, buildFindJsonNumBody());
  writeFuncBody(codeSec, buildContainsBytesCiBody());
  writeFuncBody(codeSec, buildAllocBody());
  writeFuncBody(codeSec, evalBuf.toUint8Array());
  writeSection(mod, 10, codeSec.toUint8Array());
  if (dataChunks.length > 0) {
    const dataSec = new ByteBuf();
    dataSec.uleb(1);
    dataSec.push(0, 65);
    dataSec.sleb(dataBase);
    dataSec.push(11);
    dataSec.uleb(dataChunks.length);
    dataSec.pushBytes(dataChunks);
    writeSection(mod, 11, dataSec.toUint8Array());
  }
  return mod.toUint8Array();
}

// src/lib/compiler/bundleCrypto.ts
var DEFAULT_SCORING_SEED = "sloptrap-public-scoring-v1:9f84c2e0a1b74d6e8f3c5a2b1d9e0f4a";
var OFFICIAL_MAINTAINER_KEYS = /* @__PURE__ */ new Set([
  "eb85cbf507e27e2c0f94ad723385db3138af32670ea37ca337f0c1866eae02cc",
  "33fee5d93b69abffb9d920da59d823a1c88a71119064a794ff6a8258bee2a472"
]);
var enc2 = new TextEncoder();
function bytesToHex2(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes2(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concatBytes2(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
async function generateAuthorKeypair() {
  const privSeed = utils.randomPrivateKey();
  const pub = await getPublicKeyAsync(privSeed);
  return {
    publicKeyHex: bytesToHex2(pub),
    privateSeedHex: bytesToHex2(privSeed)
  };
}
function canonicalManifestBytes(m) {
  const canon = [
    "sloptrap-manifest-v1",
    m.rule_id,
    m.name,
    m.version,
    m.author,
    m.author_public_key.trim().toLowerCase(),
    m.interpreter,
    m.inputs.join(","),
    Number(m.default_weight).toFixed(4),
    String(Math.trunc(m.overhead)),
    m.encryption
  ].join("\n");
  return enc2.encode(canon);
}
async function deriveAesKey(scoringSeed, m, usages) {
  const saltKey = await crypto.subtle.importKey(
    "raw",
    enc2.encode("sloptrap-hkdf-salt-v1"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, enc2.encode(scoringSeed)));
  const prkKey = await crypto.subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const info = enc2.encode(
    `sloptrap-bundle-v1|${m.rule_id}|${m.author_public_key.trim().toLowerCase()}|${m.version}`
  );
  const okm = await crypto.subtle.sign("HMAC", prkKey, concatBytes2(info, new Uint8Array([1])));
  return crypto.subtle.importKey("raw", okm, { name: "AES-GCM" }, false, usages);
}
async function packProjectBundle(project, privateSeedOrKeyHex, scoringSeed = DEFAULT_SCORING_SEED, ciAttestation) {
  const wasmBytes = compileProjectToWasm(project);
  const rawKey = hexToBytes2(privateSeedOrKeyHex);
  const seed32 = rawKey.length === 64 ? rawKey.slice(0, 32) : rawKey;
  if (seed32.length !== 32) {
    throw new Error("Ed25519 private key must be 32-byte seed or 64-byte keypair hex");
  }
  const pubBytes = await getPublicKeyAsync(seed32);
  const pubHex = bytesToHex2(pubBytes);
  const isOfficial = OFFICIAL_MAINTAINER_KEYS.has(pubHex);
  const hasSourceAttestation = Boolean(
    ciAttestation?.sourceCommit && /^[0-9a-f]{40}$/i.test(ciAttestation.sourceCommit)
  );
  const rawSite = project.targetSite.trim().toLowerCase() || "youtube";
  const sourceRepo = ciAttestation?.sourceRepo || project.repoUrl.trim() || void 0;
  const manifest = {
    rule_id: project.ruleId.trim(),
    target_site: rawSite === "universal" ? "*" : rawSite,
    name: project.name.trim(),
    description: project.description.trim(),
    version: project.version.trim(),
    author: project.author.trim(),
    author_public_key: pubHex,
    repo_url: sourceRepo,
    interpreter: "wasm-v1",
    inputs: inferRequiredInputs(project),
    default_weight: Number(project.defaultWeight || 1),
    overhead: Math.max(1, Math.min(10, Math.round(project.overhead || 3))),
    encryption: project.encryption || "aes-256-gcm-hkdf",
    provenance: isOfficial ? {
      verified: true,
      tier: "official",
      source_repo: sourceRepo,
      source_commit: ciAttestation?.sourceCommit,
      build_run_url: ciAttestation?.buildRunUrl
    } : hasSourceAttestation ? {
      verified: true,
      tier: "source-attested",
      source_repo: sourceRepo,
      source_commit: ciAttestation?.sourceCommit?.toLowerCase(),
      build_run_url: ciAttestation?.buildRunUrl
    } : { verified: false, tier: "unverified", source_repo: sourceRepo }
  };
  const canon = canonicalManifestBytes(manifest);
  const sigInput = concatBytes2(enc2.encode("sloptrap-sig-v1:"), canon, new Uint8Array([0]), wasmBytes);
  const sigDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", sigInput));
  const signature = await signAsync(sigDigest, seed32);
  let payloadBytes;
  if (manifest.encryption === "none") {
    payloadBytes = wasmBytes;
  } else {
    const aesKey = await deriveAesKey(scoringSeed, manifest, ["encrypt"]);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: canon },
        aesKey,
        wasmBytes
      )
    );
    payloadBytes = concatBytes2(nonce, ct);
  }
  return {
    wasmBytes,
    bundle: {
      format: "sloptrap-bundle-v1",
      manifest,
      payload_b64: bytesToBase64(payloadBytes),
      signature_b64: bytesToBase64(signature)
    }
  };
}
async function verifyAndUnpackBundle(bundle, scoringSeed = DEFAULT_SCORING_SEED) {
  if (bundle.format !== "sloptrap-bundle-v1") {
    throw new Error(`Unsupported format: ${bundle.format}`);
  }
  const m = bundle.manifest;
  const canon = canonicalManifestBytes(m);
  const rawPayload = base64ToBytes(bundle.payload_b64);
  let wasmBytes;
  if (!m.encryption || m.encryption === "none") {
    wasmBytes = rawPayload;
  } else {
    const aesKey = await deriveAesKey(scoringSeed, m, ["decrypt"]);
    const nonce = rawPayload.slice(0, 12);
    const ct = rawPayload.slice(12);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: canon },
      aesKey,
      ct
    );
    wasmBytes = new Uint8Array(plain);
  }
  const sigInput = concatBytes2(enc2.encode("sloptrap-sig-v1:"), canon, new Uint8Array([0]), wasmBytes);
  const sigDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", sigInput));
  const ok = await verifyAsync(
    base64ToBytes(bundle.signature_b64),
    sigDigest,
    hexToBytes2(m.author_public_key)
  );
  if (!ok) throw new Error("Ed25519 signature verification failed");
  return wasmBytes;
}
async function evaluateWasmBytes(compiledModule, fp) {
  const fpBytes = enc2.encode(JSON.stringify(fp));
  const t0 = performance.now();
  const instance = await WebAssembly.instantiate(compiledModule, {});
  const exports = instance.exports;
  let ptr = 16384;
  if (typeof exports.st_alloc === "function") {
    const p = exports.st_alloc(fpBytes.length);
    if (p > 0) ptr = p >>> 0;
  }
  const needed = ptr + fpBytes.length + 1024;
  if (exports.memory.buffer.byteLength < needed) {
    exports.memory.grow(Math.ceil((needed - exports.memory.buffer.byteLength) / 65536));
  }
  new Uint8Array(exports.memory.buffer, ptr, fpBytes.length).set(fpBytes);
  const packed = BigInt.asUintN(64, exports.st_evaluate(ptr, fpBytes.length));
  const execMicros = Math.max(1, Math.round((performance.now() - t0) * 1e3));
  const score = Math.max(0, Math.min(100, Number(packed & 0xffffffffn)));
  return { score, execMicros };
}
function readUleb(buf, pos) {
  let res = 0;
  let shift = 0;
  for (let i = 0; i < 5; i++) {
    if (pos >= buf.length) throw new Error("Truncated LEB128");
    const b = buf[pos++];
    res |= (b & 127) << shift;
    if ((b & 128) === 0) return [res >>> 0, pos];
    shift += 7;
  }
  throw new Error("Oversized LEB128");
}
async function auditWasmAndBundle(bundle, scoringSeed = DEFAULT_SCORING_SEED) {
  const errors = [];
  let wasm;
  try {
    wasm = await verifyAndUnpackBundle(bundle, scoringSeed);
  } catch (err2) {
    return {
      ok: false,
      errors: [`Crypto verification failed: ${err2?.message || err2}`],
      wasmBytes: 0,
      maxMemoryPages: 0,
      exports: [],
      extremeSlopScore: 0,
      cleanHumanScore: 0
    };
  }
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(bundle.manifest.rule_id)) {
    errors.push(`Invalid rule_id "${bundle.manifest.rule_id}"`);
  }
  if (!/^[0-9]+\.[0-9]+\.[0-9]+/.test(bundle.manifest.version)) {
    errors.push(`Invalid semver "${bundle.manifest.version}"`);
  }
  let pos = 8;
  let lastSec = -1;
  let maxPages = 0;
  const exps = [];
  const allowedExports = /* @__PURE__ */ new Set(["memory", "st_alloc", "st_evaluate"]);
  try {
    while (pos < wasm.length) {
      const secId = wasm[pos++];
      const [secLen, nextPos] = readUleb(wasm, pos);
      const sec = wasm.slice(nextPos, nextPos + secLen);
      pos = nextPos + secLen;
      if (secId === 0) errors.push("Custom WASM section (id 0) forbidden");
      if (secId === 2) errors.push("WASM Import section (id 2) forbidden");
      if (secId === 8) errors.push("WASM Start section (id 8) forbidden");
      if (secId <= lastSec) errors.push(`Out-of-order section ${secId}`);
      lastSec = secId;
      if (secId === 5) {
        let [, sp] = readUleb(sec, 0);
        const [flags, sp2] = readUleb(sec, sp);
        const [, sp3] = readUleb(sec, sp2);
        if ((flags & 1) === 0) errors.push("Memory must declare explicit max pages");
        else {
          const [mp] = readUleb(sec, sp3);
          maxPages = mp;
          if (mp > 32) errors.push(`Memory max ${mp} exceeds 32 pages`);
        }
      }
      if (secId === 7) {
        let [cnt, sp] = readUleb(sec, 0);
        for (let i = 0; i < cnt; i++) {
          const [nlen, sp2] = readUleb(sec, sp);
          const name = new TextDecoder().decode(sec.slice(sp2, sp2 + nlen));
          sp = sp2 + nlen + 1;
          [, sp] = readUleb(sec, sp);
          exps.push(name);
          if (!allowedExports.has(name)) errors.push(`Unauthorized export "${name}"`);
        }
      }
    }
  } catch (err2) {
    errors.push(`WASM section parse error: ${err2?.message || err2}`);
  }
  const mod = await WebAssembly.compile(wasm);
  const slopProbe = {
    schema_version: 1,
    site: bundle.manifest.target_site || "youtube",
    sample_text: "not merely nobody tells you midjourney #ai #redditstories part 2 in bio",
    channel: { has_auto_suffix: true, stem_siblings: 3, total_videos: 240, outbound_domain_share: 0.92 },
    upload_cadence: { channel_age_days: 5800, max_dormancy_gap_days: 5400, pre_pivot_videos: 2, post_pivot_videos: 238, post_pivot_share: 0.99, recent_uploads_per_day: 4.2, output_minutes_per_week: 340, duration_cv: 0.04 },
    transcript: { uncontracted_ratio: 0.9, antithesis_per_1k: 2.6, slop_hooks_per_1k: 2.4, keyword_stuffing_ratio: 0.76, intra_video_wpm_cv: 0.08, pause_cv: 0.19, earliest_has_speech: false },
    thumbnails: { title_skeleton_reuse: 0.78, raw_camera_earliest_title: true, synthetic_image_ratio: 0.94, aspect_uniformity: 0.97, repost_watermark_ratio: 0.86 },
    audio_video_stats: { dead_air_floor: true }
  };
  const humanProbe = {
    schema_version: 1,
    site: bundle.manifest.target_site || "youtube",
    sample_text: "Casual studio update from this afternoon",
    channel: { has_auto_suffix: false, stem_siblings: 0, total_videos: 260, outbound_domain_share: 0.06 },
    upload_cadence: { channel_age_days: 4200, max_dormancy_gap_days: 60, recent_uploads_per_day: 0.04, output_minutes_per_week: 8, duration_cv: 0.42 },
    transcript: { uncontracted_ratio: 0.16, first_person_per_1k: 18, disfluencies_per_1k: 2.8, keyword_stuffing_ratio: 0.04, intra_video_wpm_cv: 0.21, pause_cv: 0.52, earliest_has_speech: true },
    thumbnails: { title_skeleton_reuse: 0.1, synthetic_image_ratio: 0, aspect_uniformity: 0.24, repost_watermark_ratio: 0 },
    audio_video_stats: { dead_air_floor: false }
  };
  const rSlop = await evaluateWasmBytes(mod, slopProbe);
  const rHuman = await evaluateWasmBytes(mod, humanProbe);
  if (rHuman.score >= 50) {
    errors.push(`Anti-poisoning guard: clean human profile scored ${rHuman.score}/100 (must be < 50)`);
  }
  if (rSlop.score <= rHuman.score + 15) {
    errors.push(`Separation guard: slop score (${rSlop.score}) must exceed human score (${rHuman.score}) + 15`);
  }
  return {
    ok: errors.length === 0,
    errors,
    wasmBytes: wasm.length,
    maxMemoryPages: maxPages,
    exports: exps,
    extremeSlopScore: rSlop.score,
    cleanHumanScore: rHuman.score
  };
}

// scripts/compile_submission.ts
function argVal(flag) {
  const idx = process.argv.indexOf(flag);
  return idx >= 0 && idx + 1 < process.argv.length ? process.argv[idx + 1] : "";
}
async function main() {
  const inFile = argVal("--input");
  const outFile = argVal("--out");
  if (!inFile || !outFile) {
    throw new Error("Usage: compile_submission.ts --input <project.json> --out <bundle.strule>");
  }
  const raw = JSON.parse(fs.readFileSync(inFile, "utf8"));
  const project = raw.project ? raw.project : raw;
  let privSeed = (process.env.RULE_SIGNING_PRIVATE_KEY || "").trim();
  if (privSeed.length === 128) {
    privSeed = privSeed.slice(0, 64);
  }
  if (privSeed.length !== 64) {
    const kp = await generateAuthorKeypair();
    privSeed = kp.privateSeedHex;
  }
  const commitSha = (process.env.GITHUB_SHA || "").trim();
  const buildRunUrl = (process.env.BUILD_RUN_URL || "").trim();
  const sourceRepo = (process.env.SOURCE_REPO_URL || project.repoUrl || "https://github.com/sloptrap/sloptrap.github.io").trim();
  const { bundle, wasmBytes } = await packProjectBundle(
    project,
    privSeed,
    DEFAULT_SCORING_SEED,
    {
      sourceRepo,
      sourceCommit: /^[0-9a-f]{40}$/i.test(commitSha) ? commitSha : void 0,
      buildRunUrl: buildRunUrl || void 0
    }
  );
  const audit = await auditWasmAndBundle(bundle);
  if (!audit.ok) {
    throw new Error(`Security & accuracy audit rejected rule: ${audit.errors.join("; ")}`);
  }
  fs.writeFileSync(outFile, JSON.stringify(bundle, null, 2) + "\n");
  console.log(
    `Compiled & signed ${bundle.manifest.rule_id} v${bundle.manifest.version} (${wasmBytes.length}B WASM, tier=${bundle.manifest.provenance?.tier}, cleanScore=${audit.cleanHumanScore}/100) -> ${outFile}`
  );
}
main().catch((err2) => {
  console.error(err2);
  process.exit(1);
});
/*! Bundled license information:

@noble/ed25519/index.js:
  (*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)
*/
