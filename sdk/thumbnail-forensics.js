/** Bounded thumbnail analysis for the MV3 background worker. No cookies or remote model calls. */
const MAX_THUMB_CACHE = 256;
const thumbCache = new Map();
const eraCache = new Map();
const ERA_TTL_MS = 7 * 86400 * 1000;
const clamp = n => Math.max(0, Math.min(1, n));

function lruGet(map, key) {
  const value = map.get(key);
  if (value !== undefined) { map.delete(key); map.set(key, value); }
  return value;
}
function lruSet(map, key, value, max) {
  map.delete(key);
  map.set(key, value);
  if (map.size > max) map.delete(map.keys().next().value);
}

export function analyzeThumbnailPixels(pixels, width = 96, height = 54) {
  if (!pixels || pixels.length < width * height * 4) throw new Error("thumbnail pixels missing");
  const gray = new Float32Array(width * height);
  const cells = new Float32Array(24);
  const sums = new Float32Array(6);
  const rows = new Float32Array(height);
  const rowColor = new Float32Array(height);
  let sideDark = 0, sideCount = 0, middleDark = 0, middleCount = 0, satSum = 0;
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    const p = (y * width + x) * 4;
    const r = pixels[p] / 255, g = pixels[p + 1] / 255, b = pixels[p + 2] / 255;
    const lum = .2126 * r + .7152 * g + .0722 * b;
    const sat = Math.max(r, g, b) - Math.min(r, g, b);
    const edge = x > 0 ? Math.abs(lum - gray[y * width + x - 1]) : 0;
    gray[y * width + x] = lum;
    const ci = Math.min(1, Math.floor(y * 2 / height)) * 3 + Math.min(2, Math.floor(x * 3 / width));
    const off = ci * 4;
    cells[off] += r; cells[off + 1] += g; cells[off + 2] += b;
    cells[off + 3] += (sat + edge) / 2;
    sums[ci]++;
    rows[y] += lum;
    rowColor[y] += sat;
    satSum += sat;
    if (x < width * .17 || x >= width * .83) { sideDark += lum; sideCount++; }
    else { middleDark += lum; middleCount++; }
  }
  for (let i = 0; i < 6; i++) for (let j = 0; j < 4; j++) cells[i * 4 + j] /= sums[i] || 1;
  let hash = 0n;
  for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) {
    const sy = Math.floor((y + .5) * height / 8);
    const sx = Math.floor((x + .5) * width / 9);
    const nx = Math.floor((x + 1.5) * width / 9);
    hash = (hash << 1n) | BigInt(gray[sy * width + sx] > gray[sy * width + nx] ? 1 : 0);
  }
  let banner = 0;
  for (let y = 2; y < height - 3; y++) {
    const avg = rows[y] / width;
    const edge = Math.abs(rows[y - 1] - rows[y]) / width;
    const sat = rowColor[y] / width;
    if ((y > height * .55 || y < height * .28) && edge > .13 && sat > .16 && avg > .12) banner++;
  }
  const cableNewsChyronScore = clamp(banner / 5);
  const sideContrast = (middleDark / middleCount) - (sideDark / sideCount);
  const phoneCaptureScore = clamp(sideContrast * 2.8 + (1 - satSum / (width * height)) * .18 - cableNewsChyronScore * .45);
  return { cableNewsChyronScore, phoneCaptureScore, dHash: hash.toString(16).padStart(16, "0"), descriptor: Array.from(cells) };
}

export async function analyzeThumbnailBlob(blob) {
  const bitmap = await createImageBitmap(blob);
  try {
    const canvas = new OffscreenCanvas(96, 54);
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(bitmap, 0, 0, 96, 54);
    return analyzeThumbnailPixels(ctx.getImageData(0, 0, 96, 54).data);
  } finally { bitmap.close(); }
}

export async function analyzeThumbnailUrl(url) {
  if (!/^https:\/\/i\.ytimg\.com\/vi\/[A-Za-z0-9_-]{11}\//.test(url)) return null;
  const hit = lruGet(thumbCache, url);
  if (hit) return hit;
  const resp = await fetch(url, { credentials: "omit", redirect: "error" });
  if (!resp.ok || Number(resp.headers.get("content-length") || 0) > 2_000_000) return null;
  const blob = await resp.blob();
  if (blob.size > 2_000_000) return null;
  const result = await analyzeThumbnailBlob(blob);
  lruSet(thumbCache, url, result, MAX_THUMB_CACHE);
  return result;
}

export function visualCloneSimilarity(a, b) {
  if (!a || !b) return 0;
  let bits = BigInt(`0x${a.dHash}`) ^ BigInt(`0x${b.dHash}`), distance = 0;
  while (bits) { distance++; bits &= bits - 1n; }
  let color = 0;
  for (let i = 0; i < 24; i++) color += Math.abs(a.descriptor[i] - b.descriptor[i]);
  return clamp(.65 * (1 - distance / 64) + .35 * (1 - color / 24));
}

export function eraVisualPivot(oldest, newest) {
  if (!oldest?.length || newest?.length < 2) return 0;
  const phone = oldest.reduce((s, a) => s + a.phoneCaptureScore, 0) / oldest.length;
  let similarity = 0, pairs = 0;
  for (let i = 0; i < newest.length; i++) for (let j = i + 1; j < newest.length; j++) {
    similarity += visualCloneSimilarity(newest[i], newest[j]); pairs++;
  }
  return clamp(phone * (similarity / pairs) * 1.25);
}

function walkJson(root, visitor, max = 50000) {
  const stack = [root];
  while (stack.length && max-- > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    visitor(node);
    if (Array.isArray(node)) stack.push(...node.slice().reverse());
    else stack.push(...Object.values(node).reverse());
  }
}
function textOf(node) {
  return node?.simpleText || node?.runs?.map(x => x.text || "").join("") || "";
}
export function videoSamplesFromInitialData(data, limit = 6) {
  const videos = [], seen = new Set();
  walkJson(data, n => {
    const v = n.richGridMedia?.videoRenderer || n.videoRenderer || n.gridVideoRenderer;
    const lockup = n.richItemRenderer?.content?.lockupViewModel || n.lockupViewModel;
    const id = v?.videoId || (lockup?.contentType === "LOCKUP_CONTENT_TYPE_VIDEO" ? lockup.contentId : "");
    if (!/^[A-Za-z0-9_-]{11}$/.test(id) || seen.has(id) || videos.length >= limit) return;
    seen.add(id);
    const parts = lockup?.metadata?.lockupMetadataViewModel?.metadata?.contentMetadataViewModel?.metadataRows
      ?.flatMap(row => row.metadataParts || []) || [];
    const published = v ? textOf(v.publishedTimeText) :
      (parts.map(p => p.accessibilityLabel || p.text?.content || "").find(x => /\b(?:ago|yesterday|today)\b/i.test(x)) || "");
    videos.push({ id, title: v ? textOf(v.title) : lockup?.metadata?.lockupMetadataViewModel?.title?.content || "",
      published, thumbnailUrl: `https://i.ytimg.com/vi/${id}/mqdefault.jpg` });
  });
  return videos;
}
function oldestToken(data) {
  let token = "";
  walkJson(data, n => {
    if (token) return;
    const cv = n.chipViewModel;
    if (cv?.text?.trim().toLowerCase() === "oldest") token = cv.tapCommand?.innertubeCommand?.continuationCommand?.token || "";
    const cc = n.chipCloudChipRenderer;
    if (textOf(cc?.text).trim().toLowerCase() === "oldest") token = cc.navigationEndpoint?.continuationCommand?.token || "";
  });
  return token;
}
export function publishedAgeDays(label) {
  const text = String(label || "").toLowerCase();
  if (/\byesterday\b/.test(text)) return 1;
  const m = text.match(/(\d+)\s*(day|week|month|year|hour|minute|d|w|mo|y|h|m)s?\s+ago/);
  const units = { day: 1, week: 7, month: 30, year: 365, hour: 0, minute: 0, d: 1, w: 7, mo: 30, y: 365, h: 0, m: 0 };
  return m ? Number(m[1]) * units[m[2]] : 0;
}
function titleSkeleton(s) { return s.toLowerCase().replace(/\d+/g, "#").replace(/[^a-z# ]/g, "").trim(); }
let inFlight = 0;
const waiting = [];
async function limited(fn) {
  if (inFlight >= 2) await new Promise(resolve => waiting.push(resolve));
  inFlight++;
  try { return await fn(); } finally { inFlight--; waiting.shift()?.(); }
}

export async function probeYoutubeChannelEra(handleOrId) {
  const raw = String(handleOrId || "").trim();
  if (!/^@[A-Za-z0-9._-]{2,64}$/.test(raw) && !/^UC[A-Za-z0-9_-]{22}$/.test(raw)) return null;
  const cached = lruGet(eraCache, raw);
  if (cached && Date.now() - cached.at < ERA_TTL_MS) return cached.data;
  return limited(async () => {
    const path = raw.startsWith("UC") ? `channel/${raw}` : raw;
    const response = await fetch(`https://www.youtube.com/${path}/videos`, { credentials: "omit", redirect: "error" });
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 5_000_000) return null;
    const html = await response.text();
    if (html.length > 5_000_000) return null;
    const match = html.match(/(?:var\s+)?ytInitialData\s*=\s*(\{.*?\});\s*<\/script>/s);
    if (!match) return null;
    const data = JSON.parse(match[1]);
    const newest = videoSamplesFromInitialData(data, 6);
    let oldest = [];
    const token = oldestToken(data);
    const key = html.match(/"INNERTUBE_API_KEY"\s*:\s*"([^"]+)"/)?.[1];
    if (token && key) {
      const clientVersion = html.match(/"INNERTUBE_CLIENT_VERSION"\s*:\s*"([^"]+)"/)?.[1] || "2.20261101.00.00";
      const resp = await fetch(`https://www.youtube.com/youtubei/v1/browse?key=${encodeURIComponent(key)}`, {
        method: "POST", credentials: "omit", redirect: "error", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ context: { client: { clientName: "WEB", clientVersion } }, continuation: token }),
      });
      if (resp.ok && Number(resp.headers.get("content-length") || 0) < 5_000_000) oldest = videoSamplesFromInitialData(await resp.json(), 3);
    }
    // A missing Oldest continuation does not mean the newest six are the oldest uploads.
    // Treat the sampled dates as a complete history only when the two tabs overlap.
    const completeHistory = oldest.some(v => newest.some(n => n.id === v.id));
    const [newImages, oldImages] = await Promise.all([
      Promise.all(newest.map(v => analyzeThumbnailUrl(v.thumbnailUrl).catch(() => null))),
      Promise.all(oldest.map(v => analyzeThumbnailUrl(v.thumbnailUrl).catch(() => null))),
    ]);
    const recent = newImages.filter(Boolean), early = oldImages.filter(Boolean);
    let clone = 0, pairs = 0;
    for (let i = 0; i < recent.length; i++) for (let j = i + 1; j < recent.length; j++) {
      clone += visualCloneSimilarity(recent[i], recent[j]); pairs++;
    }
    const skeletons = newest.map(v => titleSkeleton(v.title)).filter(Boolean);
    const newestAges = newest.map(v => publishedAgeDays(v.published)).filter(n => n > 0).sort((a, b) => a - b);
    const allAges = completeHistory
      ? [...new Set([...newest, ...oldest].map(v => publishedAgeDays(v.published)).filter(n => n > 0))].sort((a, b) => a - b)
      : [];
    let maxDormancyGapDays = 0;
    for (let i = 1; i < allAges.length; i++) maxDormancyGapDays = Math.max(maxDormancyGapDays, allAges[i] - allAges[i - 1]);
    const recentSpanDays = newestAges.length > 1 ? newestAges.at(-1) - newestAges[0] : 0;
    const result = {
      newest, oldest,
      cableNewsChyronRatio: recent.length ? recent.reduce((s, v) => s + v.cableNewsChyronScore, 0) / recent.length : 0,
      visualCloneSimilarity: pairs ? clone / pairs : 0,
      eraVisualPivot: eraVisualPivot(early, recent),
      maxDormancyGapDays,
      postPivotShare: completeHistory ? newest.length / Math.max(1, new Set([...newest, ...oldest].map(v => v.id)).size) : 0,
      recentUploadsPerDay: recentSpanDays > 0 ? (newestAges.length - 1) / recentSpanDays : 0,
      titleSkeletonReuse: skeletons.length ? 1 - new Set(skeletons).size / skeletons.length : 0,
      alteredContentFlag: /"alteredContent"\s*:\s*true/.test(html),
      rawCameraEarliestTitle: oldest.some(v => /^(?:IMG|VID)[_-]|^\d{8}/i.test(v.title)),
    };
    lruSet(eraCache, raw, { at: Date.now(), data: result }, 128);
    return result;
  });
}
