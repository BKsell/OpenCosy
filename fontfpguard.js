'use strict';

// fontfpguard.js —— 字体枚举指纹（measureText/offsetWidth 探测已安装字体）裁决内核。
//
// 威胁模型：
//   1. 页面用大量候选字体名，配合 canvas measureText 或 span.offsetWidth 差异
//      探测用户安装了哪些字体（中文字体尤其稀有），形成稳定指纹；
//   2. 探测常使用 base 字体 monospace/sans-serif 作为对照，逐个候选渲染测量；
//   3. 高频/批量测量（短时间几百个字体名）是指纹脚本的典型行为；
//   4. 离屏 canvas 2d measureText 是主要读取面，且不可见、无用户感知。
//
// 纯逻辑：识别批量探测行为并按预算裁决，提供通用字体白名单（命中即返回对照宽度）。

const FF_DENY = 'deny';
const FF_ALLOW = 'allow';
const FF_GENERIC = 'generic';

const FF_REASON = Object.freeze({
  BAD_ORIGIN: 'ff-bad-origin',
  BLOCKED_ORIGIN: 'ff-blocked-origin',
  BUDGET_EXCEEDED: 'ff-budget-exceeded',
  WINDOW_THROTTLED: 'ff-window-throttled',
  NON_STRING_FONT: 'ff-non-string-font',
  FONT_NAME_TOO_LONG: 'ff-font-name-too-long',
});

// 跨平台通用字体，直接返回对照宽度不构成指纹。
const COMMON_FONTS = Object.freeze([
  'monospace', 'sans-serif', 'serif', 'cursive', 'fantasy',
  'system-ui', 'ui-monospace', 'ui-sans-serif', 'ui-serif',
  'arial', 'helvetica', 'times new roman', 'courier new', 'georgia', 'verdana',
]);

function defaultFontFpPolicy() {
  return {
    maxDistinctFontsPerOrigin: 30, // 每 origin 最多探测 30 个非通用字体名
    maxMeasurementsPerWindow: 120, // 滑动窗口内测量次数
    windowMs: 5000,
    maxFontNameLen: 128,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

function normalizeFontName(font) {
  if (typeof font !== 'string') return '';
  let s = font.trim().toLowerCase();
  if (s.indexOf(',') >= 0) s = s.split(',')[0].trim(); // font 简写只取首个
  if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
    s = s.slice(1, -1);
  }
  if (s.length >= 1 && s.charAt(0) === "'" && s.charAt(s.length - 1) === "'") {
    s = s.slice(1, -1);
  }
  return s;
}

function isCommonFont(name) {
  return COMMON_FONTS.indexOf(name) >= 0;
}

class FontFpGuard {
  constructor(policy) {
    this.policy = policy || defaultFontFpPolicy();
    this.distinct = new Map(); // origin -> Set
    this.events = new Map(); // origin -> [timestamps]
  }

  // decideMeasure 裁决一次字体测量。ctx: {origin, blocked, now}
  decideMeasure(ctx, requestedFont) {
    const pol = this.policy;
    const key = originKey(ctx && ctx.origin);
    if (!key) return { decision: FF_DENY, reason: FF_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: FF_DENY, reason: FF_REASON.BLOCKED_ORIGIN };
    if (typeof requestedFont !== 'string') return { decision: FF_DENY, reason: FF_REASON.NON_STRING_FONT };
    const name = normalizeFontName(requestedFont);
    if (name === '') return { decision: FF_DENY, reason: FF_REASON.NON_STRING_FONT };
    if (name.length > pol.maxFontNameLen) return { decision: FF_DENY, reason: FF_REASON.FONT_NAME_TOO_LONG };

    const now = ctx.now || 0;
    // 滑动窗口频控。
    let evs = this.events.get(key) || [];
    evs = evs.filter((t) => now - t < pol.windowMs);
    if (evs.length >= pol.maxMeasurementsPerWindow) {
      this.events.set(key, evs);
      return { decision: FF_DENY, reason: FF_REASON.WINDOW_THROTTLED };
    }
    evs.push(now);
    this.events.set(key, evs);

    // 通用字体不计预算。
    if (isCommonFont(name)) return { decision: FF_ALLOW, reason: '', font: name };

    let set = this.distinct.get(key);
    if (!set) { set = new Set(); this.distinct.set(key, set); }
    if (!set.has(name)) {
      if (set.size >= pol.maxDistinctFontsPerOrigin) {
        return { decision: FF_DENY, reason: FF_REASON.BUDGET_EXCEEDED, font: name };
      }
      set.add(name);
    }
    return { decision: FF_ALLOW, reason: '', font: name };
  }

  distinctCount(origin) {
    const set = this.distinct.get(originKey(origin));
    return set ? set.size : 0;
  }
}

module.exports = {
  FF_ALLOW, FF_DENY, FF_GENERIC, FF_REASON, COMMON_FONTS,
  defaultFontFpPolicy, originKey, normalizeFontName, isCommonFont, FontFpGuard,
};
