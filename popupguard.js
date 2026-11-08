'use strict';

// popupguard.js —— window.open / target=_blank 弹窗的纯逻辑安全内核。
//
// 现代浏览器里“弹窗”是高频攻击面：
//   - window.open('javascript:...') / window.open('data:text/html,...') 可在新
//     浏览上下文里执行脚本或渲染 HTML（旧内核同源继承、携带 opener）；
//   - 跨源弹窗默认带 window.opener，可反向把原页面 location 改成钓鱼站
//     （reverse tabnabbing），需要 noopener 隔离；
//   - 页面用一串 features 试图开“无边框小窗”做点击劫持 / 伪装系统对话框；
//   - 无用户手势的弹窗轰炸（配合主进程的节奏限流一起拦）。
//
// 本内核只做判定，不接触 Electron API；主进程拿到 decision 后决定开标签还是
// 拒绝。因为 OpenCosy 总是“自建标签”而不是真的弹出带 opener 的窗口，结构上
// opener 已经天然为 null，这里仍显式给出 noopener 策略，便于审计与统一口径。

const DANGEROUS_POPUP_SCHEMES = new Set([
  'javascript:', 'data:', 'vbscript:', 'file:',
]);

// NON_WEB_NAV_SCHEMES 是浏览器标签里不应作为顶层导航目标的协议
// （外部协议由专门的确认流处理，不在此拦截）。
const BLOCKED_TOP_NAV_SCHEMES = new Set([
  'javascript:', 'vbscript:', 'file:',
]);

// normalizeFeatures 解析 window.open(url, target, features) 的第三段特性串。
// 输入形如 "noopener=yes,width=400,height=300,popup"；返回规整后的小写 map，
// 布尔型特性（noopener/noreferrer/popup）只要出现就置 true。
function normalizeFeatures(features) {
  const out = Object.create(null);
  if (typeof features !== 'string' || !features) return out;
  const parts = features.split(',');
  for (const raw of parts) {
    const seg = raw.trim();
    if (!seg) continue;
    const eq = seg.indexOf('=');
    let key;
    let value;
    if (eq === -1) {
      key = seg.toLowerCase();
      value = 'true';
    } else {
      key = seg.slice(0, eq).trim().toLowerCase();
      value = seg.slice(eq + 1).trim().toLowerCase();
    }
    if (!key) continue;
    if (key === 'noopener' || key === 'noreferrer' || key === 'popup') {
      out[key] = value !== 'no' && value !== '0' && value !== 'false';
    } else {
      out[key] = value;
    }
  }
  return out;
}

// schemeOf 小写返回 URL 的协议（含冒号）；非法输入返回空串。
function schemeOf(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  const m = /^([a-z][a-z0-9+.-]*:)/i.exec(rawUrl.trim());
  return m ? m[1].toLowerCase() : '';
}

// originOf 尽可能取 URL 的源（scheme://host:port），失败返回空串。
// about:blank 的“继承源”由调用方按当前页源处理，这里返回 'about' 便于区分。
function originOfUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  try {
    const u = new URL(rawUrl);
    if (u.protocol === 'about:') return 'about';
    if (u.protocol === 'data:' || u.protocol === 'javascript:') return '';
    return u.origin === 'null' ? '' : u.origin;
  } catch {
    return '';
  }
}

// isCrossOrigin 判断两个源是否跨源；任一源为空（无法判定）时保守视为跨源。
function isCrossOrigin(originA, originB) {
  if (!originA || !originB) return true;
  if (originA === 'about' || originB === 'about') return true;
  return originA !== originB;
}

// isDangerousPopupUrl 判定弹窗目标是否是“禁止在新浏览上下文打开”的协议。
// data:/javascript: 会在新上下文渲染/执行；file: 在新上下文里可越权读本地。
function isDangerousPopupUrl(rawUrl) {
  return DANGEROUS_POPUP_SCHEMES.has(schemeOf(rawUrl));
}

// isBlockedTopNavUrl 判定窗内顶层导航是否应被阻止（javascript:/vbscript:/file:）。
function isBlockedTopNavUrl(rawUrl) {
  return BLOCKED_TOP_NAV_SCHEMES.has(schemeOf(rawUrl));
}

// isSmallWindowFeatures 判定特性串是否在请求“受限尺寸的独立小窗”（可能用于
// 伪装系统弹窗）。同时指定了宽高且明显小于常规视口时记为可疑，但不单独阻断，
// 仅作为 reason 供 UI/审计参考——OpenCosy 一律用标签承载，特性会被忽略。
function isSmallWindowFeatures(features) {
  const f = features && typeof features === 'object' ? features : normalizeFeatures(features);
  const w = parseInt(f.width, 10);
  const h = parseInt(f.height, 10);
  if (Number.isFinite(w) && Number.isFinite(h) && w > 0 && h > 0 && w <= 320 && h <= 240) {
    return true;
  }
  return false;
}

// evaluateRel 评估 <a target="_blank"> 链接的反向 tabnabbing 防护：
// 跨源且没有 noopener/noreferrer 时应补 noopener。
function evaluateRel(currentUrl, targetUrl, rel) {
  const fromOrigin = originOfUrl(currentUrl);
  const toOrigin = originOfUrl(targetUrl);
  const relTokens = typeof rel === 'string'
    ? rel.toLowerCase().split(/[ \t]+/).filter(Boolean)
    : [];
  const hasNoopener = relTokens.includes('noopener') || relTokens.includes('noreferrer');
  const cross = isCrossOrigin(fromOrigin, toOrigin);
  return {
    crossOrigin: cross,
    hasNoopener: hasNoopener,
    // 跨源且未隔离 → 存在反向 tabnabbing 面，需要 noopener。
    needsNoopener: cross && !hasNoopener,
    recommendedRel: hasNoopener ? relTokens.join(' ') : relTokens.concat('noopener').join(' '),
  };
}

// decidePopup 是主进程 setWindowOpenHandler 调用的统一入口。
//
// 输入：
//   currentUrl  当前页 URL（opener 所在页）
//   targetUrl   window.open 目标
//   features    原始特性串或已规整 map
//   disposition Electron 给的 'new-window' | 'foreground-tab' |
//               'background-tab' | 'save-to-disk' | 'other'
//   isExternal  调用方是否已识别为外部协议（mailto/tel 等），true 时本函数不拦截
//
// 返回：
//   {
//     action: 'block' | 'open-foreground' | 'open-background',
//     noopener: boolean,            // 打开时必须按 noopener 处理
//     reasons: string[],            // 命中的判定原因（审计/提示用）
//     features: object,             // 规整后的特性串
//   }
function decidePopup(input) {
  const opts = input || {};
  const currentUrl = typeof opts.currentUrl === 'string' ? opts.currentUrl : '';
  const targetUrl = typeof opts.targetUrl === 'string' ? opts.targetUrl : '';
  const features = normalizeFeatures(opts.features);
  const reasons = [];

  // 外部协议（mailto/tel 等）由专门确认流负责，这里不做决定。
  if (opts.isExternal) {
    return { action: 'open-background', noopener: true, reasons: ['external-scheme'], features };
  }

  if (isDangerousPopupUrl(targetUrl)) {
    reasons.push('dangerous-popup-scheme:' + (schemeOf(targetUrl) || 'inline-script'));
    return { action: 'block', noopener: true, reasons, features };
  }

  const fromOrigin = originOfUrl(currentUrl);
  const toOrigin = originOfUrl(targetUrl);
  const cross = isCrossOrigin(fromOrigin, toOrigin);

  // 只要跨源，或页面显式要求 noopener/noreferrer，就按 noopener 处理。
  let noopener = cross || features.noopener === true || features.noreferrer === true;
  if (cross) reasons.push('cross-origin-noopener');
  if (features.noopener === true) reasons.push('feature-noopener');
  if (features.noreferrer === true) reasons.push('feature-noreferrer');

  if (isSmallWindowFeatures(features)) {
    // 不阻断（浏览器忽略尺寸用标签打开），但留痕：疑似伪装小窗。
    reasons.push('small-window-features-ignored');
  }

  let action = 'open-foreground';
  if (opts.disposition === 'background-tab') {
    action = 'open-background';
    reasons.push('background-disposition');
  }
  // 无有效源（如 about/data 已在上面拦掉；其余无 origin 的非常规目标）保守新开。
  if (!toOrigin && targetUrl) {
    noopener = true;
  }

  return { action, noopener, reasons, features };
}

module.exports = {
  DANGEROUS_POPUP_SCHEMES,
  normalizeFeatures,
  schemeOf,
  originOfUrl,
  isCrossOrigin,
  isDangerousPopupUrl,
  isBlockedTopNavUrl,
  isSmallWindowFeatures,
  evaluateRel,
  decidePopup,
};
