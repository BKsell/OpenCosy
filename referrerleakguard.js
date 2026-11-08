'use strict';

// referrerleakguard.js —— 导航跳转时 Referer 该发多少的纯决策内核。
//
// 浏览器默认行为（no-referrer-when-downgrade）在现代站点上仍会把完整 URL（含
// 查询串里的 token、会话追踪参数）带给目标站。本模块把“这次跳转要不要剥 Referer、
// 剥到 origin 还是完全不发”收敛成纯函数，供 main.js 在 will-navigate / new-window
// 处统一调用，避免各入口各写一份又口径不一。
//
// 策略：
//   - 目标是 http://（从 https 降级）：一律不发 Referer；
//   - 目标是 http:// 且源也是 http://：剥到 origin（不把查询串带过去）；
//   - 跨域 https→https：默认剥到 origin（不发完整路径），白名单同源才发完整；
//   - 同源 https→https：发完整 Referer；
//   - 源是 file:/about:/chrome-extension:：绝不发 Referer。

function parseOrigin(url) {
  try {
    const u = new URL(url);
    return u.origin;
  } catch (_) {
    return null;
  }
}

function isSecureUrl(url) {
  return /^https:\/\//i.test(String(url || ''));
}

function isLocalSource(url) {
  return /^(file|about|chrome-extension|data|blob):/i.test(String(url || ''));
}

// decideReferrer 对一次导航返回 Referer 处理建议。
// 入参：sourceUrl、targetUrl 为完整 URL。
// 返回 { mode: 'none'|'origin'|'full', value }：
//   none  -> 不发 Referer；
//   origin-> 只发 scheme://host 部分；
//   full  -> 发完整 sourceUrl。
function decideReferrer(sourceUrl, targetUrl) {
  if (!sourceUrl || !targetUrl) {
    return { mode: 'none', value: '' };
  }
  if (isLocalSource(sourceUrl)) {
    return { mode: 'none', value: '' };
  }
  const src = parseOrigin(sourceUrl);
  const tgt = parseOrigin(targetUrl);
  if (!src || !tgt) {
    return { mode: 'none', value: '' };
  }
  // https -> http 降级：完全不发。
  if (isSecureUrl(sourceUrl) && !isSecureUrl(targetUrl)) {
    return { mode: 'none', value: '' };
  }
  // 同源：发完整。
  if (src === tgt) {
    return { mode: 'full', value: sourceUrl };
  }
  // 跨域 http(http) 或 https(https)：只发 origin。
  return { mode: 'origin', value: src };
}

// shouldStripSensitiveQuery 报告 URL 查询串里是否带常见敏感参数（token/key/sid），
// 即便决定发 full，调用方也可据此额外剥查询串。
function shouldStripSensitiveQuery(url) {
  try {
    const u = new URL(url);
    const re = /(token|access_token|api[_-]?key|session|sid|auth)/i;
    for (const k of u.searchParams.keys()) {
      if (re.test(k)) return true;
    }
    return false;
  } catch (_) {
    return false;
  }
}

module.exports = {
  parseOrigin,
  isSecureUrl,
  isLocalSource,
  decideReferrer,
  shouldStripSensitiveQuery,
};
