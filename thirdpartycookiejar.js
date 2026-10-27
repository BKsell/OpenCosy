'use strict';

// thirdpartycookiejar.js —— 第三方 Cookie 是否放行的决策内核（纯函数）。
//
// 现代浏览器默认正在全面阻止第三方 Cookie。Electron 壳如果默认全放，会被
// 跨站跟踪。本模块把“这次响应/请求带 Cookie 该不该拦”收敛成一个纯函数：
// 顶层站点与当前资源站点不同源即视为第三方；例外是显式授权过的站点
// （setThirdPartyAllowed）和安全上下文以外的退化场景。
// 不直接操作 session.cookies，只给 main 层一个 yes/no。

function siteKey(url) {
  try {
    const u = new URL(url);
    return (u.protocol + '//' + u.hostname).toLowerCase();
  } catch (_) {
    return null;
  }
}

// decideThirdPartyCookie 判定一次跨站请求的 Cookie 是否允许带。
// 入参：
//   topUrl      顶层页面 URL
//   resourceUrl 正在请求的资源/接口 URL
//   explicitAllow Set<string>：用户显式允许第三方 Cookie 的站点（resource host 前缀）
// 返回 { action:'allow'|'block', reason }
function decideThirdPartyCookie(topUrl, resourceUrl, explicitAllow) {
  const top = siteKey(topUrl);
  const res = siteKey(resourceUrl);
  if (!top || !res) {
    return { action: 'block', reason: 'unparseable url' };
  }
  if (top === res) {
    return { action: 'allow', reason: 'first-party' };
  }
  const allow = explicitAllow || new Set();
  for (const key of allow) {
    const k = String(key || '').toLowerCase();
    if (k && (res === k || res.endsWith('//' + k) || res.endsWith(k))) {
      return { action: 'allow', reason: 'explicit allow' };
    }
  }
  // 非安全上下文一律不做第三方 Cookie 透传。
  if (!/^https:\/\//i.test(resourceUrl)) {
    return { action: 'block', reason: 'insecure third-party' };
  }
  return { action: 'block', reason: 'cross-site tracking' };
}

// shouldPartitionCookies 是给 partitioned cookie 决策用的便捷入口：
// 只要不是第一方，就建议给它打分区标记。
function shouldPartitionCookies(topUrl, resourceUrl) {
  const top = siteKey(topUrl);
  const res = siteKey(resourceUrl);
  return !!top && !!res && top !== res;
}

module.exports = {
  siteKey,
  decideThirdPartyCookie,
  shouldPartitionCookies,
};
