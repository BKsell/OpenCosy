'use strict';

// referrerpolicydecider.js —— Referer 头策略决策。
//
// 浏览器默认 `strict-origin-when-cross-origin`，但对第三方分析器、跨域下载、
// 隐私敏感页需要收紧。这里把"这次导航该发什么 Referer"收敛成纯函数。

// decideReferrer 入参：
//   pageUrl      当前页 URL
//   targetUrl    目标 URL
//   userPolicy   用户全局策略：'no-referrer' | 'origin' | 'strict-origin-when-cross-origin'
//   isPrivateBrowsing 是否隐私窗口
// 返回要发给目标的 Referer 值（'' 表示不发）。
function decideReferrer(opts) {
  const o = opts || {};
  const page = safeUrl(o.pageUrl);
  const target = safeUrl(o.targetUrl);
  if (!page || !target) return '';
  if (o.isPrivateBrowsing) return '';
  const policy = String(o.userPolicy || 'strict-origin-when-cross-origin');
  switch (policy) {
    case 'no-referrer':
      return '';
    case 'origin':
      return page.origin + '/';
    case 'strict-origin':
      if (page.protocol === 'https:' && target.protocol === 'http:') return '';
      return page.origin + '/';
    case 'strict-origin-when-cross-origin':
      if (page.origin === target.origin) return page.href;
      if (page.protocol === 'https:' && target.protocol === 'http:') return '';
      return page.origin + '/';
    default:
      return '';
  }
}

function safeUrl(u) {
  try { return new URL(String(u || '')); } catch { return null; }
}

module.exports = {
  decideReferrer,
};
