'use strict';

// webshareguard.js —— Web Share API（navigator.share）调用闸门。
//
// navigator.share 会把页面数据交给系统分享面板，可能泄露到外部 App。
// 现代浏览器要求用户手势 + 安全上下文；Electron 壳如果默认放行，一个被注入的
// 页面就能静默分享剪贴板/截图/URL 给任意目标。这里把“这次 share 该不该放行”
// 收敛成纯函数。

// decideShare 入参：
//   isSecureContext 布尔
//   hasUserGesture 布尔（是否由用户手势触发）
//   payload        { title, text, url, files }
// 返回 { action:'allow'|'block', reason }
function decideShare(isSecureContext, hasUserGesture, payload) {
  if (!isSecureContext) {
    return { action: 'block', reason: 'insecure-context' };
  }
  if (!hasUserGesture) {
    return { action: 'block', reason: 'no-user-gesture' };
  }
  const p = payload || {};
  const hasContent = Boolean(p.title || p.text || p.url || (Array.isArray(p.files) && p.files.length));
  if (!hasContent) {
    return { action: 'block', reason: 'empty-payload' };
  }
  if (p.url) {
    try {
      const u = new URL(p.url);
      if (u.protocol !== 'https:') {
        return { action: 'block', reason: 'non-shareable-url' };
      }
    } catch (_) {
      return { action: 'block', reason: 'bad-url' };
    }
  }
  // 文件分享要单独确认，不在这一层静默放行。
  if (Array.isArray(p.files) && p.files.length) {
    return { action: 'block', reason: 'files-need-confirmation' };
  }
  return { action: 'allow', reason: 'ok' };
}

// shouldPromptForFiles 给 UI 层用：带文件时必须弹确认。
function shouldPromptForFiles(payload) {
  return Boolean(payload && Array.isArray(payload.files) && payload.files.length);
}

module.exports = {
  decideShare,
  shouldPromptForFiles,
};
