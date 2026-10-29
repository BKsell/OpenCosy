'use strict';

// clipboardwriteguard.js —— navigator.clipboard.writeText / write 调用闸门。
//
// 网页在没有用户手势时静默写剪贴板（把用户复制的地址替换成钓鱼链接）是
// 一类老漏洞。W3C Clipboard API 要求 transient activation；这里把“这次写
// 剪贴板该不该放行”收敛成纯函数。

// decideClipboardWrite 入参：
//   hasUserGesture 布尔
//   isSecureContext 布尔
//   targetUrl      当前页 URL（about:/devtools: 内部页不允许写）
//   textLength     写入文本长度
// 返回 { action:'allow'|'block', reason }
function decideClipboardWrite(opts) {
  const o = opts || {};
  if (!o.isSecureContext) {
    return { action: 'block', reason: 'insecure-context' };
  }
  if (!o.hasUserGesture) {
    return { action: 'block', reason: 'no-user-gesture' };
  }
  const u = String(o.targetUrl || '');
  if (u.startsWith('about:') || u.startsWith('devtools:') || u.startsWith('chrome:')) {
    return { action: 'block', reason: 'internal-page' };
  }
  const len = Number(o.textLength || 0);
  if (len > 5 * 1024 * 1024) {
    return { action: 'block', reason: 'too-large' };
  }
  return { action: 'allow', reason: 'ok' };
}

// shouldShowClipboardToast 是否在写入后给用户一个短暂 toast 提示。
// 写大段文本（>200 字符）时提示，避免静默替换用户已复制内容。
function shouldShowClipboardToast(textLength) {
  return Number(textLength || 0) > 200;
}

module.exports = {
  decideClipboardWrite,
  shouldShowClipboardToast,
};
