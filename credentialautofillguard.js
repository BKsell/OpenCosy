'use strict';

// credentialautofillguard.js —— 表单凭据自动填充决策内核（纯函数）。
//
// 现代浏览器会在密码框上自动填账号口令。 Electron 这个壳如果不加约束，恶意
// 页面可以：①在 http 页挂密码框骗出已保存凭据；②在 iframe 里跨源挂密码框；
// ③在一个明显不是登录页的普通页面（文章页/搜索页）挂隐藏密码框偷填。
// 本模块只做“这个密码框该不该允许自动填充”的判定，不操作 DOM、不读写凭据库。
//
// 决策：
//   - 非安全上下文（http:/file:）一律禁止自动填充；
//   - 嵌套在跨源 iframe 里的凭据框禁止（顶层同源才允许）；
//   - 顶层但 host 不是常见登录类路径的普通页面，默认不填密码，仅允许用户名；
//   - 已知登录路径（/login /signin /auth /account/signin 等）才放行密码填充。

const LOGIN_PATH_RE = /^\/(login|signin|sign-in|auth|account\/signin|account\/login|logon|connect)([\/?#]|$)/i;

function parseHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    return null;
  }
}

function isSecureContext(url) {
  return /^https:\/\//i.test(String(url || ''));
}

// decideCredentialAutofill 对一个凭据输入框返回策略。
// 入参：
//   pageUrl        当前顶层页面 URL
//   fieldType      'username' | 'password'
//   inCrossOrigin  是否处于跨源 iframe 内
// 返回 { allow:boolean, reason:string, mode:'off'|'username'|'password' }
function decideCredentialAutofill(pageUrl, fieldType, inCrossOrigin) {
  if (!isSecureContext(pageUrl)) {
    return { allow: false, reason: 'insecure context', mode: 'off' };
  }
  if (inCrossOrigin) {
    return { allow: false, reason: 'cross-origin iframe', mode: 'off' };
  }
  let path = '/';
  try {
    path = new URL(pageUrl).pathname || '/';
  } catch (_) {
    return { allow: false, reason: 'unparseable url', mode: 'off' };
  }
  const isLoginPage = LOGIN_PATH_RE.test(path);
  if (fieldType === 'password') {
    if (isLoginPage) {
      return { allow: true, reason: 'login path', mode: 'password' };
    }
    return { allow: false, reason: 'password field off login page', mode: 'off' };
  }
  // 用户名框：登录页可填，普通页也允许（影响小），但跨源已在前面拦掉。
  return { allow: true, reason: 'username field', mode: 'username' };
}

// shouldBlockPasswordPhishBox 是给渲染层快速判断“这个密码框长得像偷填框”的入口：
// 密码框出现在非登录路径即视为可疑，调用方可据此高亮/禁用自动填充。
function shouldBlockPasswordPhishBox(pageUrl) {
  const d = decideCredentialAutofill(pageUrl, 'password', false);
  return !d.allow;
}

module.exports = {
  parseHost,
  isSecureContext,
  decideCredentialAutofill,
  shouldBlockPasswordPhishBox,
  LOGIN_PATH_RE,
};
