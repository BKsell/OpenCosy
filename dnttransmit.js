'use strict';

// dnttransmit.js —— Do Not Track 透传策略。
//
// DNT 是浏览器发给服务端的隐私偏好头。Electron 壳默认不透传，导致站点
// 无法识别用户的"别追踪"选择。这里把"这次请求要不要带 DNT 头"收敛成
// 纯函数。

// decideDntHeader 入参：
//   userPreference   'enabled' | 'disabled' | 'unspecified'
//   requestUrl       目标 URL（只允许 http/https）
// 返回 { header: 'DNT', value: '1'|null }
function decideDntHeader(opts) {
  const o = opts || {};
  const pref = String(o.userPreference || 'unspecified');
  const u = String(o.requestUrl || '');
  if (!/^https?:\/\//i.test(u)) {
    return { header: 'DNT', value: null };
  }
  if (pref === 'enabled') {
    return { header: 'DNT', value: '1' };
  }
  // disabled / unspecified 都不发，避免悄悄注入。
  return { header: 'DNT', value: null };
}

// shouldSendSecGpcHeader Global Privacy Control 头，跟随 DNT。
function shouldSendSecGpcHeader(userPreference) {
  return String(userPreference || '') === 'enabled';
}

module.exports = {
  decideDntHeader,
  shouldSendSecGpcHeader,
};
