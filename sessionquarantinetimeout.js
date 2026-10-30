'use strict';

// sessionquarantinetimeout.js —— 站点权限信任过期。
//
// 用户给某站开了"自动弹通知/读剪贴板/自启动"，过 N 小时后还在生效。
// 如果这期间域名被接管（过期重注册、CDN 误配），权限会被新站点白捡。
// 这里把"信任是否还在有效期内"收敛成纯函数，到期自动降级。

// isTrustStillValid 入参：
//   grantedAtMs   授权时间戳
//   nowMs         当前时间戳
//   ttlMs         信任有效期（毫秒）
//   userRevoked   用户是否显式撤销
// 返回 { valid, reason }
function isTrustStillValid(opts) {
  const o = opts || {};
  if (o.userRevoked) {
    return { valid: false, reason: 'revoked' };
  }
  const granted = Number(o.grantedAtMs) || 0;
  const now = Number(o.nowMs) || 0;
  const ttl = Number(o.ttlMs) || 0;
  if (granted <= 0 || ttl <= 0) {
    return { valid: false, reason: 'missing-metadata' };
  }
  if (now - granted > ttl) {
    return { valid: false, reason: 'expired' };
  }
  return { valid: true, reason: 'ok' };
}

// nextRefreshPromptInMs 距离下次提醒用户重新授权还有多久。
// 过了 80% TTL 就该提示。
function nextRefreshPromptInMs(opts) {
  const o = opts || {};
  const granted = Number(o.grantedAtMs) || 0;
  const now = Number(o.nowMs) || 0;
  const ttl = Number(o.ttlMs) || 0;
  if (granted <= 0 || ttl <= 0) return 0;
  const refreshAt = granted + Math.floor(ttl * 0.8);
  return Math.max(0, refreshAt - now);
}

module.exports = {
  isTrustStillValid,
  nextRefreshPromptInMs,
};
