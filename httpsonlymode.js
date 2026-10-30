'use strict';

// httpsonlymode.js —— HTTPS-Only 模式决策。
//
// 用户开了 HTTPS-Only 后，输入 http:// 应该自动升级到 https://，而不是直接
// 明文凭出去。这里把"这次导航该不该自动升级"收敛成纯函数。

// decideHttpsUpgrade 入参：
//   urlStr            用户输入的 URL
//   enabled           布尔：HTTPS-Only 是否开着
//   allowOnLocalhost  布尔：是否对 localhost/内网放行（开发场景）
// 返回 { action:'upgrade'|'pass'|'block', upgradedUrl? }
function decideHttpsUpgrade(opts) {
  const o = opts || {};
  const raw = String(o.urlStr || '');
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { action: 'block' };
  }
  if (!o.enabled) {
    return { action: 'pass' };
  }
  if (u.protocol === 'https:') {
    return { action: 'pass' };
  }
  if (u.protocol !== 'http:') {
    // file: / about: / chrome: 不动。
    return { action: 'pass' };
  }
  const host = u.hostname.toLowerCase();
  const isLocal = host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.startsWith('127.') ||
    host.startsWith('10.') ||
    host.startsWith('192.168.');
  if (isLocal && o.allowOnLocalhost) {
    return { action: 'pass' };
  }
  u.protocol = 'https:';
  // 80/8080 升级后切到 443。
  if (u.port === '80' || u.port === '8080') {
    u.port = '443';
  }
  return { action: 'upgrade', upgradedUrl: u.toString() };
}

module.exports = {
  decideHttpsUpgrade,
};
