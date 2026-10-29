'use strict';

// webtransportorigin.js —— WebTransport 连接 origin 校验。
//
// WebTransport 允许 QUIC 多路复用，页面可以同时开大量并发流做穿透。
// 它跟普通 fetch 一样受 CORS 约束，但在 Electron 这种壳里，渲染进程
// 发起的 WebTransport 目标也必须是 https、不能指内网。

// decideWebTransport 入参：
//   urlStr          连接目标 URL
//   hasUserGesture  布尔
//   privateHosts   可选：由外层注入的内网/回环判定函数，缺省走内置规则
// 返回 { action:'allow'|'block', reason }
function decideWebTransport(opts) {
  const o = opts || {};
  const urlStr = String(o.urlStr || '');
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return { action: 'block', reason: 'bad-url' };
  }
  if (u.protocol !== 'https:') {
    return { action: 'block', reason: 'scheme-not-https' };
  }
  if (!o.hasUserGesture) {
    return { action: 'block', reason: 'no-user-gesture' };
  }
  const host = u.hostname.toLowerCase();
  if (typeof o.privateHosts === 'function') {
    if (o.privateHosts(host)) {
      return { action: 'block', reason: 'private-host' };
    }
  } else if (isPrivateHost(host)) {
    return { action: 'block', reason: 'private-host' };
  }
  return { action: 'allow', reason: 'ok' };
}

// isPrivateHost 粗判内网/回环。
function isPrivateHost(host) {
  const h = String(host || '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h === '[::1]') return true;
  if (h.startsWith('127.') || h.startsWith('10.') || h.startsWith('192.168.')) return true;
  if (h.startsWith('172.')) {
    const second = Number(h.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

module.exports = {
  decideWebTransport,
  isPrivateHost,
};
