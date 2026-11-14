'use strict';

function decodePunyHost(hostname) {
  // 只判断“有没有 xn-- 标签”，不真正做 IDNA 转换（Chromium 已处理显示）。
  return hostname;
}

// isIPv4Literal 判断主机是否是裸 IPv4，支持点分十进制、十六进制（0x..）、
// 八进制（前导 0）以及 inet_aton 短格式（127.1、127.0.1、单段整数 127）这类
// Node/URL 不会归一化、但部分系统仍会解析的写法。
function isIPv4Literal(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return null;
  // [::1] 这类 IPv6 字面量
  if (/^\[[0-9a-f:]+\]$/i.test(h)) return 'ipv6';
  // 单段扁平整数（http://2130706433、http://0x7f000001）
  if (/^(?:0x[0-9a-f]+|\d{1,10})$/.test(h)) return 'ipv4-flat';
  // 2~4 段数值：每段允许十进制 / 0x 十六进制 / 前导 0 八进制。
  // 旧实现只认完整四段，漏掉 127.1 / 127.0.1 这种短格式混淆回环。
  const seg = '(?:0x[0-9a-f]+|0[0-7]+|[0-9]{1,3})';
  if (new RegExp('^' + seg + '(?:\\.' + seg + '){1,3}$').test(h)) {
    const parts = h.split('.');
    const allPlainDecimal = parts.every(p => /^[0-9]{1,3}$/.test(p) && Number(p) <= 255);
    if (parts.length === 4 && allPlainDecimal) return 'ipv4';
    return 'ipv4-nondecimal';
  }
  return null;
}

// extractRawHost 从原始 URL 串切出未规范化的主机（去掉协议、userinfo、
// 端口、路径）。只用于检测“非十进制 IP / 百分号编码”这类会被 WHATWG URL
// 规范化掉的写法；结构判断仍以 new URL 的 hostname 为准。
function extractRawHost(rawUrl) {
  let s = String(rawUrl || '');
  const m = s.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//);
  if (!m) return '';
  s = s.slice(m[0].length);
  // 去掉 userinfo（@ 左侧全部内容，取最后一个 @ 之后）。
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  // 截到路径 / 查询 / 片段。
  s = s.split(/[/?#]/)[0] || '';
  // 去端口。
  s = s.replace(/:\d+$/, '');
  return s.toLowerCase();
}

// hostHasPercentEncoding 主机里若出现 %2e/%2f 之类编码，基本就是在躲地址栏检查。
function hostHasPercentEncoding(hostname) {
  return /%[0-9a-fA-F]{2}/.test(hostname);
}

function foldCompat(rawHost) {
  const raw = String(rawHost || '').toLowerCase();
  try {
    return raw.normalize('NFKC');
  } catch {
    return raw;
  }
}

function tldOf(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

// analyze 是主入口。给 URL 字符串，返回
//   null（无风险）或
//   { url, hostname, score, level, brand, signals: [{code,weight,detail}] }
// 纯函数，任何异常都吞掉返回 null，绝不影响导航主流程。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'edu.cn', 'ac.cn', 'com.hk', 'com.tw', 'co.jp', 'co.kr',
  'com.au', 'com.br', 'co.in',
]);

function registrableLabel(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts[0] || '';
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) return parts[parts.length - 3];
  return parts[parts.length - 2];
}

function leftLabels(hostname) {
  const h = String(hostname || '').toLowerCase();
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return [];
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) return parts.slice(0, -3);
  return parts.slice(0, -2);
}

// isLikelyMainstreamHost 对明显的大型托管/CDN 域名降权，避免“陌生主机”判断过宽。
const MAINSTREAM_HINTS = [
  'amazonaws.com', 'cloudfront.net', 'azureedge.net', 'akamaihd.net',
  'googleusercontent.com', 'github.io', 'vercel.app', 'netlify.app',
  'cloudflare.com', 'workers.dev', 'azurewebsites.net', 'herokuapp.com',
];
function isLikelyMainstreamHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return MAINSTREAM_HINTS.some(suffix => h === suffix || h.endsWith('.' + suffix));
}

function decodeURIComponentSafe(s) {
  try { return decodeURIComponent(s); } catch { return String(s || ''); }
}

module.exports = {
  decodePunyHost,
  isIPv4Literal,
  extractRawHost,
  hostHasPercentEncoding,
  foldCompat,
  tldOf,
  registrableLabel,
  leftLabels,
  isLikelyMainstreamHost,
  decodeURIComponentSafe,
};
