'use strict';

// pna.js —— Private Network Access（私有网络访问）判定纯内核（不依赖 Electron）。
//
// 威胁：你用浏览器打开的任意公网网页，脚本可以让浏览器去请求
//   - 家里/公司的路由器后台（http://192.168.1.1、http://192.168.0.1）
//   - 本机服务（http://127.0.0.1:xxxx、http://localhost）
//   - 云主机元数据（http://169.254.169.254/latest/meta-data/）
//   - 内网管理面板（10.x、172.16-31.x、[::1]、[fc00::]）
// 这类请求带着“你本人在可信网络里”的位置信任，公网页面本不该拥有，
// 是 CSRF 打内网、DNS rebinding、云凭据窃取的经典入口。现代 Chrome 用
// PNA（CORS-RFC1918 后继）限制“更私有”的子资源请求；本模块在
// onBeforeRequest 里做一道显式的、可测试的判定。
//
// 策略（保守但不挡正常使用）：
//   - 顶层导航（mainFrame）永不拦截，用户自己点开的地址照走；
//   - 发起方是本地/私网页面（如路由器后台自己）不拦截；
//   - 仅当“公网/安全上下文页面”发起的子资源目标落在更私有地址空间时拦截；
//   - localhost 名称、IP 字面量都识别；IPv4-mapped/IPv4-compatible IPv6
//     还原成 v4 再分类。

// 子资源类型集合（Electron webRequest resourceType 取值）。
const SUBRESOURCE_TYPES = new Set([
  'subFrame', 'stylesheet', 'script', 'image', 'font', 'object',
  'xhr', 'ping', 'cspReport', 'media', 'webSocket', 'other',
]);

// 分类结果的空间等级，数值越大越私有。
const SPACE_PUBLIC = 0;
const SPACE_LINK_LOCAL = 1; // 169.254.0.0/16、fe80::/10
const SPACE_PRIVATE = 2;    // 10/8、172.16/12、192.168/16、fc00::/7
const SPACE_LOOPBACK = 3;   // 127/8、::1
const SPACE_UNKNOWN = -1;   // 域名解析前无法判断（留给调用方放行/记录）

// 解析 IPv4 点分十进制，返回 0..0xffffffff 或 null（非法/带前导零宽松拒绝）。
function parseIPv4(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(text || ''));
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const oct = m[i];
    // 拒绝前导零（01.02 这种在不同实现里会被解释成八进制）。
    if (oct.length > 1 && oct[0] === '0') return null;
    const n = Number(oct);
    if (n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

function classifyIPv4(v) {
  const a = (v >>> 24) & 0xff;
  const b = (v >>> 16) & 0xff;
  if (a === 127) return SPACE_LOOPBACK;                 // 127.0.0.0/8
  if (a === 10) return SPACE_PRIVATE;                   // 10.0.0.0/8
  if (a === 192 && b === 168) return SPACE_PRIVATE;     // 192.168.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return SPACE_PRIVATE; // 172.16/12
  if (a === 169 && b === 254) return SPACE_LINK_LOCAL;  // 169.254.0.0/16
  if (a === 0) return SPACE_PRIVATE;                    // 0.0.0.0/8 “本网络”
  if (a === 100 && b >= 64 && b <= 127) return SPACE_LINK_LOCAL; // CGNAT 100.64/10
  if (a >= 224) return SPACE_PUBLIC;                    // 组播/保留按公网处理（不会误拦）
  return SPACE_PUBLIC;
}

// 将 IPv6 规整成 8 段 16 位数组；支持 :: 压缩、IPv4-mapped（::ffff:1.2.3.4）。
function parseIPv6(text) {
  let s = String(text || '').toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct); // 去掉 zone id（fe80::1%eth0）
  if (!s) return null;

  // 末尾嵌 IPv4（::ffff:192.168.0.1）单独取出。
  let v4Part = null;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.indexOf('.') >= 0) {
    const v4 = parseIPv4(tail);
    if (v4 == null) return null;
    s = s.slice(0, lastColon + 1) + ((v4 >>> 16) & 0xffff).toString(16) +
      ':' + (v4 & 0xffff).toString(16);
    v4Part = v4;
  }

  const dbl = s.indexOf('::');
  let groups;
  if (dbl >= 0) {
    if (s.indexOf('::', dbl + 1) >= 0) return null; // 只能有一个 ::
    const left = dbl === 0 ? [] : s.slice(0, dbl).split(':');
    const right = s.slice(dbl + 2) ? s.slice(dbl + 2).split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    groups = left.concat(new Array(missing).fill('0'), right);
  } else {
    groups = s.split(':');
  }
  if (groups.length !== 8) return null;

  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  // IPv4-mapped（::ffff:a.b.c.d）按对应 v4 分类。
  if (v4Part != null && out[0] === 0 && out[1] === 0 && out[2] === 0 &&
      out[3] === 0 && out[4] === 0 && out[5] === 0xffff) {
    return { kind: 'v4mapped', v4: v4Part };
  }
  return { kind: 'v6', groups: out };
}

function classifyIPv6(parsed) {
  if (parsed.kind === 'v4mapped') return classifyIPv4(parsed.v4);
  const g = parsed.groups;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
    return SPACE_LOOPBACK; // ::1
  }
  if ((g[0] & 0xfe00) === 0xfc00) return SPACE_PRIVATE;   // fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return SPACE_LINK_LOCAL; // fe80::/10
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0xffff && (g[6] >>> 8) === 0) {
    // ::ffff:a.b.c.d 在上面已处理，这里兜底。
    return classifyIPv4(((g[6] & 0xff) << 16 >>> 0) + g[7]);
  }
  // IPv4-compatible（::a.b.c.d，已废弃）把低 32 位当 v4。
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0 && g[6] !== 0xffff) {
    const v4 = ((g[6] >>> 0) * 65536 + g[7]) >>> 0;
    return classifyIPv4(v4);
  }
  return SPACE_PUBLIC;
}

// 主机名分类：IP 字面量精确分类；localhost 视为环回；
// 普通域名在解析前无法判定，返回 UNKNOWN。
function classifyHost(host) {
  const h = String(host || '').replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!h) return SPACE_UNKNOWN;
  if (h === 'localhost' || h.endsWith('.localhost')) return SPACE_LOOPBACK;
  if (h.indexOf('.') >= 0) {
    const v4 = parseIPv4(h);
    if (v4 != null) return classifyIPv4(v4);
  }
  if (h.indexOf(':') >= 0) {
    const parsed = parseIPv6(h);
    if (parsed) return classifyIPv6(parsed);
  }
  return SPACE_UNKNOWN;
}

// hostFromUrl 安全取小写 hostname（去端口、去方括号）。
function hostFromUrl(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ''; }
}

// 空间等级名称，用于台账/事件。
function spaceName(level) {
  switch (level) {
    case SPACE_LOOPBACK: return 'loopback';
    case SPACE_PRIVATE: return 'private';
    case SPACE_LINK_LOCAL: return 'link-local';
    case SPACE_UNKNOWN: return 'unknown';
    default: return 'public';
  }
}

// evaluatePnaRequest 是主入口。details 形如 onBeforeRequest 的回调对象：
//   { url, resourceType, documentURL|initiator? }
// options: { enabled }。返回 { block:boolean, reason:string, targetLevel,
// initiatorLevel }。
function evaluatePnaRequest(details, options) {
  const opts = Object.assign({ enabled: true }, options || {});
  const allow = (reason) => ({
    block: false, reason, targetLevel: SPACE_UNKNOWN, initiatorLevel: SPACE_UNKNOWN,
  });
  if (!opts.enabled) return allow('disabled');
  if (!details || typeof details.url !== 'string') return allow('bad-details');

  // 顶层导航与用户直接打开的内容不拦。
  const rt = details.resourceType || '';
  if (rt === 'mainFrame') return allow('main-frame');
  if (!SUBRESOURCE_TYPES.has(rt)) return allow('resource-type');

  // 只处理浏览器会带位置信任的协议；file/data/blob 不走网络地址空间判定。
  if (!/^https?:/i.test(details.url)) return allow('non-http-target');

  const targetHost = hostFromUrl(details.url);
  const targetLevel = classifyHost(targetHost);
  if (targetLevel === SPACE_UNKNOWN || targetLevel === SPACE_PUBLIC) {
    return { block: false, reason: 'target-public', targetLevel, initiatorLevel: SPACE_UNKNOWN };
  }

  // 目标确定更私有。再看发起方：私网页面自己访问私网放行。
  const initiatorUrl = details.documentURL || details.initiator || details.originURL || '';
  const initiatorHost = hostFromUrl(initiatorUrl);
  const initiatorLevel = initiatorHost ? classifyHost(initiatorHost) : SPACE_UNKNOWN;
  if (initiatorLevel === SPACE_LOOPBACK || initiatorLevel === SPACE_PRIVATE ||
      initiatorLevel === SPACE_LINK_LOCAL) {
    return { block: false, reason: 'private-initiator', targetLevel, initiatorLevel };
  }

  // 公网页面 / 无页面上下文（如浏览器直接触发的 ping）打向私有地址：拦截。
  const reasonMap = {};
  reasonMap[SPACE_LOOPBACK] = 'public-to-loopback';
  reasonMap[SPACE_LINK_LOCAL] = 'public-to-link-local';
  reasonMap[SPACE_PRIVATE] = 'public-to-private';
  return {
    block: true,
    reason: reasonMap[targetLevel] || 'public-to-private',
    targetLevel,
    initiatorLevel,
    targetHost,
    targetSpace: spaceName(targetLevel),
    initiatorSpace: spaceName(initiatorLevel),
  };
}

module.exports = {
  SPACE_PUBLIC,
  SPACE_LINK_LOCAL,
  SPACE_PRIVATE,
  SPACE_LOOPBACK,
  SPACE_UNKNOWN,
  SUBRESOURCE_TYPES,
  parseIPv4,
  classifyIPv4,
  parseIPv6,
  classifyHost,
  evaluatePnaRequest,
  spaceName,
};
