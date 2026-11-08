
const { SPACE_LINK_LOCAL, SPACE_LOOPBACK, SPACE_PRIVATE, SPACE_PUBLIC, SPACE_UNKNOWN, SUBRESOURCE_TYPES, classifyIPv4, parseIPPiece, parseIPv4, parseIPv4Literal, parseIPv6 } = require('./pna_classify');
function classifyIPv6(parsed) {
  if (parsed.kind === 'v4mapped') return classifyIPv4(parsed.v4);
  const g = parsed.groups;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
    return SPACE_LOOPBACK; // ::1
  }
  if ((g[0] & 0xfe00) === 0xfc00) return SPACE_PRIVATE;   // fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return SPACE_LINK_LOCAL; // fe80::/10
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0) {
    return classifyIPv4(((g[6] >>> 0) * 65536 + g[7]) >>> 0);
  }
  if (g[0] === 0x2002) {
    return classifyIPv4(((g[1] >>> 0) * 65536 + g[2]) >>> 0);
  }
  if (g[0] === 0x2001 && g[1] === 0) {
    const raw = ((g[6] >>> 0) * 65536 + g[7]) >>> 0;
    return classifyIPv4((raw ^ 0xffffffff) >>> 0);
  }
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
    // 含点：规范四段 + inet_aton 短格式/进制混淆写法（2130706433 之外的
    // 127.1 / 0177.0.0.1 / 0x7f.0.0.1 等）一律按归一化地址分类。
    const v4 = parseIPv4Literal(h);
    if (v4 != null) return classifyIPv4(v4);
  } else if (h.indexOf(':') < 0) {
    // 无点无冒号：可能是单段整数/十六进制/八进制 IP 字面量（如 2130706433、
    // 0x7f000001、017700000001），同样归一化分类；含字母的普通域名返回 null→UNKNOWN。
    const v4 = parseIPv4Literal(h);
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
  parseIPv4Literal,
  classifyIPv4,
  parseIPv6,
  classifyHost,
  evaluatePnaRequest,
  spaceName,
};
