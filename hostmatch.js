'use strict';

// hostmatch.js —— 主机名规范化与"精确 / 子域边界"匹配的唯一纯逻辑内核。
//
// 历史上这套判断在 main.js 里各写一份：
//   - 追踪域名拦截（hostMatchesTracker）：toLowerCase + 去一个尾点 + Set 精确命中 +
//     全表 endsWith('.' + t)；
//   - Cookie 按域查看 / 按域删除（两处重复）：d === domain || d.endsWith('.' + domain)；
//   - 私网 / 本机判定（isPrivateNetworkHost）：再写一遍 localhost、.localhost、
//     IPv4-mapped、四段 IPv4 私网段。
//
// 三处口径必须一致，否则会出现"追踪拦截认得 example.com. 的尾点写法、Cookie 归属
// 却不认得"这类缝。这里统一收口，且刻意不使用正则：主机名规范化只做小写、去
// IPv6 方括号、去尾部根点；边界匹配一律走 "相等" 或 "以 base 加一个点开头"，
// 绝不允许裸 endsWith(base)（那会把 evil-evil.com 误判成 evil.com 的子域）。

// normalizeHostname 把来自 URL.hostname / Cookie domain 的主机名归一成可直接比较的形态：
// 去首尾空白、转小写、剥掉 IPv6 的一对方括号、去掉结尾的一个或多个根点。
function normalizeHostname(host) {
  let h = String(host == null ? '' : host).trim().toLowerCase();
  if (h.length >= 2 && h.charCodeAt(0) === 91 && h.charCodeAt(h.length - 1) === 93) {
    h = h.slice(1, -1); // [::1] -> ::1
  }
  while (h.length > 0 && h.charCodeAt(h.length - 1) === 46) {
    h = h.slice(0, -1); // 去掉 FQDN 尾部根点（可能不止一个）
  }
  return h;
}

// hostEqualsOrSubdomain 判断 host 是否就是 base，或落在 base 的子域边界内。
// "a.example.com" 对 "example.com" 为真；"evilexample.com" 为假（必须隔着一个点）。
function hostEqualsOrSubdomain(host, base) {
  const h = normalizeHostname(host);
  const b = normalizeHostname(base);
  if (!h || !b) return false;
  return h === b || h.endsWith('.' + b);
}

// hostMatchesList 在一组基准域名里做精确 / 子域边界匹配。entries 支持数组或 Set。
// 基准列表由调用方持有（如 TRACKER_HOSTS），内核不缓存、不内置名单。
function hostMatchesList(host, entries) {
  const h = normalizeHostname(host);
  if (!h || !entries) return false;
  for (const entry of entries) {
    const b = normalizeHostname(entry);
    if (b && (h === b || h.endsWith('.' + b))) return true;
  }
  return false;
}

// parseIPv4Parts 解析严格的四段点分十进制，返回四个数字段；不合法返回 null。
// 与历史正则 ^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$ 逐字等价：每段 1~3 位
// 纯数字，允许前导零与 >255 的段（这类段后续不会命中任何私网条件，行为与旧实现一致）。
function parseIPv4Parts(host) {
  const h = normalizeHostname(host);
  const parts = h.split('.');
  if (parts.length !== 4) return null;
  const nums = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (part.length < 1 || part.length > 3) return null;
    for (let j = 0; j < part.length; j++) {
      const cc = part.charCodeAt(j);
      if (cc < 48 || cc > 57) return null; // 非 0-9 直接判非 IPv4
    }
    nums[i] = Number(part);
  }
  return nums;
}

// isPrivateHostname 判断主机名是否指向本机 / 私网 / 链路本地，口径与旧
// isPrivateNetworkHost 完全一致：localhost 及其子域、::1、IPv4-mapped 回环、
// 127/8、10/8、172.16/12、192.168/16、169.254/16。
function isPrivateHostname(rawHost) {
  const host = normalizeHostname(rawHost);
  if (!host) return false;
  if (host === '::1') return true;
  if (hostEqualsOrSubdomain(host, 'localhost')) return true;
  if (host === '::ffff:127.0.0.1') return true;
  const p = parseIPv4Parts(host);
  if (!p) return false;
  const a = p[0], b = p[1];
  if (a === 127 || a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

module.exports = {
  normalizeHostname,
  hostEqualsOrSubdomain,
  hostMatchesList,
  parseIPv4Parts,
  isPrivateHostname,
};
