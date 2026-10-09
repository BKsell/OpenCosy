'use strict';

// httpsonly.js —— HTTPS-Only 主动升级内核（纯逻辑，不接触 Electron，便于 node:test）。
//
// requestpipeline 在 onBeforeRequest 里把公网 http:// 请求 307 到 https://，但旧
// 实现直接 'https://' + url.slice(7)，有两个实打实的问题：
//   1) 显式 http://host:80/ 升级后变成 https://host:80/——443 服务通常并不监听
//      80，连接必失败，用户看到的是“HTTPS-Only 把本来能开的网站搞挂了”。
//   2) 反向地，http://host:8080/ 这类非标准端口不能假定 https 也在同一个端口，
//      盲目改 scheme 会把请求送到一个说明文 HTTP 的端口去做 TLS 握手，同样失败。
// 此外升级一旦失败（站点根本没有 HTTPS），旧链路只有错误页，没有“用户知情后
// 本次继续走 HTTP”的出口，纯 HTTP 内网/老站点会被彻底锁死。
//
// 本模块只提供纯判定与一个无外部依赖的例外站点集合：
//   - upgradeHttpUrl：把可安全升级的 http URL 改写成 https，不可安全升级给原因；
//   - HttpExceptionStore：按主机名记忆“用户明确同意继续走 HTTP”的站点，带容量
//     上限与输入净化，可序列化落盘；
//   - downgradeHttpsUrlForFallback：升级失败且用户确认后，把 https 候选还原成
//     最初的 http 地址；
//   - isFallbackableUpgradeError：判断哪个网络错误码才表示“站点没有 HTTPS 能力”，
//     证书错误 / 超时 / 域名解析失败一律不提供降级（避免被诱导降级）。

// 结果原因常量，便于调用方留痕与测试断言。
const REASON_NOT_HTTP = 'not-http';
const REASON_INVALID = 'invalid-url';
const REASON_EMPTY_HOST = 'empty-host';
const REASON_PRIVATE_HOST = 'private-host';
const REASON_NONSTANDARD_PORT = 'nonstandard-port';
const REASON_UPGRADED = 'upgraded';

// “站点没有可用 HTTPS”的强信号错误码（Chromium net error 负值）。
// 只收录“服务端明确没有在做 TLS / TLS 协议本身协商不起来”的码：
//   -102 ERR_CONNECTION_REFUSED：443 端口无人监听（最常见的纯 HTTP 站）；
//   -107 ERR_SSL_PROTOCOL_ERROR：端口在说明文，不是 TLS；
//   -112 ERR_SSL_VERSION_OR_CIPHER_MISMATCH：服务端只支持早已禁用的 TLS/套件；
//   -156 ERR_SSL_OBSOLETE_VERSION：服务端 TLS 版本过旧，现代客户端拒绝握手。
// 刻意不收录：
//   证书类错误（-200 系列）——可能是中间人，降级到明文反而顺了攻击者，交证书守卫；
//   -105 ERR_NAME_NOT_RESOLVED——换成 http 一样解析不出来；
//   -118 ERR_CONNECTION_TIMED_OUT / -109 ADDRESS_UNREACHABLE——可能是临时网络
//   抖动或被丢包，不能把“连不上”当成“没有 HTTPS”，否则攻击者靠丢包即可诱发降级。
const FALLBACKABLE_ERROR_CODES = new Set([-102, -107, -112, -156]);

const MAX_HOST_BYTES = 255; // DNS 全名上限，顺带挡住畸形超长主机名。
const DEFAULT_EXCEPTION_CAPACITY = 500;

function isHttpString(rawUrl) {
  return typeof rawUrl === 'string' && rawUrl.startsWith('http://');
}

// hostLooksPrivate 仅按主机名字面量判断回环 / 内网惯例地址，缺省返回 false。
// 真正的私网分类由调用方注入（hostmatch 内核），这里只兜住最明显的字面量，
// 避免本模块在没有注入回调时把 localhost 升级到一个没意义的 https。
function hostLooksPrivate(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return false;
  if (h === 'localhost' || h === 'localhost.localdomain') return true;
  if (h === '127.0.0.1' || h === '[::1]' || h === '::1') return true;
  if (h.endsWith('.localhost')) return true;
  if (h === '0.0.0.0' || h.startsWith('127.')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h.endsWith('.lan')) return true;
  return false;
}

// normalizeExceptionHost 把任意输入收敛成可作为例外键的小写主机名。
// 返回 '' 表示输入不可接受（非字符串 / 含控制字符或空白 / 超长 / 带协议路径）。
function normalizeExceptionHost(input) {
  if (typeof input !== 'string') return '';
  let h = input.trim().toLowerCase();
  if (!h) return '';
  // 允许调用方直接传 http(s) URL 或 origin，取出主机名；纯主机名也接受。
  if (h.indexOf('://') >= 0) {
    try {
      h = new URL(h).hostname.toLowerCase();
    } catch { return ''; }
  } else {
    // 纯主机名里混进路径分隔符 / 端口 / @ 一律不接受，避免一个键匹配多源。
    if (h.indexOf('/') >= 0 || h.indexOf('\\') >= 0 || h.indexOf('@') >= 0
      || h.indexOf(':') >= 0 || h.indexOf('?') >= 0 || h.indexOf('#') >= 0) {
      return '';
    }
  }
  // URL.hostname 对 IPv6 会带方括号，键里统一去掉方括号。
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (!h) return '';
  for (const ch of h) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x20 || cp === 0x7F) return ''; // 控制字符 / 空格
  }
  if (Buffer.byteLength(h, 'utf8') > MAX_HOST_BYTES) return '';
  return h;
}

// upgradeHttpUrl 判定一条 http URL 是否应、以及如何升级到 https。
//   isPrivateHost（可选）接收 hostname 返回 true 表示这是私网 / 回环主机。
// 返回 { ok:boolean, url:string, reason:string, host:string }：
//   ok=true 时 url 为目标 https 地址；ok=false 时 url 为空、reason 说明原因。
function upgradeHttpUrl(rawUrl, isPrivateHost) {
  const fail = (reason) => ({ ok: false, url: '', reason, host: '' });
  if (!isHttpString(rawUrl)) {
    // 区分一下“根本不是 http”和“是 https 但传进来了”，对调用方都是不升级。
    return fail(REASON_NOT_HTTP);
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return fail(REASON_INVALID);
  }
  const host = u.hostname.toLowerCase();
  if (!host) return fail(REASON_EMPTY_HOST);

  const privateByDefault = hostLooksPrivate(host);
  let privateByInjection = false;
  if (typeof isPrivateHost === 'function') {
    try { privateByInjection = !!isPrivateHost(host); } catch { privateByInjection = false; }
  }
  if (privateByDefault || privateByInjection) {
    return { ok: false, url: '', reason: REASON_PRIVATE_HOST, host };
  }

  // 端口处理：
  //   无显式端口（默认 80）→ 升级到 https 默认 443，不带端口；
  //   显式 80        → 同样收敛到 https 默认端口；
  //   其它显式端口   → 不升级，交给调用方放行 http 或按策略处理。
  if (u.port !== '' && u.port !== '80') {
    return { ok: false, url: '', reason: REASON_NONSTANDARD_PORT, host };
  }

  // 用 URL 对象重组，自动正确保留 pathname/search/hash 与百分号编码；显式去掉
  // 端口让其走 https 默认 443。userinfo（极少见）按同主机升级保留。
  const target = new URL('https://example.com');
  target.protocol = 'https:';
  target.hostname = host;
  target.port = '';
  target.pathname = u.pathname;
  target.search = u.search;
  target.hash = u.hash;
  target.username = u.username;
  target.password = u.password;
  return { ok: true, url: target.toString(), reason: REASON_UPGRADED, host };
}

// downgradeHttpsUrlForFallback 在“升级到 https 失败且用户确认继续 http”时，把
// https 候选还原成最初的 http 地址。只处理默认端口形态（无端口 / 443），非标
// 准端口不回退（那本来就不是我们升级出来的）。
function downgradeHttpsUrlForFallback(rawHttpsUrl) {
  if (typeof rawHttpsUrl !== 'string' || !rawHttpsUrl.startsWith('https://')) return '';
  let u;
  try {
    u = new URL(rawHttpsUrl);
  } catch {
    return '';
  }
  if (u.port !== '' && u.port !== '443') return '';
  const target = new URL('http://example.com');
  target.protocol = 'http:';
  target.hostname = u.hostname;
  target.port = '';
  target.pathname = u.pathname;
  target.search = u.search;
  target.hash = u.hash;
  target.username = u.username;
  target.password = u.password;
  return target.toString();
}

function isFallbackableUpgradeError(errorCode) {
  // 严格要求整数数字：Electron 回调给的 errorCode 本就是 number，不收字符串，
  // 避免 '-102' 这类外部拼接值被悄悄当成可降级信号。
  if (typeof errorCode !== 'number' || !Number.isInteger(errorCode)) return false;
  return FALLBACKABLE_ERROR_CODES.has(errorCode);
}

// HttpExceptionStore 是“用户已同意继续走 HTTP”的主机集合，纯内存 + 可序列化。
// 结构：Map<host, { host, addedAt }>，按加入顺序在超容量时淘汰最老条目。
class HttpExceptionStore {
  constructor(capacity) {
    const cap = Number(capacity);
    this.capacity = Number.isInteger(cap) && cap > 0 ? cap : DEFAULT_EXCEPTION_CAPACITY;
    this.map = new Map();
  }

  size() {
    return this.map.size;
  }

  has(host) {
    const key = normalizeExceptionHost(host);
    return !!key && this.map.has(key);
  }

  // add 返回规范化后的主机名；输入非法返回 ''。重复加入刷新 addedAt 但不改变
  // 容量淘汰次序之外的语义（删后重插，等于用户重新确认）。
  add(host, now) {
    const key = normalizeExceptionHost(host);
    if (!key) return '';
    if (this.map.has(key)) this.map.delete(key);
    const ts = Number(now);
    this.map.set(key, { host: key, addedAt: Number.isFinite(ts) && ts > 0 ? ts : Date.now() });
    while (this.map.size > this.capacity) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
    }
    return key;
  }

  remove(host) {
    const key = normalizeExceptionHost(host);
    if (!key) return false;
    return this.map.delete(key);
  }

  clear() {
    this.map.clear();
  }

  hosts() {
    return Array.from(this.map.values());
  }

  toJSON() {
    return { version: 1, hosts: this.hosts() };
  }

  // load 用落盘数据重建，非法 / 重复条目静默丢弃，超容量按数据顺序保留最新的。
  load(data) {
    this.map.clear();
    const rows = data && Array.isArray(data.hosts) ? data.hosts : [];
    for (const r of rows) {
      if (!r || typeof r.host !== 'string') continue;
      const key = normalizeExceptionHost(r.host);
      if (!key) continue;
      const addedAt = Number(r.addedAt);
      this.map.set(key, { host: key, addedAt: Number.isFinite(addedAt) && addedAt > 0 ? addedAt : 0 });
      if (this.map.size > this.capacity) {
        const oldest = this.map.keys().next().value;
        this.map.delete(oldest);
      }
    }
    return this.map.size;
  }
}

module.exports = {
  REASON_NOT_HTTP,
  REASON_INVALID,
  REASON_EMPTY_HOST,
  REASON_PRIVATE_HOST,
  REASON_NONSTANDARD_PORT,
  REASON_UPGRADED,
  FALLBACKABLE_ERROR_CODES,
  MAX_HOST_BYTES,
  DEFAULT_EXCEPTION_CAPACITY,
  isHttpString,
  hostLooksPrivate,
  normalizeExceptionHost,
  upgradeHttpUrl,
  downgradeHttpsUrlForFallback,
  isFallbackableUpgradeError,
  HttpExceptionStore,
};
