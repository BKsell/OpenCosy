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
const {
  classifyHost,
  SPACE_LOOPBACK,
  SPACE_PRIVATE,
  SPACE_LINK_LOCAL,
} = require('./pna_core');

const { DEFAULT_EXCEPTION_CAPACITY, FALLBACKABLE_ERROR_CODES, MAX_HOST_BYTES, REASON_EMPTY_HOST, REASON_INVALID, REASON_NONSTANDARD_PORT, REASON_NOT_HTTP, REASON_PRIVATE_HOST, REASON_UPGRADED, REASON_USERINFO, hostLooksPrivate, isHttpString, normalizeExceptionHost, upgradeHttpUrl, urlCarriesUserinfo } = require('./httpsonly_http_core');
function downgradeHttpsUrlForFallback(rawHttpsUrl) {
  if (typeof rawHttpsUrl !== 'string' || rawHttpsUrl === '') return '';
  for (let i = 0; i < rawHttpsUrl.length; i++) {
    const c = rawHttpsUrl.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return '';
  }
  let u;
  try {
    u = new URL(rawHttpsUrl);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:') return '';
  if (urlCarriesUserinfo(u, rawHttpsUrl)) return '';
  if (u.port !== '' && u.port !== '443') return '';
  const target = new URL('http://example.com');
  target.protocol = 'http:';
  target.hostname = u.hostname;
  target.port = '';
  target.pathname = u.pathname;
  target.search = u.search;
  target.hash = u.hash;
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
  REASON_USERINFO,
  REASON_UPGRADED,
  FALLBACKABLE_ERROR_CODES,
  MAX_HOST_BYTES,
  DEFAULT_EXCEPTION_CAPACITY,
  isHttpString,
  urlCarriesUserinfo,
  hostLooksPrivate,
  normalizeExceptionHost,
  upgradeHttpUrl,
  downgradeHttpsUrlForFallback,
  isFallbackableUpgradeError,
  HttpExceptionStore,
};
