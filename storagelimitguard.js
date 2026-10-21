'use strict';

// storagelimitguard.js —— 分源（per-origin）Web 存储配额与分区键裁决内核。
//
// 威胁模型：
//   浏览器为每个站点提供 localStorage / IndexedDB / Cache Storage /
//   Service-Worker 缓存等持久化能力。没有分源配额时的问题：
//     1. 单个站点写入几百 MB 把磁盘占满，造成应用与系统拒绝服务（存储轰炸）；
//     2. 分区键若直接用裸 host 字符串，大小写、尾点、默认端口、userinfo 等差异
//        会让“同一站点”落到多个桶，绕过按源限额；或让两个不同源共享一个桶，
//        造成跨源数据可见；
//     3. 存储键名带 __proto__/constructor 或超长键，下游合并/持久化时引发
//        原型污染或元数据膨胀；
//     4. 无淘汰策略时，配额到顶只能整体失败，正常站点也无法写入。
//
// 本模块是纯逻辑内核：调用方在真正写盘前调用 canStore()，按返回的 allow/deny
// 执行；配额到顶时给出可淘汰的最久未用源（LRU），由调用方清理对应分区。
// 所有字节数为调用方估算后传入（浏览器侧可用 navigator.storage.estimate()）。

const CATEGORIES = Object.freeze([
  'localStorage',
  'indexedDB',
  'cache',
  'serviceWorker',
  'fileSystem',
  'other',
]);

const DEFAULT_LIMITS = Object.freeze({
  perOriginBytes: 50 * 1024 * 1024,   // 单源 50MiB
  globalBytes: 2 * 1024 * 1024 * 1024, // 全局 2GiB
  maxKeyLength: 1024,
  maxKeysPerOrigin: 5000,
  maxOrigins: 2000,
  reserveHeadroomBytes: 16 * 1024 * 1024, // 全局保留余量，到顶前即拒绝
});

// 规范化 origin 为稳定分区键。返回 '' 表示无法安全归属（必须拒绝写入）。
// 纯字符切分，不使用正则。
function originPartitionKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) {
    return '';
  }
  // 不允许 userinfo（partition key 里出现 @ 一律拒绝）。
  if (rest.includes('@')) return '';
  let host = rest;
  let port = 0;
  if (host[0] === '[') {
    const close = host.indexOf(']');
    if (close < 0) return '';
    host = host.slice(1, close); // 键里不保留方括号，IPv6 用裸地址
    const tail = rest.slice(close + 1);
    if (tail.startsWith(':')) port = parsePortNum(tail.slice(1));
    else if (tail !== '') return '';
  } else {
    const colon = rest.indexOf(':');
    if (colon >= 0) {
      host = rest.slice(0, colon);
      port = parsePortNum(rest.slice(colon + 1));
    }
  }
  if (host === '' || port < 0) return '';
  host = host.toLowerCase();
  // 去掉尾点（example.com. 与 example.com 同一主机），但保留单点主机的语义。
  if (host.length > 1 && host.endsWith('.')) host = host.slice(0, -1);
  const defaultPort = scheme === 'https' ? 443 : 80;
  let key = scheme + '://' + host;
  if (port !== 0 && port !== defaultPort) key += ':' + port;
  return key;
}

function parsePortNum(s) {
  if (s === '') return 0;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return -1;
    n = n * 10 + (c - 48);
    if (n > 65535) return -1;
  }
  return n;
}

// isValidStorageKey 校验单个存储键名。
function isValidStorageKey(key, limits) {
  if (typeof key !== 'string') return { ok: false, reason: 'key-not-string' };
  if (key === '') return { ok: false, reason: 'key-empty' };
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return { ok: false, reason: 'key-prototype-pollution' };
  }
  if (key.length > limits.maxKeyLength) return { ok: false, reason: 'key-too-long' };
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return { ok: false, reason: 'key-control-char' };
  }
  return { ok: true };
}

class StorageQuotaGuard {
  constructor(limits, nowFn) {
    this.limits = Object.assign({}, DEFAULT_LIMITS, limits || {});
    this.now = typeof nowFn === 'function' ? nowFn : () => Date.now();
    // key -> { bytes:Map(category->n), keys:number, lastUsed:number }
    this.origins = new Map();
    this.globalBytes = 0;
  }

  _bucket(key) {
    let b = this.origins.get(key);
    if (!b) {
      b = { bytes: new Map(), keys: 0, lastUsed: this.now() };
      for (const c of CATEGORIES) b.bytes.set(c, 0);
      this.origins.set(key, b);
    }
    return b;
  }

  originBytes(bucket) {
    let n = 0;
    for (const v of bucket.bytes.values()) n += v;
    return n;
  }

  // canStore 裁决一次写入。req: { origin, category, key, addBytes }
  // 返回 { allow, reason, partitionKey, evictCandidates }。
  canStore(req) {
    const cat = req && CATEGORIES.includes(req.category) ? req.category : 'other';
    const key = originPartitionKey(req && req.origin);
    if (key === '') return { allow: false, reason: 'bad-origin' };
    if (this.origins.size >= this.limits.maxOrigins && !this.origins.has(key)) {
      return { allow: false, reason: 'too-many-origins', partitionKey: key, evictCandidates: this.evictionCandidates(1) };
    }

    if (req.key !== undefined) {
      const kc = isValidStorageKey(req.key, this.limits);
      if (!kc.ok) return { allow: false, reason: kc.reason, partitionKey: key };
    }

    const add = Number.isFinite(req.addBytes) && req.addBytes > 0 ? Math.floor(req.addBytes) : 0;
    const b = this._bucket(key);

    // 键数量（仅当本次为新增键时调用方传 isNewKey=true）。
    if (req.isNewKey && b.keys + 1 > this.limits.maxKeysPerOrigin) {
      return { allow: false, reason: 'too-many-keys', partitionKey: key, evictCandidates: this.evictionCandidates(1) };
    }

    // 单源配额。
    if (this.originBytes(b) + add > this.limits.perOriginBytes) {
      return { allow: false, reason: 'origin-quota-exceeded', partitionKey: key, evictCandidates: this.evictionCandidates(1) };
    }
    // 全局配额（含保留余量）。
    const effectiveGlobal = this.limits.globalBytes - this.limits.reserveHeadroomBytes;
    if (this.globalBytes + add > effectiveGlobal) {
      const need = this.globalBytes + add - effectiveGlobal;
      return { allow: false, reason: 'global-quota-exceeded', partitionKey: key, evictCandidates: this.evictionCandidates(need) };
    }
    return { allow: true, reason: '', partitionKey: key };
  }

  // commitWrite 在写入真正成功后登记用量。
  commitWrite(origin, category, addBytes, isNewKey) {
    const key = originPartitionKey(origin);
    if (key === '') return false;
    const cat = CATEGORIES.includes(category) ? category : 'other';
    const b = this._bucket(key);
    const n = Number.isFinite(addBytes) && addBytes > 0 ? Math.floor(addBytes) : 0;
    b.bytes.set(cat, b.bytes.get(cat) + n);
    this.globalBytes += n;
    if (isNewKey) b.keys++;
    b.lastUsed = this.now();
    return true;
  }

  // release 回退/删除已登记用量（不得使计数为负）。
  release(origin, category, delBytes) {
    const key = originPartitionKey(origin);
    const b = this.origins.get(key);
    if (!b) return false;
    const cat = CATEGORIES.includes(category) ? category : 'other';
    const n = Math.min(b.bytes.get(cat), Number.isFinite(delBytes) && delBytes > 0 ? Math.floor(delBytes) : 0);
    b.bytes.set(cat, b.bytes.get(cat) - n);
    this.globalBytes -= n;
    b.lastUsed = this.now();
    return true;
  }

  // evictionCandidates 返回最久未使用、且非当前源的分区，按 LRU 升序，
  // 直到累计可回收字节满足 need。调用方据其清理物理分区后调用 clearOrigin。
  evictionCandidates(needBytes) {
    const entries = Array.from(this.origins.entries())
      .map(([k, b]) => ({ partitionKey: k, bytes: this.originBytes(b), lastUsed: b.lastUsed }))
      .filter(e => e.bytes > 0)
      .sort((a, c) => a.lastUsed - c.lastUsed);
    const out = [];
    let freed = 0;
    for (const e of entries) {
      if (needBytes > 0 && freed >= needBytes) break;
      out.push(e);
      freed += e.bytes;
    }
    return out;
  }

  clearOrigin(origin) {
    const key = typeof origin === 'string' && origin.includes('://') ? originPartitionKey(origin) : origin;
    const b = this.origins.get(key);
    if (!b) return false;
    this.globalBytes -= this.originBytes(b);
    this.origins.delete(key);
    return true;
  }

  usage(origin) {
    const key = originPartitionKey(origin);
    const b = this.origins.get(key);
    return {
      partitionKey: key,
      originBytes: b ? this.originBytes(b) : 0,
      globalBytes: this.globalBytes,
      perOriginLimit: this.limits.perOriginBytes,
      globalLimit: this.limits.globalBytes,
    };
  }

  snapshot() {
    const origins = {};
    for (const [k, b] of this.origins) {
      origins[k] = { bytes: Object.fromEntries(b.bytes), keys: b.keys, lastUsed: b.lastUsed };
    }
    return { at: this.now(), globalBytes: this.globalBytes, origins };
  }

  restore(data) {
    if (!data || typeof data !== 'object' || !data.origins) return false;
    this.origins.clear();
    this.globalBytes = 0;
    for (const k of Object.keys(data.origins)) {
      const src = data.origins[k];
      if (!src || typeof src.bytes !== 'object') continue;
      const b = { bytes: new Map(), keys: Number.isFinite(src.keys) ? src.keys : 0, lastUsed: src.lastUsed || 0 };
      for (const c of CATEGORIES) b.bytes.set(c, Number.isFinite(src.bytes[c]) ? src.bytes[c] : 0);
      this.origins.set(k, b);
      this.globalBytes += this.originBytes(b);
    }
    return true;
  }
}

module.exports = {
  CATEGORIES,
  DEFAULT_LIMITS,
  originPartitionKey,
  isValidStorageKey,
  StorageQuotaGuard,
};
