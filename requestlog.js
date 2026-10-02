'use strict';

// requestlog.js —— 跨站连接 / 追踪请求的“按主机聚合”纯逻辑。
//
// 现代浏览器一个页面往往在后台连几十个第三方域名（统计、广告、CDN、字体、
// 埋点……），用户对此基本无感知。这里只做不依赖 Electron 的聚合逻辑：
// 主进程在 webRequest 里把每条 http(s) 请求压缩成
//   { host, resourceType, blocked, scheme, navigated, time }
// 喂进来，由本模块按主机聚合成“连了多少次 / 多少被拦 / 是否顶层打开过 /
// https 占比 / 各资源类型分布”，UI 再据此展示“谁在后台连你”。
//
// 隐私约束（刻意只存主机，永不存路径/查询）：
//  - 记录里只有 host，没有完整 URL、Cookie、请求方法或请求体；
//  - 主机数有上限，超出按最久未活动淘汰；
//  - 纯函数、无 IO、无全局状态，便于 node --test 直接验证。

const DEFAULT_MAX_HOSTS = 400;
const MAX_TYPE_KINDS = 24;

// hostFromUrl 从 URL 里取小写主机名；非法或非 http(s) 返回空串。
function hostFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return '';
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return '';
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
  return (u.hostname || '').toLowerCase();
}

// isThirdParty 判断资源主机相对页面主机是否为跨站（用 eTLD+1 近似：
// 取最后两段；对常见二级后缀 co.uk/com.cn 这类取三段）。没有引公共后缀表，
// 这里只做保守近似，宁可把一部分同源误判成第一方，也不夸大第三方数量。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'edu.cn', 'ac.cn', 'com.hk', 'com.tw', 'co.jp', 'co.kr',
  'com.au', 'com.br', 'co.in',
]);

function registrableHost(host) {
  const h = String(host || '').toLowerCase();
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

function isThirdParty(pageHost, resourceHost) {
  const a = registrableHost(pageHost);
  const b = registrableHost(resourceHost);
  if (!a || !b) return false;
  return a !== b;
}

function createStore(maxHosts) {
  return {
    maxHosts: Math.max(1, Number(maxHosts) || DEFAULT_MAX_HOSTS),
    hosts: new Map(), // host -> record
  };
}

function emptyRecord(host, time) {
  return {
    host,
    firstTime: time,
    lastTime: time,
    requests: 0,
    blocked: 0,
    https: 0,
    http: 0,
    navigated: false, // 是否曾作为顶层页面被打开
    byType: Object.create(null),
  };
}

// normalizeType 把 Electron webRequest 的 resourceType 收敛成有限种类。
function normalizeType(t) {
  const allowed = [
    'mainFrame', 'subFrame', 'stylesheet', 'script', 'image', 'font',
    'object', 'xhr', 'ping', 'cspReport', 'media', 'webSocket', 'other',
  ];
  const v = String(t || 'other');
  return allowed.includes(v) ? v : 'other';
}

// ingest 把一条请求并入存储。entry 字段缺失时按安全默认值处理；返回被更新的
// 记录（引用），未记录（非 http(s)/无主机）时返回 null。该函数不抛错。
function ingest(store, entry) {
  if (!store || !store.hosts) return null;
  const e = entry || {};
  const time = Math.max(0, Number(e.time) || Date.now());
  const host = e.host || hostFromUrl(e.url);
  if (!host) return null;

  let rec = store.hosts.get(host);
  if (!rec) {
    rec = emptyRecord(host, time);
    store.hosts.set(host, rec);
  }
  rec.lastTime = time;
  if (time < rec.firstTime) rec.firstTime = time;

  rec.requests += 1;
  if (e.blocked) rec.blocked += 1;
  if (e.scheme === 'http' || (!e.scheme && /^http:\/\//i.test(e.url || ''))) {
    rec.http += 1;
  } else {
    rec.https += 1;
  }
  if (e.navigated) rec.navigated = true;

  const kind = normalizeType(e.resourceType);
  rec.byType[kind] = (rec.byType[kind] || 0) + 1;

  if (store.hosts.size > store.maxHosts) evict(store);
  return rec;
}

// evict 淘汰最久未活动的主机，直到回到上限以内。
function evict(store) {
  while (store.hosts.size > store.maxHosts) {
    let oldestHost = '';
    let oldestTime = Infinity;
    for (const [host, rec] of store.hosts) {
      if (rec.lastTime < oldestTime) {
        oldestTime = rec.lastTime;
        oldestHost = host;
      }
    }
    if (!oldestHost) break;
    store.hosts.delete(oldestHost);
  }
}

// toList 输出可序列化的数组（Map / byType 对象都转成普通结构），按最近活动倒序。
function toList(store, pageHost) {
  if (!store || !store.hosts) return [];
  const out = [];
  for (const rec of store.hosts.values()) {
    const types = Object.entries(rec.byType)
      .slice(0, MAX_TYPE_KINDS)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);
    out.push({
      host: rec.host,
      firstTime: rec.firstTime,
      lastTime: rec.lastTime,
      requests: rec.requests,
      blocked: rec.blocked,
      https: rec.https,
      http: rec.http,
      navigated: !!rec.navigated,
      thirdParty: pageHost ? isThirdParty(pageHost, rec.host) : false,
      types,
    });
  }
  out.sort((a, b) => b.lastTime - a.lastTime);
  return out;
}

// stats 汇总总量，供安全中心顶部徽标一次取齐。全局台账没有单一“当前页面”
// 概念，无法严谨判定跨站，因此用 backgroundHosts（从未作为顶层页面打开过、
// 只在后台被连接的主机）这一中性指标，而不是夸大成“第三方主机”。
function stats(store) {
  if (!store || !store.hosts) {
    return { hosts: 0, requests: 0, blocked: 0, backgroundHosts: 0, insecureHosts: 0 };
  }
  let requests = 0, blocked = 0, backgroundHosts = 0, insecureHosts = 0;
  for (const rec of store.hosts.values()) {
    requests += rec.requests;
    blocked += rec.blocked;
    if (!rec.navigated) backgroundHosts += 1;
    if (rec.http > 0 && rec.https === 0) insecureHosts += 1;
  }
  return { hosts: store.hosts.size, requests, blocked, backgroundHosts, insecureHosts };
}

function clear(store) {
  if (store && store.hosts) store.hosts.clear();
}

// hydrate 从磁盘台账重建存储（只接受形状正确的记录，防脏数据/注入）。
function hydrate(entries, maxHosts) {
  const store = createStore(maxHosts);
  const time = Date.now();
  if (!Array.isArray(entries)) return store;
  for (const r of entries) {
    if (!r || typeof r !== 'object' || typeof r.host !== 'string' || !r.host) continue;
    const rec = emptyRecord(r.host.slice(0, 253), Number(r.firstTime) || time);
    rec.lastTime = Number(r.lastTime) || rec.firstTime;
    rec.requests = Math.max(0, Number(r.requests) || 0);
    rec.blocked = Math.max(0, Number(r.blocked) || 0);
    rec.https = Math.max(0, Number(r.https) || 0);
    rec.http = Math.max(0, Number(r.http) || 0);
    rec.navigated = !!r.navigated;
    if (r.byType && typeof r.byType === 'object') {
      for (const [k, v] of Object.entries(r.byType).slice(0, MAX_TYPE_KINDS)) {
        const n = Math.max(0, Number(v) || 0);
        if (n) rec.byType[normalizeType(k)] = n;
      }
    }
    store.hosts.set(rec.host, rec);
  }
  evict(store);
  return store;
}

module.exports = {
  DEFAULT_MAX_HOSTS,
  hostFromUrl,
  registrableHost,
  isThirdParty,
  createStore,
  normalizeType,
  ingest,
  toList,
  stats,
  clear,
  hydrate,
};
