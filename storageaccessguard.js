'use strict';

// storageaccessguard.js —— 跨框架会话存储 / 缓存分区访问的观测与洪泛检测内核。
//
// 威胁模型：
//   Chromium 的存储分区（storage partitioning）会在“子框架访问顶层存储 / 缓存”时
//   向 webContents 派发：
//     - 'seen-session-storage-data-access'(event, details)
//     - 'seen-cache-storage-data-access'(event, details)
//   details 至少带 frame（WebFrameMain）与 key，并可能带 storageType / cacheType。
//   这两类事件此前 0 接线。它们本身是“观测型”事件（不能 preventDefault），但有两个
//   安全价值：
//     1. 跨站子框架（嵌入的第三方 iframe）读写顶层分区存储，是追踪 / 侧信道的常见
//        载体。逐次弹窗会被正常页面刷爆，但完全不观测则无法发现“某个源在跨站上下文
//        里高频读写存储”的异常模式。
//     2. 恶意页面可在循环里疯狂触发存储访问制造事件洪泛，任何“逐事件落审计 / 逐事件
//        IPC 到渲染层”的朴素接线都会被放大成 CPU / 磁盘 / IPC 资源耗尽。
//
//   本内核只做纯聚合判定：按 (类别, 框架源, 顶层源, 存储类型) 分桶计数，跨源首次访问
//   上报一次做留痕，同源高频只累计；超过窗口阈值才升级为 report。key 只做长度 / 折行
//   清洗并参与哈希式分桶，不回传原值，避免把站点存储键带进审计。
// 时间窗哨兵 now < 0 表示禁用时间窗（确定性测试）；阈值检测在 now>=0 时才生效。

const KIND_SESSION = 'session-storage';
const KIND_CACHE = 'cache-storage';

const ACTION_OBSERVE = 'observe'; // 常规计数，不上报
const ACTION_REPORT = 'report';   // 值得留痕 / 通知（跨源首次或超阈值）

// 跨源子框架访问：每个桶首次出现即上报一次（去重靠 reported 集合）。
// 同源高频访问：单个窗口内超过该阈值才升级上报。
const DEFAULT_WINDOW_MS = 10 * 1000;
const DEFAULT_MAX_ACCESS_PER_WINDOW = 2000;

// 存储 / 缓存类型与 key 的长度上限，仅用于分桶 / 摘要，防止超长串灌入。
const MAX_TYPE_CHARS = 32;
const MAX_KEY_CHARS = 120;

// 单个 webContents 内同时保留的桶数上界。桶按 (类别, 框架源, 顶层源, 类型) 区分，
// 跨站追踪器很多时桶会增长；webContents 销毁时整份状态会丢弃，但长生命周期标签仍
// 可能累积，这里再设硬上界，超出后淘汰最久未新建的桶（Map 保持插入序）。
const MAX_STORAGE_BUCKETS = 2048;

const KNOWN_KINDS = new Set([KIND_SESSION, KIND_CACHE]);

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

function clampToken(value, max) {
  if (value === null || value === undefined) return '';
  let s = String(value).replace(/[\r\n]+/g, ' ');
  if (s.length > max) s = s.slice(0, max);
  return s;
}

function normalizeKind(kind) {
  return KNOWN_KINDS.has(kind) ? kind : '';
}

// bucketKey 组装分桶键。key 只取长度指纹（不使用原值），避免泄漏站点存储键内容。
function bucketKey(kind, frameOrigin, topOrigin, storageType) {
  return [kind, frameOrigin || 'no-origin', topOrigin || 'no-origin', storageType || '-'].join('|');
}

function createStorageAccessState() {
  return {
    buckets: new Map(),  // bucketKey -> { count, windowStart, windowHits, reportedCross, lastReport }
    reported: new Set(), // 已做过“跨源首次”上报的桶
    total: 0,
    reports: 0,
  };
}

function getBucket(st, key) {
  let b = st.buckets.get(key);
  if (!b) {
    if (st.buckets.size >= MAX_STORAGE_BUCKETS) {
      const oldest = st.buckets.keys().next().value;
      if (oldest !== undefined) st.buckets.delete(oldest);
    }
    b = { count: 0, windowStart: -1, windowHits: 0, reportedCross: false, lastReport: -1 };
    st.buckets.set(key, b);
  }
  return b;
}

// decideStorageAccess 裁决一次存储 / 缓存访问事件。
//   input: { kind, frameUrl, topUrl, key, storageType }
//   now:   毫秒时间戳；now < 0 禁用时间窗（逐条确定性判定，不做高频升级）。
// 返回 { action, kind, frameOrigin, topOrigin, crossOrigin, bucket, count, windowHits, reason }。
function decideStorageAccess(state, input, now, options) {
  const st = state || createStorageAccessState();
  const inp = input || {};
  const opts = options || {};
  const windowMs = (typeof opts.windowMs === 'number' && opts.windowMs > 0)
    ? opts.windowMs : DEFAULT_WINDOW_MS;
  const maxHits = (typeof opts.maxPerWindow === 'number' && opts.maxPerWindow > 0)
    ? opts.maxPerWindow : DEFAULT_MAX_ACCESS_PER_WINDOW;

  st.total++;

  const kind = normalizeKind(inp.kind);
  if (!kind) {
    // 未知类别不细分桶，单独聚合并在显式阈值下上报，避免脏事件洪泛。
    const key = 'unknown|-';
    const b = getBucket(st, key);
    b.count++;
    return {
      action: ACTION_OBSERVE, kind: '', frameOrigin: '', topOrigin: '', crossOrigin: false,
      bucket: key, count: b.count, windowHits: b.windowHits, reason: 'unknown-kind',
    };
  }

  const frameOrigin = originFromUrl(inp.frameUrl);
  const topOrigin = originFromUrl(inp.topUrl);
  const storageType = clampToken(inp.storageType, MAX_TYPE_CHARS);
  const crossOrigin = !!frameOrigin && !!topOrigin && frameOrigin !== topOrigin;
  const key = bucketKey(kind, frameOrigin, topOrigin, storageType);
  const b = getBucket(st, key);
  b.count++;

  // 窗口计数（仅在提供有效时间时滚动）。
  if (now >= 0) {
    if (b.windowStart < 0 || now - b.windowStart >= windowMs) {
      b.windowStart = now;
      b.windowHits = 0;
    }
    b.windowHits++;
  }

  // 1) 跨源子框架访问：每桶首次出现上报一次，后续同源重复不再刷屏。
  if (crossOrigin && !b.reportedCross) {
    b.reportedCross = true;
    b.lastReport = now >= 0 ? now : -1;
    st.reports++;
    return {
      action: ACTION_REPORT, kind, frameOrigin, topOrigin, crossOrigin: true,
      bucket: key, count: b.count, windowHits: b.windowHits, reason: 'cross-origin-storage-access',
    };
  }

  // 2) 高频洪泛：窗口内命中超阈值，且距上次上报超过一个窗口，做限频升级上报。
  if (now >= 0 && b.windowHits > maxHits) {
    const due = b.lastReport < 0 || (now - b.lastReport) >= windowMs;
    if (due) {
      b.lastReport = now;
      st.reports++;
      return {
        action: ACTION_REPORT, kind, frameOrigin, topOrigin, crossOrigin,
        bucket: key, count: b.count, windowHits: b.windowHits, reason: 'storage-access-flood',
      };
    }
  }

  return {
    action: ACTION_OBSERVE, kind, frameOrigin, topOrigin, crossOrigin,
    bucket: key, count: b.count, windowHits: b.windowHits, reason: '',
  };
}

// summarizeKey 仅供需要时给出键的“长度 + 前缀指纹”摘要（不含完整键）。
function summarizeKey(key) {
  const s = clampToken(key, MAX_KEY_CHARS);
  return { length: s.length, head: s.slice(0, 8) };
}

module.exports = {
  KIND_SESSION,
  KIND_CACHE,
  ACTION_OBSERVE,
  ACTION_REPORT,
  DEFAULT_WINDOW_MS,
  DEFAULT_MAX_ACCESS_PER_WINDOW,
  MAX_TYPE_CHARS,
  MAX_KEY_CHARS,
  MAX_STORAGE_BUCKETS,
  originFromUrl,
  clampToken,
  normalizeKind,
  bucketKey,
  createStorageAccessState,
  decideStorageAccess,
  summarizeKey,
};
