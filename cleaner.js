'use strict';

// cleaner.js —— 站点数据清理规划内核（跨会话统一口径）。
//
// 用途：给用户提供“按站点 / 按域名 / 按时间窗”的浏览数据清理。Electron 的
// session.clearStorageData 能力在 main 进程按 storage 类型执行；本文件负责
// 执行前的“规划”：把 main 进程枚举到的站点存储条目按用户条件过滤、校验、
// 组合成清理计划，并产出不可抵赖的清理审计。
//
// 威胁模型 / 设计约束：
//  1. 误删防线：清理是破坏性操作，必须“先计划后执行”。filterSiteEntries 只做
//     纯函数筛选（不触碰 session），main 进程把计划展示给用户确认后再执行。
//  2. 通配滥用：matchMode 只有 exact（完全匹配）/ subdomains（含子域）/ all
//     （全部站点）三档；禁止任意正则 / 前缀通配，防止“误伤”合法站点数据。
//  3. 时间窗一致性：since 必须与 lastAccessed 同一时间语义（毫秒时间戳）；
//     越界 / 非法值回退为 0（全部）。
//  4. 审计完整性：recordCleanAudit 追加条目并封顶（cap），审计带时间戳与发起
//     条件快照，后续“删了什么”可回溯。

const MAX_AUDIT_ENTRIES = 200;
const MAX_TARGETS = 10000;

// normalizeMatchMode 收口三档匹配模式。
function normalizeMatchMode(mode) {
  if (mode === 'exact' || mode === 'subdomains' || mode === 'all') return mode;
  return 'exact';
}

// normalizeSince 校验毫秒时间戳；非法值回退 0（不过滤时间）。
function normalizeSince(since) {
  if (typeof since !== 'number' || !Number.isFinite(since) || since < 0) return 0;
  return Math.floor(since);
}

// hostMatchesOrigin 判断条目 origin 是否命中站点条件。
// origin 例：https://example.com、http://sub.example.com:8080。
function hostMatchesOrigin(origin, host, mode) {
  if (mode === 'all') return true;
  if (typeof origin !== 'string' || typeof host !== 'string') return false;
  const lowerOrigin = origin.toLowerCase();
  let ohost;
  try {
    ohost = new URL(lowerOrigin).hostname;
  } catch {
    // 非 URL 的条目名（如部分扩展数据）按字符串前缀兜底。
    const idx = lowerOrigin.indexOf('://');
    if (idx < 0) return false;
    ohost = lowerOrigin.slice(idx + 3).split(/[/:]/)[0];
  }
  if (ohost === '') return false;
  const h = host.toLowerCase();
  if (h === '') return false;
  if (mode === 'exact') return ohost === h;
  // subdomains：主机相等或“以 .host 结尾”（限定在标签边界，防止 example.com 命中
  // notexample.com）。
  return ohost === h || ohost.endsWith('.' + h);
}

// filterSiteEntries 纯函数筛选：entries 为 { origin, storageType, bytes, lastAccessed }
// 列表；返回命中的目标 + 汇总（站点数 / 字节 / 分类型统计）。
function filterSiteEntries(entries, opts) {
  opts = opts || {};
  const mode = normalizeMatchMode(opts.matchMode);
  const since = normalizeSince(opts.since);
  const host = typeof opts.host === 'string' ? opts.host.trim().toLowerCase() : '';
  const wantedTypes = Array.isArray(opts.storageTypes)
    ? opts.storageTypes.filter((t) => typeof t === 'string')
    : [];

  if (!Array.isArray(entries)) return { ok: false, reason: 'bad-entries' };
  if (mode !== 'all' && host === '') return { ok: false, reason: 'bad-host' };
  if (entries.length > MAX_TARGETS) return { ok: false, reason: 'too-many-targets' };

  const targets = [];
  const seen = new Set();
  const byType = {};
  let totalBytes = 0;
  for (const e of entries) {
    if (!e || typeof e !== 'object') continue;
    const origin = typeof e.origin === 'string' ? e.origin : '';
    if (origin === '') continue;
    if (wantedTypes.length > 0 && !wantedTypes.includes(e.storageType)) continue;
    if (!hostMatchesOrigin(origin, host, mode)) continue;
    if (since > 0) {
      const last = typeof e.lastAccessed === 'number' ? e.lastAccessed : 0;
      if (last > 0 && last < since) continue;
    }
    const bytes = typeof e.bytes === 'number' && Number.isFinite(e.bytes) && e.bytes > 0
      ? Math.floor(e.bytes) : 0;
    const key = origin + '|' + (e.storageType || '');
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ origin, storageType: e.storageType || 'other', bytes, lastAccessed: e.lastAccessed || 0 });
    totalBytes += bytes;
    byType[e.storageType || 'other'] = (byType[e.storageType || 'other'] || 0) + 1;
  }

  const sites = new Set(targets.map((t) => t.origin)).size;
  return { ok: true, targets, sites, totalBytes, byType, mode, host, since };
}

// summarizePlan 生成计划摘要（用于展示确认 / 审计快照），不触达文件系统。
function summarizePlan(filtered, actions) {
  if (!filtered || !filtered.ok) return { ok: false, reason: 'bad-filter' };
  const acts = Array.isArray(actions) ? actions.slice() : [];
  return {
    ok: true,
    sites: filtered.sites,
    targetCount: filtered.targets.length,
    totalBytes: filtered.totalBytes,
    actions: acts,
    createdAt: Date.now(),
  };
}

// recordCleanAudit 把一次清理写入审计台账（封顶保留最近 MAX_AUDIT_ENTRIES 条）。
// 审计包含条件快照与结果，用于后续回查“什么时候删了什么”。
function recordCleanAudit(log, event) {
  if (!Array.isArray(log)) return { ok: false, reason: 'bad-log' };
  if (!event || typeof event !== 'object') return { ok: false, reason: 'bad-event' };
  const entry = {
    at: typeof event.at === 'number' ? event.at : Date.now(),
    mode: normalizeMatchMode(event.mode),
    host: typeof event.host === 'string' ? event.host : '',
    sites: typeof event.sites === 'number' ? event.sites : 0,
    targetCount: typeof event.targetCount === 'number' ? event.targetCount : 0,
    bytes: typeof event.bytes === 'number' ? event.bytes : 0,
    actions: Array.isArray(event.actions) ? event.actions.slice() : [],
    source: typeof event.source === 'string' ? event.source : '',
  };
  log.push(entry);
  if (log.length > MAX_AUDIT_ENTRIES) {
    log.splice(0, log.length - MAX_AUDIT_ENTRIES);
  }
  return { ok: true, entry };
}

// pruneAuditLog 显式清空 / 修剪审计台账（保留最近 keep 条）。
function pruneAuditLog(log, keep) {
  if (!Array.isArray(log)) return { ok: false, reason: 'bad-log' };
  const n = Number.isInteger(keep) && keep >= 0 ? keep : 0;
  if (n === 0) {
    return { ok: true, log: [] };
  }
  const kept = log.slice(-n);
  return { ok: true, log: kept };
}

// classifyStorageType 归一化 Electron storage 类型名，未知类型保留原样（不拒绝，
// 但审计按原样记录）。
function classifyStorageType(t) {
  const known = ['cookies', 'localstorage', 'indexeddb', 'cachestorage',
    'serviceworkers', 'downloads', 'filesystem', 'websql', 'shadercache',
    'mediakeys', 'backgroundfetch'];
  if (typeof t !== 'string') return '';
  const lower = t.toLowerCase();
  if (known.includes(lower)) return lower;
  return t;
}

module.exports = {
  MAX_AUDIT_ENTRIES,
  MAX_TARGETS,
  normalizeMatchMode,
  normalizeSince,
  hostMatchesOrigin,
  filterSiteEntries,
  summarizePlan,
  recordCleanAudit,
  pruneAuditLog,
  classifyStorageType,
};
