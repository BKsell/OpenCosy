const { app } = require('electron');
const path = require('path');
const fsSync = require('fs');
const ledgerStore = require('./ledgerstore');

const { CSP_RATE_MAX_PER_WINDOW, CSP_RATE_WINDOW_MS, MAX_CSP_REPORTS, MAX_SECURITY_DETAIL_CHARS, MAX_SECURITY_EVENTS, SECURITY_EVENT_TYPES, bindRendererNotifier, clearSecurityEvents, cspReportStorePath, listSecurityEvents, loadSecurityEvents, persistSecurityEvents, recordSecurityEvent, sanitizeSecurityDetail, securityEventSaveTimer, securityEventStorePath, securityEvents, securityEventsLoaded, sendToRenderer } = require('./securitycenter_csp');
const CSP_FIELD_MAX = 300;

const cspReports = [];
let cspReportsLoaded = false;
let cspReportSaveTimer = null;
const cspRateBuckets = new Map(); // senderFrame.id -> { start, count }
const CSP_RATE_MAX_BUCKETS = 1024;

function isInternalFrameSender(senderFrame) {
  if (!senderFrame || typeof senderFrame.url !== 'string') return false;
  let u = '';
  try { u = new URL(senderFrame.url); } catch { return false; }
  return u.protocol === 'cosy:';
}

function loadCspReports() {
  if (cspReportsLoaded) return;
  cspReportsLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(cspReportStorePath, {});
    const entries = Array.isArray(data && data.reports) ? data.reports : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.documentUri !== 'string' || !r.documentUri.startsWith('cosy:')) continue;
      if (typeof r.directive !== 'string' || !r.directive) continue;
      cspReports.push({
        id: String(r.id || ''),
        time: Number(r.time) || Date.now(),
        documentUri: r.documentUri.slice(0, CSP_FIELD_MAX),
        directive: r.directive.slice(0, CSP_FIELD_MAX),
        blockedUri: typeof r.blockedUri === 'string' ? r.blockedUri.slice(0, CSP_FIELD_MAX) : '',
        sourceFile: typeof r.sourceFile === 'string' ? r.sourceFile.slice(0, CSP_FIELD_MAX) : '',
        lineNumber: Number.isFinite(Number(r.lineNumber)) ? Number(r.lineNumber) : 0,
        columnNumber: Number.isFinite(Number(r.columnNumber)) ? Number(r.columnNumber) : 0,
        disposition: r.disposition === 'report' ? 'report' : 'enforce',
        // hits 是同一来源（documentUri+directive+blockedUri）的累计命中次数；
        // 老台账没有该字段，按 1 次补默认值，避免旧数据展示成 NaN/空白。
        hits: Math.max(1, Number(r.hits) || 1),
        lastTime: Number(r.lastTime) || (Number(r.time) || Date.now()),
      });
      if (cspReports.length >= MAX_CSP_REPORTS) break;
    }
  } catch {}
}

function persistCspReports() {
  if (cspReportSaveTimer) clearTimeout(cspReportSaveTimer);
  cspReportSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(cspReportStorePath, { version: 1, reports: cspReports });
    } catch {}
  }, 300);
}

function sanitizeCspField(v) {
  let s = String(v == null ? '' : v);
  s = s.replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > CSP_FIELD_MAX ? s.slice(0, CSP_FIELD_MAX) + '…' : s;
}

// cspRateLimitAllowed 判断该帧当前窗口内是否还能再上报一条。
// 帧关闭后 bucket 不会立刻清理，但 Map 体积受存活内部页数量限制，
// 下一轮窗口自然过期复用，无需额外生命周期钩子。
function cspRateLimitAllowed(frame) {
  const now = Date.now();
  const key = frame && frame.frameTreeNodeId != null ? frame.frameTreeNodeId : 0;
  if (cspRateBuckets.size >= CSP_RATE_MAX_BUCKETS) {
    for (const [k, b] of cspRateBuckets) {
      if (now - b.start >= CSP_RATE_WINDOW_MS) cspRateBuckets.delete(k);
    }
    while (cspRateBuckets.size >= CSP_RATE_MAX_BUCKETS) {
      cspRateBuckets.delete(cspRateBuckets.keys().next().value);
    }
  }
  let bucket = cspRateBuckets.get(key);
  if (!bucket || now - bucket.start >= CSP_RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    cspRateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  return bucket.count <= CSP_RATE_MAX_PER_WINDOW;
}

// recordCspViolationFromRenderer 处理 renderer 上报。返回 { accepted }；
// 拒绝不抛错（上报通道本身不能影响页面运行）。
function recordCspViolationFromRenderer(senderFrame, payload) {
  if (!isInternalFrameSender(senderFrame)) {
    return { accepted: false, reason: 'non-internal frame' };
  }
  if (!cspRateLimitAllowed(senderFrame)) {
    recordSecurityEvent('permission-blocked', 'warn',
      '内部页面 CSP 上报过于频繁，已丢弃后续报告', senderFrame.url);
    return { accepted: false, reason: 'rate limited' };
  }
  loadCspReports();
  let frameUrl = '';
  try { frameUrl = new URL(senderFrame.url).href; } catch { frameUrl = senderFrame.url; }
  const directive = sanitizeCspField(payload && payload.directive);
  if (!directive) return { accepted: false, reason: 'missing directive' };
  const documentUri = sanitizeCspField(frameUrl);
  const blockedUri = sanitizeCspField(payload && payload.blockedUri);
  const now = Date.now();

  // 同一页面、同一指令、同一被拦资源反复触发时只保留一条聚合记录，
  // 用 hits 记次数并把它移到队尾（等同“最近再次出现”），避免一个页面
  // 的持续性违规把 500 条台账瞬间刷满、淹没其它来源。
  const dedupeKey = `${documentUri}\u0000${directive}\u0000${blockedUri}`;
  const existingIdx = cspReports.findIndex(r =>
    `${r.documentUri}\u0000${r.directive}\u0000${r.blockedUri}` === dedupeKey);
  if (existingIdx >= 0) {
    const existing = cspReports[existingIdx];
    existing.hits = Math.min(Number.MAX_SAFE_INTEGER, (Number(existing.hits) || 1) + 1);
    existing.lastTime = now;
    // 行/列等定位信息更新为最近一次，方便点进最新现场。
    existing.sourceFile = sanitizeCspField(payload && payload.sourceFile);
    existing.lineNumber = Math.max(0, Number(payload && payload.lineNumber) || 0);
    existing.columnNumber = Math.max(0, Number(payload && payload.columnNumber) || 0);
    cspReports.splice(existingIdx, 1);
    cspReports.push(existing);
    if (cspReports.length > MAX_CSP_REPORTS) {
      cspReports.splice(0, cspReports.length - MAX_CSP_REPORTS);
    }
    persistCspReports();
    sendToRenderer('csp-report-added', { ...existing });
    return { accepted: true, aggregated: true };
  }

  const report = {
    id: `${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    time: now,
    documentUri,
    directive,
    blockedUri,
    sourceFile: sanitizeCspField(payload && payload.sourceFile),
    lineNumber: Math.max(0, Number(payload && payload.lineNumber) || 0),
    columnNumber: Math.max(0, Number(payload && payload.columnNumber) || 0),
    disposition: payload && payload.disposition === 'report' ? 'report' : 'enforce',
    hits: 1,
    lastTime: now,
  };
  cspReports.push(report);
  if (cspReports.length > MAX_CSP_REPORTS) {
    cspReports.splice(0, cspReports.length - MAX_CSP_REPORTS);
  }
  persistCspReports();
  sendToRenderer('csp-report-added', { ...report });
  return { accepted: true };
}

function listCspReports(limit = 200) {
  loadCspReports();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_CSP_REPORTS));
  return cspReports.slice(-n).reverse().map(r => ({ ...r }));
}

function clearCspReports() {
  loadCspReports();
  cspReports.length = 0;
  try { fsSync.unlinkSync(cspReportStorePath); } catch {}
  persistCspReports();
  return true;
}

// removeCspReport 按 id 删除单条聚合记录（安全页面板“忽略/删除这一条”用）。
// id 只接受字符串并做限长，命中才落盘；返回是否真的删掉了一条。
function removeCspReport(id) {
  loadCspReports();
  if (typeof id !== 'string') return false;
  const target = id.slice(0, 128);
  const idx = cspReports.findIndex(r => r.id === target);
  if (idx < 0) return false;
  cspReports.splice(idx, 1);
  persistCspReports();
  return true;
}

// getCspReportStats 返回台账总量与命中总数，供安全页面板顶部徽标使用，
// 不必把全部记录拉到 renderer 再做 reduce。
function getCspReportStats() {
  loadCspReports();
  let totalHits = 0;
  for (const r of cspReports) totalHits += Number(r.hits) || 1;
  return { groups: cspReports.length, totalHits };
}

module.exports = {
  bindRendererNotifier,
  recordSecurityEvent,
  listSecurityEvents,
  clearSecurityEvents,
  recordCspViolationFromRenderer,
  listCspReports,
  clearCspReports,
  removeCspReport,
  getCspReportStats,
};
