'use strict';
let d = {};

function dohStatus() {
  return {
    mode: d.dohMode,
    provider: d.dohProvider,
    active: d.dohActive,
    events: d.dohLedger.list().slice(0, 50),
  };
}

function applyWebRequestFiltering(targetSession, options) {
  // options.logRequests 仅控制是否把请求量计入默认会话的连接统计（分区不重复计数）；
  // 阻断 / 升级 / 安全审计在所有会话上行为一致。
  const logRequests = !!(options && options.logRequests);
  const noteAttempt = logRequests ? d.recordRequestAttempt : () => {};
  d.requestPipeline.applyPipeline(targetSession.webRequest, d.buildRequestPipelineDeps(), noteAttempt);
}

function originOfContents(contents) {
  if (!contents || typeof contents.getURL !== 'function') return '';
  return d.urlResolve.safeOrigin(contents.getURL(), '');
}

function persistHeaderGrades() {
  if (d.headerGradeSaveTimer) clearTimeout(d.headerGradeSaveTimer);
  d.headerGradeSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.headerGradeStorePath, { version: 1, hosts: d.headerGrades });
    } catch {}
  }, 400);
}

function listHeaderGrades(limit = 200) {
  d.loadHeaderGrades();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_HEADER_GRADE_HOSTS));
  return d.headerGrades.slice(-n).reverse().map(h => ({ ...h, checks: h.checks.map(c => ({ ...c })) }));
}

function clearHeaderGrades() {
  d.loadHeaderGrades();
  d.headerGrades.length = 0;
  try { d.fsSync.unlinkSync(d.headerGradeStorePath); } catch {}
  persistHeaderGrades();
  return true;
}

function getHeaderGradeStats() {
  d.loadHeaderGrades();
  const byGrade = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  let insecure = 0;
  for (const h of d.headerGrades) {
    if (byGrade[h.grade] != null) byGrade[h.grade] += 1;
    if (h.insecureTransport) insecure += 1;
  }
  return { hosts: d.headerGrades.length, byGrade, insecureHosts: insecure };
}

function loadRequestLog() {
  if (d.requestLogLoaded) return;
  d.requestLogLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.requestLogStorePath, {});
    if (data && Array.isArray(data.entries)) {
      d.requestLogStore = d.requestLog.hydrate(data.entries, d.MAX_REQUEST_LOG_HOSTS);
    }
  } catch {}
}

function persistRequestLog() {
  if (d.requestLogSaveTimer) clearTimeout(d.requestLogSaveTimer);
  d.requestLogSaveTimer = setTimeout(() => {
    try {
      const entries = d.requestLog.toList(d.requestLogStore);
      d.ledgerStore.writeJSONStore(d.requestLogStorePath, { version: 1, savedAt: Date.now(), entries });
    } catch {}
  }, 5000);
}

function listRequestLogEntries(limit = 200) {
  loadRequestLog();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_REQUEST_LOG_HOSTS));
  return d.requestLog.toList(d.requestLogStore).slice(0, n);
}

function getRequestLogStats() {
  loadRequestLog();
  return d.requestLog.stats(d.requestLogStore);
}

function clearRequestLog() {
  loadRequestLog();
  d.requestLog.clear(d.requestLogStore);
  try { d.fsSync.unlinkSync(d.requestLogStorePath); } catch {}
  persistRequestLog();
  return true;
}

function bindDeps(x) { d = x; }

module.exports = { dohStatus, applyWebRequestFiltering, originOfContents, persistHeaderGrades, listHeaderGrades, clearHeaderGrades, getHeaderGradeStats, loadRequestLog, persistRequestLog, listRequestLogEntries, getRequestLogStats, clearRequestLog, bindDeps };
