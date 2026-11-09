'use strict';
let d = {};
function bindDeps(x) {
  d = x;
}
function loadPnaLedger() {
  if (d.pnaLedgerLoaded) return;
  d.pnaLedgerLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.pnaLedgerStorePath, {});
    const rows = Array.isArray(data && data.rows) ? data.rows : [];
    for (const r of rows) {
      if (!r || typeof r.host !== 'string') continue;
      d.pnaLedger.set(r.host, {
        host: String(r.host).slice(0, 255),
        space: String(r.space || 'private').slice(0, 32),
        hits: Number(r.hits) || 1,
        lastTime: Number(r.lastTime) || Date.now(),
      });
    }
  } catch {}
}
function persistPnaLedger() {
  if (d.pnaLedgerSaveTimer) clearTimeout(d.pnaLedgerSaveTimer);
  d.pnaLedgerSaveTimer = setTimeout(() => {
    try {
      const rows = [...d.pnaLedger.values()];
      d.ledgerStore.writeJSONStore(d.pnaLedgerStorePath, { version: 1, rows });
    } catch {}
  }, 400);
}
function pnaLedgerStats() {
  let blocked = 0;
  for (const v of d.pnaLedger.values()) blocked += v.hits;
  return { hosts: d.pnaLedger.size, blocked };
}
function recordPnaBlock(details, verdict) {
  loadPnaLedger();
  const host = String(verdict.targetHost || '').slice(0, 255);
  if (!host) return;
  const cur = d.pnaLedger.get(host) || { host, space: verdict.targetSpace || 'private', hits: 0, lastTime: 0 };
  cur.hits += 1;
  cur.lastTime = Date.now();
  cur.space = verdict.targetSpace || cur.space;
  d.pnaLedger.set(host, cur);
  if (d.pnaLedger.size > d.MAX_PNA_LEDGER) {
    const oldest = [...d.pnaLedger.entries()]
      .sort((a, b) => a[1].lastTime - b[1].lastTime)[0][0];
    d.pnaLedger.delete(oldest);
  }
  persistPnaLedger();
  d.sendToRenderer('pna-blocked-updated', pnaLedgerStats());
}
function loadFpLedger() {
  if (d.fpLedgerLoaded) return;
  d.fpLedgerLoaded = true;
  try {
    d.fpLedger.load(d.ledgerStore.readJSONStore(d.fpLedgerStorePath, {}));
  } catch {}
}
function persistFpLedger() {
  if (d.fpLedgerSaveTimer) clearTimeout(d.fpLedgerSaveTimer);
  d.fpLedgerSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.fpLedgerStorePath, d.fpLedger.toJSON());
    } catch {}
  }, 400);
}
function applyWebRtcPolicy() {
  // WebRTC ICE 候选默认可能暴露内网/真实公网 IP（可穿透 VPN）。
  // strict 只用默认公网接口；balanced 允许 mDNS 混淆候选；legacy 不干预。
  try {
    d.session.defaultSession.setWebRTCIPHandlingPolicy(d.fpGuard.resolveWebRtcPolicy(d.webrtcMode));
  } catch {}
}
function loadDohLedger() {
  if (d.dohLedgerLoaded) return;
  d.dohLedgerLoaded = true;
  try {
    d.dohLedger.load(d.ledgerStore.readJSONStore(d.dohStorePath, {}));
  } catch {}
}
function persistDohLedger() {
  if (d.dohSaveTimer) clearTimeout(d.dohSaveTimer);
  d.dohSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.dohStorePath, d.dohLedger.toJSON());
    } catch {}
  }, 400);
}
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

module.exports = { bindDeps, loadPnaLedger, persistPnaLedger, pnaLedgerStats, recordPnaBlock, loadFpLedger, persistFpLedger, applyWebRtcPolicy, loadDohLedger, persistDohLedger, dohStatus, applyWebRequestFiltering, originOfContents, persistHeaderGrades, listHeaderGrades, clearHeaderGrades, getHeaderGradeStats, loadRequestLog, persistRequestLog, listRequestLogEntries, getRequestLogStats, clearRequestLog };
