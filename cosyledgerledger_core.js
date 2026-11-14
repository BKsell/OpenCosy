'use strict';
const { persistHeaderGrades, listHeaderGrades, clearHeaderGrades, getHeaderGradeStats, loadRequestLog, persistRequestLog, listRequestLogEntries, getRequestLogStats, clearRequestLog } = require('./cosyledgerlog_core');
const { loadLedgerOnce } = require('./ledgerhydrate_core');
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
  loadLedgerOnce(d, 'fpLedgerLoaded', 'fpLedger', 'fpLedgerStorePath');
}

function persistLedgerDebounced(store, timerKey, storePath, ledger) {
  if (store[timerKey]) clearTimeout(store[timerKey]);
  store[timerKey] = setTimeout(() => {
    try {
      store.ledgerStore.writeJSONStore(storePath, ledger.toJSON());
    } catch {}
  }, 400);
}

function persistFpLedger() {
  return persistLedgerDebounced(d, 'fpLedgerSaveTimer', d.fpLedgerStorePath, d.fpLedger);
}

function applyWebRtcPolicy() {
  // WebRTC ICE 候选默认可能暴露内网/真实公网 IP（可穿透 VPN）。
  // strict 只用默认公网接口；balanced 允许 mDNS 混淆候选；legacy 不干预。
  try {
    d.session.defaultSession.setWebRTCIPHandlingPolicy(d.fpGuard.resolveWebRtcPolicy(d.webrtcMode));
  } catch {}
}

function loadDohLedger() {
  loadLedgerOnce(d, 'dohLedgerLoaded', 'dohLedger', 'dohStorePath');
}

function persistDohLedger() {
  return persistLedgerDebounced(d, 'dohSaveTimer', d.dohStorePath, d.dohLedger);
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

module.exports = Object.assign({}, {
  dohStatus,
  applyWebRequestFiltering,
  originOfContents,
  persistHeaderGrades,
  listHeaderGrades,
  clearHeaderGrades,
  getHeaderGradeStats,
  loadRequestLog,
  persistRequestLog,
  listRequestLogEntries,
  getRequestLogStats,
  clearRequestLog },
  {   bindDeps,
  loadPnaLedger,
  persistPnaLedger,
  pnaLedgerStats,
  recordPnaBlock,
  loadFpLedger,
  persistFpLedger,
  applyWebRtcPolicy,
  loadDohLedger,
  persistDohLedger,
  clearRequestLog,
});;
