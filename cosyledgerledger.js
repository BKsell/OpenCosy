'use strict';
const { persistHeaderGrades, listHeaderGrades, clearHeaderGrades, getHeaderGradeStats, loadRequestLog, persistRequestLog, listRequestLogEntries, getRequestLogStats, clearRequestLog } = require('./cosyledgerlog');
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
