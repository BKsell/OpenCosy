const path = require('path');
const { app } = require('electron');
const ledgerStore = require('./ledgerstore_core');
const permissionGrants = require('./permissiongrants_core');

const { MAX_PERMISSION_DECISIONS, PERMISSION_DECISION_TTL_MS, REMEMBERED_PAGE_PERMISSIONS, bindSecurityRecorder, clearPermissionDecisionsForOrigin, forgetPermission, getRememberedPermission, isRememberableOrigin, listPermissionDecisions, loadPermissionDecisions, permissionDecisions, permissionDecisionsLoaded, permissionSaveTimer, permissionStoreKey, permissionStorePath, persistPermissionDecisions, recordSecurityEvent, rememberPermission } = require('./permissionstore_ops_core');
function auditPermissionDecisions() {
  loadPermissionDecisions();
  const report = permissionGrants.auditGrants(Object.fromEntries(permissionDecisions), {
    now: Date.now(),
    ttlMs: PERMISSION_DECISION_TTL_MS,
  });
  return { ...report, summary: permissionGrants.summarizeRisk(report) };
}

function prunePermissionDecisions() {
  loadPermissionDecisions();
  const before = permissionDecisions.size;
  const pruned = permissionGrants.pruneExpired(Object.fromEntries(permissionDecisions), {
    now: Date.now(),
    ttlMs: PERMISSION_DECISION_TTL_MS,
  });
  for (const key of pruned.removed) permissionDecisions.delete(key);
  if (pruned.removed.length > 0) persistPermissionDecisions();
  return { success: true, removed: pruned.removed.length, remaining: permissionDecisions.size, before };
}

const protocolDecisionStorePath = path.join(app.getPath('userData'), 'protocol-decisions.json');
const MAX_PROTOCOL_DECISIONS = 500;
// 只有这两个协议允许在用户确认后交给系统处理器；其它外部协议没有商量余地。
const CONFIRMABLE_EXTERNAL_SCHEMES = new Set(['mailto:', 'tel:']);
// 子框架允许的协议集合。iframe 场景下 blob:/data: 有正当用途（预览、文档），
// 但 file:/cosy:/任何外部协议都不允许。
const SUBFRAME_WEB_SCHEMES = new Set(['http:', 'https:', 'blob:', 'data:', 'about:']);
// key: `${origin} ${scheme}` -> { decision: 'allow'|'deny', updatedAt }
const protocolDecisions = new Map();
let protocolDecisionsLoaded = false;
let protocolSaveTimer = null;

function protocolDecisionKey(origin, scheme) {
  return origin + ' ' + scheme;
}

function normalizeExternalScheme(url) {
  try {
    const scheme = new URL(url).protocol.toLowerCase();
    // 协议名只允许 RFC 3986 字母开头的有限字符，挡掉伪造 / 控制字符输入。
    if (!/^[a-z][a-z0-9+.-]{0,31}:$/.test(scheme)) return '';
    return scheme;
  } catch {
    return '';
  }
}

function loadProtocolDecisions() {
  if (protocolDecisionsLoaded) return;
  protocolDecisionsLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(protocolDecisionStorePath, {});
    const entries = data && typeof data === 'object' ? data.decisions : null;
    if (!entries || typeof entries !== 'object') return;
    for (const [k, v] of Object.entries(entries)) {
      if (typeof k !== 'string' || !v || typeof v !== 'object') continue;
      const sp = k.indexOf(' ');
      if (sp <= 0) continue;
      const origin = k.slice(0, sp);
      const scheme = k.slice(sp + 1);
      if (!isRememberableOrigin(origin)) continue;
      if (!CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) continue;
      if (v.decision !== 'allow' && v.decision !== 'deny') continue;
      if (protocolDecisions.size >= MAX_PROTOCOL_DECISIONS) break;
      protocolDecisions.set(k, { decision: v.decision, updatedAt: Number(v.updatedAt) || Date.now() });
    }
  } catch {}
}

function persistProtocolDecisions() {
  if (protocolSaveTimer) clearTimeout(protocolSaveTimer);
  protocolSaveTimer = setTimeout(() => {
    try {
      const decisions = {};
      for (const [k, v] of protocolDecisions) decisions[k] = v;
      ledgerStore.writeJSONStore(protocolDecisionStorePath, { version: 1, decisions });
    } catch {}
  }, 300);
}

function getRememberedProtocolDecision(origin, scheme) {
  loadProtocolDecisions();
  if (!isRememberableOrigin(origin) || !CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return null;
  const v = protocolDecisions.get(protocolDecisionKey(origin, scheme));
  return v ? v.decision : null;
}

function rememberProtocolDecision(origin, scheme, decision) {
  loadProtocolDecisions();
  if (!isRememberableOrigin(origin)) return false;
  if (!CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return false;
  if (decision !== 'allow' && decision !== 'deny') return false;
  if (protocolDecisions.size >= MAX_PROTOCOL_DECISIONS &&
      !protocolDecisions.has(protocolDecisionKey(origin, scheme))) {
    return false;
  }
  protocolDecisions.set(protocolDecisionKey(origin, scheme), { decision, updatedAt: Date.now() });
  persistProtocolDecisions();
  return true;
}


function listProtocolDecisions() {
  loadProtocolDecisions();
  const items = [];
  for (const [k, v] of protocolDecisions) {
    const sp = k.indexOf(' ');
    items.push({ origin: k.slice(0, sp), scheme: k.slice(sp + 1), decision: v.decision, updatedAt: v.updatedAt });
  }
  items.sort((a, b) => b.updatedAt - a.updatedAt);
  return items;
}

function forgetProtocolDecision(origin, scheme) {
  if (!isRememberableOrigin(origin) || !CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) {
    return { ok: false, reason: 'invalid key' };
  }
  const deleted = protocolDecisions.delete(protocolDecisionKey(origin, scheme));
  if (deleted) persistProtocolDecisions();
  return { ok: true, deleted };
}

module.exports = {
  bindSecurityRecorder,
  REMEMBERED_PAGE_PERMISSIONS,
  PERMISSION_DECISION_TTL_MS,
  isRememberableOrigin,
  loadPermissionDecisions,
  persistPermissionDecisions,
  getRememberedPermission,
  rememberPermission,
  forgetPermission,
  listPermissionDecisions,
  clearPermissionDecisionsForOrigin,
  auditPermissionDecisions,
  prunePermissionDecisions,
  CONFIRMABLE_EXTERNAL_SCHEMES,
  loadProtocolDecisions,
  getRememberedProtocolDecision,
  rememberProtocolDecision,
  listProtocolDecisions,
  forgetProtocolDecision,
};
