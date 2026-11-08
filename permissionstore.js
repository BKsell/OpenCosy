const path = require('path');
const { app } = require('electron');
const ledgerStore = require('./ledgerstore');
const permissionGrants = require('./permissiongrants');

let recordSecurityEvent = () => {};

function bindSecurityRecorder(fn) {
  if (typeof fn === 'function') recordSecurityEvent = fn;
}

// 与 Chromium 自带的内容设置平行：用户在询问条上勾"始终允许/拒绝"后，按
// origin+permission 持久化，下次同站点再请求时不再打扰。决定文件与缩放记忆
// 一样放 userData，原子 rename 落盘，损坏静默丢弃，绝不拖垮启动。
const REMEMBERED_PAGE_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex', 'clipboard-read',
]);
const permissionStorePath = path.join(app.getPath('userData'), 'permission-decisions.json');
const MAX_PERMISSION_DECISIONS = 1000;
const PERMISSION_DECISION_TTL_MS = permissionGrants.DEFAULT_TTL_MS;
// key 为 `${origin} ${permission}` -> { decision: 'allow'|'deny', updatedAt }
const permissionDecisions = new Map();
let permissionDecisionsLoaded = false;
let permissionSaveTimer = null;

function permissionStoreKey(origin, permission) {
  return origin + ' ' + permission;
}

// 只记忆真实网页 origin：cosy:// 内部页、file://、data: 等不允许进入决定表，
// 避免内部页名或本地文件路径被当成站点长期授权。
function isRememberableOrigin(origin) {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > 300) return false;
  try {
    const u = new URL(origin);
    return (u.protocol === 'https:' || u.protocol === 'http:') && !!u.hostname;
  } catch {
    return false;
  }
}

function loadPermissionDecisions() {
  if (permissionDecisionsLoaded) return;
  permissionDecisionsLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(permissionStorePath, {});
    const entries = data && typeof data === 'object' ? data.decisions : null;
    if (!entries || typeof entries !== 'object') return;
    for (const [k, v] of Object.entries(entries)) {
      if (typeof k !== 'string' || !v || typeof v !== 'object') continue;
      const sp = k.indexOf(' ');
      if (sp <= 0) continue;
      const origin = k.slice(0, sp);
      const permission = k.slice(sp + 1);
      if (!isRememberableOrigin(origin)) continue;
      if (!REMEMBERED_PAGE_PERMISSIONS.has(permission)) continue;
      if (v.decision !== 'allow' && v.decision !== 'deny') continue;
      if (permissionDecisions.size >= MAX_PERMISSION_DECISIONS) break;
      permissionDecisions.set(k, { decision: v.decision, updatedAt: Number(v.updatedAt) || Date.now() });
    }
    const pruned = permissionGrants.pruneExpired(Object.fromEntries(permissionDecisions), {
      now: Date.now(),
      ttlMs: PERMISSION_DECISION_TTL_MS,
    });
    if (pruned.removed.length > 0) {
      for (const key of pruned.removed) permissionDecisions.delete(key);
      recordSecurityEvent('permission-expired', 'info',
        `清理 ${pruned.removed.length} 条过期站点权限记忆`, 'permission-decisions');
      persistPermissionDecisions();
    }
  } catch {}
}

function persistPermissionDecisions() {
  if (permissionSaveTimer) clearTimeout(permissionSaveTimer);
  permissionSaveTimer = setTimeout(() => {
    try {
      const decisions = {};
      for (const [k, v] of permissionDecisions) decisions[k] = v;
      ledgerStore.writeJSONStore(permissionStorePath, { version: 1, decisions });
    } catch {}
  }, 300);
}

function getRememberedPermission(origin, permission) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin) || !REMEMBERED_PAGE_PERMISSIONS.has(permission)) return null;
  const key = permissionStoreKey(origin, permission);
  const v = permissionDecisions.get(key);
  if (!v) return null;
  const state = permissionGrants.effectiveDecision(v, Date.now(), PERMISSION_DECISION_TTL_MS);
  if (state === permissionGrants.STATE.EXPIRED || state === permissionGrants.STATE.UNKNOWN) {
    permissionDecisions.delete(key);
    persistPermissionDecisions();
    recordSecurityEvent('permission-expired', 'info',
      `站点权限记忆已过期（${permission}），本次回到询问流程`, origin);
    return null;
  }
  return state;
}

function rememberPermission(origin, permission, decision) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin)) return false;
  if (!REMEMBERED_PAGE_PERMISSIONS.has(permission)) return false;
  if (decision !== 'allow' && decision !== 'deny') return false;
  const key = permissionStoreKey(origin, permission);
  if (!permissionDecisions.has(key) && permissionDecisions.size >= MAX_PERMISSION_DECISIONS) return false;
  permissionDecisions.set(key, { decision, updatedAt: Date.now() });
  const droppedKeys = permissionGrants.enforceOriginCap(Object.fromEntries(permissionDecisions), origin, {
    now: Date.now(),
    ttlMs: PERMISSION_DECISION_TTL_MS,
    maxPerOrigin: permissionGrants.DEFAULT_MAX_PER_ORIGIN,
  });
  for (const dropped of droppedKeys) permissionDecisions.delete(dropped);
  if (droppedKeys.length > 0) {
    recordSecurityEvent('permission-cap', 'warn',
      `单个站点授权数超过上限，撤销 ${droppedKeys.length} 条旧授权`, origin);
  }
  persistPermissionDecisions();
  return true;
}

function forgetPermission(origin, permission) {
  loadPermissionDecisions();
  const deleted = permissionDecisions.delete(permissionStoreKey(origin, permission));
  if (deleted) persistPermissionDecisions();
  return deleted;
}

function listPermissionDecisions() {
  loadPermissionDecisions();
  const out = [];
  const now = Date.now();
  for (const [k, v] of permissionDecisions) {
    const sp = k.indexOf(' ');
    const effective = permissionGrants.effectiveDecision(v, now, PERMISSION_DECISION_TTL_MS);
    out.push({
      origin: k.slice(0, sp),
      permission: k.slice(sp + 1),
      decision: v.decision,
      updatedAt: v.updatedAt,
      state: effective,
      expired: effective === permissionGrants.STATE.EXPIRED,
      ageDays: permissionGrants.ageDays(v, now),
    });
  }
  out.sort((a, b) => a.origin.localeCompare(b.origin) || a.permission.localeCompare(b.permission));
  return out;
}

function clearPermissionDecisionsForOrigin(origin) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin)) return 0;
  let n = 0;
  const prefix = origin + ' ';
  for (const k of Array.from(permissionDecisions.keys())) {
    if (k.startsWith(prefix)) {
      permissionDecisions.delete(k);
      n++;
    }
  }
  if (n) persistPermissionDecisions();
  return n;
}

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
