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


module.exports = {
  recordSecurityEvent,
  bindSecurityRecorder,
  REMEMBERED_PAGE_PERMISSIONS,
  permissionStorePath,
  MAX_PERMISSION_DECISIONS,
  PERMISSION_DECISION_TTL_MS,
  permissionDecisions,
  permissionDecisionsLoaded,
  permissionSaveTimer,
  permissionStoreKey,
  isRememberableOrigin,
  loadPermissionDecisions,
  persistPermissionDecisions,
  getRememberedPermission,
  rememberPermission,
  forgetPermission,
  listPermissionDecisions,
  clearPermissionDecisionsForOrigin,
};
