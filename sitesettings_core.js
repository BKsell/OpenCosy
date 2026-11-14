'use strict';

const PERMISSION = {
  CAMERA: 'camera',
  MICROPHONE: 'microphone',
  GEOLOCATION: 'geolocation',
  NOTIFICATIONS: 'notifications',
  CLIPBOARD: 'clipboard-read',
  MIDI: 'midi-sysex',
  FULLSCREEN: 'fullscreen',
  POPUPS: 'popups',
  IDLE: 'idle-detection'
};

const DECISION = {
  ALLOW: 'allow',
  BLOCK: 'block',
  ASK: 'ask'
};

const PERMISSION_LIST = Object.keys(PERMISSION).map((key) => PERMISSION[key]);
const DECISION_LIST = [DECISION.ALLOW, DECISION.BLOCK, DECISION.ASK];
const MAX_ORIGINS = 400;

function isPermission(name) {
  return PERMISSION_LIST.indexOf(name) >= 0;
}

function isDecision(value) {
  return DECISION_LIST.indexOf(value) >= 0;
}

function normalizeOrigin(origin) {
  if (typeof origin !== 'string') return null;
  let text = origin.trim().toLowerCase();
  if (!text) return null;
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const cut = text.search(/[/?#]/);
  if (cut >= 0) text = text.slice(0, cut);
  const at = text.lastIndexOf('@');
  if (at >= 0) text = text.slice(at + 1);
  const colon = text.indexOf(':');
  if (colon >= 0) text = text.slice(0, colon);
  if (!text || text.length > 255) return null;
  if (!/^[a-z0-9._-]+$/.test(text)) return null;
  return text;
}

function emptyStore() {
  return { sites: {}, updatedAt: 0 };
}

function readStore(store) {
  if (!store || typeof store !== 'object') return emptyStore();
  if (!store.sites || typeof store.sites !== 'object') return emptyStore();
  return store;
}

function setDecision(store, origin, permission, decision) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', store: readStore(store) };
  if (!isPermission(permission)) return { ok: false, reason: 'bad-permission', store: readStore(store) };
  if (!isDecision(decision)) return { ok: false, reason: 'bad-decision', store: readStore(store) };
  const base = readStore(store);
  const sites = Object.assign({}, base.sites);
  const site = Object.assign({}, sites[key] || {});
  site[permission] = decision;
  sites[key] = site;
  return finishStore(sites);
}

function getDecision(store, origin, permission) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', decision: DECISION.ASK };
  if (!isPermission(permission)) return { ok: false, reason: 'bad-permission', decision: DECISION.ASK };
  const base = readStore(store);
  const site = base.sites[key];
  if (!site || site[permission] === undefined) {
    return { ok: true, reason: 'default', decision: DECISION.ASK };
  }
  return { ok: true, reason: 'ok', decision: site[permission] };
}

function listForOrigin(store, origin) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', entries: [] };
  const base = readStore(store);
  const site = base.sites[key] || {};
  const entries = PERMISSION_LIST
    .filter((name) => site[name] !== undefined)
    .map((name) => ({ permission: name, decision: site[name] }));
  return { ok: true, reason: 'ok', entries };
}

function listOrigins(store) {
  const base = readStore(store);
  return Object.keys(base.sites).sort();
}

function resetOrigin(store, origin) {
  const key = normalizeOrigin(origin);
  if (!key) return { ok: false, reason: 'bad-origin', store: readStore(store) };
  const base = readStore(store);
  const sites = Object.assign({}, base.sites);
  delete sites[key];
  return finishStore(sites);
}

function resetAll() {
  return { ok: true, reason: 'ok', store: emptyStore() };
}

function finishStore(sites) {
  const keys = Object.keys(sites);
  if (keys.length > MAX_ORIGINS) {
    const kept = {};
    for (const key of keys.sort().slice(keys.length - MAX_ORIGINS)) kept[key] = sites[key];
    return { ok: true, reason: 'ok', store: { sites: kept, updatedAt: Date.now() } };
  }
  return { ok: true, reason: 'ok', store: { sites, updatedAt: Date.now() } };
}

function describeDecision(decision) {
  switch (decision) {
    case DECISION.ALLOW: return '允许';
    case DECISION.BLOCK: return '阻止';
    case DECISION.ASK: return '每次询问';
    default: return '未知决定';
  }
}

function buildPrompt(origin, permission) {
  const key = normalizeOrigin(origin);
  if (!key || !isPermission(permission)) return null;
  return {
    origin: key,
    permission,
    text: key + ' 请求使用 ' + permission,
    options: DECISION_LIST.slice()
  };
}

module.exports = {
  PERMISSION,
  DECISION,
  PERMISSION_LIST,
  isPermission,
  isDecision,
  normalizeOrigin,
  setDecision,
  getDecision,
  listForOrigin,
  listOrigins,
  resetOrigin,
  resetAll,
  describeDecision,
  buildPrompt
};
