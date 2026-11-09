'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function registerProtocolIpc() {
d.ipcMain.handle('get-tab-groups', (event) => {
  if (!d.isMainSender(event)) return { groups: [], order: [] };
  return { groups: d.tabGroupModel.serialize(), order: d.tabGroupOrder() };
});

d.ipcMain.handle('create-tab-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const opts = payload || {};
  // 入参全部由内核净化：标题 / 颜色 / 标签 id 列表 / 折叠态都走白名单校验，
  // 固定标签会被剔除；脏输入不会进入模型或台账。
  const r = d.tabGroupModel.createGroup({
    title: opts.title,
    color: opts.color,
    tabIds: Array.isArray(opts.tabIds) ? opts.tabIds : [],
    collapsed: opts.collapsed === true,
  }, d.tabGroupIsPinned);
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, group: r.group };
});

d.ipcMain.handle('add-tabs-to-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.addTabs(
    payload && payload.groupId,
    Array.isArray(payload && payload.tabIds) ? payload.tabIds : [],
    d.tabGroupIsPinned
  );
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, added: r.added, skippedPinned: r.skippedPinned };
});

d.ipcMain.handle('remove-tabs-from-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.removeTabs(
    Array.isArray(payload && payload.tabIds) ? payload.tabIds : []
  );
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, removed: r.removed };
});

d.ipcMain.handle('move-tab-to-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.moveTab(
    payload && payload.tabId,
    payload && payload.groupId,
    d.tabGroupIsPinned
  );
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, movedTo: r.movedTo || null };
});

d.ipcMain.handle('rename-tab-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.renameGroup(payload && payload.groupId, payload && payload.title);
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.broadcastTabGroups();
  return { ok: true, group: r.group };
});

d.ipcMain.handle('set-tab-group-color', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.setGroupColor(payload && payload.groupId, payload && payload.color);
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.broadcastTabGroups();
  return { ok: true, group: r.group };
});

d.ipcMain.handle('set-tab-group-collapsed', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.setGroupCollapsed(payload && payload.groupId, !!(payload && payload.collapsed));
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.broadcastTabGroups();
  return { ok: true, group: r.group };
});

d.ipcMain.handle('move-tab-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.moveGroup(payload && payload.groupId, payload && payload.toGroupId);
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, order: r.order };
});

d.ipcMain.handle('dissolve-tab-group', (event, payload) => {
  if (!d.isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = d.tabGroupModel.dissolveGroup(payload && payload.groupId);
  if (!r.ok) return d.tabGroupError(r);
  d.persistTabGroups();
  d.applyTabGroupArrangement();
  return { ok: true, freedTabs: r.freedTabs };
});
}

const cosyruntimestate = require('./cosyruntimestate');

function bindDepsAll(x) {
  d = x;
  cosyruntimestate.bindDeps(x);
}

module.exports = Object.assign({ bindDeps: bindDepsAll }, cosyruntimestate, { bindDeps, registerProtocolIpc });
