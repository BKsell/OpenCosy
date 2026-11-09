'use strict';
const { readStoredSection } = require('./modutil');

let d = {};

function bindDeps(next) {
  d = next;
}

function applyTabGroupArrangement() {
  const target = tabGroupOrder();
  const before = d.tabs.map(t => t.id);
  const diff = d.tabOrderDiff.diffOrder(before, target);
  if (!diff.ok) return;
  if (diff.unchanged) return;
  // 目标顺序与当前标签集合必须一致（diff 已确认 created/removed 为空才可重排）。
  if (diff.created.length > 0 || diff.removed.length > 0) return;
  if (reorderTabsByGroupPlan(target)) {
    broadcastTabGroups();
    d.sendToRenderer('pins-order-changed', { ids: d.pinModel.ids() });
  }
}

function broadcastTabGroups() {
  d.sendToRenderer('tab-groups-changed', {
    groups: d.tabGroupModel.serialize(),
    order: tabGroupOrder(),
  });
}

function clearStoredTabGroups() {
  try {
    if (d.fsSync.existsSync(d.tabGroupStorePath)) d.fsSync.unlinkSync(d.tabGroupStorePath);
  } catch (e) {
    console.error('清除标签分组失败:', e);
  }
}

function loadStoredTabGroups() {
  return readStoredSection(d.ledgerStore.readJSONStore, d.tabGroupStorePath,
    data => d.tabGroups.sanitizeStoredGroups(data.groups), '读取标签分组失败:');
}

function persistTabGroups() {
  if (d.tabGroupSaveTimer) clearTimeout(d.tabGroupSaveTimer);
  d.tabGroupSaveTimer = setTimeout(saveTabGroupsNow, 400);
}

function saveTabGroupsNow() {
  try {
    d.ledgerStore.writeJSONStore(d.tabGroupStorePath, {
      version: 1,
      groups: d.tabGroupModel.serialize(),
    });
  } catch (e) {
    console.error('保存标签分组失败:', e);
  }
}

function reorderTabsByGroupPlan(targetOrder) {
  if (!Array.isArray(targetOrder) || targetOrder.length !== d.tabs.length) return false;
  const byId = new Map(d.tabs.map(t => [t.id, t]));
  const next = targetOrder.map(id => byId.get(id));
  if (next.some(t => !t)) return false; // 目标顺序与当前标签不一致时不擅动
  const currentTab = d.tabs[d.currentTabIndex];
  for (let i = 0; i < d.tabs.length; i++) d.tabs[i] = next[i];
  if (currentTab) {
    const ni = d.tabs.indexOf(currentTab);
    if (ni >= 0) d.currentTabIndex = ni;
  }
  return true;
}

function tabGroupError(r) {
  return { ok: false, reason: r && r.reason ? d.tabGroups.describeReject(r.reason) : '分组操作失败' };
}

function tabGroupIsPinned(tabId) {
  const idx = d.findTabIndexById(tabId);
  return idx >= 0 && !!d.tabs[idx].pinned;
}

function tabGroupOrder() {
  return d.tabGroups.arrangeTabs(
    d.tabs.map(t => ({ id: t.id, pinned: !!t.pinned })),
    d.tabGroupModel,
    { isPinnedFn: tabGroupIsPinned }
  );
}

function tabKeepsAlive(tab) {
  if (!tab) return true;
  const idx = d.tabs.indexOf(tab);
  if (idx === d.currentTabIndex) return true;            // 正在看的标签
  if (tab.discarded || tab.crashed || !tab.view) return true; // 已休眠/崩溃/无视图
  if (tab.isLoading) return true;                      // 正在加载，打断会留下半成品
  try {
    if (tab.view.webContents.isCurrentlyAudible() && !tab.muted) return true; // 正在放声音
  } catch {}
  try {
    if (tab.view.webContents.isBeingCaptured()) return true; // 正在录屏/共享标签
  } catch {}
  if (tab.url.startsWith('cosy://')) return true;      // 内置页面很轻且承载 UI 状态
  return false;
}

module.exports = { applyTabGroupArrangement, broadcastTabGroups, clearStoredTabGroups, loadStoredTabGroups, persistTabGroups, saveTabGroupsNow, reorderTabsByGroupPlan, tabGroupError, tabGroupIsPinned, tabGroupOrder, tabKeepsAlive, bindDeps };
