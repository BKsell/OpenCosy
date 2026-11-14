'use strict';
const { describeReasonFrom } = require('./reasontext');

require('./modutil_core');

const { DEFAULT_GROUP_TITLE, FALLBACK_GROUP_COLOR, GROUP_COLORS, GROUP_COLOR_BLUE, GROUP_COLOR_CYAN, GROUP_COLOR_GREEN, GROUP_COLOR_GREY, GROUP_COLOR_ORANGE, GROUP_COLOR_PINK, GROUP_COLOR_PURPLE, GROUP_COLOR_RED, GROUP_COLOR_SET, GROUP_COLOR_YELLOW, MAX_GROUPS, MAX_GROUP_ID_LEN, MAX_GROUP_TITLE_LEN, MAX_TABS_PER_GROUP, MAX_TAB_ID_LEN, REJECT_BAD_COLOR, REJECT_CONTROL, REJECT_DUPLICATE, REJECT_EMPTY, REJECT_LIMIT, REJECT_NOT_ARRAY, REJECT_NOT_FOUND, REJECT_NOT_STRING, REJECT_PINNED, REJECT_TOO_LONG, hasControlChar, makeGroupId, sanitizeGroupColor, sanitizeGroupId, sanitizeGroupTitle, sanitizeStoredGroups, sanitizeTabId, sanitizeTabIdList } = require('./tabgroupsnorm_rules_core');
function rehydrateGroupsByTabs(storedGroups, currentTabs) {
  const groups = sanitizeStoredGroups(storedGroups);
  const tabs = Array.isArray(currentTabs) ? currentTabs : [];
  const alive = new Set();
  for (const t of tabs) {
    if (t && typeof t.id === 'string' && !t.pinned) alive.add(t.id);
  }
  const out = [];
  for (const g of groups) {
    const tabIds = g.tabIds.filter(id => alive.has(id));
    if (tabIds.length === 0) continue;
    out.push({
      id: g.id,
      title: g.title,
      color: g.color,
      collapsed: g.collapsed,
      tabIds,
    });
  }
  return out;
}

// arrangeTabs 给定一份标签描述（顺序即当前标签栏顺序），返回编排后的标签 id 顺序：
//   1) 固定区永远在最前，顺序以传入的 pinnedIdOrder（pintabs 模型顺序）为准；
//   2) 非固定区里，已入组标签按“分组顺序 -> 组内顺序”聚成连续色块；
//   3) 未入组的非固定标签保持原相对顺序，排在已分组标签之后。
// 入参：
//   orderedTabs   : [{ id, pinned }]（pinned 可省略，用 isPinnedFn 兜底）
//   model         : TabGroupModel
//   options       : { pinnedIdOrder:string[], isPinnedFn:fn }
function arrangeTabs(orderedTabs, model, options) {
  const opts = options || {};
  const list = Array.isArray(orderedTabs) ? orderedTabs : [];
  const isPinned = (id) =>
    (Array.isArray(opts.pinnedIdOrder) && opts.pinnedIdOrder.indexOf(id) >= 0) ||
    (typeof opts.isPinnedFn === 'function' && !!opts.isPinnedFn(id));

  const pinned = [];
  const ungrouped = [];
  const present = new Set();
  for (const t of list) {
    if (!t || typeof t.id !== 'string' || present.has(t.id)) continue;
    present.add(t.id);
    if (t.pinned || isPinned(t.id)) pinned.push(t.id);
    else if (!model.isGrouped(t.id)) ungrouped.push(t.id);
  }

  // 固定区：优先按 pinnedIdOrder 输出，模型未覆盖的固定标签按原顺序补在后面。
  const pinnedSet = new Set(pinned);
  const pinnedOrdered = [];
  if (Array.isArray(opts.pinnedIdOrder)) {
    for (const id of opts.pinnedIdOrder) {
      if (pinnedSet.has(id)) {
        pinnedOrdered.push(id);
        pinnedSet.delete(id);
      }
    }
  }
  for (const id of pinned) {
    if (pinnedSet.has(id)) pinnedOrdered.push(id);
  }

  // 分组区：只输出当前仍存在的标签，按模型分组顺序与组内顺序聚类。
  const grouped = [];
  for (const gid of model.orderedGroupIds()) {
    for (const id of model.tabsInGroup(gid)) {
      if (present.has(id) && !pinnedSet.has(id)) grouped.push(id);
    }
  }
  return pinnedOrdered.concat(grouped, ungrouped);
}

// describeReject 把原因码翻译成中文说明，供 IPC 层回传与审计。
const REJECT_TEXT = {
  [REJECT_NOT_STRING]: '标识或标题必须是字符串',
  [REJECT_NOT_ARRAY]: '标签列表必须是数组',
  [REJECT_TOO_LONG]: '分组标识、标题或标签标识超出长度限制',
  [REJECT_CONTROL]: '分组字段包含非法控制字符',
  [REJECT_BAD_COLOR]: '分组颜色不在允许范围内',
  [REJECT_LIMIT]: '分组数量或单组标签数已达上限',
  [REJECT_NOT_FOUND]: '目标分组不存在',
  [REJECT_PINNED]: '固定标签不能加入分组',
  [REJECT_DUPLICATE]: '分组标识重复',
  [REJECT_EMPTY]: '没有可加入分组的标签',
};

function describeReject(reason) {
  return describeReasonFrom(REJECT_TEXT, reason, '分组操作被拒绝');
}

module.exports = {
  MAX_GROUPS,
  MAX_TABS_PER_GROUP,
  MAX_GROUP_ID_LEN,
  MAX_GROUP_TITLE_LEN,
  MAX_TAB_ID_LEN,
  DEFAULT_GROUP_TITLE,
  GROUP_COLOR_GREY,
  GROUP_COLOR_BLUE,
  GROUP_COLOR_RED,
  GROUP_COLOR_YELLOW,
  GROUP_COLOR_GREEN,
  GROUP_COLOR_PINK,
  GROUP_COLOR_PURPLE,
  GROUP_COLOR_CYAN,
  GROUP_COLOR_ORANGE,
  GROUP_COLORS,
  GROUP_COLOR_SET,
  FALLBACK_GROUP_COLOR,
  REJECT_NOT_STRING,
  REJECT_NOT_ARRAY,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  REJECT_BAD_COLOR,
  REJECT_LIMIT,
  REJECT_NOT_FOUND,
  REJECT_PINNED,
  REJECT_DUPLICATE,
  REJECT_EMPTY,
  sanitizeGroupId,
  sanitizeTabId,
  sanitizeGroupTitle,
  sanitizeGroupColor,
  sanitizeTabIdList,
  sanitizeStoredGroups,
  rehydrateGroupsByTabs,
  arrangeTabs,
  describeReject,
  hasControlChar,
  makeGroupId,
};
