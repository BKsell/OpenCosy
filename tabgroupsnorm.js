'use strict';

const { hasControlCharV2 } = require('./modutil');
const hasControlChar = hasControlCharV2;

// ---- 数量与长度上界 ----
const MAX_GROUPS = 50;          // 单个窗口分组数硬上界
const MAX_TABS_PER_GROUP = 100; // 单组标签数硬上界
const MAX_GROUP_ID_LEN = 64;    // 组 id 长度上界（运行时 id 很短，64 已极宽松）
const MAX_GROUP_TITLE_LEN = 64; // 组标题长度上界，对齐标签栏可读宽度
const MAX_TAB_ID_LEN = 128;     // 标签 id 长度上界，与 pintabs 保持一致

// 默认标题：新建分组未显式命名时由调用方套用，内核不偷偷改用户传入的标题。
const DEFAULT_GROUP_TITLE = '';

// 允许的分组颜色。颜色只用于 UI 展示，但同样做白名单枚举校验：磁盘清单里出现未知
// 颜色时回退到灰色，而不是把任意字符串带进样式 / 台账。
const GROUP_COLOR_GREY = 'grey';
const GROUP_COLOR_BLUE = 'blue';
const GROUP_COLOR_RED = 'red';
const GROUP_COLOR_YELLOW = 'yellow';
const GROUP_COLOR_GREEN = 'green';
const GROUP_COLOR_PINK = 'pink';
const GROUP_COLOR_PURPLE = 'purple';
const GROUP_COLOR_CYAN = 'cyan';
const GROUP_COLOR_ORANGE = 'orange';

const GROUP_COLORS = [
  GROUP_COLOR_GREY,
  GROUP_COLOR_BLUE,
  GROUP_COLOR_RED,
  GROUP_COLOR_YELLOW,
  GROUP_COLOR_GREEN,
  GROUP_COLOR_PINK,
  GROUP_COLOR_PURPLE,
  GROUP_COLOR_CYAN,
  GROUP_COLOR_ORANGE,
];
const GROUP_COLOR_SET = new Set(GROUP_COLORS);
const FALLBACK_GROUP_COLOR = GROUP_COLOR_GREY;

// 拒绝 / 状态原因码，供上层给出明确反馈与审计。
const REJECT_NOT_STRING = 'not-string';
const REJECT_NOT_ARRAY = 'not-array';
const REJECT_TOO_LONG = 'too-long';
const REJECT_CONTROL = 'control-char';
const REJECT_BAD_COLOR = 'bad-color';
const REJECT_LIMIT = 'limit-reached';
const REJECT_NOT_FOUND = 'not-found';
const REJECT_PINNED = 'pinned-tab';
const REJECT_DUPLICATE = 'duplicate';
const REJECT_EMPTY = 'empty-selection';

// hasControlChar 判断字符串是否含 ASCII 控制字符（0x00-0x1F、0x7F）。

// sanitizeGroupId 校验组 id：非空字符串、不超长、不含控制字符。
function sanitizeGroupId(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: REJECT_NOT_STRING };
  if (raw.length === 0 || raw.length > MAX_GROUP_ID_LEN) return { ok: false, reason: REJECT_TOO_LONG };
  if (hasControlChar(raw)) return { ok: false, reason: REJECT_CONTROL };
  return { ok: true, value: raw };
}

// sanitizeTabId 校验标签 id，规则与 pintabs.sanitizePinId 对齐。
function sanitizeTabId(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: REJECT_NOT_STRING };
  if (raw.length === 0 || raw.length > MAX_TAB_ID_LEN) return { ok: false, reason: REJECT_TOO_LONG };
  if (hasControlChar(raw)) return { ok: false, reason: REJECT_CONTROL };
  return { ok: true, value: raw };
}

// sanitizeGroupTitle 校验标题：必须是字符串（允许空串，表示用默认标题）、不超长、
// 不含控制字符；首尾空白裁剪后返回。
function sanitizeGroupTitle(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: REJECT_NOT_STRING };
  const title = raw.trim();
  if (title.length > MAX_GROUP_TITLE_LEN) return { ok: false, reason: REJECT_TOO_LONG };
  if (hasControlChar(title)) return { ok: false, reason: REJECT_CONTROL };
  return { ok: true, value: title };
}

// sanitizeGroupColor 校验颜色枚举；未知颜色回退灰色而不是拒绝，保证磁盘上出现新 /
// 旧版本不认识的颜色时仍能安全展示。返回 { ok:true,value }。
function sanitizeGroupColor(raw) {
  if (typeof raw === 'string' && GROUP_COLOR_SET.has(raw)) return { ok: true, value: raw };
  return { ok: true, value: FALLBACK_GROUP_COLOR };
}

// sanitizeTabIdList 净化一个标签 id 数组：去非法、去重、保序、截断到上界。
function sanitizeTabIdList(raw, limit) {
  if (!Array.isArray(raw)) return { ok: false, reason: REJECT_NOT_ARRAY, value: [] };
  const max = Number.isInteger(limit) && limit > 0 ? limit : MAX_TABS_PER_GROUP;
  const out = [];
  const seen = new Set();
  for (const item of raw) {
    const v = sanitizeTabId(item);
    if (!v.ok || seen.has(v.value)) continue;
    seen.add(v.value);
    out.push(v.value);
    if (out.length >= max) break;
  }
  return { ok: true, value: out };
}

// makeGroupId 生成一个短的、只含安全字符的组 id（时间基 + 随机后缀）。
// id 只在单次运行期内作为主进程权威集合的键，跨重启不靠它恢复（恢复走标签匹配），
// 因此不要求全局唯一，只需在同一窗口生命周期内极小概率碰撞即可。
function makeGroupId(now) {
  const ts = (typeof now === 'number' && Number.isFinite(now) && now > 0) ? Math.floor(now) : Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  return 'g' + ts.toString(36) + '-' + rand;
}

// sanitizeStoredGroups 净化磁盘读出的分组清单（不与当前标签匹配，只做格式净化）。
// 规则：
//   - 顶层必须是数组，否则整体丢弃；
//   - 每项必须是对象，组 id 合法且不重复；标题 / 颜色 / 折叠 / 标签 id 全部净化；
//   - 组数量、单组标签数受上界约束；
//   - 同一标签在多个组出现时，只保留首次归属；
// 任何脏字段都被丢弃，绝不抛异常阻断启动。
function sanitizeStoredGroups(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seenGroup = new Set();
  const seenTab = new Set();
  for (const rec of raw) {
    if (!rec || typeof rec !== 'object') continue;
    if (out.length >= MAX_GROUPS) break;
    const iv = sanitizeGroupId(rec.id);
    if (!iv.ok || seenGroup.has(iv.value)) continue;
    const tv = sanitizeGroupTitle(rec.title === undefined ? DEFAULT_GROUP_TITLE : rec.title);
    if (!tv.ok) continue;
    const cv = sanitizeGroupColor(rec.color);
    const tabs = sanitizeTabIdList(rec.tabIds, MAX_TABS_PER_GROUP).value;
    const uniqueTabs = [];
    for (const tabId of tabs) {
      if (seenTab.has(tabId)) continue;
      seenTab.add(tabId);
      uniqueTabs.push(tabId);
    }
    if (uniqueTabs.length === 0) continue;
    seenGroup.add(iv.value);
    out.push({
      id: iv.value,
      title: tv.value,
      color: cv.value,
      collapsed: rec.collapsed === true,
      tabIds: uniqueTabs,
    });
  }
  return out;
}

// rehydrateGroupsByTabs 用净化后的分组清单与本次启动的当前标签匹配，剔除：
//   - 本次没有打开的标签 id；
//   - 当前已固定的标签（固定与分组互斥，固定优先）；
// 匹配后丢弃变空的分组。返回可直接交给 model.loadStored 的干净数组。
//   storedGroups : sanitizeStoredGroups 的输出（原始数组也可，会再净化一次）
//   currentTabs  : [{ id, pinned }]
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
function describeReject(reason) {
  switch (reason) {
    case REJECT_NOT_STRING: return '标识或标题必须是字符串';
    case REJECT_NOT_ARRAY: return '标签列表必须是数组';
    case REJECT_TOO_LONG: return '分组标识、标题或标签标识超出长度限制';
    case REJECT_CONTROL: return '分组字段包含非法控制字符';
    case REJECT_BAD_COLOR: return '分组颜色不在允许范围内';
    case REJECT_LIMIT: return '分组数量或单组标签数已达上限';
    case REJECT_NOT_FOUND: return '目标分组不存在';
    case REJECT_PINNED: return '固定标签不能加入分组';
    case REJECT_DUPLICATE: return '分组标识重复';
    case REJECT_EMPTY: return '没有可加入分组的标签';
    default: return '分组操作被拒绝';
  }
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
