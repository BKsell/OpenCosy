'use strict';

// tabgroups.js —— 标签分组（Tab Groups）纯逻辑内核。
//
// 背景：
//   标签一多，标签栏就退化成一排看不清标题的小条。现代浏览器（Chrome/Edge/Firefox）
//   都支持“把一批标签收进一个带名字、带颜色的分组”，可整组折叠、整组关闭、跨重启
//   保留。OpenCosy 此前只有固定标签（pintabs），缺少“临时把同主题的十几个标签收成
//   一团”的能力。本模块补齐这一层。
//
// 本模块只做纯计算，不碰 DOM / Electron：维护分组的有序集合、组内标签顺序、标签到
//   组的反向索引、折叠态与颜色 / 标题，裁决“哪些标签能入组 / 入哪个组 / 整组排列
//   成什么样”，以及把磁盘清单净化后按当前标签重水合。main.js 在 IPC 处理器里据结果
//   真正移动 / 关闭标签，渲染层只负责画分组色块与标签。
//
// 与固定标签（pintabs）的协同：
//   固定标签是“长期常驻、不参与批量关闭”的特殊区，分组是“同主题临时成团”。二者语义
//   冲突，因此固定标签一律不允许入组；编排时固定区永远在最前，分组只作用于非固定区。
//
// 安全：
//   分组清单落盘（tabgroups.json）可能被外部进程篡改。重水合入口对组 id / 标题 /
//   颜色 / 标签 id 全部做类型、长度、控制字符、枚举与数量上界校验，任何脏字段都丢弃
//   对应条目（必要时整组丢弃），而不是半信任地恢复，避免脏字符串进入 IPC / 台账，也
//   防止被撑大的清单拖垮重排。

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
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 0x1F || code === 0x7F) return true;
  }
  return false;
}

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

// TabGroup 是单个分组的可变数据对象。tabIds 即组内从左到右的展示顺序。
class TabGroup {
  constructor(id, title, color) {
    this.id = id;
    this.title = title;
    this.color = color;
    this.collapsed = false;
    this.tabIds = [];
  }

  has(tabId) {
    return this.tabIds.indexOf(tabId) >= 0;
  }

  count() {
    return this.tabIds.length;
  }
}

// TabGroupModel 维护全部分组（有序）+ 标签到组的反向索引。
class TabGroupModel {
  constructor() {
    this._groups = [];                 // TabGroup[]，顺序即分组从左到右
    this._byId = new Map();           // groupId -> TabGroup
    this._tabIndex = new Map();        // tabId -> groupId
  }

  // ---- 查询 ----
  groupCount() {
    return this._groups.length;
  }

  hasGroup(groupId) {
    return this._byId.has(groupId);
  }

  groupOf(tabId) {
    return this._tabIndex.has(tabId) ? this._tabIndex.get(tabId) : null;
  }

  isGrouped(tabId) {
    return this._tabIndex.has(tabId);
  }

  getGroup(groupId) {
    return this._byId.get(groupId) || null;
  }

  // orderedGroupIds 返回分组 id 的有序快照。
  orderedGroupIds() {
    return this._groups.map(g => g.id);
  }

  // tabsInGroup 返回组内标签 id 的有序快照；组不存在返回 null。
  tabsInGroup(groupId) {
    const g = this._byId.get(groupId);
    return g ? g.tabIds.slice() : null;
  }

  // groupedTabIds 返回当前已入组的全部标签 id（按分组顺序、组内顺序）。
  groupedTabIds() {
    const out = [];
    for (const g of this._groups) for (const id of g.tabIds) out.push(id);
    return out;
  }

  // ---- 变更 ----

  // createGroup 新建一个分组。tabIds 为初始成员（可为空）；isPinnedFn 用于剔除固定
  // 标签。返回 { ok,reason?,group? }。分组数达上界或初始成员里没有可入组标签时，
  // 由调用方决定是否仍允许空组（allowEmpty=true 时允许，默认不允许空组）。
  createGroup(options, isPinnedFn) {
    const opts = options || {};
    if (this._groups.length >= MAX_GROUPS) return { ok: false, reason: REJECT_LIMIT };

    const tv = sanitizeGroupTitle(opts.title === undefined ? DEFAULT_GROUP_TITLE : opts.title);
    if (!tv.ok) return { ok: false, reason: tv.reason };
    const cv = sanitizeGroupColor(opts.color);

    const listRes = sanitizeTabIdList(opts.tabIds, MAX_TABS_PER_GROUP);
    const candidate = listRes.value;
    const members = this._filterJoinable(candidate, isPinnedFn);
    if (members.length === 0 && !opts.allowEmpty) {
      return { ok: false, reason: members.length < candidate.length ? REJECT_PINNED : REJECT_EMPTY };
    }

    let id = opts.id;
    if (id !== undefined) {
      const iv = sanitizeGroupId(id);
      if (!iv.ok) return { ok: false, reason: iv.reason };
      id = iv.value;
      if (this._byId.has(id)) return { ok: false, reason: REJECT_DUPLICATE };
    } else {
      id = this._allocateId(opts.now);
    }

    const group = new TabGroup(id, tv.value, cv.value);
    if (opts.collapsed === true) group.collapsed = true;
    for (const tabId of members) {
      group.tabIds.push(tabId);
      this._tabIndex.set(tabId, id);
    }
    // 新分组默认排在最右侧（数组末尾）。
    this._groups.push(group);
    this._byId.set(id, group);
    return { ok: true, group: this._snapshot(group), tabIds: group.tabIds.slice() };
  }

  // addTabs 把一批标签加入既有分组：已在其它组的先从原组移除（移动语义），固定标签
  // 跳过。返回实际加入的标签 id 与被跳过（固定）的 id。
  addTabs(groupId, rawTabIds, isPinnedFn) {
    const g = this._byId.get(groupId);
    if (!g) return { ok: false, reason: REJECT_NOT_FOUND };
    const listRes = sanitizeTabIdList(rawTabIds, MAX_TABS_PER_GROUP * 4);
    const added = [];
    const skippedPinned = [];
    for (const tabId of listRes.value) {
      if (typeof isPinnedFn === 'function' && isPinnedFn(tabId)) {
        skippedPinned.push(tabId);
        continue;
      }
      const existing = this._tabIndex.get(tabId);
      if (existing === g.id) continue; // 已在本组，幂等
      if (existing) this._removeTabFromGroup(existing, tabId); // 从别组移动
      if (g.tabIds.length >= MAX_TABS_PER_GROUP) break;
      g.tabIds.push(tabId);
      this._tabIndex.set(tabId, g.id);
      added.push(tabId);
    }
    return {
      ok: true,
      added,
      skippedPinned,
      group: this._snapshot(g),
      tabIds: g.tabIds.slice(),
    };
  }

  // removeTabs 把标签移出分组，回到未分组状态；不删除所在分组。
  removeTabs(rawTabIds) {
    const listRes = sanitizeTabIdList(rawTabIds, MAX_TABS_PER_GROUP * 4);
    const removed = [];
    for (const tabId of listRes.value) {
      const gid = this._tabIndex.get(tabId);
      if (!gid) continue;
      if (this._removeTabFromGroup(gid, tabId)) removed.push(tabId);
    }
    return { ok: true, removed };
  }

  // moveTab 把标签移到目标组（groupId 为 null 表示移出分组）。固定标签不可入组。
  moveTab(tabId, groupId, isPinnedFn) {
    const tv = sanitizeTabId(tabId);
    if (!tv.ok) return { ok: false, reason: tv.reason };
    if (groupId === null || groupId === undefined) {
      const r = this.removeTabs([tv.value]);
      return { ok: true, movedTo: null, removed: r.removed };
    }
    if (typeof isPinnedFn === 'function' && isPinnedFn(tv.value)) {
      return { ok: false, reason: REJECT_PINNED };
    }
    if (!this._byId.has(groupId)) return { ok: false, reason: REJECT_NOT_FOUND };
    const r = this.addTabs(groupId, [tv.value], isPinnedFn);
    return { ok: true, movedTo: groupId, added: r.added };
  }

  // renameGroup / setGroupColor / setGroupCollapsed 更新组属性，返回快照。
  renameGroup(groupId, rawTitle) {
    const g = this._byId.get(groupId);
    if (!g) return { ok: false, reason: REJECT_NOT_FOUND };
    const tv = sanitizeGroupTitle(rawTitle === undefined ? DEFAULT_GROUP_TITLE : rawTitle);
    if (!tv.ok) return { ok: false, reason: tv.reason };
    g.title = tv.value;
    return { ok: true, group: this._snapshot(g) };
  }

  setGroupColor(groupId, rawColor) {
    const g = this._byId.get(groupId);
    if (!g) return { ok: false, reason: REJECT_NOT_FOUND };
    const cv = sanitizeGroupColor(rawColor);
    g.color = cv.value;
    return { ok: true, group: this._snapshot(g) };
  }

  setGroupCollapsed(groupId, collapsed) {
    const g = this._byId.get(groupId);
    if (!g) return { ok: false, reason: REJECT_NOT_FOUND };
    g.collapsed = !!collapsed;
    return { ok: true, group: this._snapshot(g) };
  }

  // moveGroup 调整分组之间的左右顺序：把 groupId 移动到 toGroupId 的前面
  // （toGroupId 为 null 表示移到末尾）。
  moveGroup(groupId, toGroupId) {
    const from = this._groups.findIndex(g => g.id === groupId);
    if (from < 0) return { ok: false, reason: REJECT_NOT_FOUND };
    let to = this._groups.length;
    if (toGroupId !== null && toGroupId !== undefined) {
      const idx = this._groups.findIndex(g => g.id === toGroupId);
      if (idx < 0) return { ok: false, reason: REJECT_NOT_FOUND };
      to = idx;
    }
    const [moved] = this._groups.splice(from, 1);
    if (to > from) to -= 1; // 删除后目标索引前移
    this._groups.splice(to, 0, moved);
    return { ok: true, order: this.orderedGroupIds() };
  }

  // dissolveGroup 解散分组：保留其标签（全部回到未分组状态），删除分组本身。
  dissolveGroup(groupId) {
    const g = this._byId.get(groupId);
    if (!g) return { ok: false, reason: REJECT_NOT_FOUND };
    const freed = g.tabIds.slice();
    for (const tabId of freed) this._tabIndex.delete(tabId);
    this._groups = this._groups.filter(x => x.id !== groupId);
    this._byId.delete(groupId);
    return { ok: true, freedTabs: freed };
  }

  // onTabClosed 标签被关闭时清理其成员身份；若所在分组因此变空，则按 removeEmpty
  // 决定是否自动解散（默认 Chrome 行为：最后一个标签关闭后组消失）。
  onTabClosed(tabId, removeEmpty) {
    const gid = this._tabIndex.get(tabId);
    if (!gid) return { ok: true, removed: false, dissolved: false };
    this._removeTabFromGroup(gid, tabId);
    let dissolved = false;
    if (removeEmpty !== false) {
      const g = this._byId.get(gid);
      if (g && g.tabIds.length === 0) {
        this.dissolveGroup(gid);
        dissolved = true;
      }
    }
    return { ok: true, removed: true, groupId: gid, dissolved };
  }

  // ---- 序列化 / 重水合 ----

  // serialize 输出可直接 JSON.stringify 的纯数据数组（按分组顺序）。
  serialize() {
    return this._groups.map(g => ({
      id: g.id,
      title: g.title,
      color: g.color,
      collapsed: g.collapsed,
      tabIds: g.tabIds.slice(),
    }));
  }

  clear() {
    this._groups = [];
    this._byId.clear();
    this._tabIndex.clear();
  }

  // loadStored 用净化后的存储数据重建模型（见 sanitizeStoredGroups /
  // rehydrateGroupsByTabs）。这里直接接收已经与当前标签匹配好的干净分组数据。
  loadStored(cleanGroups) {
    this.clear();
    const list = Array.isArray(cleanGroups) ? cleanGroups : [];
    for (const rec of list) {
      if (!rec || typeof rec !== 'object') continue;
      if (this._groups.length >= MAX_GROUPS) break;
      const iv = sanitizeGroupId(rec.id);
      if (!iv.ok || this._byId.has(iv.value)) continue;
      const tv = sanitizeGroupTitle(rec.title === undefined ? DEFAULT_GROUP_TITLE : rec.title);
      if (!tv.ok) continue;
      const cv = sanitizeGroupColor(rec.color);
      const tabs = sanitizeTabIdList(rec.tabIds, MAX_TABS_PER_GROUP).value;
      if (tabs.length === 0) continue; // 空组不恢复
      const g = new TabGroup(iv.value, tv.value, cv.value);
      if (rec.collapsed === true) g.collapsed = true;
      for (const tabId of tabs) {
        if (this._tabIndex.has(tabId)) continue; // 一个标签只能属于一个组
        g.tabIds.push(tabId);
        this._tabIndex.set(tabId, g.id);
      }
      if (g.tabIds.length === 0) continue;
      this._groups.push(g);
      this._byId.set(g.id, g);
    }
    return this.serialize();
  }

  // ---- 内部辅助 ----

  _filterJoinable(candidate, isPinnedFn) {
    const out = [];
    for (const tabId of candidate) {
      if (this._tabIndex.has(tabId)) continue; // 已在某组
      if (typeof isPinnedFn === 'function' && isPinnedFn(tabId)) continue;
      out.push(tabId);
    }
    return out;
  }

  _removeTabFromGroup(groupId, tabId) {
    const g = this._byId.get(groupId);
    if (!g) return false;
    const idx = g.tabIds.indexOf(tabId);
    if (idx < 0) return false;
    g.tabIds.splice(idx, 1);
    this._tabIndex.delete(tabId);
    return true;
  }

  _allocateId(now) {
    for (let i = 0; i < 16; i++) {
      const id = makeGroupId(now);
      if (!this._byId.has(id)) return id;
    }
    // 极小概率连续碰撞时退化为计数后缀，保证仍能分配。
    let n = this._groups.length;
    while (this._byId.has('g-fallback-' + n)) n++;
    return 'g-fallback-' + n;
  }

  _snapshot(g) {
    return {
      id: g.id,
      title: g.title,
      color: g.color,
      collapsed: g.collapsed,
      tabIds: g.tabIds.slice(),
    };
  }
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
  GROUP_COLORS,
  GROUP_COLOR_SET,
  FALLBACK_GROUP_COLOR,
  GROUP_COLOR_GREY,
  GROUP_COLOR_BLUE,
  GROUP_COLOR_RED,
  GROUP_COLOR_YELLOW,
  GROUP_COLOR_GREEN,
  GROUP_COLOR_PINK,
  GROUP_COLOR_PURPLE,
  GROUP_COLOR_CYAN,
  GROUP_COLOR_ORANGE,
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
  hasControlChar,
  makeGroupId,
  sanitizeGroupId,
  sanitizeTabId,
  sanitizeGroupTitle,
  sanitizeGroupColor,
  sanitizeTabIdList,
  sanitizeStoredGroups,
  rehydrateGroupsByTabs,
  arrangeTabs,
  describeReject,
  TabGroup,
  TabGroupModel,
};
