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

module.exports = {
  hasControlChar,
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
  makeGroupId,
  sanitizeStoredGroups,
};
