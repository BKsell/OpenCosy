'use strict';

// pintabs.js —— 固定标签页（Pinned Tabs）纯逻辑内核。
//
// 背景：
//   旧标签栏所有标签一视同仁，“关闭其他 / 关闭左侧 / 关闭右侧 / 退出时清理”会
//   顺手把用户长期挂着的邮箱、文档、控制台等常用标签一起关掉，重启后固定状态也
//   不保留。固定标签页是现代浏览器的标配能力：固定后标签收窄成只剩图标、不参与
//   任何批量关闭、跨重启保留、并排在标签栏最前。
//
// 本模块只做纯计算，不碰 DOM / Electron：维护固定集合与顺序、裁决批量关闭时哪些
//   标签允许关闭、把固定标签稳定地排到最前、以及把磁盘上的固定清单净化后重水合。
//   main.js 在 IPC 处理器里据结果真正移动 / 关闭标签，渲染层只负责展示。
//
// 安全：
//   固定清单落盘（pintabs.json）可能被外部进程篡改，重水合入口对 id / url 全部做
//   类型、长度、控制字符与数量上界校验，损坏数据整体丢弃而不是半信任地恢复。

const MAX_PINNED_TABS = 100;   // 固定标签硬上界，防止清单文件被撑大后拖垮重排
const MAX_PIN_ID_LEN = 128;    // 标签 id 长度上界（运行时 id 本就很短，128 已极宽松）
const MAX_PIN_URL_LEN = 4096;  // 固定标签记录的 URL 长度上界，与浏览器地址栏上界对齐

// 批量关闭模式。
const CLOSE_ALL = 'all';       // 关闭全部（固定标签除外）
const CLOSE_OTHERS = 'others'; // 关闭除锚点外的全部（固定标签除外）
const CLOSE_LEFT = 'left';     // 关闭锚点左侧（固定标签除外）
const CLOSE_RIGHT = 'right';   // 关闭锚点右侧（固定标签除外）

const CLOSE_MODES = new Set([CLOSE_ALL, CLOSE_OTHERS, CLOSE_LEFT, CLOSE_RIGHT]);

// REJECT_* 是固定 / 重水合被拒绝时的原因码，供上层给出明确反馈与审计。
const REJECT_NOT_STRING = 'not-string';
const REJECT_TOO_LONG = 'too-long';
const REJECT_CONTROL = 'control-char';
const REJECT_LIMIT = 'limit-reached';

// hasControlChar 判断字符串是否含 ASCII 控制字符（0x00-0x1F、0x7F）。
// 固定 id 会进 IPC 与磁盘，控制字符没有合法用途，统一拒绝。
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 0x1F || code === 0x7F) return true;
  }
  return false;
}

// sanitizePinId 校验单个标签 id：必须是非空字符串、不超长、不含控制字符。
// 返回 { ok:true,value } 或 { ok:false,reason }。
function sanitizePinId(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: REJECT_NOT_STRING };
  const id = raw;
  if (id.length === 0 || id.length > MAX_PIN_ID_LEN) return { ok: false, reason: REJECT_TOO_LONG };
  if (hasControlChar(id)) return { ok: false, reason: REJECT_CONTROL };
  return { ok: true, value: id };
}

// sanitizePinUrl 校验固定记录里的 URL。仅用于跨重启重水合匹配，不要求它一定能
// 通过完整的 isSafeUrl（协议白名单由调用方在真正导航时再判），这里只挡非字符串、
// 超长与控制字符，避免脏数据进入比较。
function sanitizePinUrl(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: REJECT_NOT_STRING };
  if (raw.length === 0 || raw.length > MAX_PIN_URL_LEN) return { ok: false, reason: REJECT_TOO_LONG };
  if (hasControlChar(raw)) return { ok: false, reason: REJECT_CONTROL };
  return { ok: true, value: raw };
}

// PinModel 维护固定标签的有序集合。顺序即固定区从左到右的展示顺序。
class PinModel {
  constructor() {
    this._order = [];
    this._set = new Set();
  }

  isPinned(id) {
    return this._set.has(id);
  }

  count() {
    return this._order.length;
  }

  // ids 返回固定 id 的有序快照，避免外部直接改内部数组。
  ids() {
    return this._order.slice();
  }

  // pin 把标签加入固定区末尾；已固定则幂等无变化。达到上界返回 REJECT_LIMIT。
  pin(id) {
    const v = sanitizePinId(id);
    if (!v.ok) return { ok: false, reason: v.reason, changed: false };
    if (this._set.has(v.value)) return { ok: true, changed: false };
    if (this._order.length >= MAX_PINNED_TABS) return { ok: false, reason: REJECT_LIMIT, changed: false };
    this._order.push(v.value);
    this._set.add(v.value);
    return { ok: true, changed: true };
  }

  // unpin 取消固定；未固定时幂等无变化。
  unpin(id) {
    const v = sanitizePinId(id);
    if (!v.ok) return { ok: false, reason: v.reason, changed: false };
    if (!this._set.has(v.value)) return { ok: true, changed: false };
    this._set.delete(v.value);
    this._order = this._order.filter(x => x !== v.value);
    return { ok: true, changed: true };
  }

  // toggle 在固定 / 取消固定之间切换，返回切换后的 pinned 状态。
  toggle(id) {
    if (this.isPinned(id)) {
      const r = this.unpin(id);
      return { ok: r.ok, reason: r.reason, pinned: false, changed: r.changed };
    }
    const r = this.pin(id);
    return { ok: r.ok, reason: r.reason, pinned: r.ok, changed: r.changed };
  }

  // arrange 给定一份标签 id 的当前顺序，返回“固定区在前、非固定区在后”的新顺序，
  // 两个分区内部都保持原相对顺序（稳定分区）。固定区顺序以模型内顺序为准，模型里
  // 没有但 isPinnedFn 认定固定的 id（兼容调用方传入额外判定）追加在固定区末尾。
  arrange(orderedIds, isPinnedFn) {
    const pinnedKnown = [];
    const pinnedExtra = [];
    const rest = [];
    const seen = new Set();
    const isPin = (x) => this._set.has(x) || (typeof isPinnedFn === 'function' && !!isPinnedFn(x));
    for (const id of orderedIds) {
      if (typeof id !== 'string' || seen.has(id)) continue;
      seen.add(id);
      if (isPin(id)) {
        if (this._set.has(id)) pinnedKnown.push(id);
        else pinnedExtra.push(id);
      } else {
        rest.push(id);
      }
    }
    // pinnedKnown 按模型固定顺序输出；模型里有、但本轮 orderedIds 缺失的 id 忽略。
    const knownSet = new Set(pinnedKnown);
    const orderedKnown = this._order.filter(id => knownSet.has(id));
    return orderedKnown.concat(pinnedExtra, rest);
  }

  clear() {
    this._order = [];
    this._set.clear();
  }

  // serialize 输出可直接 JSON.stringify 的有序 id 数组。
  serialize() {
    return this._order.slice();
  }

  // applyStored 用一份净化后的 id 数组重置模型（用于只按 id 恢复的场景）。
  applyStored(ids) {
    this.clear();
    const clean = sanitizeStoredPins(ids);
    for (const id of clean) this._set.add(id), this._order.push(id);
    return this.serialize();
  }
}

// sanitizeStoredPins 净化磁盘读出的固定 id 清单：
// 必须是数组、元素为合法 id、去重并保留首次出现顺序、截断到上界。
// 任何脏元素直接丢弃，绝不抛异常阻断启动。
function sanitizeStoredPins(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seen = new Set();
  for (const item of raw) {
    const v = sanitizePinId(item);
    if (!v.ok) continue;
    if (seen.has(v.value)) continue;
    seen.add(v.value);
    out.push(v.value);
    if (out.length >= MAX_PINNED_TABS) break;
  }
  return out;
}

// sanitizeStoredPinEntries 净化 [{id,url}] 形态的跨重启固定清单。
// 运行时标签 id 每次启动都会重新生成，无法跨重启使用，因此持久化时记录固定标签
// 的 URL，重水合时按 URL 与新标签匹配。脏条目整体丢弃。
function sanitizeStoredPinEntries(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seenUrl = new Set();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const u = sanitizePinUrl(entry.url);
    if (!u.ok) continue;
    if (seenUrl.has(u.value)) continue;
    seenUrl.add(u.value);
    // id 仅作调试线索，可有可无；存在时也要净化，防止脏字符串混进台账。
    const rec = { url: u.value };
    if (entry.id !== undefined && entry.id !== null) {
      const iv = sanitizePinId(entry.id);
      if (iv.ok) rec.id = iv.value;
    }
    out.push(rec);
    if (out.length >= MAX_PINNED_TABS) break;
  }
  return out;
}

// rehydratePinsByUrl 用磁盘上的固定 URL 清单，与本次启动后新建的标签匹配，
// 返回应当被置为固定的“当前标签 id”有序数组（按存储清单顺序）。
//   storedEntries : sanitizeStoredPinEntries 的输出（或原始数组，会再净化一次）
//   currentTabs   : [{ id, url }]
// 同一 URL 多个标签时只固定第一个；存储里没匹配到的 URL 忽略（对应标签本次没恢复）。
function rehydratePinsByUrl(storedEntries, currentTabs) {
  const entries = sanitizeStoredPinEntries(storedEntries);
  const tabs = Array.isArray(currentTabs) ? currentTabs : [];
  const pinnedIds = [];
  const usedTabIndex = new Set();
  for (const rec of entries) {
    let found = -1;
    for (let i = 0; i < tabs.length; i++) {
      if (usedTabIndex.has(i)) continue;
      const t = tabs[i];
      if (t && typeof t.id === 'string' && t.url === rec.url) { found = i; break; }
    }
    if (found >= 0) {
      usedTabIndex.add(found);
      pinnedIds.push(tabs[found].id);
    }
  }
  return pinnedIds;
}

// planBatchClose 裁决一次批量关闭应关掉哪些标签。
//   tabs    : [{ id, pinned }]，顺序即标签栏顺序
//   options : { mode, anchorId }
// 固定标签在任何模式下都保留；返回 closeIds / keepIds（均为标签栏原顺序的 id）。
// 非法 mode 或缺锚点（left/right/others 需要）返回 null，由调用方拒绝该操作。
function planBatchClose(tabs, options) {
  const opts = options || {};
  const mode = opts.mode;
  if (!CLOSE_MODES.has(mode)) return null;
  const list = Array.isArray(tabs) ? tabs : [];

  let anchorIndex = -1;
  if (mode !== CLOSE_ALL) {
    anchorIndex = list.findIndex(t => t && t.id === opts.anchorId);
    if (anchorIndex < 0) return null;
  }

  const closeIds = [];
  const keepIds = [];
  list.forEach((t, i) => {
    if (!t || typeof t.id !== 'string') return;
    let willClose;
    if (t.pinned) {
      willClose = false; // 固定标签永远不参与批量关闭
    } else if (mode === CLOSE_ALL) {
      willClose = true;
    } else if (mode === CLOSE_OTHERS) {
      willClose = i !== anchorIndex;
    } else if (mode === CLOSE_LEFT) {
      willClose = i < anchorIndex;
    } else { // CLOSE_RIGHT
      willClose = i > anchorIndex;
    }
    if (willClose) closeIds.push(t.id);
    else keepIds.push(t.id);
  });
  return { mode, anchorIndex, closeIds, keepIds };
}

// describeReject 把拒绝原因码翻译成中文说明，供 IPC 层回传与审计使用。
function describeReject(reason) {
  switch (reason) {
    case REJECT_NOT_STRING: return '固定标签标识必须是字符串';
    case REJECT_TOO_LONG: return '固定标签标识或网址超出长度限制';
    case REJECT_CONTROL: return '固定标签标识包含非法控制字符';
    case REJECT_LIMIT: return '固定标签数量已达上限';
    default: return '固定标签操作被拒绝';
  }
}

module.exports = {
  MAX_PINNED_TABS,
  MAX_PIN_ID_LEN,
  MAX_PIN_URL_LEN,
  CLOSE_ALL,
  CLOSE_OTHERS,
  CLOSE_LEFT,
  CLOSE_RIGHT,
  CLOSE_MODES,
  REJECT_NOT_STRING,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  REJECT_LIMIT,
  hasControlChar,
  sanitizePinId,
  sanitizePinUrl,
  sanitizeStoredPins,
  sanitizeStoredPinEntries,
  rehydratePinsByUrl,
  planBatchClose,
  describeReject,
  PinModel,
};
