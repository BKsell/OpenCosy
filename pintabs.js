'use strict';
const { describeReasonFrom } = require('./reasontext');

const { hasControlCharV2 } = require('./modutil');

const { CLOSE_ALL, CLOSE_LEFT, CLOSE_MODES, CLOSE_OTHERS, CLOSE_RIGHT, MAX_PINNED_TABS, MAX_PIN_ID_LEN, MAX_PIN_URL_LEN, PinModel, REJECT_CONTROL, REJECT_LIMIT, REJECT_NOT_STRING, REJECT_TOO_LONG, hasControlChar, sanitizePinId, sanitizePinUrl, sanitizeStoredPins } = require('./pintabs_ops');
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
const REJECT_TEXT = {
  [REJECT_NOT_STRING]: '固定标签标识必须是字符串',
  [REJECT_TOO_LONG]: '固定标签标识或网址超出长度限制',
  [REJECT_CONTROL]: '固定标签标识包含非法控制字符',
  [REJECT_LIMIT]: '固定标签数量已达上限',
};

function describeReject(reason) {
  return describeReasonFrom(REJECT_TEXT, reason, '固定标签操作被拒绝');
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
