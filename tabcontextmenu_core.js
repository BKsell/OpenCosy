'use strict';

const ACTION = {
  CLOSE: 'close-tab',
  CLOSE_OTHERS: 'close-other-tabs',
  RELOAD: 'reload-tab',
  DUPLICATE: 'duplicate-tab',
  TOGGLE_PIN: 'toggle-pin',
  TOGGLE_MUTE: 'toggle-mute',
  COPY_URL: 'copy-tab-url',
  MOVE_NEW_WINDOW: 'move-to-new-window',
  SAVE_PAGE: 'save-page'
};

const LABELS = {
  [ACTION.CLOSE]: '关闭标签页',
  [ACTION.CLOSE_OTHERS]: '关闭其他标签页',
  [ACTION.RELOAD]: '重新加载',
  [ACTION.DUPLICATE]: '复制标签页',
  [ACTION.TOGGLE_PIN]: '固定标签页',
  [ACTION.TOGGLE_MUTE]: '静音标签页',
  [ACTION.COPY_URL]: '复制网址',
  [ACTION.MOVE_NEW_WINDOW]: '移动到新窗口',
  [ACTION.SAVE_PAGE]: '保存页面'
};

const SHORTCUTS = {
  [ACTION.CLOSE]: 'Ctrl+W',
  [ACTION.CLOSE_OTHERS]: 'Ctrl+Shift+W',
  [ACTION.RELOAD]: 'Ctrl+R',
  [ACTION.DUPLICATE]: 'Ctrl+Shift+D',
  [ACTION.COPY_URL]: 'Ctrl+L'
};

const PINNED_LABEL = '取消固定标签页';
const UNMUTE_LABEL = '取消静音';

function normalizeContext(raw) {
  const ctx = raw && typeof raw === 'object' ? raw : {};
  return {
    tabId: typeof ctx.tabId === 'string' ? ctx.tabId : '',
    tabCount: Number.isSafeInteger(ctx.tabCount) ? ctx.tabCount : 0,
    hasUrl: typeof ctx.url === 'string' && ctx.url.length > 0,
    isPinned: ctx.isPinned === true,
    isMuted: ctx.isMuted === true,
    canReload: ctx.canReload !== false,
    canSave: ctx.canSave !== false
  };
}

function labelFor(action, ctx) {
  if (action === ACTION.TOGGLE_PIN) return ctx.isPinned ? PINNED_LABEL : LABELS[action];
  if (action === ACTION.TOGGLE_MUTE) return ctx.isMuted ? UNMUTE_LABEL : LABELS[action];
  return LABELS[action] || '';
}

function buildTabMenuItems(raw) {
  const ctx = normalizeContext(raw);
  const actions = [];
  if (ctx.canReload) actions.push(ACTION.RELOAD);
  if (ctx.hasUrl) actions.push(ACTION.DUPLICATE);
  actions.push(ACTION.TOGGLE_PIN);
  actions.push(ACTION.TOGGLE_MUTE);
  if (ctx.hasUrl) actions.push(ACTION.COPY_URL);
  if (ctx.canSave) actions.push(ACTION.SAVE_PAGE);
  if (ctx.tabCount > 1) actions.push(ACTION.CLOSE_OTHERS);
  if (ctx.tabCount > 1) actions.push(ACTION.MOVE_NEW_WINDOW);
  if (ctx.tabCount >= 1) actions.push(ACTION.CLOSE);
  return actions.map((action) => {
    const item = { action, label: labelFor(action, ctx), enabled: true };
    if (SHORTCUTS[action]) item.accelerator = SHORTCUTS[action];
    if (action === ACTION.CLOSE && ctx.tabCount <= 1) item.enabled = false;
    return item;
  });
}

function isKnownAction(action) {
  return Object.prototype.hasOwnProperty.call(LABELS, action);
}

function resolveMenuAction(items, action) {
  if (!Array.isArray(items) || typeof action !== 'string') return { ok: false, reason: 'malformed' };
  const hit = items.find((item) => item && item.action === action);
  if (!hit) return { ok: false, reason: 'unknown-action' };
  if (hit.enabled !== true) return { ok: false, reason: 'disabled' };
  return { ok: true, reason: 'ok', action: hit.action };
}

function splitMenuItems(items, beforeAction) {
  if (!Array.isArray(items)) return { top: [], bottom: [] };
  const index = items.findIndex((item) => item && item.action === beforeAction);
  if (index < 0) return { top: items.slice(), bottom: [] };
  return { top: items.slice(0, index), bottom: items.slice(index) };
}

function describeMenuAction(action) {
  if (!isKnownAction(action)) return '未知菜单动作';
  return LABELS[action];
}

module.exports = {
  ACTION,
  LABELS,
  SHORTCUTS,
  buildTabMenuItems,
  resolveMenuAction,
  splitMenuItems,
  describeMenuAction,
  isKnownAction
};
