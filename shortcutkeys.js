'use strict';

// shortcutkeys.js —— 全局键盘快捷键的纯判定内核（无正则、无 Electron 依赖、无副作用）。
//
// 历史问题：main.js 的 before-input-event 里是约 160 行、30 余条的 if / else if 链，
// 每条分支各自重复 ctrl/shift/alt 与键名比较。键名大小写处理也不统一（单字符走
// input.key.toLowerCase()，F 键 / 方向键 / Tab 又直接比 input.key），既容易写错，
// 又无法在不启动 Electron 的情况下单测。
//
// 本文件只负责回答一个问题：“这一次键盘输入命中哪个动作”。动作的实际执行（建标签、
// 关闭、缩放等）仍留在 main 进程，由它把动作 id 映射到处理函数。
//
// 键名一律用 input.key.toLowerCase() 比较，因此 'Tab' -> 'tab'、'F6' -> 'f6'、
// 'ArrowLeft' -> 'arrowleft'、'Delete' -> 'delete'，与旧链每条分支的实际比较等价。

// 动作 id：main 进程据此派发；新增快捷键时在这里登记，不要在 main.js 里再写 if。
const ACTION = Object.freeze({
  NEW_TAB: 'new-tab',
  REOPEN_CLOSED_TAB: 'reopen-closed-tab',
  CLOSE_TAB: 'close-tab',
  NEW_WINDOW: 'new-window',
  DUPLICATE_TAB: 'duplicate-tab',
  TOGGLE_BOOKMARKS_BAR: 'toggle-bookmarks-bar',
  BOOKMARK_ALL_TABS: 'bookmark-all-tabs',
  DISCARD_BACKGROUND_TABS: 'discard-background-tabs',
  NEXT_TAB: 'next-tab',
  PREV_TAB: 'prev-tab',
  FOCUS_ADDRESS_BAR: 'focus-address-bar',
  CLOSE_TAB_F4: 'close-tab-f4',
  FIND: 'find',
  FIND_NEXT: 'find-next',
  FIND_PREV: 'find-prev',
  OPEN_DOWNLOADS: 'open-downloads',
  PRINT: 'print',
  VIEW_SOURCE: 'view-source',
  OPEN_FILE: 'open-file',
  GO_HOME: 'go-home',
  RELOAD: 'reload',
  RELOAD_BYPASSING_CACHE: 'reload-bypassing-cache',
  TOGGLE_DEVTOOLS: 'toggle-devtools',
  OPEN_TASK_MANAGER: 'open-task-manager',
  ENTER_READER: 'enter-reader',
  EXIT_FULLSCREEN: 'exit-fullscreen',
  ZOOM_IN: 'zoom-in',
  ZOOM_OUT: 'zoom-out',
  ZOOM_RESET: 'zoom-reset',
  BACK: 'back',
  FORWARD: 'forward',
  TOGGLE_BOOKMARK: 'toggle-bookmark',
  OPEN_HISTORY: 'open-history',
  CLEAR_BROWSING_DATA: 'clear-browsing-data',
});

// 修饰三态：
//   true  = 必须按下
//   false = 必须未按下
//   null  = 不关心（旧链对该修饰没有限制，保持逐字等价）
//
// 数组顺序即优先级，必须与重构前的 if / else if 链一致：例如 Ctrl+Shift+D（收藏全部）
// 必须排在 Ctrl+D（切换当前页书签）之前，Ctrl+Shift+T 排在 Ctrl+T 的非 shift 分支前。
const SHORTCUT_RULES = Object.freeze([
  { action: ACTION.NEW_TAB, key: 't', ctrl: true, shift: false, alt: false },
  { action: ACTION.REOPEN_CLOSED_TAB, key: 't', ctrl: true, shift: true, alt: false },
  { action: ACTION.CLOSE_TAB, key: 'w', ctrl: true, shift: null, alt: null },
  { action: ACTION.NEW_WINDOW, key: 'n', ctrl: true, shift: null, alt: null },
  { action: ACTION.DUPLICATE_TAB, key: 'k', ctrl: true, shift: true, alt: null },
  { action: ACTION.TOGGLE_BOOKMARKS_BAR, key: 'b', ctrl: true, shift: true, alt: null },
  { action: ACTION.BOOKMARK_ALL_TABS, key: 'd', ctrl: true, shift: true, alt: null },
  { action: ACTION.DISCARD_BACKGROUND_TABS, key: 's', ctrl: true, shift: true, alt: null },
  { action: ACTION.PREV_TAB, key: 'tab', ctrl: true, shift: true, alt: null },
  { action: ACTION.NEXT_TAB, key: 'tab', ctrl: true, shift: false, alt: null },
  { action: ACTION.FOCUS_ADDRESS_BAR, key: 'l', ctrl: true, shift: null, alt: null },
  { action: ACTION.FOCUS_ADDRESS_BAR, key: 'f6', ctrl: null, shift: null, alt: null },
  { action: ACTION.CLOSE_TAB_F4, key: 'f4', ctrl: true, shift: null, alt: null },
  { action: ACTION.FIND, key: 'f', ctrl: true, shift: null, alt: null },
  { action: ACTION.FIND_PREV, key: 'f3', ctrl: null, shift: true, alt: null },
  { action: ACTION.FIND_NEXT, key: 'f3', ctrl: null, shift: false, alt: null },
  { action: ACTION.FIND_PREV, key: 'g', ctrl: true, shift: true, alt: null },
  { action: ACTION.FIND_NEXT, key: 'g', ctrl: true, shift: false, alt: null },
  { action: ACTION.OPEN_DOWNLOADS, key: 'j', ctrl: true, shift: null, alt: null },
  { action: ACTION.PRINT, key: 'p', ctrl: true, shift: null, alt: null },
  { action: ACTION.VIEW_SOURCE, key: 'u', ctrl: true, shift: null, alt: null },
  { action: ACTION.OPEN_FILE, key: 'o', ctrl: true, shift: null, alt: null },
  { action: ACTION.GO_HOME, key: 'home', ctrl: null, shift: null, alt: true },
  // Ctrl+Alt+R 进入阅读模式。必须排在 Ctrl+R 刷新之前：刷新规则 alt 为“不关心”，
  // 若靠后会先吞掉 Ctrl+Alt+R；本条显式要求 alt 按下、shift 未按下，普通 Ctrl+R
  // 与 Ctrl+Shift+R 均不命中，继续落到各自的刷新规则。
  { action: ACTION.ENTER_READER, key: 'r', ctrl: true, shift: false, alt: true },
  { action: ACTION.RELOAD, key: 'r', ctrl: true, shift: false, alt: null },
  { action: ACTION.RELOAD_BYPASSING_CACHE, key: 'r', ctrl: true, shift: true, alt: null },
  { action: ACTION.RELOAD, key: 'f5', ctrl: null, shift: false, alt: null },
  { action: ACTION.RELOAD_BYPASSING_CACHE, key: 'f5', ctrl: null, shift: true, alt: null },
  { action: ACTION.TOGGLE_DEVTOOLS, key: 'f12', ctrl: null, shift: null, alt: null },
  // Shift+Esc 打开任务管理器，必须排在通吃的纯 Esc 退出全屏规则之前；
  // 纯 Esc（shift 未按）不命中本条，Ctrl+Shift+Esc 因要求 ctrl:false 也落到退出全屏。
  { action: ACTION.OPEN_TASK_MANAGER, key: 'escape', ctrl: false, shift: true, alt: false },
  { action: ACTION.EXIT_FULLSCREEN, key: 'escape', ctrl: null, shift: null, alt: null },
  { action: ACTION.ZOOM_IN, key: '=', ctrl: true, shift: null, alt: null },
  { action: ACTION.ZOOM_OUT, key: '-', ctrl: true, shift: null, alt: null },
  { action: ACTION.ZOOM_RESET, key: '0', ctrl: true, shift: null, alt: null },
  { action: ACTION.BACK, key: 'arrowleft', ctrl: null, shift: null, alt: true },
  { action: ACTION.FORWARD, key: 'arrowright', ctrl: null, shift: null, alt: null },
  { action: ACTION.TOGGLE_BOOKMARK, key: 'd', ctrl: true, shift: false, alt: null },
  { action: ACTION.OPEN_HISTORY, key: 'h', ctrl: true, shift: null, alt: null },
  { action: ACTION.CLEAR_BROWSING_DATA, key: 'delete', ctrl: true, shift: true, alt: null },
]);

// normalizeKey 把 Electron input.key 收敛成规则表里的小写形式。
function normalizeKey(input) {
  const k = input && input.key;
  if (typeof k !== 'string') return '';
  return k.toLowerCase();
}

// modifierWants 判断单一一味修饰是否满足规则要求；want 为 null 时恒满足。
function modifierWants(active, want) {
  if (want === null) return true;
  return active === want;
}

// ruleMatches 判断一次输入是否命中单条规则。ctrl 与 meta（macOS 的 Command）等价，
// 与旧实现 input.control || input.meta 一致。
function ruleMatches(input, key, rule) {
  if (rule.key !== key) return false;
  const ctrlActive = input.control === true || input.meta === true;
  return modifierWants(ctrlActive, rule.ctrl)
    && modifierWants(input.shift === true, rule.shift)
    && modifierWants(input.alt === true, rule.alt);
}

// matchShortcut 返回输入命中的动作 id；非 keyDown 或无命中返回 null。
// 取 SHORTCUT_RULES 中第一条命中规则，保证与旧 if / else if 链同序同优先级。
function matchShortcut(input, rules) {
  if (!input || input.type !== 'keyDown') return null;
  const key = normalizeKey(input);
  if (!key) return null;
  const table = rules || SHORTCUT_RULES;
  for (const rule of table) {
    if (ruleMatches(input, key, rule)) return rule.action;
  }
  return null;
}

// PRIMARY_ACCELERATOR 给出每个动作的主加速键人类可读形式，供设置页 / 菜单 / 单测使用。
// 一个动作存在多个绑定（如刷新有 Ctrl+R 与 F5）时只列最主要的一个。
const PRIMARY_ACCELERATOR = Object.freeze({
  [ACTION.NEW_TAB]: 'Ctrl+T',
  [ACTION.REOPEN_CLOSED_TAB]: 'Ctrl+Shift+T',
  [ACTION.CLOSE_TAB]: 'Ctrl+W',
  [ACTION.NEW_WINDOW]: 'Ctrl+N',
  [ACTION.DUPLICATE_TAB]: 'Ctrl+Shift+K',
  [ACTION.TOGGLE_BOOKMARKS_BAR]: 'Ctrl+Shift+B',
  [ACTION.BOOKMARK_ALL_TABS]: 'Ctrl+Shift+D',
  [ACTION.DISCARD_BACKGROUND_TABS]: 'Ctrl+Shift+S',
  [ACTION.NEXT_TAB]: 'Ctrl+Tab',
  [ACTION.PREV_TAB]: 'Ctrl+Shift+Tab',
  [ACTION.FOCUS_ADDRESS_BAR]: 'Ctrl+L',
  [ACTION.CLOSE_TAB_F4]: 'Ctrl+F4',
  [ACTION.FIND]: 'Ctrl+F',
  [ACTION.FIND_NEXT]: 'F3',
  [ACTION.FIND_PREV]: 'Shift+F3',
  [ACTION.OPEN_DOWNLOADS]: 'Ctrl+J',
  [ACTION.PRINT]: 'Ctrl+P',
  [ACTION.VIEW_SOURCE]: 'Ctrl+U',
  [ACTION.OPEN_FILE]: 'Ctrl+O',
  [ACTION.GO_HOME]: 'Alt+Home',
  [ACTION.RELOAD]: 'Ctrl+R',
  [ACTION.RELOAD_BYPASSING_CACHE]: 'Ctrl+Shift+R',
  [ACTION.TOGGLE_DEVTOOLS]: 'F12',
  [ACTION.OPEN_TASK_MANAGER]: 'Shift+Esc',
  [ACTION.ENTER_READER]: 'Ctrl+Alt+R',
  [ACTION.EXIT_FULLSCREEN]: 'Esc',
  [ACTION.ZOOM_IN]: 'Ctrl+=',
  [ACTION.ZOOM_OUT]: 'Ctrl+-',
  [ACTION.ZOOM_RESET]: 'Ctrl+0',
  [ACTION.BACK]: 'Alt+Left',
  [ACTION.FORWARD]: 'Alt+Right',
  [ACTION.TOGGLE_BOOKMARK]: 'Ctrl+D',
  [ACTION.OPEN_HISTORY]: 'Ctrl+H',
  [ACTION.CLEAR_BROWSING_DATA]: 'Ctrl+Shift+Delete',
});

// describeAccelerator 返回动作的主加速键文本；未登记动作返回空串。
function describeAccelerator(action) {
  return PRIMARY_ACCELERATOR[action] || '';
}

module.exports = {
  ACTION,
  SHORTCUT_RULES,
  PRIMARY_ACCELERATOR,
  normalizeKey,
  ruleMatches,
  matchShortcut,
  describeAccelerator,
};
