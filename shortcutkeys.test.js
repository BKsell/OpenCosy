'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  ACTION,
  SHORTCUT_RULES,
  PRIMARY_ACCELERATOR,
  normalizeKey,
  ruleMatches,
  matchShortcut,
  describeAccelerator,
} = require('./shortcutkeys');

// mk 构造一个 before-input-event 的 input；默认 keyDown，修饰键默认未按下。
function mk(key, mod) {
  return Object.assign({
    type: 'keyDown',
    key,
    control: false,
    meta: false,
    shift: false,
    alt: false,
  }, mod || {});
}

test('每个动作 id 都有主加速键文本且无空缺', () => {
  for (const id of Object.values(ACTION)) {
    assert.ok(describeAccelerator(id), `缺少动作 ${id} 的加速键文本`);
    assert.strictEqual(describeAccelerator(id), PRIMARY_ACCELERATOR[id]);
  }
});

test('normalizeKey 归一化大小写，非法输入回空串', () => {
  assert.strictEqual(normalizeKey(mk('F6')), 'f6');
  assert.strictEqual(normalizeKey(mk('ArrowLeft')), 'arrowleft');
  assert.strictEqual(normalizeKey(mk('Tab')), 'tab');
  assert.strictEqual(normalizeKey(null), '');
  assert.strictEqual(normalizeKey({ key: 5 }), '');
});

test('基础绑定：标签 / 窗口 / 书签栏', () => {
  assert.strictEqual(matchShortcut(mk('t', { control: true })), ACTION.NEW_TAB);
  assert.strictEqual(matchShortcut(mk('t', { control: true, shift: true })), ACTION.REOPEN_CLOSED_TAB);
  assert.strictEqual(matchShortcut(mk('w', { control: true })), ACTION.CLOSE_TAB);
  assert.strictEqual(matchShortcut(mk('n', { control: true })), ACTION.NEW_WINDOW);
  assert.strictEqual(matchShortcut(mk('k', { control: true, shift: true })), ACTION.DUPLICATE_TAB);
  assert.strictEqual(matchShortcut(mk('b', { control: true, shift: true })), ACTION.TOGGLE_BOOKMARKS_BAR);
});

test('Ctrl+Shift+D（收藏全部）优先于 Ctrl+D（切换书签）', () => {
  assert.strictEqual(matchShortcut(mk('d', { control: true, shift: true })), ACTION.BOOKMARK_ALL_TABS);
  assert.strictEqual(matchShortcut(mk('d', { control: true })), ACTION.TOGGLE_BOOKMARK);
});

test('Ctrl+Shift+S 休眠后台标签', () => {
  assert.strictEqual(matchShortcut(mk('s', { control: true, shift: true })), ACTION.DISCARD_BACKGROUND_TABS);
  // 非 shift 的 Ctrl+S 原本就不绑定，应为 null
  assert.strictEqual(matchShortcut(mk('s', { control: true })), null);
});

test('Ctrl+Tab 前进 / Ctrl+Shift+Tab 后退', () => {
  assert.strictEqual(matchShortcut(mk('Tab', { control: true })), ACTION.NEXT_TAB);
  assert.strictEqual(matchShortcut(mk('Tab', { control: true, shift: true })), ACTION.PREV_TAB);
});

test('地址栏：Ctrl+L 与无修饰 F6（F6 不校验 ctrl）', () => {
  assert.strictEqual(matchShortcut(mk('l', { control: true })), ACTION.FOCUS_ADDRESS_BAR);
  assert.strictEqual(matchShortcut(mk('F6')), ACTION.FOCUS_ADDRESS_BAR);
  // 原链 F6 不判断 ctrl，Ctrl+F6 同样聚焦，保持逐字等价
  assert.strictEqual(matchShortcut(mk('F6', { control: true })), ACTION.FOCUS_ADDRESS_BAR);
});

test('Ctrl+F4 关闭标签', () => {
  assert.strictEqual(matchShortcut(mk('F4', { control: true })), ACTION.CLOSE_TAB_F4);
  assert.strictEqual(matchShortcut(mk('F4')), null);
});

test('查找：Ctrl+F、F3/Shift+F3、Ctrl+G/Ctrl+Shift+G', () => {
  assert.strictEqual(matchShortcut(mk('f', { control: true })), ACTION.FIND);
  assert.strictEqual(matchShortcut(mk('F3')), ACTION.FIND_NEXT);
  assert.strictEqual(matchShortcut(mk('F3', { shift: true })), ACTION.FIND_PREV);
  assert.strictEqual(matchShortcut(mk('g', { control: true })), ACTION.FIND_NEXT);
  assert.strictEqual(matchShortcut(mk('g', { control: true, shift: true })), ACTION.FIND_PREV);
});

test('下载 / 打印 / 源码 / 打开文件 / 历史', () => {
  assert.strictEqual(matchShortcut(mk('j', { control: true })), ACTION.OPEN_DOWNLOADS);
  assert.strictEqual(matchShortcut(mk('p', { control: true })), ACTION.PRINT);
  assert.strictEqual(matchShortcut(mk('u', { control: true })), ACTION.VIEW_SOURCE);
  assert.strictEqual(matchShortcut(mk('o', { control: true })), ACTION.OPEN_FILE);
  assert.strictEqual(matchShortcut(mk('h', { control: true })), ACTION.OPEN_HISTORY);
});

test('Alt+Home 回主页（不校验 ctrl/shift）', () => {
  assert.strictEqual(matchShortcut(mk('Home', { alt: true })), ACTION.GO_HOME);
  assert.strictEqual(matchShortcut(mk('Home')), null);
});

test('刷新：Ctrl+R / Ctrl+Shift+R / F5 / Shift+F5（F5 不校验 ctrl）', () => {
  assert.strictEqual(matchShortcut(mk('r', { control: true })), ACTION.RELOAD);
  assert.strictEqual(matchShortcut(mk('r', { control: true, shift: true })), ACTION.RELOAD_BYPASSING_CACHE);
  assert.strictEqual(matchShortcut(mk('F5')), ACTION.RELOAD);
  assert.strictEqual(matchShortcut(mk('F5', { shift: true })), ACTION.RELOAD_BYPASSING_CACHE);
  assert.strictEqual(matchShortcut(mk('F5', { control: true })), ACTION.RELOAD);
});

test('F12 与 Esc 不校验任何修饰（与原 input.key 直判一致）', () => {
  assert.strictEqual(matchShortcut(mk('F12')), ACTION.TOGGLE_DEVTOOLS);
  assert.strictEqual(matchShortcut(mk('F12', { control: true, shift: true, alt: true })), ACTION.TOGGLE_DEVTOOLS);
  assert.strictEqual(matchShortcut(mk('Escape')), ACTION.EXIT_FULLSCREEN);
  assert.strictEqual(matchShortcut(mk('Escape', { control: true, shift: true })), ACTION.EXIT_FULLSCREEN);
});

test('Shift+Esc 打开任务管理器；纯 Esc / Ctrl+Shift+Esc 仍是退出全屏', () => {
  assert.strictEqual(matchShortcut(mk('Escape', { shift: true })), ACTION.OPEN_TASK_MANAGER);
  assert.strictEqual(matchShortcut(mk('Escape', { shift: true, alt: false })), ACTION.OPEN_TASK_MANAGER);
  // 纯 Esc（无 shift）不命中任务管理器。
  assert.strictEqual(matchShortcut(mk('Escape')), ACTION.EXIT_FULLSCREEN);
  // 带 ctrl/meta/alt 的 Shift+Esc 不劫持：Ctrl+Shift+Esc 落回退出全屏。
  assert.strictEqual(matchShortcut(mk('Escape', { control: true, shift: true })), ACTION.EXIT_FULLSCREEN);
  assert.strictEqual(matchShortcut(mk('Escape', { meta: true, shift: true })), ACTION.EXIT_FULLSCREEN);
  assert.strictEqual(matchShortcut(mk('Escape', { shift: true, alt: true })), ACTION.EXIT_FULLSCREEN);
  assert.strictEqual(describeAccelerator(ACTION.OPEN_TASK_MANAGER), 'Shift+Esc');
});

test('缩放三连', () => {
  assert.strictEqual(matchShortcut(mk('=', { control: true })), ACTION.ZOOM_IN);
  assert.strictEqual(matchShortcut(mk('-', { control: true })), ACTION.ZOOM_OUT);
  assert.strictEqual(matchShortcut(mk('0', { control: true })), ACTION.ZOOM_RESET);
});

test('Alt+方向键前进后退', () => {
  assert.strictEqual(matchShortcut(mk('ArrowLeft', { alt: true })), ACTION.BACK);
  assert.strictEqual(matchShortcut(mk('ArrowRight', { alt: true })), ACTION.FORWARD);
  assert.strictEqual(matchShortcut(mk('ArrowLeft')), null);
});

test('Ctrl+Shift+Delete 清除数据', () => {
  assert.strictEqual(matchShortcut(mk('Delete', { control: true, shift: true })), ACTION.CLEAR_BROWSING_DATA);
  assert.strictEqual(matchShortcut(mk('Delete', { control: true })), null);
});

test('meta（Command）与 control 等价', () => {
  assert.strictEqual(matchShortcut(mk('t', { meta: true })), ACTION.NEW_TAB);
  assert.strictEqual(matchShortcut(mk('w', { meta: true })), ACTION.CLOSE_TAB);
});

test('非 keyDown、空输入、未绑定键返回 null', () => {
  assert.strictEqual(matchShortcut(mk('t', { control: true, type: 'keyUp' })), null);
  assert.strictEqual(matchShortcut(null), null);
  assert.strictEqual(matchShortcut(mk('q', { control: true })), null);
  assert.strictEqual(matchShortcut(mk('a')), null);
});

test('规则表无重复 action+键 的同序歧义（表本身结构合法）', () => {
  for (const rule of SHORTCUT_RULES) {
    assert.ok(typeof rule.key === 'string' && rule.key.length > 0);
    assert.ok(Object.values(ACTION).includes(rule.action));
    for (const m of ['ctrl', 'shift', 'alt']) {
      assert.ok(rule[m] === true || rule[m] === false || rule[m] === null);
    }
  }
});

test('ruleMatches 对错误键名直接返回 false', () => {
  const rule = { action: ACTION.NEW_TAB, key: 't', ctrl: true, shift: false, alt: null };
  assert.strictEqual(ruleMatches(mk('t', { control: true }), 'x', rule), false);
  assert.strictEqual(ruleMatches(mk('t', { control: true }), 't', rule), true);
});
