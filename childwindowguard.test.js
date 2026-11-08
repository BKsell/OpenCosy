'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./childwindowguard');

test('危险协议首屏一律关闭', () => {
  const bad = [
    'javascript:alert(1)',
    'vbscript:msgbox',
    'data:text/html,<script>alert(1)</script>',
    'file:///C:/Windows/win.ini',
    'blob:https://example.com/uuid',
  ];
  for (const url of bad) {
    const v = g.evaluateChildUrl(url);
    assert.equal(v.grade, g.CHILD_CLOSE, url);
  }
});

test('http/https 与 about:blank 判定为隔离', () => {
  assert.equal(g.evaluateChildUrl('https://a.com/x').grade, g.CHILD_ISOLATE);
  assert.equal(g.evaluateChildUrl('http://a.com').origin, 'http://a.com');
  assert.equal(g.evaluateChildUrl('about:blank').grade, g.CHILD_ISOLATE);
  assert.equal(g.evaluateChildUrl('').grade, g.CHILD_ISOLATE);
});

test('schemeOf 大小写与空白', () => {
  assert.equal(g.schemeOf('  JAVASCRIPT:x'), 'javascript:');
  assert.equal(g.schemeOf('not a url'), '');
  assert.equal(g.schemeOf(42), '');
});

test('安全基线：合规 prefs 通过', () => {
  const ok = g.evaluateWebPreferences({
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
    webSecurity: true,
    webviewTag: false,
  });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.violations, []);
});

test('安全基线：缺字段不误判（沿用默认）', () => {
  assert.equal(g.evaluateWebPreferences({}).ok, true);
  assert.equal(g.evaluateWebPreferences(null).ok, true);
});

test('安全基线：逐项危险配置被识别', () => {
  const cases = [
    { nodeIntegration: true },
    { nodeIntegrationInWorker: true },
    { nodeIntegrationInSubFrames: true },
    { webSecurity: false },
    { allowRunningInsecureContent: true },
    { sandbox: false },
    { contextIsolation: false },
    { webviewTag: true },
    { enableRemoteModule: true },
    { allowpopups: true },
  ];
  for (const prefs of cases) {
    const v = g.evaluateWebPreferences(prefs);
    assert.equal(v.ok, false, JSON.stringify(prefs));
    assert.ok(v.violations.length > 0);
  }
});

test('preload 远程地址 / 非法类型被识别', () => {
  assert.ok(g.evaluateWebPreferences({ preload: 'https://evil.com/p.js' }).violations.includes('preload-remote'));
  assert.ok(g.evaluateWebPreferences({ preload: 123 }).violations.includes('preload'));
  // 本地绝对路径字符串通过形态校验。
  assert.equal(g.evaluateWebPreferences({ preload: 'C:\\app\\preload.js' }).ok, true);
});

test('evaluateChildWindow：危险 URL 关闭', () => {
  const st = g.createChildWindowState(1000);
  const v = g.evaluateChildWindow({ url: 'file:///etc/passwd' }, st, 1000);
  assert.equal(v.action, g.CHILD_CLOSE);
  assert.ok(v.reasons.some(r => r.startsWith('dangerous-scheme')));
});

test('evaluateChildWindow：prefs 提权覆盖 URL 判定直接关闭', () => {
  const st = g.createChildWindowState(1000);
  const v = g.evaluateChildWindow(
    { url: 'https://a.com', prefs: { nodeIntegration: true } }, st, 1000);
  assert.equal(v.action, g.CHILD_CLOSE);
  assert.ok(v.violations.includes('nodeIntegration'));
});

test('evaluateChildWindow：正常 web 子窗隔离保留', () => {
  const st = g.createChildWindowState(1000);
  const v = g.evaluateChildWindow(
    { url: 'https://a.com', prefs: { sandbox: true, contextIsolation: true } }, st, 1000);
  assert.equal(v.action, g.CHILD_ISOLATE);
  assert.equal(v.origin, 'https://a.com');
});

test('短窗超阈进入冷却', () => {
  const st = g.createChildWindowState(0);
  let closed = 0;
  for (let i = 0; i < g.CHILD_BURST_MAX; i++) {
    const r = g.admitChildWindow(st, 10);
    if (r.cooldown) closed += 1;
  }
  const overflow = g.admitChildWindow(st, 10);
  assert.equal(overflow.cooldown, true);
  // 冷却期内持续拒绝。
  assert.equal(g.admitChildWindow(st, 5000).cooldown, true);
  // 冷却结束恢复。
  assert.equal(g.admitChildWindow(st, 10 + g.CHILD_COOLDOWN_MS + 1).cooldown, false);
  assert.equal(closed, 0);
});

test('长窗慢速累积同样触发冷却', () => {
  const st = g.createChildWindowState(0);
  const step = 2000; // 每 2 秒一个，短窗不超，长窗累积
  let cooled = false;
  for (let i = 0; i < g.CHILD_LONG_MAX + 1; i++) {
    if (g.admitChildWindow(st, i * step).cooldown) cooled = true;
  }
  assert.equal(cooled, true);
});

test('总入口在冷却期把正常窗口也关闭', () => {
  const st = g.createChildWindowState(0);
  for (let i = 0; i < g.CHILD_BURST_MAX; i++) {
    g.evaluateChildWindow({ url: 'https://a.com' }, st, 0);
  }
  const v = g.evaluateChildWindow({ url: 'https://a.com' }, st, 10);
  assert.equal(v.action, g.CHILD_CLOSE);
  assert.ok(v.reasons.includes('child-window-flood'));
});
