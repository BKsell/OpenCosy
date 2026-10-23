'use strict';

// selectionguard.test.js —— 复制劫持、危险 scheme、危险 HTML、禁止复制滥用、跨框读取。

const test = require('node:test');
const assert = require('node:assert/strict');
const sg = require('./selectionguard');
const {
  SelectionGuard, SEL_ALLOW, SEL_DENY, SEL_FORCE_REAL,
  leadingDangerousScheme, textContainsDangerousURL,
  htmlHasDangerousContent, sanitizePlainForClipboard, byteLen,
} = sg;

const context = (over) => Object.assign({
  origin: 'https://docs.example.com',
  isSecureContext: true,
  hasUserGesture: true,
  isTopFrame: true,
}, over || {});

const input = (over) => Object.assign({
  context: context(),
  selectedText: 'hello world',
  overrideText: 'hello world',
  overrideHtml: '',
}, over || {});

test('一致的选区复制允许', () => {
  const g = new SelectionGuard();
  const r = g.evaluateClipboardOverride(input());
  assert.equal(r.decision, SEL_ALLOW);
});

test('良性小尾巴（差异）默认允许', () => {
  const g = new SelectionGuard();
  const r = g.evaluateClipboardOverride(input({
    overrideText: 'hello world\n来自 https://docs.example.com',
  }));
  assert.equal(r.decision, SEL_ALLOW);
});

test('严格策略下覆盖与选区不一致回落真实选区', () => {
  const g = new SelectionGuard();
  g.policy.allowBenignAttribution = false;
  const r = g.evaluateClipboardOverride(input({ overrideText: 'totally different ad' }));
  assert.equal(r.decision, SEL_FORCE_REAL);
  assert.equal(r.reason, 'sel-override-differs-from-selection');
  assert.equal(r.text, 'hello world');
});

test('行首 javascript: 拒绝', () => {
  const g = new SelectionGuard();
  const r = g.evaluateClipboardOverride(input({
    selectedText: 'x', overrideText: 'javascript:alert(1)',
  }));
  assert.equal(r.reason, 'sel-clipboard-dangerous-url');
});

test('多行中混入 javascript: 拒绝', () => {
  const g = new SelectionGuard();
  const r = g.evaluateClipboardOverride(input({
    selectedText: 'x', overrideText: 'normal text\n  javascript:steal()',
  }));
  assert.equal(r.reason, 'sel-clipboard-dangerous-url');
});

test('data:text/html 拒绝', () => {
  const g = new SelectionGuard();
  const r = g.evaluateClipboardOverride(input({
    selectedText: 'x', overrideText: 'see data:text/html,<script>',
  }));
  assert.equal(r.reason, 'sel-clipboard-dangerous-url');
});

test('HTML 含脚本/事件句柄拒绝', () => {
  const g = new SelectionGuard();
  assert.equal(g.evaluateClipboardOverride(input({
    overrideHtml: '<b onclick="x()">hi</b>',
  })).reason, 'sel-clipboard-dangerous-html');
  assert.equal(g.evaluateClipboardOverride(input({
    overrideHtml: '<a href="javascript:x()">x</a>',
  })).reason, 'sel-clipboard-dangerous-html');
  assert.equal(g.evaluateClipboardOverride(input({
    overrideHtml: '<iframe src="x"></iframe>',
  })).reason, 'sel-clipboard-dangerous-html');
});

test('超大剪贴板内容拒绝', () => {
  const g = new SelectionGuard();
  const big = 'a'.repeat(2_000_000);
  assert.equal(g.evaluateClipboardOverride(input({ overrideText: big })).reason, 'sel-payload-too-large');
});

test('非安全上下文/无手势/iframe 拒绝', () => {
  const g = new SelectionGuard();
  assert.equal(g.evaluateClipboardOverride({ context: context({ isSecureContext: false, origin: 'http://x' }) }).decision, SEL_DENY);
  assert.equal(g.evaluateClipboardOverride({ context: context({ hasUserGesture: false }) }).decision, SEL_DENY);
  assert.equal(g.evaluateClipboardOverride({ context: context({ isTopFrame: false }) }).decision, SEL_DENY);
});

test('页面阻断真实选区复制 → 强制写真实选区', () => {
  const g = new SelectionGuard();
  const r = g.onCopyPrevented(context(), true);
  assert.equal(r.decision, SEL_FORCE_REAL);
  assert.equal(r.reason, 'sel-copy-prevented-abusively');
});

test('无选区时阻断复制不强制', () => {
  const g = new SelectionGuard();
  assert.equal(g.onCopyPrevented(context(), false).decision, SEL_ALLOW);
});

test('跨源跨框读取默认拒绝', () => {
  const g = new SelectionGuard();
  assert.equal(g.canReadSelection(context(), false).allowed, false);
  assert.equal(g.canReadSelection(context(), true).allowed, true);
});

test('scheme 检测助手', () => {
  assert.equal(leadingDangerousScheme('  JavaScript:x'), 'javascript:');
  assert.equal(leadingDangerousScheme('https://ok.com'), '');
  assert.equal(textContainsDangerousURL('a\nvbscript:x'), 'vbscript:');
});

test('HTML 检测助手', () => {
  assert.ok(htmlHasDangerousContent('<img src=x onerror=1>'));
  assert.equal(htmlHasDangerousContent('<b>safe</b>'), '');
});

test('纯文本净化移除可执行行', () => {
  const out = sanitizePlainForClipboard('keep\njavascript:bad\nkeep2');
  assert.equal(out, 'keep\nkeep2');
});

test('字节长度', () => {
  assert.equal(byteLen('abc'), 3);
  assert.ok(byteLen('中') >= 2);
});
