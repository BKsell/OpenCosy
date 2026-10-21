'use strict';

// formautofillguard.test.js —— 覆盖按源精确绑定、跨源/非 https action、
// 非安全上下文、隐藏密码框、无手势降级手动、可疑信号与凭据索引隔离。

const test = require('node:test');
const assert = require('node:assert/strict');
const fg = require('./formautofillguard');
const {
  originKey, originsEqual, analyzeForm, decideFill, decideSave, CredentialIndex, FILL,
} = fg;

const loginForm = (over) => Object.assign({
  pageOrigin: 'https://bank.example.com',
  action: 'https://bank.example.com/login',
  method: 'POST',
  isSecureContext: true,
  hasUserGesture: true,
  fields: [
    { type: 'text', name: 'username', autocomplete: 'username', visible: true, editable: true },
    { type: 'password', name: 'password', autocomplete: 'current-password', visible: true, editable: true },
  ],
}, over || {});

const cred = (over) => Object.assign({ id: 'c1', origin: 'https://bank.example.com', username: 'alice' }, over || {});

test('originKey 归一', () => {
  assert.equal(originKey('https://Bank.Example.com'), 'https://bank.example.com');
  assert.equal(originKey('https://bank.example.com:443'), 'https://bank.example.com');
  assert.equal(originKey('http://bank.example.com:80'), 'http://bank.example.com');
  assert.equal(originKey('https://bank.example.com:8443'), 'https://bank.example.com:8443');
  assert.equal(originKey('not-a-url'), '');
});

test('精确同源判定，后缀模糊不通过', () => {
  assert.equal(originsEqual('https://bank.example.com', 'https://bank.example.com'), true);
  assert.equal(originsEqual('https://bank.example.com', 'https://bank.example.com.evil.net'), false);
  assert.equal(originsEqual('https://bank.example.com', 'http://bank.example.com'), false);
});

test('正常登录表单允许填充', () => {
  const d = decideFill(cred(), loginForm());
  assert.equal(d.decision, FILL.ALLOW);
});

test('http 页面拒绝填充 https 保存的凭据', () => {
  const d = decideFill(cred({ origin: 'https://bank.example.com' }), loginForm({
    pageOrigin: 'http://bank.example.com', action: 'http://bank.example.com/login', isSecureContext: false,
  }));
  assert.equal(d.decision, FILL.DENY);
  assert.ok(d.signals.includes('insecure-context'));
});

test('凭据来源与页面不同源拒绝', () => {
  const d = decideFill(cred({ origin: 'https://other.example.com' }), loginForm());
  assert.equal(d.decision, FILL.DENY);
  assert.equal(d.reason, 'credential-origin-mismatch');
});

test('表单 action 跨源提交拒绝', () => {
  const d = decideFill(cred(), loginForm({ action: 'https://collector.evil.net/steal' }));
  assert.equal(d.decision, FILL.DENY);
  assert.equal(d.reason, 'action-cross-origin');
});

test('action 为 http 拒绝', () => {
  const d = decideFill(cred(), loginForm({ action: 'http://bank.example.com/login' }));
  assert.equal(d.decision, FILL.DENY);
  assert.ok(d.signals.includes('action-insecure-scheme'));
});

test('无密码字段拒绝', () => {
  const d = decideFill(cred(), loginForm({ fields: [{ type: 'text', name: 'q' }] }));
  assert.equal(d.decision, FILL.DENY);
  assert.equal(d.reason, 'no-password-field');
});

test('隐藏密码框拒绝', () => {
  const d = decideFill(cred(), loginForm({
    fields: [
      { type: 'text', name: 'u' },
      { type: 'password', name: 'p', visible: false, editable: true },
    ],
  }));
  assert.equal(d.decision, FILL.DENY);
  assert.equal(d.reason, 'hidden-password-field');
});

test('无用户手势降级手动，不静默预填', () => {
  const d = decideFill(cred(), loginForm({ hasUserGesture: false }));
  assert.equal(d.decision, FILL.MANUAL);
  assert.equal(d.reason, 'requires-user-selection');
});

test('多个密码框或 autocomplete=off 降级手动', () => {
  const many = loginForm({
    fields: [
      { type: 'password', name: 'p1', autocomplete: 'on', visible: true, editable: true },
      { type: 'password', name: 'p2', autocomplete: 'on', visible: true, editable: true },
      { type: 'password', name: 'p3', autocomplete: 'on', visible: true, editable: true },
    ],
  });
  assert.equal(decideFill(cred(), many).decision, FILL.MANUAL);
  const off = loginForm({
    fields: [{ type: 'password', name: 'p', autocomplete: 'off', visible: true, editable: true }],
  });
  assert.equal(decideFill(cred(), off).decision, FILL.MANUAL);
});

test('隐藏的秘钥命名字段触发信号', () => {
  const s = analyzeForm(loginForm({
    fields: [
      { type: 'hidden', name: 'session_token' },
      { type: 'password', name: 'p', visible: true, editable: true },
    ],
  }));
  assert.ok(s.includes('hidden-secret-named-field'));
});

test('坏凭据拒绝', () => {
  assert.equal(decideFill(null, loginForm()).decision, FILL.DENY);
  assert.equal(decideFill({}, loginForm()).reason, 'bad-credential');
});

test('保存裁决：安全表单允许，跨源/明文拒绝', () => {
  assert.equal(decideSave(loginForm()).allow, true);
  assert.equal(decideSave(loginForm({ isSecureContext: false, pageOrigin: 'http://bank.example.com', action: 'http://bank.example.com/x' })).allow, false);
  assert.equal(decideSave(loginForm({ action: 'https://evil.net/x' })).allow, false);
});

test('凭据索引按源隔离候选', () => {
  const idx = new CredentialIndex();
  idx.add(cred({ id: '1', origin: 'https://a.com', username: 'u1' }));
  idx.add(cred({ id: '2', origin: 'https://a.com', username: 'u2' }));
  idx.add(cred({ id: '3', origin: 'https://b.com', username: 'u3' }));
  const list = idx.candidatesFor('https://a.com');
  assert.equal(list.length, 2);
  assert.equal(idx.candidatesFor('https://b.com').length, 1);
  assert.equal(idx.candidatesFor('https://evil.com').length, 0);
});

test('索引拒绝坏凭据并支持删除/清源', () => {
  const idx = new CredentialIndex();
  assert.equal(idx.add({ origin: 'bad' }), false);
  assert.equal(idx.add({ id: 'x', origin: 'https://a.com' }), true);
  assert.equal(idx.remove('x'), true);
  assert.equal(idx.remove('x'), false);
  idx.add({ id: 'y', origin: 'https://a.com' });
  assert.equal(idx.clearOrigin('https://a.com'), true);
  assert.equal(idx.candidatesFor('https://a.com').length, 0);
});

test('action 缺省视为提交回当前页（同源）', () => {
  const d = decideFill(cred(), loginForm({ action: undefined }));
  assert.equal(d.decision, FILL.ALLOW);
});
