'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./autocompletepolicyguard');

test('普通邮箱字段放行', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'email', name: 'email', autocomplete: 'email' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('密码字段 autocomplete=on 被纠正', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'password', name: 'password', autocomplete: 'on' });
  assert.strictEqual(r.autocomplete, 'off');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.blocked, false);
});

test('密码字段缺省 autocomplete 被纠正', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'password' });
  assert.strictEqual(r.autocomplete, 'off');
});

test('未知 token 被剔除', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'text', name: 'q', autocomplete: 'foo-bar' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.WEAK_AUTOCOMPLETE);
  assert.strictEqual(r.autocomplete, 'off');
});

test('跨站密码字段强制 off', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'password', autocomplete: 'current-password', crossSite: true });
  assert.strictEqual(r.autocomplete, 'off');
});

test('一次性验证码字段纠正为 one-time-code', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'one-time-code', autocomplete: 'off' });
  assert.strictEqual(r.autocomplete, 'one-time-code');
  assert.strictEqual(r.reason, guard.REASON.MISSING_OFF);
});

test('敏感 name 触发纠正', () => {
  const r = guard.applyAutocompletePolicyGuard({ fieldType: 'text', name: 'otp', autocomplete: 'on' });
  assert.strictEqual(r.autocomplete, 'off');
});

test('批量审计统计风险字段数', () => {
  const report = guard.auditAutocompleteBatch([
    { fieldType: 'password', autocomplete: 'on' },
    { fieldType: 'email', name: 'email', autocomplete: 'email' },
    { fieldType: 'text', autocomplete: 'weird' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.risky, 2);
});
