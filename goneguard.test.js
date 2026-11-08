'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./goneguard');

test('只有安全协议允许自动重载', () => {
  assert.equal(g.isReloadable('https://example.com/'), true);
  assert.equal(g.isReloadable('http://example.com/'), true);
  assert.equal(g.isReloadable('file:///C:/a.html'), true);
  assert.equal(g.isReloadable('cosy://security'), true);
  assert.equal(g.isReloadable('data:text/html,x'), false);
  assert.equal(g.isReloadable('blob:https://example.com/u'), false);
  assert.equal(g.isReloadable('mailto:a@b.com'), false);
  assert.equal(g.isReloadable(''), false);
});

test('窗口内自动重载次数有上限，超限转错误页并熔断', () => {
  let st = g.createState(0);
  const url = 'https://crash.example/';
  let r;
  r = g.decideReload(st, url, 1000); st = r.state;
  assert.equal(r.action, 'reload');
  r = g.decideReload(st, url, 5000); st = r.state;
  assert.equal(r.action, 'reload');
  // 第三次（默认上限 2）应熔断
  r = g.decideReload(st, url, 9000); st = r.state;
  assert.equal(r.action, 'error-page');
  assert.equal(r.reason, 'rate-limit');
  assert.ok(st.circuitOpenUntil > 9000);
  // 熔断期内再来仍是错误页
  r = g.decideReload(st, url, 10000); st = r.state;
  assert.equal(r.action, 'error-page');
  assert.equal(r.reason, 'circuit-open');
});

test('重载冷却间隔生效', () => {
  let st = g.createState(0);
  let r1 = g.decideReload(st, 'https://a.com/', 1000);
  st = r1.state;
  assert.equal(r1.action, 'reload');
  // 1 秒后又崩，小于默认 3 秒冷却
  const r2 = g.decideReload(st, 'https://a.com/', 2000);
  assert.equal(r2.action, 'error-page');
  assert.equal(r2.reason, 'cooldown');
});

test('窗口滑出后计数复位', () => {
  let st = g.createState(0);
  let r = g.decideReload(st, 'https://a.com/', 0); st = r.state;
  r = g.decideReload(st, 'https://a.com/', 4000); st = r.state;
  assert.equal(r.action, 'reload');
  // 超过 60s 窗口后，旧重载被清出，又允许重载
  r = g.decideReload(st, 'https://a.com/', 70000); st = r.state;
  assert.equal(r.action, 'reload');
  assert.equal(st.reloads.length, 1);
});

test('不可重载上下文崩溃直接错误页', () => {
  let st = g.createState(0);
  const r = g.decideReload(st, 'data:text/html,<script>boom</script>', 1000);
  assert.equal(r.action, 'error-page');
  assert.equal(r.reason, 'not-reloadable');
});

test('无响应提示有冷却去抖', () => {
  let st = g.createState(0);
  const a = g.decideUnresponsive(st, 1000); st = a.state;
  assert.equal(a.notify, true);
  const b = g.decideUnresponsive(st, 2000); st = b.state;
  assert.equal(b.notify, false);
  const c = g.decideUnresponsive(st, 20000); st = c.state;
  assert.equal(c.notify, true);
});

test('稳定一段时间后恢复计数', () => {
  let st = g.createState(0);
  st._windowMs = 60000;
  let r = g.decideReload(st, 'https://a.com/', 1000, { windowMs: 60000 });
  st = r.state;
  st._windowMs = 60000;
  assert.equal(st.consecutiveCrashes, 1);
  g.noteRecovery(st, 90000);
  assert.equal(st.consecutiveCrashes, 0);
  assert.equal(st.circuitOpenUntil, 0);
});

test('异常输入不抛错', () => {
  assert.doesNotThrow(() => g.decideReload(null, null, 0));
  assert.doesNotThrow(() => g.decideUnresponsive(null, 0));
});
