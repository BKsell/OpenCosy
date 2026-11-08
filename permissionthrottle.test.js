'use strict';

// permissionthrottle.test.js —— 覆盖突发限流、手势门、指数退避、持久决策、
// 嵌入收紧、未知权限拒绝、快照恢复。

const test = require('node:test');
const assert = require('node:assert/strict');
const { PermissionThrottle, DECIDE, DEFAULT_POLICY } = require('./permissionthrottle');

function makeThrottle(policy, start = 1_000_000) {
  let t = start;
  const th = new PermissionThrottle(policy, () => t);
  return { th, now: () => t, advance: ms => { t += ms; } };
}

const req = (over) => Object.assign({
  origin: 'https://example.com',
  permission: 'camera',
  hasGesture: true,
  embedded: false,
}, over || {});

test('首次手势请求放行弹窗', () => {
  const { th } = makeThrottle();
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
});

test('高敏权限无手势被静默并退避', () => {
  const { th, now } = makeThrottle();
  const d = th.decide(req({ hasGesture: false }));
  assert.equal(d.decision, DECIDE.SUPPRESS);
  assert.equal(d.reason, 'requires-gesture');
  // 立刻再请求（即便带手势）也处于退避期。
  assert.equal(th.decide(req()).decision, DECIDE.SUPPRESS);
});

test('超过突发阈值后静默', () => {
  const { th } = makeThrottle({ promptBurstLimitGesture: 2 });
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
  assert.equal(th.decide(req()).decision, DECIDE.SUPPRESS);
});

test('窗口滑过后恢复', () => {
  const { th, advance } = makeThrottle({ promptBurstLimitGesture: 1, windowMs: 1000 });
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
  assert.equal(th.decide(req()).decision, DECIDE.SUPPRESS);
  advance(1001);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
});

test('允许后命中持久允许不弹窗', () => {
  const { th } = makeThrottle();
  th.decide(req());
  th.recordResult(req(), 'allow');
  const d = th.decide(req());
  assert.equal(d.decision, DECIDE.ALLOW);
  assert.equal(d.reason, 'sticky-allow');
});

test('拒绝后命中持久拒绝', () => {
  const { th } = makeThrottle();
  th.decide(req());
  th.recordResult(req(), 'block');
  const d = th.decide(req());
  assert.equal(d.decision, DECIDE.BLOCK);
  assert.equal(d.reason, 'sticky-block');
});

test('持久允许过期后重新弹窗', () => {
  const { th, advance } = makeThrottle({ grantTtlMs: 1000 });
  th.decide(req());
  th.recordResult(req(), 'allow');
  assert.equal(th.decide(req()).decision, DECIDE.ALLOW);
  advance(1001);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
});

test('忽略也产生指数退避，封顶', () => {
  const { th, advance } = makeThrottle({
    denyBackoffBaseMs: 100, denyBackoffMaxMs: 800, maxDenyLevel: 3,
  });
  th.decide(req({ hasGesture: false })); // 无手势 -> deny level1
  advance(101);
  th.decide(req({ hasGesture: false })); // level2
  advance(201);
  th.decide(req({ hasGesture: false })); // level3
  // level3 退避 800，100ms 内仍 suppress。
  advance(100);
  assert.equal(th.decide(req()).reason, 'deny-backoff');
  advance(701);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
});

test('嵌入上下文无手势阈值更严', () => {
  const { th } = makeThrottle({ promptBurstLimit: 2, embeddedExtraStrict: true });
  const r = req({ hasGesture: false, embedded: true }); // 阈值降到 1
  assert.equal(th.decide(r).decision, DECIDE.SUPPRESS); // 高敏无手势直接手势拒
  // 换一个不需手势的权限验证嵌入阈值。
  const low = req({ permission: 'persistent-storage', hasGesture: false, embedded: true });
  assert.equal(th.decide(low).decision, DECIDE.PROMPT);
  assert.equal(th.decide(low).decision, DECIDE.SUPPRESS);
});

test('不同权限独立计数', () => {
  const { th } = makeThrottle({ promptBurstLimitGesture: 1 });
  assert.equal(th.decide(req({ permission: 'camera' })).decision, DECIDE.PROMPT);
  assert.equal(th.decide(req({ permission: 'microphone' })).decision, DECIDE.PROMPT);
});

test('未知权限直接拒绝', () => {
  const { th } = makeThrottle();
  assert.equal(th.decide(req({ permission: 'unknown-x' })).decision, DECIDE.BLOCK);
});

test('坏请求拒绝', () => {
  const { th } = makeThrottle();
  assert.equal(th.decide(null).decision, DECIDE.BLOCK);
  assert.equal(th.decide({ origin: '', permission: 'camera' }).decision, DECIDE.BLOCK);
});

test('resetSticky 清除持久决策', () => {
  const { th } = makeThrottle();
  th.decide(req());
  th.recordResult(req(), 'allow');
  assert.equal(th.resetSticky('https://example.com', 'camera'), true);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
  assert.equal(th.resetSticky('https://other.com'), false);
});

test('快照与恢复保持节流/持久状态', () => {
  const a = makeThrottle();
  a.th.decide(req());
  a.th.recordResult(req(), 'allow');
  const data = a.th.snapshot();

  const b = makeThrottle();
  assert.equal(b.th.restore(data), true);
  assert.equal(b.th.decide(req()).decision, DECIDE.ALLOW);
});

test('恢复非法数据不抛异常', () => {
  const { th } = makeThrottle();
  assert.equal(th.restore(null), false);
  assert.equal(th.restore({ buckets: 'x' }), true);
  assert.equal(th.decide(req()).decision, DECIDE.PROMPT);
});

test('默认阈值常量存在', () => {
  assert.ok(DEFAULT_POLICY.promptBurstLimit > 0);
  assert.ok(DEFAULT_POLICY.denyBackoffMaxMs >= DEFAULT_POLICY.denyBackoffBaseMs);
});
