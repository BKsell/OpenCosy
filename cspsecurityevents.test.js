'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

// cspsecurityevents_core 依赖 electron.app 来定位 userData；测试里注入一个
// 纯内存 stub，避免在 CI / 无 Electron 环境下 require 直接失败。
const stubPath = path.join(os.tmpdir(), '__cosy_electron_stub__.js');
const stubExports = {
  app: { getPath: () => path.join(os.tmpdir(), 'cosy-sec-events-test') },
  ipcMain: { handle() {}, on() {} },
};
require.cache[stubPath] = { id: stubPath, filename: stubPath, loaded: true, exports: stubExports };
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'electron') return stubPath;
  return origResolve.call(this, request, ...rest);
};

function test(name, fn) {
  try {
    fn();
    console.log('ok - ' + name);
  } catch (err) {
    console.error('FAIL - ' + name + ': ' + ((err && err.stack) || err));
    process.exitCode = 1;
  }
}

const se = require('./cspsecurityevents_core');
const storeDir = path.join(os.tmpdir(), 'cosy-sec-events-test');
fs.mkdirSync(storeDir, { recursive: true });
if (fs.existsSync(se.securityEventStorePath)) fs.unlinkSync(se.securityEventStorePath);

test('未登记的类型必须被静默丢弃', () => {
  const before = se.securityEvents.length;
  se.recordSecurityEvent('not-a-real-type', 'warn', 'x');
  assert.strictEqual(se.securityEvents.length, before);
});

test('非法 severity 必须被丢弃', () => {
  const before = se.securityEvents.length;
  se.recordSecurityEvent('protocol-blocked', 'error', 'x');
  assert.strictEqual(se.securityEvents.length, before);
});

test('合法事件写入并可被 listSecurityEvents 读回', () => {
  se.recordSecurityEvent('protocol-blocked', 'warn', 'msteams://open');
  const items = se.listSecurityEvents('', 10);
  assert.strictEqual(items.length, 1);
  assert.strictEqual(items[0].type, 'protocol-blocked');
  assert.strictEqual(items[0].severity, 'warn');
});

test('detail 脱敏覆盖 URL userinfo 与查询串凭据', () => {
  const s = se.sanitizeSecurityDetail('https://alice:s3cr3t@example.com/a?token=abc123&x=1');
  assert.ok(!s.includes('s3cr3t'), 'userinfo 未脱敏');
  assert.ok(!s.includes('abc123'), 'query token 未脱敏');
  assert.ok(s.includes('[REDACTED]'));
});

test('detail 脱敏覆盖 Authorization 认证头', () => {
  const s = se.sanitizeSecurityDetail('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig');
  assert.ok(!s.includes('eyJhbGciOiJIUzI1NiJ9'), 'Bearer 凭据未脱敏');
  assert.ok(s.includes('[REDACTED]'));
});

test('容量上限为 1000，超出时保留最新事件', () => {
  se.clearSecurityEvents();
  for (let i = 0; i < se.MAX_SECURITY_EVENTS + 50; i++) {
    se.recordSecurityEvent('protocol-blocked', 'info', 'e' + i);
  }
  assert.strictEqual(se.securityEvents.length, se.MAX_SECURITY_EVENTS);
  const newest = se.listSecurityEvents('', 1)[0];
  assert.ok(newest.detail.endsWith(String(se.MAX_SECURITY_EVENTS + 49)));
});

test('summarizeSecurityEvents 按类型与严重级聚合', () => {
  se.clearSecurityEvents();
  se.recordSecurityEvent('protocol-blocked', 'warn', 'a');
  se.recordSecurityEvent('protocol-blocked', 'critical', 'b');
  se.recordSecurityEvent('download-quota', 'info', 'c');
  const sum = se.summarizeSecurityEvents(60000);
  assert.strictEqual(sum.total, 3);
  assert.strictEqual(sum.byType['protocol-blocked'], 2);
  assert.strictEqual(sum.byType['download-quota'], 1);
  assert.strictEqual(sum.bySeverity.critical, 1);
  assert.strictEqual(sum.bySeverity.warn, 1);
  assert.ok(sum.lastTime >= sum.firstTime);
});

test('重启加载时保留末尾（最新）1000 条而不是最旧的', () => {
  const total = se.MAX_SECURITY_EVENTS + 200;
  const events = [];
  for (let i = 0; i < total; i++) {
    events.push({ id: 'i' + i, time: 1000 + i, type: 'protocol-blocked', severity: 'info', origin: '', detail: 'd' + i });
  }
  fs.mkdirSync(path.dirname(se.securityEventStorePath), { recursive: true });
  fs.writeFileSync(se.securityEventStorePath, JSON.stringify({ version: 1, events }));
  delete require.cache[require.resolve('./cspsecurityevents_core')];
  const reloaded = require('./cspsecurityevents_core');
  reloaded.loadSecurityEvents();
  assert.strictEqual(reloaded.securityEvents.length, reloaded.MAX_SECURITY_EVENTS);
  assert.strictEqual(reloaded.securityEvents[0].detail, 'd' + (total - reloaded.MAX_SECURITY_EVENTS));
  const last = reloaded.securityEvents[reloaded.securityEvents.length - 1];
  assert.strictEqual(last.detail, 'd' + (total - 1));
  if (fs.existsSync(se.securityEventStorePath)) fs.unlinkSync(se.securityEventStorePath);
});

test('clearSecurityEvents 清空内存与落盘', () => {
  const s = require('./cspsecurityevents_core');
  s.recordSecurityEvent('protocol-blocked', 'info', 'to-clear');
  s.clearSecurityEvents();
  assert.strictEqual(s.securityEvents.length, 0);
});

test('listSecurityEvents 支持按严重级过滤且不影响类型过滤', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'critical', 'c1');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'w1');
  s.recordSecurityEvent('download-quota', 'critical', 'c2');
  const crit = s.listSecurityEvents('', 200, 'critical');
  assert.strictEqual(crit.length, 2);
  assert.ok(crit.every(e => e.severity === 'critical'));
  const both = s.listSecurityEvents('protocol-blocked', 200, 'critical');
  assert.strictEqual(both.length, 1);
  assert.strictEqual(both[0].detail, 'c1');
  const bad = s.listSecurityEvents('', 200, 'nope');
  assert.strictEqual(bad.length, 3);
  s.clearSecurityEvents();
});

test('summarizeSecurityEvents 按 origin 聚合', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'warn', 'x', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'y', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'info', 'z', 'https://b.example');
  s.recordSecurityEvent('protocol-blocked', 'info', 'z2', '');
  const sum = s.summarizeSecurityEvents(0);
  assert.strictEqual(sum.byOrigin['https://a.example'], 2);
  assert.strictEqual(sum.byOrigin['https://b.example'], 1);
  assert.strictEqual(sum.byOrigin['(unknown)'], 1);
  s.clearSecurityEvents();
});

test('pruneSecurityEvents 按时间删除旧事件并落盘', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'info', 'old1');
  s.recordSecurityEvent('protocol-blocked', 'info', 'old2');
  s.recordSecurityEvent('protocol-blocked', 'info', 'new1');
  s.securityEvents[0].time = 1000;
  s.securityEvents[1].time = 1001;
  const removed = s.pruneSecurityEvents(1500);
  assert.strictEqual(removed, 2);
  assert.strictEqual(s.securityEvents.length, 1);
  assert.strictEqual(s.securityEvents[0].detail, 'new1');
  assert.strictEqual(s.pruneSecurityEvents(0), 0);
  assert.strictEqual(s.pruneSecurityEvents(Number.NaN), 0);
  s.clearSecurityEvents();
});

test('exportSecurityEvents 输出可归档结构且过滤生效', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'warn', 'e1', 'https://a.example');
  s.recordSecurityEvent('download-quota', 'critical', 'e2');
  const out = s.exportSecurityEvents({});
  assert.strictEqual(out.schema, 'cosy.security-events/v1');
  assert.strictEqual(out.count, 2);
  assert.strictEqual(out.events.length, 2);
  assert.ok(out.events[0].time <= out.events[1].time);
  assert.ok(out.summary.total >= 2);
  const crit = s.exportSecurityEvents({ severity: 'critical' });
  assert.strictEqual(crit.count, 1);
  assert.strictEqual(crit.events[0].detail, 'e2');
  const limited = s.exportSecurityEvents({ limit: 1 });
  assert.strictEqual(limited.count, 1);
  const nothing = s.exportSecurityEvents({ sinceMs: Date.now() + 60000 });
  assert.strictEqual(nothing.count, 0);
  s.clearSecurityEvents();
});

test('byOrigin/byType 使用无原型对象，origin 为 __proto__ 时不丢计数也不污染原型', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'warn', 'p1', '__proto__');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'p2', 'constructor');
  s.recordSecurityEvent('protocol-blocked', 'info', 'p3', 'https://ok.example');
  const sum = s.summarizeSecurityEvents(0);
  assert.strictEqual(sum.total, 3);
  assert.strictEqual(sum.byOrigin['__proto__'], 1);
  assert.strictEqual(sum.byOrigin.constructor, 1);
  assert.strictEqual(sum.byOrigin['https://ok.example'], 1);
  assert.strictEqual(Object.getPrototypeOf(sum.byOrigin), null);
  assert.strictEqual({}.polluted, undefined);
  s.clearSecurityEvents();
});

test('origin 规范化只保留 scheme 与 host，路径与查询串不落台账', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'warn', 'n1', 'https://a.example/path?token=abc');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'n2', 'https://a.example/other');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'n3', '__proto__');
  assert.strictEqual(s.securityEvents[0].origin, 'https://a.example');
  assert.strictEqual(s.securityEvents[1].origin, 'https://a.example');
  assert.strictEqual(s.securityEvents[2].origin, '__proto__');
  s.clearSecurityEvents();
});

test('listSecurityEvents 支持 offset 分页且不破坏默认行为', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  for (let i = 0; i < 5; i++) s.recordSecurityEvent('protocol-blocked', 'info', 'p' + i);
  const first = s.listSecurityEvents('', 2);
  assert.deepStrictEqual(first.map(e => e.detail), ['p4', 'p3']);
  const second = s.listSecurityEvents('', 2, '', 2);
  assert.deepStrictEqual(second.map(e => e.detail), ['p2', 'p1']);
  const huge = s.listSecurityEvents('', 2, '', 1e9);
  assert.strictEqual(huge.length, 0);
  const neg = s.listSecurityEvents('', 2, '', -5);
  assert.deepStrictEqual(neg.map(e => e.detail), ['p4', 'p3']);
  s.clearSecurityEvents();
});

test('summarizeSecurityEvents 给出站点×严重级交叉计数', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'critical', 'c', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'w', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'w2', 'https://b.example');
  const sum = s.summarizeSecurityEvents(0);
  assert.strictEqual(sum.byOriginSeverity['https://a.example|critical'], 1);
  assert.strictEqual(sum.byOriginSeverity['https://a.example|warn'], 1);
  assert.strictEqual(sum.byOriginSeverity['https://b.example|warn'], 1);
  s.clearSecurityEvents();
});

test('summarizeSecurityEvents 给出最吵站点排行', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  s.recordSecurityEvent('protocol-blocked', 'warn', 'a1', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'a2', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'a3', 'https://a.example');
  s.recordSecurityEvent('protocol-blocked', 'warn', 'b1', 'https://b.example');
  const sum = s.summarizeSecurityEvents(0);
  assert.strictEqual(sum.topOrigins.length, 2);
  assert.deepStrictEqual(sum.topOrigins[0], { origin: 'https://a.example', count: 3 });
  assert.deepStrictEqual(sum.topOrigins[1], { origin: 'https://b.example', count: 1 });
  s.clearSecurityEvents();
});

test('trimSecurityEvents 只保留最近 maxKeep 条并对非法值不动作', () => {
  const s = require('./cspsecurityevents_core');
  s.clearSecurityEvents();
  for (let i = 0; i < 6; i++) s.recordSecurityEvent('protocol-blocked', 'info', 't' + i);
  assert.strictEqual(s.trimSecurityEvents(2), 4);
  assert.deepStrictEqual(s.securityEvents.map(e => e.detail), ['t4', 't5']);
  assert.strictEqual(s.trimSecurityEvents(2), 0);
  assert.strictEqual(s.trimSecurityEvents(0), 0);
  assert.strictEqual(s.trimSecurityEvents(Number.NaN), 0);
  s.clearSecurityEvents();
});
