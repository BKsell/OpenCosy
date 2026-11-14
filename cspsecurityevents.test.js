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
