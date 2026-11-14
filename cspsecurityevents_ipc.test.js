'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');
const path = require('path');
const os = require('os');

const stubDir = path.join(os.tmpdir(), 'cosy-sec-ipc-stub');
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === 'electron') return path.join(stubDir, 'electron.js');
  return originalResolve.call(this, request, ...rest);
};
const fs = require('fs');
fs.mkdirSync(stubDir, { recursive: true });
fs.writeFileSync(path.join(stubDir, 'electron.js'),
  "module.exports = { app: { getPath: () => " + JSON.stringify(stubDir) + " } };\n");

const { registerSecurityEventIpc } = require('./cosyipcsettingspanel');
const core = require('./cspsecurityevents_core');

function makeDeps(authorized) {
  const handlers = new Map();
  return {
    handlers,
    ipcMain: { handle: (name, fn) => handlers.set(name, fn) },
    isMainSender: () => authorized,
  };
}

test('未受信 sender 一律拒绝，且不触碰台账', () => {
  const d = makeDeps(false);
  registerSecurityEventIpc(d);
  for (const name of ['security-events-summary', 'security-events-prune', 'security-events-trim', 'security-events-export']) {
    assert.deepStrictEqual(d.handlers.get(name)({}), { success: false });
  }
});

test('summary 默认窗口为 1 小时，非法 sinceMs 回退默认', () => {
  const d = makeDeps(true);
  registerSecurityEventIpc(d);
  core.clearSecurityEvents();
  core.recordSecurityEvent('protocol-blocked', 'warn', 'x');
  const a = d.handlers.get('security-events-summary')({}, {});
  assert.strictEqual(a.success, true);
  assert.strictEqual(a.summary.total, 1);
  const b = d.handlers.get('security-events-summary')({}, { sinceMs: -1 });
  assert.strictEqual(b.summary.total, 1);
  const c = d.handlers.get('security-events-summary')({}, { sinceMs: 'abc' });
  assert.strictEqual(c.summary.total, 1);
});

test('prune/trim 对非法参数返回失败且不改动台账', () => {
  const d = makeDeps(true);
  registerSecurityEventIpc(d);
  core.clearSecurityEvents();
  core.recordSecurityEvent('protocol-blocked', 'warn', 'y');
  assert.deepStrictEqual(d.handlers.get('security-events-prune')({}, { beforeMs: 0 }), { success: false, reason: 'invalid-before' });
  assert.deepStrictEqual(d.handlers.get('security-events-prune')({}, {}), { success: false, reason: 'invalid-before' });
  assert.deepStrictEqual(d.handlers.get('security-events-trim')({}, { maxKeep: -3 }), { success: false, reason: 'invalid-maxkeep' });
  assert.strictEqual(core.securityEvents.length, 1);
});

test('export 透传过滤条件并给出归档结构', () => {
  const d = makeDeps(true);
  registerSecurityEventIpc(d);
  core.clearSecurityEvents();
  core.recordSecurityEvent('protocol-blocked', 'warn', 'z');
  const r = d.handlers.get('security-events-export')({}, { sinceMs: 0, limit: 5 });
  assert.strictEqual(r.success, true);
  assert.strictEqual(r.archive.schema, 'cosy.security-events/v1');
  assert.strictEqual(r.archive.count, 1);
  core.clearSecurityEvents();
});
