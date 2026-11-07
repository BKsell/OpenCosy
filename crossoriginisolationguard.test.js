'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./crossoriginisolationguard');

test('默认输出 COOP 与 CORP', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com' });
  assert.strictEqual(r.isolated, false);
  assert.strictEqual(r.headers['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.strictEqual(r.headers['Cross-Origin-Resource-Policy'], 'same-origin');
});

test('需要隔离时强制 COEP', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', requiresIsolation: true });
  assert.strictEqual(r.isolated, true);
  assert.strictEqual(r.headers['Cross-Origin-Embedder-Policy'], 'require-corp');
});

test('缺少 COEP 产生 finding', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', requiresIsolation: true, coep: false });
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.COEP_MISSING));
});

test('unsafe COOP 被纠正为 same-origin', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', coop: 'unsafe-none' });
  assert.strictEqual(r.headers['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.COOP_UNSAFE));
});

test('CORP 过宽被收紧', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', corp: 'cross-origin' });
  assert.strictEqual(r.headers['Cross-Origin-Resource-Policy'], 'same-origin');
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.CORP_TOO_OPEN));
});

test('跨源嵌入被记录', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', requiresIsolation: true, embeds: ['https://cdn.example.org/x'] });
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.CROSS_ORIGIN_EMBED));
});

test('非法 URL 返回 INVALID', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'nope' });
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('隔离状态降级被记录', () => {
  const r = guard.applyCrossOriginIsolationGuard({ url: 'https://a.example.com', previousIsolated: true });
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.ISOLATION_DOWNGRADE));
});

test('批量审计统计隔离页数量', () => {
  const report = guard.auditIsolationBatch([
    { url: 'https://a.example.com', requiresIsolation: true },
    { url: 'https://b.example.com' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.isolated, 1);
});
