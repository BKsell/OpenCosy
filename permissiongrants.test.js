'use strict';

const test = require('node:test');
const assert = require('node:assert');
const grants = require('./permissiongrants');

const NOW = 1_760_000_000_000;
const DAY = 24 * 60 * 60 * 1000;

function record(decision, ageDays) {
  return { decision, updatedAt: NOW - ageDays * DAY };
}

test('effectiveDecision honors allow and deny', () => {
  assert.strictEqual(grants.effectiveDecision(record('allow', 1), NOW), 'allow');
  assert.strictEqual(grants.effectiveDecision(record('deny', 1), NOW), 'deny');
  assert.strictEqual(grants.effectiveDecision(null, NOW), 'unknown');
  assert.strictEqual(grants.effectiveDecision({ decision: 'maybe' }, NOW), 'unknown');
});

test('effectiveDecision expires stale grants', () => {
  assert.strictEqual(grants.effectiveDecision(record('allow', 40), NOW), 'expired');
  assert.strictEqual(grants.effectiveDecision(record('allow', 29), NOW), 'allow');
  assert.strictEqual(grants.effectiveDecision(record('allow', 3), NOW, 2 * DAY), 'expired');
});

test('normalizeTtl clamps extremes', () => {
  assert.strictEqual(grants.normalizeTtl(0), 60 * 1000);
  assert.strictEqual(grants.normalizeTtl(10 * 365 * DAY), 365 * DAY);
  assert.strictEqual(grants.normalizeTtl(undefined), grants.DEFAULT_TTL_MS);
});

test('pruneExpired drops expired and malformed records only', () => {
  const decisions = {
    'https://a.example media': record('allow', 1),
    'https://a.example geolocation': record('allow', 45),
    'https://b.example notifications': { decision: 'deny' },
    'https://c.example midi': record('deny', 2),
  };
  const out = grants.pruneExpired(decisions, { now: NOW });
  assert.deepStrictEqual(Object.keys(out.decisions).sort(), [
    'https://a.example media',
    'https://c.example midi',
  ]);
  assert.strictEqual(out.removed.length, 2);
});

test('enforceOriginCap removes oldest low-risk allows first', () => {
  const decisions = {
    'https://cap.example media': record('allow', 1),
    'https://cap.example geolocation': record('allow', 2),
    'https://cap.example notifications': record('allow', 3),
    'https://cap.example midi': record('allow', 4),
    'https://cap.example clipboard-read': record('allow', 5),
    'https://other.example media': record('allow', 1),
  };
  const dropped = grants.enforceOriginCap(decisions, 'https://cap.example', {
    now: NOW,
    maxPerOrigin: 3,
  });
  assert.strictEqual(dropped.length, 2);
  assert.ok(dropped.includes('https://cap.example notifications'));
  assert.ok(dropped.includes('https://cap.example midi'));
  assert.ok(!dropped.some((key) => key.startsWith('https://other.example')));
});

test('enforceOriginCap ignores deny and expired entries', () => {
  const decisions = {
    'https://cap.example media': record('deny', 1),
    'https://cap.example geolocation': record('allow', 60),
    'https://cap.example notifications': record('allow', 1),
  };
  assert.deepStrictEqual(grants.enforceOriginCap(decisions, 'https://cap.example', {
    now: NOW,
    maxPerOrigin: 1,
  }), []);
});

test('auditGrants counts states and flags risky origins', () => {
  const decisions = {
    'https://video.example media': record('allow', 2),
    'https://video.example clipboard-read': record('allow', 3),
    'https://video.example geolocation': record('deny', 4),
    'https://map.example geolocation': record('allow', 5),
    'https://old.example media': record('allow', 50),
  };
  const report = grants.auditGrants(decisions, { now: NOW });
  assert.strictEqual(report.total, 5);
  assert.strictEqual(report.allowed, 3);
  assert.strictEqual(report.denied, 1);
  assert.strictEqual(report.expired, 1);
  assert.strictEqual(report.origins, 3);
  assert.strictEqual(report.riskyOrigins.length, 1);
  assert.strictEqual(report.riskyOrigins[0].origin, 'https://video.example');
  assert.strictEqual(report.riskyOrigins[0].weight, 6);
  assert.deepStrictEqual(report.riskyOrigins[0].permissions, ['clipboard-read', 'media']);
});

test('auditGrants reports origins over cap', () => {
  const decisions = {
    'https://cap.example media': record('allow', 1),
    'https://cap.example geolocation': record('allow', 2),
    'https://cap.example notifications': record('allow', 3),
    'https://cap.example midi': record('allow', 4),
    'https://cap.example clipboard-read': record('allow', 5),
  };
  const report = grants.auditGrants(decisions, { now: NOW, maxPerOrigin: 3 });
  assert.strictEqual(report.overCapOrigins.length, 1);
  assert.strictEqual(report.overCapOrigins[0].allows, 5);
});

test('auditGrants of empty store is all zeros', () => {
  const report = grants.auditGrants({}, { now: NOW });
  assert.strictEqual(report.total, 0);
  assert.strictEqual(report.origins, 0);
  assert.strictEqual(report.oldestDays, 0);
});

test('grantKey and splitKey round trip', () => {
  const key = grants.grantKey('https://a.example', 'media');
  assert.strictEqual(key, 'https://a.example media');
  assert.deepStrictEqual(grants.splitKey(key), { origin: 'https://a.example', permission: 'media' });
  assert.strictEqual(grants.grantKey('https://a.example', ''), '');
  assert.strictEqual(grants.splitKey('nonsense'), null);
});

test('summarizeRisk describes report', () => {
  const report = grants.auditGrants({
    'https://a.example media': record('allow', 1),
    'https://a.example geolocation': record('deny', 2),
  }, { now: NOW });
  const text = grants.summarizeRisk(report);
  assert.ok(text.includes('2 条决定'));
  assert.strictEqual(grants.describeGrantState('expired'), '已过期');
  assert.strictEqual(grants.describeGrantState('other'), '状态未知');
});
