const test = require('node:test');
const assert = require('node:assert');
const posture = require('./securityposture');

test('scorePosture gives top grade for a hardened profile', () => {
  const report = posture.scorePosture({
    httpsOnly: true,
    blockRules: 12,
    cspReports: 0,
    certExceptions: 0,
    riskyOrigins: 0,
    criticalEvents: 0,
    headerGrades: { A: 3, B: 1 },
    expiredGrants: 0,
  });
  assert.strictEqual(report.score, 100);
  assert.strictEqual(report.grade, 'A');
  assert.strictEqual(report.findings.length, 0);
  assert.ok(posture.describePosture(report).includes('未发现需要处理的问题'));
});

test('scorePosture penalises https-only disabled', () => {
  const report = posture.scorePosture({ httpsOnly: false, blockRules: 5 });
  assert.strictEqual(report.score, 72);
  assert.strictEqual(report.grade, 'C');
  assert.strictEqual(posture.worstSeverity(report), 'high');
});

test('scorePosture flags cert exceptions and risky origins', () => {
  const report = posture.scorePosture({
    httpsOnly: true,
    blockRules: 3,
    certExceptions: 2,
    riskyOrigins: 1,
  });
  assert.strictEqual(report.findings.length, 2);
  assert.ok(report.findings.every((f) => f.severity === 'high'));
  assert.strictEqual(report.score, 64);
});

test('scorePosture clamps and floors at zero', () => {
  const report = posture.scorePosture({
    httpsOnly: false,
    certExceptions: 9,
    riskyOrigins: 9,
    criticalEvents: 9,
    cspReports: 30,
    headerGrades: { F: 10 },
    blockRules: 0,
    expiredGrants: 9,
  });
  assert.strictEqual(report.score, 0);
  assert.strictEqual(report.grade, 'F');
});

test('scorePosture handles empty and malformed input', () => {
  const report = posture.scorePosture();
  assert.ok(report.score <= 100);
  assert.ok(report.findings.length >= 2);
  const bad = posture.scorePosture({ blockRules: -5, cspReports: 'x', headerGrades: null });
  assert.strictEqual(bad.summary.blockRules, 0);
  assert.strictEqual(bad.summary.cspReports, 0);
  assert.strictEqual(bad.summary.weakHeaderSites, 0);
});

test('scorePosture counts weak header grades deterministically', () => {
  const report = posture.scorePosture({ httpsOnly: true, blockRules: 1, headerGrades: { A: 2, C: 1, F: 2 } });
  assert.strictEqual(report.summary.weakHeaderSites, 3);
  assert.strictEqual(report.findings.length, 1);
  assert.strictEqual(report.findings[0].id, 'weak-headers');
});

test('describePosture tolerates missing report', () => {
  assert.strictEqual(posture.describePosture(null), '安全态势不可用');
  assert.strictEqual(posture.worstSeverity({}), 'none');
});

test('gradeForScore boundaries are reflected through scorePosture', () => {
  const c = posture.scorePosture({ httpsOnly: true, blockRules: 1, certExceptions: 3, riskyOrigins: 1 });
  assert.strictEqual(c.score, 64);
  assert.strictEqual(c.grade, 'C');
  const d = posture.scorePosture({ httpsOnly: true, blockRules: 0, certExceptions: 2, riskyOrigins: 1, cspReports: 6, headerGrades: { D: 4 } });
  assert.strictEqual(d.grade, 'D');
  assert.ok(posture.worstSeverity(d) === 'high');
});

test('scorePosture reports expired grants without other penalties', () => {
  const report = posture.scorePosture({ httpsOnly: true, blockRules: 2, expiredGrants: 4 });
  assert.strictEqual(report.score, 96);
  assert.strictEqual(report.findings[0].id, 'expired-grants');
  assert.strictEqual(report.findings[0].severity, 'low');
});

test('scorePosture ignores unknown header grade keys', () => {
  const report = posture.scorePosture({ httpsOnly: true, blockRules: 1, headerGrades: { A: 1, Z: 9 } });
  assert.strictEqual(report.summary.weakHeaderSites, 9);
  assert.strictEqual(report.findings.length, 1);
});
