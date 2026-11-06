const test = require('node:test');
const assert = require('node:assert');
const report = require('./permissionriskreport');

function decision(origin, permission, state = 'allow') {
  return { origin, permission, decision: state === 'deny' ? 'deny' : 'allow', updatedAt: 1, state };
}

test('buildPermissionReport ranks risky origins by weighted score', () => {
  const data = report.buildPermissionReport([
    decision('https://a.example', 'geolocation'),
    decision('https://a.example', 'media'),
    decision('https://b.example', 'notifications'),
  ]);
  assert.strictEqual(data.rows.length, 2);
  assert.strictEqual(data.rows[0].origin, 'https://a.example');
  assert.strictEqual(data.rows[0].riskScore, 5);
  assert.strictEqual(data.rows[0].level, 'medium');
  assert.strictEqual(data.totals.allowed, 3);
  assert.strictEqual(data.totals.highRiskOrigins, 0);
});

test('buildPermissionReport marks high risk when score reaches threshold', () => {
  const data = report.buildPermissionReport([
    decision('https://a.example', 'media'),
    decision('https://a.example', 'clipboard-read'),
    decision('https://a.example', 'midiSysex'),
  ]);
  assert.strictEqual(data.rows[0].riskScore, 9);
  assert.strictEqual(data.rows[0].level, 'high');
  assert.strictEqual(data.totals.highRiskOrigins, 1);
  assert.ok(data.rows[0].recommendation.includes('撤销'));
});

test('buildPermissionReport separates denied and expired decisions', () => {
  const data = report.buildPermissionReport([
    decision('https://a.example', 'geolocation', 'deny'),
    decision('https://a.example', 'media', 'expired'),
    decision('https://a.example', 'midi'),
  ]);
  assert.deepStrictEqual(data.rows[0].denied, ['geolocation']);
  assert.deepStrictEqual(data.rows[0].expired, ['media']);
  assert.deepStrictEqual(data.rows[0].allowed, ['midi']);
  assert.strictEqual(data.totals.denied, 1);
  assert.strictEqual(data.totals.expired, 1);
});

test('buildPermissionReport skips malformed entries', () => {
  const data = report.buildPermissionReport([
    null,
    { origin: '', permission: 'media' },
    { origin: 'https://a.example', permission: '' },
    decision('https://ok.example', 'midi'),
  ]);
  assert.strictEqual(data.totals.skipped, 3);
  assert.strictEqual(data.rows.length, 1);
});

test('buildPermissionReport honours row limit', () => {
  const many = [];
  for (let i = 0; i < 10; i += 1) {
    many.push(decision(`https://s${i}.example`, 'media'));
  }
  const data = report.buildPermissionReport(many, { limit: 3 });
  assert.strictEqual(data.rows.length, 3);
  assert.strictEqual(data.truncated, true);
  assert.strictEqual(data.totals.origins, 10);
});

test('buildPermissionReport tolerates non-array input', () => {
  const data = report.buildPermissionReport(undefined);
  assert.strictEqual(data.totals.origins, 0);
  assert.deepStrictEqual(data.rows, []);
  assert.strictEqual(data.truncated, false);
});

test('describePermissionReport summarises high risk origins', () => {
  const data = report.buildPermissionReport([
    decision('https://a.example', 'media'),
    decision('https://a.example', 'clipboard-read'),
    decision('https://b.example', 'notifications'),
  ]);
  const text = report.describePermissionReport(data);
  assert.ok(text.includes('2 个站点'));
  assert.ok(text.includes('https://a.example'));
  assert.strictEqual(report.describePermissionReport(null), '站点权限风险报告不可用');
});

test('describePermissionReport handles clean data', () => {
  const data = report.buildPermissionReport([decision('https://a.example', 'notifications', 'deny')]);
  assert.ok(report.describePermissionReport(data).includes('未发现高危授权'));
  assert.strictEqual(report.needsAttention(data), false);
});

test('topRiskyOrigins and needsAttention behave on empty rows', () => {
  const data = report.buildPermissionReport([decision('https://a.example', 'midi', 'deny')]);
  assert.deepStrictEqual(report.topRiskyOrigins(data), []);
  const risky = report.buildPermissionReport([decision('https://a.example', 'midi'), decision('https://a.example', 'media', 'expired')]);
  assert.strictEqual(report.needsAttention(risky), true);
  assert.deepStrictEqual(report.topRiskyOrigins(risky, 1), ['https://a.example']);
});
