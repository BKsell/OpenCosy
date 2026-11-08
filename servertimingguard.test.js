'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./servertimingguard');

const { REASON, timingAllowOriginIsRisky, evaluateTimingHeaders, applyServerTimingGuard, describeReason } = guard;

nodeTest.test('server timing header is stripped', () => {
  const headers = { 'server-timing': ['db;dur=120', 'app;dur=40'] };
  const result = applyServerTimingGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers['server-timing'], undefined);
  assert.equal(result.findings.length, 2);
});

nodeTest.test('timing allow origin wildcard is stripped', () => {
  const headers = { 'Timing-Allow-Origin': ['*'] };
  const result = applyServerTimingGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers['Timing-Allow-Origin'], undefined);
});

nodeTest.test('timing allow origin same origin survives', () => {
  const headers = { 'timing-allow-origin': ['https://example.com'] };
  const result = applyServerTimingGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, false);
  assert.deepEqual(headers['timing-allow-origin'], ['https://example.com']);
});

nodeTest.test('timing allow origin foreign origin is risky', () => {
  assert.equal(timingAllowOriginIsRisky('https://evil.example', 'https://example.com'), true);
  assert.equal(timingAllowOriginIsRisky('https://example.com', 'https://example.com'), false);
  assert.equal(timingAllowOriginIsRisky('', 'https://example.com'), false);
});

nodeTest.test('report-to and reporting-endpoints are stripped', () => {
  const headers = {
    'Report-To': ['{"group":"default","max_age":60,"endpoints":[{"url":"https://evil.example"}]}'],
    'Reporting-Endpoints': ['default="https://evil.example/report"'],
  };
  const result = applyServerTimingGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers['Report-To'], undefined);
  assert.equal(headers['Reporting-Endpoints'], undefined);
  assert.equal(result.findings.filter((f) => f.reason === REASON.reportTo).length, 2);
});

nodeTest.test('nel header is stripped', () => {
  const headers = { NEL: ['{"report_to":"default","max_age":3600}'] };
  const result = applyServerTimingGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers.NEL, undefined);
  assert.equal(result.findings[0].reason, REASON.nel);
});

nodeTest.test('clean headers stay untouched', () => {
  const headers = { 'content-type': ['text/html'], 'cache-control': ['no-store'] };
  assert.equal(applyServerTimingGuard(headers, { url: 'https://example.com/' }).changed, false);
});

nodeTest.test('missing details keeps wildcard risky', () => {
  const headers = { 'timing-allow-origin': ['*'] };
  const verdict = evaluateTimingHeaders(headers, {});
  assert.equal(verdict.findings[0].reason, REASON.timingAllowOrigin);
});

nodeTest.test('only risky timing entries trigger changes', () => {
  const headers = { 'timing-allow-origin': ['https://example.com'] };
  const verdict = evaluateTimingHeaders(headers, { url: 'https://example.com/' });
  assert.equal(verdict.changed, false);
  assert.equal(verdict.findings.length, 0);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
