'use strict';

// csppolicy.test.js —— 解析、缺失指令、unsafe-inline/eval、通配/data、nonce 兼容、
// 重复/未知指令、Report-Only 与评级。

const test = require('node:test');
const assert = require('node:assert/strict');
const csp = require('./csppolicy');
const { parseCsp, analyzeCsp, gradeFor, effectiveScriptSources, FINDING, SEV } = csp;

function ids(result) {
  return result.findings.map((f) => f.id);
}
function has(result, id) {
  return ids(result).includes(id);
}

test('空策略报高危', () => {
  const r = analyzeCsp('', true);
  assert.ok(has(r, FINDING.POLICY_EMPTY));
  assert.equal(gradeFor(r.findings), SEV.HIGH);
});

test('强策略通过', () => {
  const r = analyzeCsp(
    "default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    true,
  );
  assert.equal(has(r, FINDING.SCRIPT_UNSAFE_INLINE), false);
  assert.equal(has(r, FINDING.MISSING_OBJECT_SRC), false);
  assert.equal(gradeFor(r.findings), 'pass');
});

test('script-src unsafe-inline 高危', () => {
  const r = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.ok(has(r, FINDING.SCRIPT_UNSAFE_INLINE));
  assert.equal(gradeFor(r.findings), SEV.HIGH);
});

test('unsafe-inline 与 nonce 共存降级为低危', () => {
  const r = analyzeCsp(
    "script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'",
    true,
  );
  const f = r.findings.find((x) => x.id === FINDING.SCRIPT_UNSAFE_INLINE);
  assert.ok(f);
  assert.equal(f.severity, SEV.LOW);
  assert.ok(has(r, FINDING.NONCE_PRESENT));
});

test('unsafe-eval 高危', () => {
  const r = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.ok(has(r, FINDING.SCRIPT_UNSAFE_EVAL));
});

test('通配与 http(s): 兜底高危', () => {
  const r1 = analyzeCsp("script-src *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'", true);
  assert.ok(has(r1, FINDING.SCRIPT_WILDCARD));
  const r2 = analyzeCsp("script-src https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'", true);
  assert.ok(has(r2, FINDING.SCRIPT_WILDCARD));
});

test('data: 脚本来源高危', () => {
  const r = analyzeCsp("script-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'", true);
  assert.ok(has(r, FINDING.SCRIPT_DATA_SCHEME));
});

test('script-src 缺失回退 default-src', () => {
  const r = analyzeCsp("default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.equal(has(r, FINDING.MISSING_SCRIPT_SRC), false);
  const parsed = parseCsp("default-src 'self'");
  assert.equal(effectiveScriptSources(parsed).fellBack, true);
});

test('两者都缺失高危', () => {
  const r = analyzeCsp("object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.ok(has(r, FINDING.MISSING_SCRIPT_SRC));
});

test('缺失 object-src/base-uri/frame-ancestors 报中危', () => {
  const r = analyzeCsp("default-src 'self'; script-src 'self'", true);
  assert.ok(has(r, FINDING.MISSING_OBJECT_SRC));
  assert.ok(has(r, FINDING.MISSING_BASE_URI));
  assert.ok(has(r, FINDING.MISSING_FRAME_ANCESTORS));
});

test('重复指令检测', () => {
  const r = analyzeCsp("default-src 'self'; default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.ok(has(r, FINDING.DUPLICATE_DIRECTIVE));
});

test('未知指令拼写检测', () => {
  const r = analyzeCsp("defualt-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", true);
  assert.ok(has(r, FINDING.UNKNOWN_DIRECTIVE));
});

test('Report-Only 不强制', () => {
  const r = analyzeCsp(
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    false,
  );
  assert.ok(has(r, FINDING.REPORT_ONLY));
});

test('解析结构正确', () => {
  const p = parseCsp("script-src 'self' https://x.com; img-src *");
  assert.deepEqual(p.directives.get('img-src'), ['*']);
  assert.deepEqual(p.directives.get('script-src'), ["'self'", 'https://x.com']);
});

test('strict-dynamic 识别', () => {
  const r = analyzeCsp("script-src 'nonce-x' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'", true);
  assert.ok(has(r, FINDING.STRICT_DYNAMIC));
});

test('大小写与多余空白容错', () => {
  const r = analyzeCsp("  SCRIPT-SRC   'self'  'UNSAFE-EVAL'  ; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; default-src 'self'", true);
  assert.ok(has(r, FINDING.SCRIPT_UNSAFE_EVAL));
});
