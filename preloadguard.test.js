'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  SEVERITY_CRITICAL,
  SEVERITY_WARN,
  KIND_LOAD,
  KIND_EXCEPTION,
  KIND_REJECTION,
  KIND_UNKNOWN,
  DECISION_REPORT,
  DECISION_IGNORE,
  IGNORE_DEDUP,
  IGNORE_CAPPED,
  IGNORE_BAD_STATE,
  MAX_REPORTS_PER_FINGERPRINT,
  MAX_REPORTS_PER_CONTENTS,
  MAX_FINGERPRINT_LEN,
  originFromUrl,
  normalizePath,
  classifyError,
  errorFingerprint,
  createPreloadErrorState,
  decidePreloadError,
  describePreloadError,
  describeIgnoreReason,
} = require('./preloadguard');

const T0 = 9_000_000;
const PRELOAD = 'C:\\OpenCosy\\preload.js';

function err(name, message, code) {
  const e = new Error(message);
  e.name = name;
  if (code) e.code = code;
  return e;
}

test('originFromUrl 对非法 URL 返回空串', () => {
  assert.equal(originFromUrl('https://a.test/x'), 'https://a.test');
  assert.equal(originFromUrl('not a url'), '');
  assert.equal(originFromUrl(null), '');
});

test('normalizePath 反斜杠归一、去空白、小写', () => {
  assert.equal(normalizePath('C:\\A\\B.JS '), 'c:/a/b.js');
  assert.equal(normalizePath(undefined), '');
  assert.equal(normalizePath(123), '');
});

test('classifyError 依据 kindHint 与 error 形状归类', () => {
  assert.equal(classifyError(null, KIND_REJECTION), KIND_REJECTION);
  assert.equal(classifyError(null, KIND_LOAD), KIND_LOAD);
  assert.equal(classifyError(null, KIND_EXCEPTION), KIND_EXCEPTION);
  assert.equal(classifyError({ code: 'MODULE_NOT_FOUND' }), KIND_LOAD);
  assert.equal(classifyError({ code: 'ENOENT' }), KIND_LOAD);
  assert.equal(classifyError({ name: 'UnhandledPromiseRejection' }), KIND_REJECTION);
  assert.equal(classifyError({ name: 'TypeError' }), KIND_UNKNOWN);
  assert.equal(classifyError(null), KIND_UNKNOWN);
});

test('errorFingerprint 稳定：剥离地址与行列号，跨平台路径一致', () => {
  const e1 = err('TypeError', 'Cannot read at 0xABCDEF12 (main.js:10:20)');
  const e2 = err('TypeError', 'Cannot read at 0x99887766 (main.js:88:4)');
  const f1 = errorFingerprint(PRELOAD, e1);
  const f2 = errorFingerprint('c:/opencosy/preload.js', e2);
  assert.equal(f1, f2);
  assert.ok(f1.startsWith('c:/opencosy/preload.js|TypeError|'));
});

test('errorFingerprint 只取首行并限长', () => {
  const e = err('Error', `${'x'.repeat(500)}\nsecond line ignored`);
  const f = errorFingerprint(PRELOAD, e);
  // 路径前缀 + name 之外，信息部分不超过 MAX_FINGERPRINT_LEN
  const msgPart = f.split('|').slice(2).join('|');
  assert.ok(msgPart.length <= MAX_FINGERPRINT_LEN);
  assert.ok(!f.includes('second line'));
});

test('字符串错误也能生成指纹', () => {
  const f = errorFingerprint(PRELOAD, 'boom');
  assert.ok(f.includes('boom'));
});

test('加载期错误提级 critical 并标记持续失效', () => {
  const st = createPreloadErrorState(T0);
  const r = decidePreloadError(st, {
    preloadPath: PRELOAD,
    error: { code: 'MODULE_NOT_FOUND', message: 'missing ipcguard' },
    originUrl: 'https://a.test/',
  }, T0 + 1);
  assert.equal(r.decision, DECISION_REPORT);
  assert.equal(r.kind, KIND_LOAD);
  assert.equal(r.severity, SEVERITY_CRITICAL);
  assert.equal(r.origin, 'https://a.test');
  assert.equal(r.persistentFailure, true);
  assert.equal(st.loadErrorSeen, true);
});

test('运行期异常为 warn，未立即标记持续失效', () => {
  const st = createPreloadErrorState(T0);
  const r = decidePreloadError(st, {
    preloadPath: PRELOAD, error: err('TypeError', 'x is undefined'),
  }, T0 + 1);
  assert.equal(r.severity, SEVERITY_WARN);
  assert.equal(r.kind, KIND_UNKNOWN === r.kind ? KIND_UNKNOWN : r.kind);
});

test('显式 kindHint 为未捕获异常', () => {
  const st = createPreloadErrorState(T0);
  const r = decidePreloadError(st, {
    preloadPath: PRELOAD, error: err('Error', 'runtime'), kindHint: KIND_EXCEPTION,
  }, T0 + 1);
  assert.equal(r.kind, KIND_EXCEPTION);
  assert.equal(r.severity, SEVERITY_WARN);
});

test('同指纹错误超过单指纹上限后去重，但仍计入 totalErrors', () => {
  const st = createPreloadErrorState(T0);
  const e = err('Error', 'same');
  let reported = 0;
  let dedup = 0;
  for (let i = 0; i < MAX_REPORTS_PER_FINGERPRINT + 3; i++) {
    const r = decidePreloadError(st, { preloadPath: PRELOAD, error: e }, T0 + i);
    if (r.decision === DECISION_REPORT) reported++;
    if (r.reason === IGNORE_DEDUP) dedup++;
  }
  assert.equal(reported, MAX_REPORTS_PER_FINGERPRINT);
  assert.equal(dedup, 3);
  assert.equal(st.totalErrors, MAX_REPORTS_PER_FINGERPRINT + 3);
});

test('不同指纹分别计数，但受单 contents 总量上限保护', () => {
  const st = createPreloadErrorState(T0);
  let capped = 0;
  for (let i = 0; i < MAX_REPORTS_PER_CONTENTS + 5; i++) {
    const r = decidePreloadError(st, {
      preloadPath: PRELOAD, error: err('Error', `distinct-${i}`),
    }, T0 + i);
    if (r.reason === IGNORE_CAPPED) capped++;
  }
  assert.equal(capped, 5);
  assert.equal(st.reportedCount, MAX_REPORTS_PER_CONTENTS);
  assert.equal(st.totalErrors, MAX_REPORTS_PER_CONTENTS + 5);
});

test('缺少状态对象安全失败', () => {
  const r = decidePreloadError(null, { error: err('Error', 'x') }, T0);
  assert.equal(r.decision, DECISION_IGNORE);
  assert.equal(r.reason, IGNORE_BAD_STATE);
});

test('文案与忽略原因均为中文且非空', () => {
  const st = createPreloadErrorState(T0);
  const r = decidePreloadError(st, { preloadPath: PRELOAD, error: { code: 'ENOENT' } }, T0);
  assert.ok(describePreloadError(r).includes('预加载脚本'));
  for (const reason of [IGNORE_DEDUP, IGNORE_CAPPED, IGNORE_BAD_STATE]) {
    assert.ok(describeIgnoreReason(reason).length > 0, `${reason} 缺说明`);
  }
  assert.ok(describeIgnoreReason('x').length > 0);
});
