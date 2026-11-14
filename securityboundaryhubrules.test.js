'use strict';

const test = require('node:test');
const assert = require('node:assert');
const rules = require('./securityboundaryhubrules_core');

const AREA_FN = {
  'ipc-payload': 'inspectIpcRequest',
  'ipc-reply': 'inspectIpcReply',
  path: 'inspectPathWithin',
  'json-import': 'inspectImportJson',
  download: 'inspectDownloadCandidate',
  'file-magic': 'inspectDownloadedBuffer',
  clipboard: 'sanitizeClipboard',
  secret: 'redactText',
  redirect: 'inspectRedirectHop',
  proxy: 'inspectProxySettings',
  sri: 'inspectIntegrity',
  update: 'inspectUpdateManifest',
  csp: 'inspectCspPolicy',
  mime: 'inspectContentTypeHeader',
  archive: 'inspectArchiveEntries',
  csv: 'sanitizeCsvRows',
  cookie: 'inspectSetCookie',
  encoding: 'inspectContentEncoding',
  svg: 'inspectSvgScript',
  pdf: 'inspectPdfJavaScript',
  'html-text': 'inspectHtmlInjection',
};

test('CHAIN_AREAS 每一类都有对应检查函数', () => {
  assert.strictEqual(rules.CHAIN_AREAS.length, Object.keys(AREA_FN).length);
  for (const area of rules.CHAIN_AREAS) {
    const fn = AREA_FN[area];
    assert.ok(fn, 'area ' + area + ' 未登记检查函数');
    assert.strictEqual(typeof rules[fn], 'function', 'area ' + area + ' 的 ' + fn + ' 未导出');
  }
});

test('跨域 Cookie 在规则链路中被标记', () => {
  const r = rules.inspectSetCookie('sid=1; Domain=evil.example', 'example.com');
  assert.strictEqual(r.area, rules.AREA.COOKIE);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, 'domain-mismatch');
});

test('正常 Cookie 在规则链路中放行', () => {
  const r = rules.inspectSetCookie('sid=1; Path=/; Secure', 'example.com');
  assert.strictEqual(r.area, rules.AREA.COOKIE);
  assert.strictEqual(r.changed, false);
});

test('多重压缩编码在规则链路中被标记', () => {
  const r = rules.inspectContentEncoding({ 'content-encoding': 'gzip, br, deflate', 'content-length': '1024' });
  assert.strictEqual(r.area, rules.AREA.ENCODING);
  assert.strictEqual(r.changed, true);
});

test('SVG 内联事件处理器被标记', () => {
  const r = rules.inspectSvgScript('<svg onload="alert(1)"><rect/></svg>');
  assert.strictEqual(r.area, rules.AREA.SVG);
  assert.strictEqual(r.changed, true);
});

test('PDF 内嵌 JavaScript 被标记', () => {
  const r = rules.inspectPdfJavaScript(Buffer.from('/Type /Catalog /JavaScript 1 0 R'));
  assert.strictEqual(r.area, rules.AREA.PDF);
  assert.strictEqual(r.changed, true);
});

test('HTML 注入片段被标记', () => {
  const r = rules.inspectHtmlInjection('<img src=x onerror=alert(1)>');
  assert.strictEqual(r.area, rules.AREA.HTML_TEXT);
  assert.strictEqual(r.changed, true);
});

test('纯文本 HTML 放行', () => {
  const r = rules.inspectHtmlInjection('hello world');
  assert.strictEqual(r.changed, false);
});
