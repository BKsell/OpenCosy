'use strict';

// dragdropguard.test.js —— 覆盖拖放条目分类、危险扩展名、UNC/盘符、协议白名单、
// file:// 解包、控制字符、批量上限与去重。

const test = require('node:test');
const assert = require('node:assert/strict');
const dd = require('./dragdropguard');
const {
  classifyDroppedItem,
  auditDroppedItems,
  permissivePolicy,
  DEFAULT_POLICY,
  isUncPath,
  isDrivePath,
  fileUriToPath,
  extOf,
} = dd;

test('https 链接默认放行', () => {
  const v = classifyDroppedItem({ kind: 'uri', uri: 'https://example.com/a' }, DEFAULT_POLICY);
  assert.equal(v.ok, true);
  assert.equal(v.entry.scheme, 'https:');
});

test('javascript:/data:/vbscript: 链接拒绝', () => {
  for (const uri of [
    'javascript:alert(1)',
    'data:text/html,<script>x</script>',
    'vbscript:msgbox',
    'file:///C:/Windows/win.ini',
  ]) {
    const v = classifyDroppedItem({ kind: 'uri', uri }, DEFAULT_POLICY);
    assert.equal(v.ok, false, uri);
    if (uri.startsWith('file:')) assert.equal(v.reason, 'file-uri-not-allowed');
    else assert.equal(v.reason, 'scheme-not-allowed');
  }
});

test('无 scheme 裸字符串拒绝', () => {
  const v = classifyDroppedItem({ kind: 'uri', uri: 'not a link' }, DEFAULT_POLICY);
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'scheme-missing');
});

test('默认策略拒绝本地文件条目', () => {
  const v = classifyDroppedItem({ kind: 'file', name: 'a.txt', uri: 'C:\\tmp\\a.txt' }, DEFAULT_POLICY);
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'file-not-allowed');
});

test('危险扩展名在宽松策略下仍拒绝', () => {
  const pol = permissivePolicy();
  for (const name of ['evil.exe', 'x.scr', 'a.bat', 'link.lnk', 'p.msi', 'NUL.reg', 'x.LNK']) {
    const v = classifyDroppedItem({ kind: 'file', name, uri: 'C:\\dl\\' + name }, pol);
    assert.equal(v.ok, false, name);
    assert.equal(v.reason, 'dangerous-ext', name);
  }
});

test('白名单外扩展名拒绝，白名单内放行', () => {
  const pol = permissivePolicy();
  const bad = classifyDroppedItem({ kind: 'file', name: 'a.bin', uri: 'D:\\a.bin' }, pol);
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'ext-not-whitelisted');
  const good = classifyDroppedItem({ kind: 'file', name: 'a.png', uri: 'D:\\a.png' }, pol);
  assert.equal(good.ok, true);
});

test('UNC 路径拒绝（防 SMB 凭据外带）', () => {
  assert.equal(isUncPath('\\\\10.0.0.1\\share'), true);
  assert.equal(isUncPath('//evil/x'), true);
  const pol = permissivePolicy();
  const v1 = classifyDroppedItem({ kind: 'file', name: 'x.png', uri: '\\\\srv\\share\\x.png' }, pol);
  assert.equal(v1.ok, false);
  assert.equal(v1.reason, 'unc-path');
  const v2 = classifyDroppedItem({ kind: 'uri', uri: 'file://///srv/share/x.png' }, pol);
  assert.equal(v2.ok, false);
  assert.equal(v2.reason, 'unc-path');
  const v3 = classifyDroppedItem({ kind: 'uri', uri: 'file://srv/share/x.png' }, pol);
  assert.equal(v3.ok, false);
  assert.equal(v3.reason, 'unc-path');
});

test('盘符路径识别', () => {
  assert.equal(isDrivePath('C:\\Windows\\x'), true);
  assert.equal(isDrivePath('d:/x'), true);
  assert.equal(isDrivePath('\\\\srv\\x'), false);
});

test('file:// URI 解路径与扩展名', () => {
  assert.equal(fileUriToPath('file:///C:/a/b.png'), 'C:/a/b.png');
  assert.equal(fileUriToPath('file:///tmp/a%20b.txt'), '/tmp/a b.txt');
  assert.equal(extOf('photo.JPG'), '.jpg');
  assert.equal(extOf('noext'), '');
});

test('控制字符与超长拒绝', () => {
  const v1 = classifyDroppedItem({ kind: 'uri', uri: 'https://a.com/\nx' }, DEFAULT_POLICY);
  assert.equal(v1.ok, false);
  assert.equal(v1.reason, 'control-char');
  const long = 'https://a.com/' + 'x'.repeat(5000);
  const v2 = classifyDroppedItem({ kind: 'uri', uri: long }, DEFAULT_POLICY);
  assert.equal(v2.ok, false);
  assert.equal(v2.reason, 'uri-too-long');
});

test('text 片段放行但受长度与控制字符约束', () => {
  const ok = classifyDroppedItem({ kind: 'text', uri: 'hello' }, DEFAULT_POLICY);
  assert.equal(ok.ok, true);
  const bad = classifyDroppedItem({ kind: 'text', uri: 'a\x00b' }, DEFAULT_POLICY);
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'control-char');
});

test('空拖放与未知 kind 拒绝', () => {
  assert.equal(classifyDroppedItem(null, DEFAULT_POLICY).ok, false);
  assert.equal(classifyDroppedItem({ kind: 'image' }, DEFAULT_POLICY).reason, 'unknown-kind');
  const batch = auditDroppedItems([]);
  assert.equal(batch.allow, false);
  assert.equal(batch.reason, 'empty-drop');
});

test('批量超限整批拒绝', () => {
  const items = [];
  for (let i = 0; i < DEFAULT_POLICY.maxItems + 1; i++) {
    items.push({ kind: 'uri', uri: 'https://example.com/' + i });
  }
  const r = auditDroppedItems(items);
  assert.equal(r.allow, false);
  assert.equal(r.reason, 'too-many-items');
});

test('任一危险条目整批拒绝', () => {
  const r = auditDroppedItems([
    { kind: 'uri', uri: 'https://example.com/a' },
    { kind: 'uri', uri: 'javascript:x' },
  ]);
  assert.equal(r.allow, false);
  assert.equal(r.reason, 'scheme-not-allowed');
  assert.equal(r.allowed.length, 1);
  assert.equal(r.rejected.length, 1);
});

test('重复条目去重计数', () => {
  const r = auditDroppedItems([
    { kind: 'uri', uri: 'https://example.com/a' },
    { kind: 'uri', uri: 'https://example.com/a' },
  ]);
  assert.equal(r.allow, true);
  assert.equal(r.allowed.length, 1);
  assert.equal(r.duplicates, 1);
});

test('合法混合批次在宽松策略下放行', () => {
  const pol = permissivePolicy();
  const r = auditDroppedItems([
    { kind: 'uri', uri: 'https://example.com/a' },
    { kind: 'file', name: 'shot.png', uri: 'C:\\dl\\shot.png' },
    { kind: 'text', uri: 'note' },
  ], pol);
  assert.equal(r.allow, true, JSON.stringify(r.rejected));
  assert.equal(r.allowed.length, 3);
});

test('宽松策略仍拒绝 file:// 可执行', () => {
  const r = auditDroppedItems([
    { kind: 'uri', uri: 'file:///C:/Windows/System32/cmd.exe' },
  ], permissivePolicy());
  assert.equal(r.allow, false);
  assert.equal(r.reason, 'dangerous-ext');
});
