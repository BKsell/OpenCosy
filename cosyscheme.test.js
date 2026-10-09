'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const os = require('os');

const {
  COSY_SCHEME,
  COSY_PAGES,
  privilegedSchemeOptions,
  normalizeHost,
  resolveCosyPage,
  resolveCosyFilePath,
  isPathInsideDir,
  resolveAllowedFileUrl,
} = require('./cosyscheme');

test('privilegedSchemeOptions 为 cosy 登记标准安全特权', () => {
  const opts = privilegedSchemeOptions();
  assert.equal(opts.length, 1);
  assert.equal(opts[0].scheme, COSY_SCHEME);
  const p = opts[0].privileges;
  assert.equal(p.standard, true);
  assert.equal(p.secure, true);
  assert.equal(p.supportFetchAPI, true);
  assert.equal(p.corsEnabled, true);
  // 绝不放开 CSP 绕过。
  assert.equal(p.bypassCSP, undefined);
});

test('normalizeHost', () => {
  assert.equal(normalizeHost('SETTING.'), 'setting');
  assert.equal(normalizeHost('  NewTab '), 'newtab');
  assert.equal(normalizeHost(null), '');
});

test('resolveCosyPage 白名单命中与回落', () => {
  assert.equal(resolveCosyPage('cosy://security/').file, COSY_PAGES.security);
  assert.equal(resolveCosyPage('cosy://security/').known, true);
  assert.equal(resolveCosyPage('cosy://download/?x=1').file, COSY_PAGES.download);
  assert.equal(resolveCosyPage('cosy://httpsonly/').file, COSY_PAGES.httpsonly);
  assert.equal(resolveCosyPage('cosy://httpsonly/').known, true);
  // 未知 host 回落 newtab，且 path/query 不参与文件选择。
  const r = resolveCosyPage('cosy://unknown/../../etc/passwd');
  assert.equal(r.file, 'newtab.html');
  assert.equal(r.known, false);
  // 畸形 URL 不抛异常。
  assert.equal(resolveCosyPage('not a url').file, 'newtab.html');
});

test('resolveCosyFilePath 锁在 srcDir 内', () => {
  const srcDir = path.join(os.tmpdir(), 'opencosy-src');
  const r = resolveCosyFilePath('cosy://setting/', srcDir);
  assert.equal(r.absolutePath, path.resolve(srcDir, 'settings.html'));
});

test('isPathInsideDir 前缀边界', () => {
  const root = path.resolve('/safe');
  assert.equal(isPathInsideDir(path.join(root, 'a', 'b'), root), true);
  assert.equal(isPathInsideDir(root, root), true);
  // /safe-evil 不得被误判进 /safe。
  assert.equal(isPathInsideDir(path.resolve('/safe-evil'), root), false);
  if (process.platform === 'win32') {
    assert.equal(isPathInsideDir('C:\\safe\\x', 'C:\\safe'), true);
    assert.equal(isPathInsideDir('D:\\safe\\x', 'C:\\safe'), false);
  }
});

test('file: 本机路径在允许目录内放行', () => {
  const dir = os.tmpdir();
  const target = path.join(dir, 'opencosy-protocol-test', 'page.html');
  const url = 'file:///' + target.replace(/\\/g, '/').replace(/^\//, '');
  const r = resolveAllowedFileUrl(url, [path.join(dir, 'opencosy-protocol-test')]);
  assert.equal(r.ok, true);
  assert.match(r.reason, /^$/);
});

test('file: 目录外被拒', () => {
  const r = resolveAllowedFileUrl('file:///etc/passwd', [path.join(os.tmpdir(), 'only-here')]);
  assert.equal(r.ok, false);
  // Windows 下 /etc/passwd 不是合法盘符路径，fileURLToPath 直接判 malformed；
  // POSIX 下可解析但落在允许目录外。两种都必须拒绝。
  assert.ok(r.reason === 'outside-allowed' || r.reason === 'malformed');
});

test('file: 远程/UNC host 被拒', () => {
  const r = resolveAllowedFileUrl('file://server/share/secret.txt', [os.tmpdir()]);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'remote-host');
});

test('localhost host 视为本机', () => {
  const dir = os.tmpdir();
  const r = resolveAllowedFileUrl('file://localhost/' + dir.replace(/\\/g, '/').replace(/^\/+/, '') + '/x',
    [dir]);
  assert.ok(r.ok === true || r.reason === 'outside-allowed'); // 不允许 remote-host
  assert.notEqual(r.reason, 'remote-host');
});

test('非 file scheme / 畸形 URL', () => {
  assert.equal(resolveAllowedFileUrl('http://a.test/x', [os.tmpdir()]).reason, 'non-file-scheme');
  assert.equal(resolveAllowedFileUrl('file://not a url', [os.tmpdir()]).ok, false);
  assert.equal(resolveAllowedFileUrl('%%%%', [os.tmpdir()]).reason, 'malformed');
});

test('百分号编码与穿越尝试', () => {
  const dir = os.tmpdir();
  // 编码后的 ../ 仍应在规范化后落在目录外而被拒。
  const enc = 'file:///' + path.join(dir, 'allowed')
    .replace(/\\/g, '/').replace(/^\//, '') + '/%2e%2e%2f%2e%2e%2fetc%2fpasswd';
  const r = resolveAllowedFileUrl(enc, [path.join(dir, 'allowed')]);
  assert.equal(r.ok, false);
});
