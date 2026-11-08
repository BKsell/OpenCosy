'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sg = require('./shellguard');

test('合法 mailto / tel 放行', () => {
  assert.equal(sg.reviewExternalUrl('mailto:user@example.com').ok, true);
  assert.equal(sg.reviewExternalUrl('mailto:a@b.com?cc=c@d.com&subject=hi').ok, true);
  assert.equal(sg.reviewExternalUrl('tel:+8613800138000').ok, true);
  assert.equal(sg.reviewExternalUrl('tel:10086').ok, true);
});

test('非白名单协议拒绝', () => {
  for (const u of [
    'file:///C:/Windows/notepad.exe',
    'javascript:alert(1)',
    'ms-word:ofe|u|https://x',
    'smb://host/share',
    'https://example.com/',
  ]) {
    const r = sg.reviewExternalUrl(u);
    assert.equal(r.ok, false, `${u} 应拒绝`);
    assert.equal(r.reason, 'scheme');
  }
});

test('控制字符与编码控制字符拒绝', () => {
  assert.equal(sg.reviewExternalUrl('mailto:a@b.com\nBcc: z@q.com').reason, 'control-char');
  assert.equal(sg.reviewExternalUrl('mailto:a@b.com\r\n').reason, 'control-char');
  assert.equal(sg.reviewExternalUrl('mailto:a@b.com?x=%0d%0a').reason, 'encoded-control');
  assert.equal(sg.reviewExternalUrl('tel:10086%00').reason, 'encoded-control');
});

test('形似开关 / 过长 / userinfo 拒绝', () => {
  assert.equal(sg.reviewExternalUrl('-mailto:a@b.com').reason, 'switch-like');
  assert.equal(sg.reviewExternalUrl('/mailto:a@b.com').reason, 'switch-like');
  assert.equal(sg.reviewExternalUrl('mailto:' + 'a'.repeat(5000)).reason, 'too-long');
  assert.equal(sg.reviewExternalUrl('').ok, false);
  assert.equal(sg.reviewExternalUrl(null).ok, false);
});

test('非法邮件地址拒绝', () => {
  assert.equal(sg.reviewExternalUrl('mailto:no-at-sign').reason, 'mailto-bad-addr');
  assert.equal(sg.reviewExternalUrl('mailto:a b@c.com').reason, 'mailto-bad-local');
  assert.equal(sg.reviewExternalUrl('mailto:a@c_o.com').reason, 'mailto-bad-domain');
  assert.equal(sg.reviewExternalUrl('mailto:a@c..com').reason, 'mailto-bad-domain');
  assert.equal(sg.reviewExternalUrl('mailto:@b.com').reason, 'mailto-bad-addr');
});

test('非法电话号码拒绝', () => {
  assert.equal(sg.reviewExternalUrl('tel:').reason, 'tel-empty');
  assert.equal(sg.reviewExternalUrl('tel:abc').reason, 'tel-bad-char');
  assert.equal(sg.reviewExternalUrl('tel:+-()').reason, 'tel-no-digit');
  assert.equal(sg.reviewExternalUrl('tel:12 34').reason, 'tel-bad-char');
  assert.equal(sg.reviewExternalUrl('tel:' + '1'.repeat(40)).reason, 'tel-too-long');
});

test('自定义协议白名单生效', () => {
  const r = sg.reviewExternalUrl('custom://action', new Set(['custom:']));
  assert.equal(r.ok, true);
  assert.equal(sg.reviewExternalUrl('custom://action', ['other:']).ok, false);
});

test('可执行 / 快捷方式扩展名识别', () => {
  for (const f of ['a.exe', 'a.EXE', 'x.lnk', 'x.bat', 'x.cmd', 'x.msi', 'x.ps1', 'x.url']) {
    assert.equal(sg.isExecutableName(f), true, `${f} 应识别为可执行`);
  }
  assert.equal(sg.isExecutableName('a.txt'), false);
  assert.equal(sg.isExecutableName('a.pdf'), false);
  assert.equal(sg.isExecutableName('a.png'), false);
});

test('本地路径：穿越 / UNC / 越界拒绝', () => {
  assert.equal(sg.reviewLocalLaunchPath('C:\\dl\\..\\..\\windows\\x.txt', true).reason, 'path-traversal');
  assert.equal(sg.reviewLocalLaunchPath('\\\\host\\share\\x.txt', true).reason, 'path-unc');
  assert.equal(sg.reviewLocalLaunchPath('C:\\windows\\x.txt', false).reason, 'path-outside');
  assert.equal(sg.reviewLocalLaunchPath('C:\dl\a\nb.txt', true).reason, 'path-control');
  assert.equal(sg.reviewLocalLaunchPath('', true).reason, 'path-empty');
});

test('本地路径：openPath 直接运行拒绝可执行文件，定位不拒绝', () => {
  const run = sg.reviewLocalLaunchPath('C:\\dl\\setup.exe', true, { rejectExecutable: true });
  assert.equal(run.ok, false);
  assert.equal(run.reason, 'path-executable');
  // showItemInFolder 只是在资源管理器里定位，允许。
  const reveal = sg.reviewLocalLaunchPath('C:\\dl\\setup.exe', true);
  assert.equal(reveal.ok, true);
  // 普通文档两种都允许。
  assert.equal(sg.reviewLocalLaunchPath('C:\\dl\\note.txt', true, { rejectExecutable: true }).ok, true);
});

test('审计说明不回显输入', () => {
  const r = sg.reviewExternalUrl('mailto:a@secret.com\nX');
  assert.equal(sg.describeReason(r.reason).includes('secret'), false);
});
