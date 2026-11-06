'use strict';

// dloadopen 单元测试：覆盖“通知点击 / 下载列表打开”两条入口共用的判定。
const test = require('node:test');
const assert = require('node:assert');
const dloadOpen = require('./dloadopen');

const { ACTION } = dloadOpen;

test('普通文档直接打开，来源未知的压缩包要求确认', () => {
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.pdf', filename: 'a.pdf' }).action, ACTION.OPEN);
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.txt', filename: 'a.txt' }).action, ACTION.OPEN);
  // 来源未知时容器类与可执行类同级：MOTW 不随解压继承，先确认再开。
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.zip', filename: 'a.zip' }).action, ACTION.CONFIRM);
});

test('可执行 / 脚本一律要求确认', () => {
  for (const name of ['setup.exe', 'run.bat', 'x.ps1', 'a.msi', 'lib.jar', 'go.cmd']) {
    const v = dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\' + name, filename: name });
    assert.strictEqual(v.action, ACTION.CONFIRM, name);
    assert.ok(v.reasons.length > 0, name);
  }
});

test('双扩展名伪装要求确认', () => {
  const v = dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\invoice.exe.pdf', filename: 'invoice.exe.pdf' });
  assert.strictEqual(v.action, ACTION.CONFIRM);
  assert.match(v.reasons.join(' '), /伪装|可执行/);
});

test('RTL 覆盖字符与 NTFS ADS 名字要求确认', () => {
  const rtl = dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.txt', filename: 'photo\u202egpj.exe' });
  assert.strictEqual(rtl.action, ACTION.CONFIRM);
  const ads = dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.txt:hidden.exe', filename: 'a.txt:hidden.exe' });
  assert.strictEqual(ads.action, ACTION.CONFIRM);
});

test('空目标与非法文件名直接拒绝', () => {
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: '', filename: '' }).action, ACTION.BLOCK);
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\..', filename: '..' }).action, ACTION.BLOCK);
});

test('本地网页只定位不执行', () => {
  for (const name of ['page.html', 'icon.svg', 'doc.xhtml']) {
    const v = dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\' + name, filename: name });
    assert.strictEqual(v.action, ACTION.REVEAL, name);
  }
});

test('磁盘镜像只定位', () => {
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.iso', filename: 'a.iso' }).action, ACTION.REVEAL);
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.vhdx', filename: 'a.vhdx' }).action, ACTION.REVEAL);
});

test('来自互联网的容器升级为确认', () => {
  const v = dloadOpen.decideOpenTarget({
    filePath: 'C:\\dl\\pack.zip',
    filename: 'pack.zip',
    hostUrl: 'https://example.com/pack.zip',
  });
  assert.strictEqual(v.action, ACTION.CONFIRM);
  assert.ok(v.reasons.join(' ').includes('来源标记') || v.reasons.join(' ').includes('SmartScreen'));
});

test('无扩展名与普通 MIME 仍可打开', () => {
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\README', filename: 'README' }).action, ACTION.OPEN);
  assert.strictEqual(dloadOpen.decideOpenTarget({ filePath: 'C:\\dl\\a.pdf', filename: 'a.pdf', mime: 'application/pdf' }).action, ACTION.OPEN);
});

test('MIME 声明为可执行却叫 PDF 要求确认', () => {
  const v = dloadOpen.decideOpenTarget({
    filePath: 'C:\\dl\\report.pdf',
    filename: 'report.pdf',
    mime: 'application/x-msdownload',
  });
  assert.strictEqual(v.action, ACTION.CONFIRM);
});

test('extOfName 边界', () => {
  assert.strictEqual(dloadOpen.extOfName('a.tar.gz'), 'gz');
  assert.strictEqual(dloadOpen.extOfName('.bashrc'), '');
  assert.strictEqual(dloadOpen.extOfName('noext'), '');
  assert.strictEqual(dloadOpen.extOfName('trailing.'), '');
});
