'use strict';

// quarantine.test.js —— 下载来源隔离内核：ZoneId 判定、ADS 文本生成与注入防护、
// 平台/来源 gating、打开可执行前二次确认、失败不抛错。

const test = require('node:test');
const assert = require('node:assert/strict');
const q = require('./quarantine');

test('公网 http(s) 归 Internet(3)', () => {
  assert.equal(q.zoneForUrl('https://example.com/a.zip'), q.ZONE_INTERNET);
  assert.equal(q.zoneForUrl('http://1.2.3.4/x'), q.ZONE_INTERNET);
});

test('私网 / 回环归 Intranet(1)', () => {
  assert.equal(q.zoneForUrl('http://192.168.1.10/f'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://10.0.0.5/'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://172.16.0.1/'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://127.0.0.1:8080/'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://localhost/'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://nas.local/'), q.ZONE_INTRANET);
  assert.equal(q.zoneForUrl('http://router/'), q.ZONE_INTRANET);
});

test('172 私网段边界：172.15 公网、172.32 公网', () => {
  assert.equal(q.zoneForUrl('http://172.15.0.1/'), q.ZONE_INTERNET);
  assert.equal(q.zoneForUrl('http://172.32.0.1/'), q.ZONE_INTERNET);
  assert.equal(q.zoneForUrl('http://172.31.255.255/'), q.ZONE_INTRANET);
});

test('非法 / file / 其它协议处理', () => {
  assert.equal(q.zoneForUrl('not a url'), q.ZONE_INTERNET);
  assert.equal(q.zoneForUrl('file:///C:/x'), q.ZONE_LOCAL_MACHINE);
  assert.equal(q.zoneForUrl('ftp://a.com/f'), q.ZONE_INTERNET);
});

test('扩展名识别与隐藏文件', () => {
  assert.equal(q.extOf('C:\\dl\\a.EXE'), '.exe');
  assert.equal(q.extOf('/tmp/a.tar.gz'), '.gz');
  assert.equal(q.extOf('.bashrc'), '');
  assert.equal(q.isOpenRiskExt('x.bat'), true);
  assert.equal(q.isOpenRiskExt('x.txt'), false);
});

test('字段净化剥换行 / 控制字符并截断', () => {
  const dirty = 'https://a.com/x\r\nZoneId=0\x00tail';
  const clean = q.sanitizeZoneField(dirty);
  assert.ok(!/\r|\n/.test(clean), '不应含换行');
  // 换行被折叠成空格后，伪造的 ZoneId=0 只是同一行的延续文本，不再是新 ini 键。
  assert.ok(!/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(clean), '不应含控制字符');
  assert.equal(q.sanitizeZoneField('a'.repeat(5000)).length, 2048);
});

test('生成的 ADS 文本结构正确（ZoneId/Referrer/Host）', () => {
  const text = q.formatZoneIdentifier({
    zoneId: q.ZONE_INTERNET,
    referrerUrl: 'https://ref.com/page',
    hostUrl: 'https://cdn.com/file.exe',
  });
  assert.match(text, /\[ZoneTransfer\]\r\nZoneId=3\r\n/);
  assert.match(text, /ReferrerUrl=https:\/\/ref\.com\/page\r\n/);
  assert.match(text, /HostUrl=https:\/\/cdn\.com\/file\.exe\r\n/);
});

test('ADS 流路径带 :Zone.Identifier 后缀', () => {
  assert.ok(q.adsStreamPath('C:\\dl\\f.exe').endsWith(':Zone.Identifier'));
});

test('applyMarkOfTheWeb：Windows 公网下载写入 ADS', () => {
  let written = null;
  const fsImpl = {
    platform: 'win32',
    appendFileSync(p, c) { written = { p, c }; },
  };
  const r = q.applyMarkOfTheWeb(fsImpl, 'C:\\dl\\f.exe', { hostUrl: 'https://evil.example/x.exe' });
  assert.equal(r.wrote, true);
  assert.equal(r.reason, 'ok');
  assert.ok(written.p.endsWith(':Zone.Identifier'));
  assert.match(written.c, /ZoneId=3/);
});

test('applyMarkOfTheWeb：非 Windows 平台不写', () => {
  const fsImpl = { platform: 'darwin', appendFileSync() { throw new Error('should not call'); } };
  const r = q.applyMarkOfTheWeb(fsImpl, '/tmp/f', { hostUrl: 'https://a.com/f' });
  assert.equal(r.wrote, false);
  assert.equal(r.reason, 'unsupported-platform');
});

test('applyMarkOfTheWeb：内网下载不写 MOTW', () => {
  let called = false;
  const fsImpl = { platform: 'win32', appendFileSync() { called = true; } };
  const r = q.applyMarkOfTheWeb(fsImpl, 'C:\\f', { hostUrl: 'http://192.168.1.1/f' });
  assert.equal(r.wrote, false);
  assert.equal(r.reason, 'not-internet');
  assert.equal(called, false);
});

test('applyMarkOfTheWeb：写失败不抛错（FAT/exFAT）', () => {
  const fsImpl = { platform: 'win32', appendFileSync() { throw new Error('EBADF'); } };
  const r = q.applyMarkOfTheWeb(fsImpl, 'E:\\f.exe', { hostUrl: 'https://a.com/f' });
  assert.equal(r.wrote, false);
  assert.equal(r.reason, 'write-failed');
  assert.match(r.error, /EBADF/);
});

test('applyMarkOfTheWeb：缺 fs / 非法路径安全返回', () => {
  assert.equal(q.applyMarkOfTheWeb(null, 'C:\\f', { hostUrl: 'https://a.com' }).reason, 'no-fs');
  assert.equal(q.applyMarkOfTheWeb({ platform: 'win32', appendFileSync() {} }, '', {}).reason, 'invalid-path');
});

test('openDecision：互联网可执行需确认，内网/普通文件放行', () => {
  assert.equal(q.openDecision({ filePath: 'C:\\a.exe', hostUrl: 'https://evil.example/a' }), 'confirm');
  assert.equal(q.openDecision({ filePath: 'C:\\a.txt', hostUrl: 'https://evil/a' }), 'allow');
  assert.equal(q.openDecision({ filePath: 'C:\\a.exe', hostUrl: 'http://10.0.0.1/a' }), 'allow');
});

test('openDecision：无来源信息的可执行文件也需确认', () => {
  assert.equal(q.openDecision({ filePath: 'a.msi' }), 'confirm');
});

test('openDecision：显式 zoneId 覆盖 hostUrl', () => {
  assert.equal(q.openDecision({ filePath: 'a.exe', hostUrl: 'http://10.0.0.1', zoneId: q.ZONE_INTERNET }), 'confirm');
  assert.equal(q.openDecision({ filePath: 'a.exe', hostUrl: 'https://a.com', zoneId: q.ZONE_INTRANET }), 'allow');
});
