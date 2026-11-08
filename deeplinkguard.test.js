'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const dg = require('./deeplinkguard');

test('http(s) 深链放行', () => {
  assert.equal(dg.reviewStartupArg('https://example.com/').ok, true);
  assert.equal(dg.reviewStartupArg('http://localhost:8080/x').kind, 'web');
});

test('cosy 深链只放行白名单主机', () => {
  const ok = dg.reviewStartupArg('cosy://security');
  assert.equal(ok.ok, true);
  assert.equal(ok.host, 'security');
  assert.equal(dg.reviewStartupArg('cosy://evil/steal').ok, false);
  assert.equal(dg.reviewStartupArg('cosy://evil/steal').reason, 'host');
  // 大小写主机归一
  assert.equal(dg.reviewStartupArg('cosy://NEWTAB').ok, true);
});

test('Windows 盘符 HTML 被识别为本地文件而非协议', () => {
  const r = dg.reviewStartupArg('C:\\Users\\me\\page.html');
  assert.equal(r.ok, true);
  assert.equal(r.kind, 'local-html');
  assert.ok(path.isAbsolute(r.value));
  assert.equal(r.value.toLowerCase().endsWith('page.html'), true);
});

test('本地 HTML 后缀大小写与尾点', () => {
  assert.equal(dg.reviewStartupArg('C:\\x\\index.HTML').ok, true);
  assert.equal(dg.reviewStartupArg('C:\\x\\index.HTM').ok, true);
  assert.equal(dg.reviewStartupArg('C:\\x\\a.txt').reason, 'not-html');
});

test('相对路径 / UNC / 穿越拒绝', () => {
  assert.equal(dg.reviewStartupArg('page.html').reason, 'not-absolute');
  assert.equal(dg.reviewStartupArg('\\\\host\\share\\a.html').reason, 'unc');
  assert.equal(dg.reviewStartupArg('C:\\x\\..\\..\\a.html').reason, 'traversal');
});

test('开关样参数与控制字符拒绝', () => {
  assert.equal(dg.reviewStartupArg('--disable-web-security').reason, 'switch-like');
  assert.equal(dg.reviewStartupArg('-app=https://x').reason, 'switch-like');
  assert.equal(dg.reviewStartupArg('https://a.com/\r\n').reason, 'control-char');
  assert.equal(dg.reviewStartupArg('https://a.com/\x00').reason, 'control-char');
});

test('其它协议深链拒绝', () => {
  assert.equal(dg.reviewStartupArg('file:///C:/Windows/a.html').reason, 'scheme');
  assert.equal(dg.reviewStartupArg('javascript:alert(1)').reason, 'scheme');
  assert.equal(dg.reviewStartupArg('ms-word:ofe|u|x').reason, 'scheme');
  assert.equal(dg.reviewStartupArg('data:text/html,x').reason, 'scheme');
});

test('非法 web 深链拒绝', () => {
  assert.equal(dg.reviewStartupArg('https://').reason, 'unparseable');
  assert.equal(dg.reviewStartupArg('not a url at all.html').reason, 'not-absolute');
  assert.equal(dg.reviewStartupArg('').ok, false);
  assert.equal(dg.reviewStartupArg(null).ok, false);
  assert.equal(dg.reviewStartupArg(undefined).reason, 'not-string');
});

test('独立的 local/html/internal/web 判定一致', () => {
  assert.equal(dg.reviewLocalHtml('C:\\a\\b.html').ok, true);
  assert.equal(dg.reviewLocalHtml('C:\\a\\b.exe').reason, 'not-html');
  assert.equal(dg.reviewWebUrl('https://a.com/').ok, true);
  assert.equal(dg.reviewWebUrl('cosy://security').ok, false);
  assert.equal(dg.reviewInternalUrl('cosy://setting').ok, true);
  assert.equal(dg.reviewInternalUrl('cosy://nope').reason, 'host');
});

test('自定义内部主机白名单', () => {
  const r = dg.reviewInternalUrl('cosy://lab', new Set(['lab']));
  assert.equal(r.ok, true);
  assert.equal(dg.reviewInternalUrl('cosy://lab', ['other']).ok, false);
});

test('后缀识别工具', () => {
  assert.equal(dg.isHtmlFile('C:\\x\\a.HTML'), true);
  assert.equal(dg.isHtmlFile('a.htm.'), true);
  assert.equal(dg.isHtmlFile('a.htmlx'), false);
});

test('审计说明不回显输入', () => {
  const r = dg.reviewStartupArg('C:\\secret\\a.txt');
  assert.equal(dg.describeReason(r.reason).includes('secret'), false);
});

test('argv 遍历：跳过开关与 exe，深链位置不固定也能找到', () => {
  // argv[0] 是可执行路径，前面还混着 Chromium 开关，深链在后面。
  const argv = [
    'C:\\Program Files\\OpenCosy\\OpenCosy.exe',
    '--disable-features=X',
    '--allow',
    'cosy://setting',
  ];
  const r = dg.pickDeepLinkFromArgv(argv);
  assert.ok(r);
  assert.equal(r.ok, true);
  assert.equal(r.kind, 'internal');
  assert.equal(r.host, 'setting');
});

test('argv 遍历：全是开关 / 无合法深链返回 null', () => {
  assert.equal(dg.pickDeepLinkFromArgv(['app.exe', '--foo', '-bar']), null);
  assert.equal(dg.pickDeepLinkFromArgv([]), null);
  assert.equal(dg.pickDeepLinkFromArgv(null), null);
});

test('argv 遍历：web 深链优先于后续参数', () => {
  const r = dg.pickDeepLinkFromArgv(['app.exe', 'https://a.com/', 'cosy://newtab']);
  assert.equal(r.kind, 'web');
  assert.equal(r.value, 'https://a.com/');
});

test('argv 遍历：开关形式的恶意深链不被当成开关后面的链接漏过', () => {
  // 即便开关后面紧跟可疑串，整体仍要能找到合法者；开关本身绝不当深链。
  const r = dg.pickDeepLinkFromArgv(['app.exe', '-cosy://setting']);
  assert.equal(r, null);
});

test('argv 扫描数量有界', () => {
  const many = ['app.exe'];
  for (let i = 0; i < 100; i++) many.push('--flag' + i);
  many.push('cosy://newtab'); // 落在 101 位，超出扫描窗
  // 超窗不崩溃；深链超出 MAX_ARGV_SCAN 找不到（返回 null）。
  assert.equal(dg.pickDeepLinkFromArgv(many), null);
  // 把合法深链放在窗口内（第 64 个参数位）能找到。
  const inWindow = ['app.exe'];
  for (let i = 0; i < 62; i++) inWindow.push('--flag' + i);
  inWindow.push('cosy://newtab');
  assert.equal(dg.pickDeepLinkFromArgv(inWindow).ok, true);
});
