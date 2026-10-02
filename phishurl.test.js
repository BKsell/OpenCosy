'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const pu = require('./phishurl');

function signalsOf(r) {
  return new Set((r && r.signals || []).map(s => s.code));
}

// ---- IP 识别 ----

test('isIPv4Literal 识别标准/非标准/扁平/IPv6 写法', () => {
  assert.equal(pu.isIPv4Literal('192.168.1.1'), 'ipv4');
  assert.equal(pu.isIPv4Literal('10.0.0.255'), 'ipv4');
  assert.equal(pu.isIPv4Literal('0x7f.0.0.1'), 'ipv4-nondecimal');
  assert.equal(pu.isIPv4Literal('0177.0.0.1'), 'ipv4-nondecimal');
  assert.equal(pu.isIPv4Literal('2130706433'), 'ipv4-flat');
  assert.equal(pu.isIPv4Literal('0x7f000001'), 'ipv4-flat');
  assert.equal(pu.isIPv4Literal('[::1]'), 'ipv6');
  assert.equal(pu.isIPv4Literal('example.com'), null);
  assert.equal(pu.isIPv4Literal('999.1.1.1'), 'ipv4-nondecimal');
});

test('非法段（>255）点分写法不被当成合法 ipv4', () => {
  assert.equal(pu.isIPv4Literal('999.1.1.1'), 'ipv4-nondecimal');
});

// ---- 品牌词 ----

test('findBrandToken 精确切词优先，连写兜底', () => {
  assert.equal(pu.findBrandToken('login paypal verify'), 'paypal');
  assert.equal(pu.findBrandToken('secure-appleid-page'), 'appleid');
  assert.equal(pu.findBrandToken('mygithubmirror'), 'github');
  assert.equal(pu.findBrandToken('random-site.org'), null);
  assert.equal(pu.findBrandToken(''), null);
});

// ---- 主流程：强信号 ----

test('userinfo 偷渡：paypal.com@evil.com 高危', () => {
  const r = pu.analyze('http://paypal.com@evil-account-update.xyz/login');
  assert.ok(r);
  const s = signalsOf(r);
  assert.ok(s.has('userinfo'));
  assert.ok(s.has('brandInUserinfo'));
  assert.equal(r.brand, 'paypal');
  assert.equal(r.level, 'high');
});

test('userinfo 带密码也命中', () => {
  const r = pu.analyze('http://user:p%40ss@10.20.30.40/');
  assert.ok(r);
  assert.ok(signalsOf(r).has('userinfo'));
  assert.equal(r.level, 'high');
});

test('裸 IPv4 主机判为高危', () => {
  const r = pu.analyze('http://192.168.90.11/');
  assert.ok(r);
  assert.ok(signalsOf(r).has('bareIPv4'));
  assert.equal(r.level, 'high');
});

test('十六进制 IP 主机额外命中 decimalHexIp', () => {
  const r = pu.analyze('http://0x7f.0.0.1/');
  assert.ok(r);
  const s = signalsOf(r);
  assert.ok(s.has('bareIPv4'));
  assert.ok(s.has('decimalHexIp'));
  assert.equal(r.level, 'high');
});

test('主机百分号编码命中', () => {
  const r = pu.analyze('http://paypal%2ecom%40evil.com@example.org/');
  // userinfo 内含编码品牌 + 编码主机信号至少其一命中
  assert.ok(r);
  assert.ok(signalsOf(r).has('userinfo'));
});

test('punycode 主机 + 品牌词高危', () => {
  const r = pu.analyze('http://xn--pypal-4ve.com/google-login');
  assert.ok(r);
  assert.ok(signalsOf(r).has('punycodeWithBrand'));
});

// ---- 组合弱信号叠加 ----

test('可疑 TLD + 非标端口 + 品牌词叠加到高危', () => {
  const r = pu.analyze('https://paypal-secure.xyz:8099/');
  assert.ok(r);
  const s = signalsOf(r);
  assert.ok(s.has('suspiciousTldWithBrand'));
  assert.ok(s.has('unusualPortWithBrand'));
  assert.equal(r.level, 'high');
});

test('深层子域 + 品牌词给出弱信号（单独不升级，靠叠加增强）', () => {
  const r = pu.analyze('https://login.apple.id.secure.evilwork.example.org/');
  assert.ok(r);
  assert.ok(signalsOf(r).has('deepSubdomainWithBrand'));
  assert.equal(r.level, 'low');
});

test('深层子域品牌词叠加可疑 TLD 升到高危', () => {
  const r = pu.analyze('https://login.apple.id.verify.apple-secure.xyz/');
  assert.ok(r);
  assert.ok(signalsOf(r).has('deepSubdomainWithBrand'));
  assert.ok(signalsOf(r).has('suspiciousTldWithBrand'));
  assert.equal(r.level, 'high');
});

test('注册名连字符堆叠 + 品牌词命中', () => {
  const r = pu.analyze('https://apple-id-login-verify-secure.com/');
  assert.ok(r);
  assert.ok(signalsOf(r).has('hyphenStackWithBrand'));
});

test('路径含品牌词 + 陌生可疑主机命中', () => {
  const r = pu.analyze('http://random-host.xyz/paypal/signin');
  assert.ok(r);
  assert.ok(signalsOf(r).has('brandInPathOnForeignHost'));
});

// ---- 误伤边界 ----

test('正规官网与常见网站零误报', () => {
  const ok = [
    'https://www.paypal.com/signin',
    'https://appleid.apple.com/',
    'https://mail.google.com/mail/u/0/',
    'https://github.com/BKsell/bool-hybrid-array',
    'https://login.microsoftonline.com/',
    'https://smile.amazon.com/',
    'https://world.taobao.com/',
    'https://example.org/',
    'https://my-personal-blog.net/post/1',
    'http://localhost:3000/',
  ];
  for (const url of ok) {
    assert.equal(pu.analyze(url), null, `${url} 不应报警`);
  }
});

test('普通 8080/8443 端口不单独构成信号', () => {
  assert.equal(pu.analyze('https://app.example.com:8443/'), null);
});

test('可疑 TLD 但无品牌词不报警', () => {
  assert.equal(pu.analyze('https://cool-name.xyz/'), null);
  assert.equal(pu.analyze('https://totally-generic-shop.click/'), null);
});

test('主流托管/CDN 上的路径品牌词不被当钓鱼', () => {
  // github.io 个人页路径里出现别的词不应轻易误报。
  assert.equal(pu.analyze('https://some-user.github.io/paypal-notes/'), null);
});

// ---- 协议与容错 ----

test('只分析 http/https，其余协议与坏输入安全返回 null', () => {
  assert.equal(pu.analyze('ftp://paypal.com@evil.com/'), null);
  assert.equal(pu.analyze('mailto:a@b.com'), null);
  assert.equal(pu.analyze('not a url'), null);
  assert.equal(pu.analyze(''), null);
  assert.equal(pu.analyze(null), null);
  assert.equal(pu.analyze(undefined), null);
});

// ---- 输出结构 ----

test('命中结果字段形状稳定、可序列化、分数非负', () => {
  const r = pu.analyze('http://10.0.0.1/');
  for (const k of ['url', 'hostname', 'score', 'level', 'brand', 'signals']) {
    assert.ok(Object.prototype.hasOwnProperty.call(r, k), '缺字段 ' + k);
  }
  assert.ok(r.score >= pu.HIGH_SCORE);
  assert.doesNotThrow(() => JSON.stringify(r));
  for (const s of r.signals) {
    assert.ok(s.weight > 0);
    assert.equal(typeof s.code, 'string');
  }
});

test('分数与等级单调：高危阈值常量正确', () => {
  assert.ok(pu.HIGH_SCORE > pu.MEDIUM_SCORE);
  assert.ok(pu.WEIGHTS.userinfo >= pu.HIGH_SCORE);
  assert.ok(pu.WEIGHTS.encodedHost >= pu.HIGH_SCORE);
});

// ---- 注册域/子域切分 ----

test('registrableLabel / leftLabels 处理多级后缀', () => {
  assert.equal(pu.registrableLabel('a.b.example.co.uk'), 'example');
  assert.deepEqual(pu.leftLabels('a.b.example.co.uk'), ['a', 'b']);
  assert.equal(pu.registrableLabel('example.com'), 'example');
  assert.deepEqual(pu.leftLabels('example.com'), []);
  assert.equal(pu.registrableLabel('login.apple.com'), 'apple');
  assert.deepEqual(pu.leftLabels('login.apple.com'), ['login']);
});

// ---- 原始主机提取（WHATWG 会规范化，必须自己切）----

test('extractRawHost 去掉协议/userinfo/端口/路径', () => {
  assert.equal(pu.extractRawHost('http://paypal.com@evil.com:8080/a?b=1'), 'evil.com');
  assert.equal(pu.extractRawHost('https://0x7f.0.0.1/login'), '0x7f.0.0.1');
  assert.equal(pu.extractRawHost('http://0177.0.0.1/'), '0177.0.0.1');
  assert.equal(pu.extractRawHost('https://example.com/'), 'example.com');
  assert.equal(pu.extractRawHost('not-a-url'), '');
});

test('扁平整数/十六进制 IP 由主流程识别为高危', () => {
  assert.ok(pu.analyze('http://2130706433/'));
  assert.equal(pu.analyze('http://2130706433/').level, 'high');
  assert.ok(pu.analyze('http://0x7f000001/'));
});

// ---- 多信号与分数 ----

test('多个信号时按权重降序排列，且分数为权重之和', () => {
  const r = pu.analyze('http://paypal.com@paypal-secure.xyz:8099/x');
  assert.ok(r);
  const ws = r.signals.map(s => s.weight);
  const sorted = [...ws].sort((x, y) => y - x);
  assert.deepEqual(ws, sorted);
  const sum = r.signals.reduce((t, s) => t + s.weight, 0);
  assert.equal(r.score, sum);
});

test('每条信号都带 code 与非空 detail', () => {
  const r = pu.analyze('http://10.0.0.1/');
  for (const s of r.signals) {
    assert.equal(typeof s.detail, 'string');
    assert.ok(s.detail.length > 0);
  }
});

test('纯凭据 userinfo 但无品牌词仍高危（userinfo 本身即强信号）', () => {
  const r = pu.analyze('http://admin:hunter2@example.com/');
  assert.ok(r);
  assert.equal(r.level, 'high');
  assert.ok(signalsOf(r).has('userinfo'));
});

// ---- 主流托管判定 ----

test('isLikelyMainstreamHost 识别 CDN/托管后缀', () => {
  assert.ok(pu.isLikelyMainstreamHost('d111111.cloudfront.net'));
  assert.ok(pu.isLikelyMainstreamHost('my-site.vercel.app'));
  assert.ok(pu.isLikelyMainstreamHost('bucket.s3.amazonaws.com'));
  assert.equal(pu.isLikelyMainstreamHost('notamazonaws.com.evil.xyz'), false);
  assert.equal(pu.isLikelyMainstreamHost('example.org'), false);
});

// ---- 大小写与缺省 ----

test('大写协议/主机被归一化处理', () => {
  const r = pu.analyze('HTTP://192.168.0.1/');
  assert.ok(r);
  assert.equal(r.hostname, '192.168.0.1');
});

test('非 HTTP(S) 协议里的 userinfo 不分析（交给外部协议模块）', () => {
  assert.equal(pu.analyze('ssh://root@10.0.0.1/'), null);
});

