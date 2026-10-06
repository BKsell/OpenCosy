'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  normalizeHostname,
  hostEqualsOrSubdomain,
  hostMatchesList,
  parseIPv4Parts,
  isPrivateHostname,
} = require('./hostmatch');

test('normalizeHostname 小写/去空白/去方括号/去尾根点', () => {
  assert.strictEqual(normalizeHostname('Example.COM'), 'example.com');
  assert.strictEqual(normalizeHostname('  example.com. '), 'example.com');
  assert.strictEqual(normalizeHostname('example.com...'), 'example.com');
  assert.strictEqual(normalizeHostname('[::1]'), '::1');
  assert.strictEqual(normalizeHostname('[2001:db8::1]'), '2001:db8::1');
  assert.strictEqual(normalizeHostname(null), '');
  assert.strictEqual(normalizeHostname(undefined), '');
});

test('hostEqualsOrSubdomain 边界精确', () => {
  assert.ok(hostEqualsOrSubdomain('example.com', 'example.com'));
  assert.ok(hostEqualsOrSubdomain('a.example.com', 'example.com'));
  assert.ok(hostEqualsOrSubdomain('a.b.example.com', 'example.com'));
  // 必须隔着一个点，裸后缀不算子域。
  assert.ok(!hostEqualsOrSubdomain('evilexample.com', 'example.com'));
  assert.ok(!hostEqualsOrSubdomain('notexample.com', 'example.com'));
  // 尾点 / 大小写 / 子域带点两边都归一。
  assert.ok(hostEqualsOrSubdomain('A.Example.COM.', 'example.com'));
  assert.ok(!hostEqualsOrSubdomain('', 'example.com'));
  assert.ok(!hostEqualsOrSubdomain('x', ''));
});

test('hostMatchesList 精确与子域、跨域不误伤', () => {
  const list = ['doubleclick.net', 'google-analytics.com'];
  assert.ok(hostMatchesList('doubleclick.net', list));
  assert.ok(hostMatchesList('stats.doubleclick.net', list));
  assert.ok(hostMatchesList('www.google-analytics.com', list));
  assert.ok(!hostMatchesList('notdoubleclick.net', list));
  assert.ok(!hostMatchesList('example.com', list));
  // 支持 Set，并容忍条目带尾点。
  assert.ok(hostMatchesList('a.tracker.test.', new Set(['tracker.test'])));
  assert.ok(!hostMatchesList('x', null));
});

test('parseIPv4Parts 严格四段，等价旧正则', () => {
  assert.deepStrictEqual(parseIPv4Parts('192.168.1.1'), [192, 168, 1, 1]);
  assert.deepStrictEqual(parseIPv4Parts('127.0.0.1'), [127, 0, 0, 1]);
  assert.strictEqual(parseIPv4Parts('1.2.3'), null);
  assert.strictEqual(parseIPv4Parts('1.2.3.4.5'), null);
  assert.strictEqual(parseIPv4Parts('a.b.c.d'), null);
  assert.strictEqual(parseIPv4Parts('1.2.3.x'), null);
  // 旧正则允许 1~3 位数字段（含超 255 / 前导零），内核保持同一语法口径。
  assert.deepStrictEqual(parseIPv4Parts('999.00.1.2'), [999, 0, 1, 2]);
  assert.strictEqual(parseIPv4Parts('1234.1.1.1'), null);
  assert.strictEqual(parseIPv4Parts('::1'), null);
});

test('isPrivateHostname 私网/本机判定与旧实现一致', () => {
  const priv = ['localhost', 'sub.localhost', '::1', '::ffff:127.0.0.1',
    '127.0.0.1', '127.255.255.255', '10.0.0.1', '10.255.255.255',
    '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254'];
  for (const h of priv) assert.ok(isPrivateHostname(h), '应判私网: ' + h);
  const pub = ['example.com', '8.8.8.8', '172.32.0.1', '172.15.0.1',
    '100.65.0.1', '192.169.0.1', '169.255.0.1', '::2', 'notlocalhost'];
  for (const h of pub) assert.ok(!isPrivateHostname(h), '不应判私网: ' + h);
  // FQDN 根点写法也应识别为本机（硬化：旧实现漏判尾点）。
  assert.ok(isPrivateHostname('127.0.0.1.'));
  assert.ok(isPrivateHostname('localhost.'));
  assert.ok(!isPrivateHostname(''));
});
