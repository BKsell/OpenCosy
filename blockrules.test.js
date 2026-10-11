'use strict';
// blockrules.test.js —— 自定义拦截规则内核测试。
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const br = require('./blockrules');

function tmpRulesFile(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'brtest-'));
  t.cleanup && t.cleanup();
  return path.join(dir, 'blockrules.json');
}

function test(name, fn) {
  try { fn(); console.log('ok - ' + name); }
  catch (err) { console.error('FAIL - ' + name + ': ' + (err && err.stack || err)); process.exitCode = 1; }
}

test('normalizeHostRule 接受合法域名并规范化', () => {
  assert.strictEqual(br.normalizeHostRule('Evil.com'), 'evil.com');
  assert.strictEqual(br.normalizeHostRule('evil.com.'), 'evil.com');
  assert.strictEqual(br.normalizeHostRule('  ads.evil.com '), 'ads.evil.com');
});

test('normalizeHostRule 拒绝非法输入', () => {
  assert.strictEqual(br.normalizeHostRule(''), null);
  assert.strictEqual(br.normalizeHostRule('com'), null);            // 单段
  assert.strictEqual(br.normalizeHostRule('evil..com'), null);       // 空段
  assert.strictEqual(br.normalizeHostRule('evil.com<script>'), null);
  assert.strictEqual(br.normalizeHostRule('a'.repeat(300)), null);   // 超长
});

test('normalizeGlobRule 校验', () => {
  assert.strictEqual(br.normalizeGlobRule('https://*.ads.example/*'), 'https://*.ads.example/*');
  assert.strictEqual(br.normalizeGlobRule('http://x.example/'), null);       // 无 *
  assert.strictEqual(br.normalizeGlobRule('ftp://x/*'), null);                // 非 http(s)
  assert.strictEqual(br.normalizeGlobRule('https://x/ads/'), null);           // 无 * → 走 path
  assert.strictEqual(br.normalizeGlobRule('https://x/a b/*'), null);          // 空格
});

test('normalizePathRule 校验', () => {
  assert.strictEqual(br.normalizePathRule('https://x.example/ads/'), 'https://x.example/ads/');
  assert.strictEqual(br.normalizePathRule('https://x.example/ads/*'), null);  // 有 * → 走 glob
  assert.strictEqual(br.normalizePathRule('ftp://x/ads'), null);
});

test('parseRuleLine 裸域名视为 host', () => {
  const r = br.parseRuleLine('evil.com');
  assert.ok(r && r.kind === 'host' && r.value === 'evil.com');
});

test('parseRuleLine 带前缀解析', () => {
  assert.deepStrictEqual(br.parseRuleLine('host:evil.com'), { kind: 'host', value: 'evil.com' });
  assert.deepStrictEqual(br.parseRuleLine('glob:https://*.x/*'), { kind: 'glob', value: 'https://*.x/*' });
  assert.deepStrictEqual(br.parseRuleLine('path:https://x.example/ads/'), { kind: 'path', value: 'https://x.example/ads/' });
});

test('parseRuleLine 拒绝注释/空/非法', () => {
  assert.strictEqual(br.parseRuleLine('# comment'), null);
  assert.strictEqual(br.parseRuleLine(''), null);
  assert.strictEqual(br.parseRuleLine('   '), null);
  assert.strictEqual(br.parseRuleLine('host:'), null);
  assert.strictEqual(br.parseRuleLine('glob:ftp://x/*'), null);
});

test('addRule 去重与上限', () => {
  const rules = br.createEmptyRules();
  assert.strictEqual(br.addRule(rules, 'evil.com').ok, true);
  assert.strictEqual(br.addRule(rules, 'evil.com').reason, 'duplicate');
  assert.strictEqual(br.ruleCount(rules), 1);
  // 填满上限
  for (let i = 0; i < br.MAX_RULES - 1; i++) rules.host.push('h' + i + '.example.com');
  assert.strictEqual(br.addRule(rules, 'other.net').ok, false);
  assert.strictEqual(br.addRule(rules, 'other.net').reason, 'limit');
});

test('removeRule 按前缀或原文移除', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'evil.com');
  br.addRule(rules, 'glob:https://*.x/*');
  assert.strictEqual(br.removeRule(rules, 'host:evil.com'), true);
  assert.strictEqual(br.ruleCount(rules), 1);
  assert.strictEqual(br.removeRule(rules, 'https://*.x/*'), true);
  assert.strictEqual(br.ruleCount(rules), 0);
  assert.strictEqual(br.removeRule(rules, 'nope'), false);
});

test('importRulesText 统计与容错', () => {
  const rules = br.createEmptyRules();
  const text = ['# head', 'evil.com', 'host:ads.example', 'glob:https://cdn.bad/*', 'bad line !!!', ''].join('\n');
  const r = br.importRulesText(rules, text);
  assert.strictEqual(r.added, 3);
  assert.strictEqual(r.skipped, 1);
  assert.strictEqual(br.ruleCount(rules), 3);
});

test('exportRulesText 可回读', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'evil.com');
  br.addRule(rules, 'glob:https://*.x/*');
  const text = br.exportRulesText(rules);
  const rules2 = br.createEmptyRules();
  const r = br.importRulesText(rules2, text);
  assert.strictEqual(r.added, 2);
  assert.strictEqual(br.ruleCount(rules2), 2);
});

test('decideBlocked host 规则含子域', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'evil.com');
  const compiled = br.compileRules(rules);
  assert.deepStrictEqual(br.decideBlocked('https://evil.com/pix.gif', compiled, null), { blockedBy: 'custom', rule: 'evil.com' });
  assert.deepStrictEqual(br.decideBlocked('https://sub.evil.com/pix', compiled, null), { blockedBy: 'custom', rule: 'evil.com' });
  assert.strictEqual(br.decideBlocked('https://evile.com/pix', compiled, null), null);
  assert.strictEqual(br.decideBlocked('https://notevil.com/pix', compiled, null), null);
});

test('decideBlocked glob 规则', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'glob:https://cdn.bad.net/assets/*');
  const compiled = br.compileRules(rules);
  assert.ok(br.decideBlocked('https://cdn.bad.net/assets/a.js', compiled, null));
  assert.strictEqual(br.decideBlocked('https://cdn.bad.net/other.js', compiled, null), null);
});

test('decideBlocked path 规则', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'path:https://ok.example/ads/');
  const compiled = br.compileRules(rules);
  assert.ok(br.decideBlocked('https://ok.example/ads/banner.png', compiled, null));
  assert.strictEqual(br.decideBlocked('https://ok.example/home', compiled, null), null);
  assert.strictEqual(br.decideBlocked('https://evil.example/ads/banner.png', compiled, null), null);
});

test('decideBlocked 内置列表兜底', () => {
  const rules = br.createEmptyRules();
  const compiled = br.compileRules(rules);
  const trackerHosts = new Set(['doubleclick.net']);
  assert.deepStrictEqual(br.decideBlocked('https://sub.doubleclick.net/p', compiled, trackerHosts), { blockedBy: 'builtin', rule: 'doubleclick.net' });
  assert.strictEqual(br.decideBlocked('https://normal.example/p', compiled, trackerHosts), null);
});

test('decideBlocked 自定义优先于内置', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'doubleclick.net'); // 用户自己加了豁免/覆盖? 这里是同域自定义 → 仍拦，标记 custom
  const compiled = br.compileRules(rules);
  const trackerHosts = new Set(['doubleclick.net']);
  assert.deepStrictEqual(br.decideBlocked('https://doubleclick.net/p', compiled, trackerHosts), { blockedBy: 'custom', rule: 'doubleclick.net' });
});

test('decideBlocked 畸形 URL 放行', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'evil.com');
  const compiled = br.compileRules(rules);
  assert.strictEqual(br.decideBlocked('not-a-url', compiled, null), null);
  assert.strictEqual(br.decideBlocked('', compiled, null), null);
});

test('loadRules 缺失文件返回空规则集', () => {
  const rules = br.loadRules(path.join(os.tmpdir(), 'no-such-dir-' + Date.now(), 'x.json'));
  assert.strictEqual(br.ruleCount(rules), 0);
});

test('loadRules 损坏文件返回空规则集', () => {
  const f = path.join(os.tmpdir(), 'bad-blockrules-' + Date.now() + '.json');
  fs.writeFileSync(f, '{ not json', 'utf8');
  const rules = br.loadRules(f);
  assert.strictEqual(br.ruleCount(rules), 0);
  fs.unlinkSync(f);
});

test('loadRules 结构校验：非数组字段被拒', () => {
  const f = path.join(os.tmpdir(), 'struct-blockrules-' + Date.now() + '.json');
  fs.writeFileSync(f, JSON.stringify({ version: 1, host: 'evil.com', glob: [], path: [] }), 'utf8');
  const rules = br.loadRules(f);
  assert.strictEqual(br.ruleCount(rules), 0);
  fs.unlinkSync(f);
});

test('loadRules 超限元素被截断', () => {
  const f = path.join(os.tmpdir(), 'big-blockrules-' + Date.now() + '.json');
  const big = [];
  for (let i = 0; i < 2500; i++) big.push('h' + i + '.example.com');
  fs.writeFileSync(f, JSON.stringify({ version: 1, host: big, glob: [], path: [] }), 'utf8');
  const rules = br.loadRules(f);
  assert.ok(br.ruleCount(rules) <= br.MAX_RULES);
  fs.unlinkSync(f);
});

test('saveRules 原子写并可回读', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'brsave-')), 'blockrules.json');
  const rules = br.createEmptyRules();
  br.addRule(rules, 'evil.com');
  const r = br.saveRules(f, rules);
  assert.strictEqual(r.ok, true);
  const loaded = br.loadRules(f);
  assert.deepStrictEqual(loaded.host, ['evil.com']);
});

test('globToRegex 特殊字符转义', () => {
  const re = br.compileRules({ host: [], glob: ['https://a.example/x?y=1*'], path: [] }).glob[0].re;
  assert.ok(re.test('https://a.example/x?y=1zzz'));
  assert.ok(!re.test('https://a.example/x?y=2zzz'));
});

test('compileRules 大写 host 归一小写', () => {
  const rules = br.createEmptyRules();
  br.addRule(rules, 'EVIL.COM');
  const compiled = br.compileRules(rules);
  assert.ok(compiled.host.has('evil.com'));
  assert.ok(br.decideBlocked('https://EVIL.COM/x', compiled, null));
});
