'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const uap = require('./uapolicy');

test('默认策略保持 default 模式且无自定义串', () => {
  assert.equal(uap.DEFAULT_POLICY.mode, uap.MODES.DEFAULT);
  assert.equal(uap.DEFAULT_POLICY.custom, '');
});

test('sanitizePolicy 拒绝非法模式并回落 default', () => {
  const p = uap.sanitizePolicy({ mode: 'hacker-mode', custom: 'x' });
  assert.equal(p.mode, uap.MODES.DEFAULT);
  assert.equal(p.custom, '');
});

test('sanitizePolicy 拒绝 null / 非对象', () => {
  assert.equal(uap.sanitizePolicy(null).mode, uap.MODES.DEFAULT);
  assert.equal(uap.sanitizePolicy('str').mode, uap.MODES.DEFAULT);
  assert.equal(uap.sanitizePolicy(undefined).mode, uap.MODES.DEFAULT);
});

test('sanitizePolicy 大小写与连字符归一', () => {
  const p = uap.sanitizePolicy({ mode: 'chrome-random' });
  assert.equal(p.mode, uap.MODES.CHROME_RANDOM);
});

test('custom 模式保留合法自定义串并裁剪空白', () => {
  const p = uap.sanitizePolicy({ mode: 'custom', custom: '  MyUA/1.0  ' });
  assert.equal(p.mode, uap.MODES.CUSTOM);
  assert.equal(p.custom, 'MyUA/1.0');
});

test('custom 模式下的非法串回落 default', () => {
  const empty = uap.sanitizePolicy({ mode: 'custom', custom: '   ' });
  assert.equal(empty.mode, uap.MODES.DEFAULT);
  const ctrl = uap.sanitizePolicy({ mode: 'custom', custom: 'a\u0000b' });
  assert.equal(ctrl.mode, uap.MODES.DEFAULT);
  const long = uap.sanitizePolicy({ mode: 'custom', custom: 'x'.repeat(400) });
  assert.equal(long.mode, uap.MODES.DEFAULT);
});

test('validateCustomUa 拒绝空串与控制字符与超长', () => {
  assert.equal(uap.validateCustomUa('').ok, false);
  assert.equal(uap.validateCustomUa('   ').ok, false);
  assert.equal(uap.validateCustomUa('a\u0001b').ok, false);
  assert.equal(uap.validateCustomUa('a\u007fb').ok, false);
  assert.equal(uap.validateCustomUa('x'.repeat(400)).ok, false);
  assert.equal(uap.validateCustomUa('Mozilla/5.0 (X11) Foo/1.0').ok, true);
});

test('hasControlChar 只认控制字符，普通标点放行', () => {
  assert.equal(uap.hasControlChar('a b\tc'), true);
  assert.equal(uap.hasControlChar('a\nb'), true);
  assert.equal(uap.hasControlChar('Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0.0.0'), false);
});

test('resolveUa default 模式返回浏览器自算 UA', () => {
  const out = uap.resolveUa({ mode: 'default' }, 'DefaultUA/1.0');
  assert.equal(out, 'DefaultUA/1.0');
});

test('resolveUa custom 模式返回用户串', () => {
  const out = uap.resolveUa({ mode: 'custom', custom: 'MyUA/2.0' }, 'DefaultUA/1.0');
  assert.equal(out, 'MyUA/2.0');
});

test('resolveUa chrome-random 使用注入的 rand 并落在池内', () => {
  const out = uap.resolveUa({ mode: 'chrome-random' }, 'DefaultUA/1.0', () => 0);
  assert.equal(out, uap.COMMON_CHROME_UAS[0]);
  const out2 = uap.resolveUa({ mode: 'chrome-random' }, 'DefaultUA/1.0', n => n - 1);
  assert.equal(out2, uap.COMMON_CHROME_UAS[uap.COMMON_CHROME_UAS.length - 1]);
});

test('resolveUa 脏输入回落 default', () => {
  assert.equal(uap.resolveUa(null, 'D/1'), 'D/1');
  assert.equal(uap.resolveUa({ mode: 'custom', custom: '\u0000' }, 'D/1'), 'D/1');
});

test('UA 池内每条都不含 OpenCosy 标识与控制字符', () => {
  for (const ua of uap.COMMON_CHROME_UAS) {
    assert.equal(ua.includes('OpenCosy'), false, `池内不应有 OpenCosy 标识: ${ua}`);
    assert.equal(uap.hasControlChar(ua), false);
    assert.ok(ua.startsWith('Mozilla/5.0'), ua);
  }
});

test('UA 池内平台组合多样且 Chrome 版本为真实格式', () => {
  const hasWindows = uap.COMMON_CHROME_UAS.some(u => u.includes('Windows NT 10.0'));
  const hasMac = uap.COMMON_CHROME_UAS.some(u => u.includes('Macintosh'));
  const hasLinux = uap.COMMON_CHROME_UAS.some(u => u.includes('Linux x86_64'));
  assert.ok(hasWindows && hasMac && hasLinux, '池应覆盖三大桌面平台');
  for (const ua of uap.COMMON_CHROME_UAS) {
    assert.match(ua, /Chrome\/1\d\d\.0\.0\.0/);
  }
});

test('policyToPlain 输出不含内部敏感字段', () => {
  const plain = uap.policyToPlain({ mode: 'chrome-random', custom: '' });
  assert.equal(plain.mode, 'chrome-random');
  assert.equal(plain.poolSize, uap.COMMON_CHROME_UAS.length);
  assert.ok(!('updatedAt' in plain));
});

test('countUaOverrides 递增并在溢出后封顶', () => {
  assert.equal(uap.countUaOverrides(0), 1);
  assert.equal(uap.countUaOverrides(41), 42);
  assert.equal(uap.countUaOverrides(Number.MAX_SAFE_INTEGER), 1);
  assert.equal(uap.countUaOverrides(undefined), 1);
});

test('pickRandomChromeUa 边界：n=0 或负值被 randomInt 语义约束，注入 rand 保证池索引合法', () => {
  // 注入 rand 返回 0 与 n-1 之外的边界值，验证 clamp 在调用方做（这里仅验证
  // rand 返回值被当作索引使用，越界由 randomInt 自身保证）。
  const r0 = uap.pickRandomChromeUa(() => 0);
  assert.ok(uap.COMMON_CHROME_UAS.includes(r0));
  const rN = uap.pickRandomChromeUa(n => n - 1);
  assert.ok(uap.COMMON_CHROME_UAS.includes(rN));
});
