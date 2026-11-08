'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  SEVERITY_CRITICAL,
  SEVERITY_WARN,
  tokenizeSwitchArgs,
  splitExtraLaunchArgs,
  analyzeFlag,
  auditSwitches,
  collectSources,
} = require('./switchguard');

test('tokenizeSwitchArgs 识别 flag 与键值', () => {
  const toks = tokenizeSwitchArgs([
    'OpenCosy.exe', '--disable-web-security',
    '--remote-debugging-port=9222', 'positional', '--single-process',
  ], 'argv');
  const names = toks.map(t => t.name);
  assert.deepEqual(names, [
    'disable-web-security',
    'remote-debugging-port',
    'single-process',
  ]);
  const port = toks.find(t => t.name === 'remote-debugging-port');
  assert.equal(port.hasValue, true);
  assert.equal(port.value, '9222');
  const dws = toks.find(t => t.name === 'disable-web-security');
  assert.equal(dws.hasValue, false);
});

test('splitExtraLaunchArgs 处理引号包裹的带空格值', () => {
  const out = splitExtraLaunchArgs('--proxy-server="http://127.0.0.1:8080" --no-sandbox');
  assert.deepEqual(out, ['--proxy-server=http://127.0.0.1:8080', '--no-sandbox']);
  assert.deepEqual(splitExtraLaunchArgs('   '), []);
});

test('analyzeFlag 精确命中 critical 开关', () => {
  for (const name of [
    'disable-web-security', 'ignore-certificate-errors', 'no-sandbox',
    'remote-debugging-port', 'proxy-server', 'host-resolver-rules',
    'js-flags', 'allow-file-access-from-files', 'single-process',
  ]) {
    const v = analyzeFlag({ name, hasValue: false, value: '' });
    assert.equal(v && v.severity, SEVERITY_CRITICAL, `${name} 应 critical`);
  }
});

test('analyzeFlag warn 开关', () => {
  const v = analyzeFlag({ name: 'disable-popup-blocking', hasValue: false, value: '' });
  assert.equal(v.severity, SEVERITY_WARN);
});

test('disable-features 命中受保护安全特性判 critical', () => {
  const hit = analyzeFlag({
    name: 'disable-features', hasValue: true,
    value: 'MediaRouter,SameSiteByDefaultCookies,SomeOtherThing',
  });
  assert.equal(hit.severity, SEVERITY_CRITICAL);
  assert.match(hit.reason, /SameSiteByDefaultCookies/);

  const miss = analyzeFlag({
    name: 'disable-features', hasValue: true, value: 'MediaRouter,UnrelatedThing',
  });
  assert.equal(miss.severity, SEVERITY_WARN);
});

test('普通无关开关判安全', () => {
  assert.equal(analyzeFlag({ name: 'autoplay-policy', hasValue: true, value: 'x' }), null);
  assert.equal(analyzeFlag({ name: 'window-size', hasValue: true, value: '800,600' }), null);
});

test('auditSwitches 同时覆盖 argv 与环境变量注入', () => {
  const r = auditSwitches({
    argv: ['--disable-web-security', '--disable-popup-blocking'],
    extraLaunchArgs: '--remote-debugging-port=9222',
  });
  assert.equal(r.hasCritical, true);
  const critNames = r.criticalFlags.map(f => f.name).sort();
  assert.deepEqual(critNames, ['disable-web-security', 'remote-debugging-port']);
  assert.equal(r.warnFlags.length, 1);
  assert.equal(r.envInjected, true);
  // 环境变量来源被正确标记。
  assert.ok(r.criticalFlags.some(f => f.source === 'env:ELECTRON_EXTRA_LAUNCH_ARGS'));
});

test('auditSwitches 干净启动零发现', () => {
  const r = auditSwitches({ argv: ['--autoplay-policy=document-user-activation-required'], extraLaunchArgs: '' });
  assert.equal(r.hasCritical, false);
  assert.equal(r.findings.length, 0);
});

test('collectSources 去掉前两个 argv 并取环境变量', () => {
  const s = collectSources({
    argv: ['electron', 'app', '--no-sandbox', '--x=1'],
    env: { ELECTRON_EXTRA_LAUNCH_ARGS: '--proxy-server=x' },
  });
  assert.deepEqual(s.argv, ['--no-sandbox', '--x=1']);
  assert.equal(s.extraLaunchArgs, '--proxy-server=x');
  const empty = collectSources(undefined);
  assert.deepEqual(empty.argv, []);
  assert.equal(empty.extraLaunchArgs, '');
});

test('引号内空格的值能被识别为代理注入', () => {
  const r = auditSwitches({
    argv: [],
    extraLaunchArgs: '--host-resolver-rules="MAP * 127.0.0.1"',
  });
  assert.equal(r.hasCritical, true);
  assert.equal(r.criticalFlags[0].name, 'host-resolver-rules');
});
