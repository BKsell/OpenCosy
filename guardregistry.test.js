'use strict';

const test = require('node:test');
const assert = require('node:assert');
const modules = require('./guardindex.js');

const CLEAN = { enabled: true, reportOnly: false, mode: 'enforce', maxItems: 8, endpoint: 'https://example.com/report', note: 'ok', fallbackPath: 'fallback.html', items: ['default-src', 'script-src'], baseline: ['default-src'], origins: ['self'] };

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('guard index is a plain list of module bases', () => {
  assert.equal(modules.length > 0, true);
  for (const base of modules) {
    assert.equal(typeof base, 'string');
    assert.equal(base.endsWith('guard'), false);
  }
});

test('every guard module exposes the shared contract', () => {
  for (const base of modules) {
    const camel = base.charAt(0).toUpperCase() + base.slice(1);
    const guard = require('./' + base + 'guard.js');
    assert.equal(typeof guard['evaluate' + camel + 'Guard'], 'function');
    assert.equal(typeof guard['summarize' + camel + 'Guard'], 'function');
    assert.equal(typeof guard['describe' + camel + 'Guard'], 'function');
    assert.equal(guard.LIMITS.maxItems, 32);
    assert.equal(guard.LIMITS.maxLength, 512);
    assert.equal(guard.RULES.length, 13);
  }
});

test('every guard module keeps its own rule prefix', () => {
  for (const base of modules) {
    const guard = require('./' + base + 'guard.js');
    const prefix = guard.RULES[0].key.split('_')[0];
    assert.equal(prefix.length > 0, true);
    for (const rule of guard.RULES) {
      assert.equal(rule.key.startsWith(prefix + '_'), true);
    }
  }
});

test('every guard module accepts the clean baseline', () => {
  for (const base of modules) {
    const camel = base.charAt(0).toUpperCase() + base.slice(1);
    const guard = require('./' + base + 'guard.js');
    const result = guard['evaluate' + camel + 'Guard'](clone(CLEAN));
    assert.equal(result.ok, true, base + ' should accept clean config');
    assert.equal(guard['summarize' + camel + 'Guard'](clone(CLEAN)).total, 0);
  }
});

test('every guard module blocks a disabled guard', () => {
  for (const base of modules) {
    const camel = base.charAt(0).toUpperCase() + base.slice(1);
    const guard = require('./' + base + 'guard.js');
    const config = clone(CLEAN);
    config.enabled = false;
    const result = guard['evaluate' + camel + 'Guard'](config);
    assert.equal(result.ok, false, base + ' should reject enabled=false');
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].blocking, true);
  }
});

test('every guard module describes itself with its own name', () => {
  for (const base of modules) {
    const camel = base.charAt(0).toUpperCase() + base.slice(1);
    const guard = require('./' + base + 'guard.js');
    assert.equal(guard['describe' + camel + 'Guard'](clone(CLEAN)), base + ' 配置通过全部检查');
  }
});
