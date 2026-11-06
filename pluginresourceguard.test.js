'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const plugins = require('./pluginresourceguard');

const { REASON, evaluatePluginResource, describeReason } = plugins;

nodeTest.test('ordinary script and image resources pass', () => {
  for (const type of ['script', 'image', 'stylesheet', 'xhr', 'subFrame']) {
    const verdict = evaluatePluginResource({ url: 'https://example.com/a', resourceType: type });
    assert.equal(verdict.action, 'allow', type);
  }
});

nodeTest.test('object resource is cancelled', () => {
  const verdict = evaluatePluginResource({ url: 'https://example.com/player', resourceType: 'object' });
  assert.equal(verdict.action, 'cancel');
  assert.equal(verdict.reason, REASON.LEGACY_OBJECT);
});

nodeTest.test('plugin resource is cancelled', () => {
  const verdict = evaluatePluginResource({ url: 'https://example.com/x', resourceType: 'plugin' });
  assert.equal(verdict.reason, REASON.LEGACY_OBJECT);
});

nodeTest.test('resource type matching is case insensitive', () => {
  const verdict = evaluatePluginResource({ url: 'https://example.com/x', resourceType: 'OBJECT' });
  assert.equal(verdict.reason, REASON.LEGACY_OBJECT);
});

nodeTest.test('cosy internal resources are exempt from object blocking', () => {
  const verdict = evaluatePluginResource({ url: 'cosy://settings/index.html', resourceType: 'object' });
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.INTERNAL_ALLOWED);
});

nodeTest.test('flash file paths are cancelled even as image resource', () => {
  const verdict = evaluatePluginResource({ url: 'https://example.com/banner.swf', resourceType: 'image' });
  assert.equal(verdict.action, 'cancel');
  assert.equal(verdict.reason, REASON.FLASH_CONTENT);
});

nodeTest.test('flash query and fragment forms are cancelled', () => {
  assert.equal(evaluatePluginResource({ url: 'https://example.com/a.swf?v=1' }).reason, REASON.FLASH_CONTENT);
  assert.equal(evaluatePluginResource({ url: 'https://example.com/a.swf#x' }).reason, REASON.FLASH_CONTENT);
});

nodeTest.test('flash url matching is case insensitive', () => {
  assert.equal(evaluatePluginResource({ url: 'https://example.com/A.SWF' }).reason, REASON.FLASH_CONTENT);
});

nodeTest.test('data object is cancelled with a dedicated reason', () => {
  const verdict = evaluatePluginResource({ url: 'data:text/html,<embed>', resourceType: 'object' });
  assert.equal(verdict.reason, REASON.DATA_OBJECT);
});

nodeTest.test('data: image is not blocked', () => {
  const verdict = evaluatePluginResource({ url: 'data:image/png;base64,AA', resourceType: 'image' });
  assert.equal(verdict.action, 'allow');
});

nodeTest.test('missing input defaults to allow', () => {
  assert.equal(evaluatePluginResource().action, 'allow');
});

nodeTest.test('describeReason covers every reason code', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0);
  }
  assert.equal(describeReason('other'), '未知原因');
});
