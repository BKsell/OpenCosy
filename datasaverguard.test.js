'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const d = require('./datasaverguard');

test('offline 最高优先', () => {
  assert.equal(d.decideTier(true, true, false), d.TIER.OFFLINE);
});

test('saveData 开关', () => {
  assert.equal(d.decideTier(true, false, false), d.TIER.SAVE);
  assert.equal(d.decideTier(true, false, true), d.TIER.FULL);
});

test('默认 full', () => {
  assert.equal(d.decideTier(false, false, false), d.TIER.FULL);
});

test('媒体自动拦', () => {
  assert.equal(d.shouldAutoBlockMedia(d.TIER.SAVE, 'video'), true);
  assert.equal(d.shouldAutoBlockMedia(d.TIER.SAVE, 'animated-gif'), true);
  assert.equal(d.shouldAutoBlockMedia(d.TIER.SAVE, 'image'), false);
  assert.equal(d.shouldAutoBlockMedia(d.TIER.FULL, 'video'), false);
});

test('大图降档', () => {
  assert.equal(d.shouldDownscaleImage(d.TIER.SAVE, 500 * 1024), true);
  assert.equal(d.shouldDownscaleImage(d.TIER.SAVE, 100 * 1024), false);
  assert.equal(d.shouldDownscaleImage(d.TIER.FULL, 500 * 1024), false);
});

test('Save-Data 头', () => {
  assert.equal(d.saveDataHeaderValue(d.TIER.SAVE), 'on');
  assert.equal(d.saveDataHeaderValue(d.TIER.FULL), '');
  assert.equal(d.saveDataHeaderValue(d.TIER.OFFLINE), '');
});
