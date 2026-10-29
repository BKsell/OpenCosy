'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const m = require('./mediasessionfocus');

test('无 handler 直接丢', () => {
  const r = m.decideMediaKeyDispatch({ audible: true, focusedTab: true, hasMediaSessionHandler: false });
  assert.equal(r.action, 'drop');
});

test('发声标签即使后台也发键', () => {
  const r = m.decideMediaKeyDispatch({ audible: true, focusedTab: false, hasMediaSessionHandler: true });
  assert.equal(r.action, 'dispatch');
});

test('前台未发声标签发键', () => {
  const r = m.decideMediaKeyDispatch({ audible: false, focusedTab: true, hasMediaSessionHandler: true });
  assert.equal(r.action, 'dispatch');
});

test('后台未发声标签默认拦', () => {
  const r = m.decideMediaKeyDispatch({ audible: false, focusedTab: false, hasMediaSessionHandler: true });
  assert.equal(r.action, 'drop');
  assert.equal(r.reason, 'background-hijack-blocked');
});

test('用户允许后台才发', () => {
  const r = m.decideMediaKeyDispatch({
    audible: false, focusedTab: false,
    hasMediaSessionHandler: true, backgroundKeyHijackAllowed: true,
  });
  assert.equal(r.action, 'dispatch');
});

test('已知动作名', () => {
  assert.equal(m.isMediaSessionActionKnown('nexttrack'), true);
  assert.equal(m.isMediaSessionActionKnown('play'), true);
  assert.equal(m.isMediaSessionActionKnown('reboot'), false);
  assert.equal(m.isMediaSessionActionKnown(''), false);
});
