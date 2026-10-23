'use strict';

// contactpickerguard.test.js —— Contact Picker：手势/可见、字段白名单、address/icon、multiple、返回条数、频率。

const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('./contactpickerguard');
const { ContactPickerGuard, CP_REASON, defaultContactPickerPolicy } = c;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://m.example.com', userGesture: true, visible: true }, over || {}); }

test('合规单选 name+tel 放行', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideSelect(ctx(), ['name', 'tel'], {}).decision, 'allow');
});

test('无手势/不可见/非 https 拒绝', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideSelect(ctx({ userGesture: false }), ['name'], {}).reason, CP_REASON.NO_GESTURE);
  assert.equal(g.decideSelect(ctx({ visible: false }), ['name'], {}).reason, CP_REASON.NOT_VISIBLE);
  assert.equal(g.decideSelect(ctx({ origin: 'http://x' }), ['name'], {}).reason, CP_REASON.INSECURE_ORIGIN);
});

test('空字段/不支持字段拒绝', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideSelect(ctx(), [], {}).reason, CP_REASON.NO_PROPERTIES);
  assert.equal(g.decideSelect(ctx(), ['ssn'], {}).reason, CP_REASON.PROPERTY_NOT_ALLOWED);
});

test('address/icon 默认拒绝', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideSelect(ctx(), ['address'], {}).reason, CP_REASON.ADDRESS_ICON_DISABLED);
  assert.equal(g.decideSelect(ctx(), ['icon'], {}).reason, CP_REASON.ADDRESS_ICON_DISABLED);
});

test('multiple 默认拒绝，放开后允许', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideSelect(ctx(), ['name'], { multiple: true }).reason, CP_REASON.MULTIPLE_DISABLED);
  const pol = defaultContactPickerPolicy();
  pol.allowMultiple = true;
  pol.maxContacts = 20;
  const g2 = new ContactPickerGuard(pol, clock);
  assert.equal(g2.decideSelect(ctx(), ['name'], { multiple: true }).decision, 'allow');
});

test('返回联系人条数上限', () => {
  const g = new ContactPickerGuard(undefined, clock);
  assert.equal(g.decideResult([{ name: ['a'] }, { name: ['b'] }]).reason, CP_REASON.TOO_MANY_CONTACTS);
  assert.equal(g.decideResult([{ name: ['a'] }]).decision, 'allow');
});

test('选择频率上限', () => {
  const pol = defaultContactPickerPolicy();
  pol.maxPicksPerMinute = 2;
  const g = new ContactPickerGuard(pol, clock);
  assert.equal(g.decideSelect(ctx(), ['name'], {}).decision, 'allow');
  assert.equal(g.decideSelect(ctx(), ['name'], {}).decision, 'allow');
  assert.equal(g.decideSelect(ctx(), ['name'], {}).reason, CP_REASON.RATE_LIMIT);
});
