'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const s = require('./shortcutconflictresolver');

test('desired 空闲直接用', () => {
  const r = s.pickFallbackAccelerator({
    desired: 'Ctrl+Shift+N',
    existing: ['Ctrl+T', 'Ctrl+W'],
  });
  assert.equal(r.chosen, 'Ctrl+Shift+N');
  assert.equal(r.collisionsWithExisting, false);
});

test('desired 冲突，选第一个空闲 fallback', () => {
  const r = s.pickFallbackAccelerator({
    desired: 'Ctrl+Shift+N',
    existing: ['Ctrl+Shift+N', 'Ctrl+Alt+N'],
    preferredFallback: ['Ctrl+Alt+N', 'Ctrl+Shift+K'],
  });
  assert.equal(r.chosen, 'Ctrl+Shift+K');
  assert.equal(r.collisionsWithExisting, true);
});

test('全部 fallback 冲突返回 null', () => {
  const r = s.pickFallbackAccelerator({
    desired: 'Ctrl+Shift+N',
    existing: ['Ctrl+Shift+N', 'Ctrl+Shift+K', 'Ctrl+Alt+N'],
    preferredFallback: ['Ctrl+Shift+K', 'Ctrl+Alt+N'],
  });
  assert.equal(r.chosen, null);
});

test('大小写不敏感', () => {
  const r = s.pickFallbackAccelerator({
    desired: 'ctrl+shift+n',
    existing: ['Ctrl+Shift+N'],
    preferredFallback: ['Ctrl+Shift+K'],
  });
  assert.equal(r.chosen, 'Ctrl+Shift+K');
});

test('语法粗判', () => {
  assert.equal(s.isAcceleratorSyntaxOk('Ctrl+Shift+N'), true);
  assert.equal(s.isAcceleratorSyntaxOk('F5'), false);
  assert.equal(s.isAcceleratorSyntaxOk(''), false);
  assert.equal(s.isAcceleratorSyntaxOk('Ctrl+Shift'), false);
});
