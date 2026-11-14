'use strict';

const test = require('node:test');
const assert = require('node:assert');
const pagesave = require('./pagesave');

test('buildSaveName strips illegal characters', () => {
  assert.equal(pagesave.buildSaveName('a/b:c*d?e"f<g>h|i', '.html'), 'a_b_c_d_e_f_g_h_i.html');
  assert.equal(pagesave.buildSaveName('  标题  ', '.html'), '标题.html');
});

test('buildSaveName falls back and trims', () => {
  assert.equal(pagesave.buildSaveName('', '.html'), 'page.html');
  assert.equal(pagesave.buildSaveName('...', '.html'), 'page.html');
  assert.equal(pagesave.buildSaveName('trailing. ', '.html'), 'trailing.html');
  const long = 'x'.repeat(200);
  assert.equal(pagesave.buildSaveName(long, '.html').length, 125);
});

test('buildSaveName guards reserved device names', () => {
  assert.equal(pagesave.buildSaveName('CON', '.html'), 'CON_.html');
  assert.equal(pagesave.buildSaveName('lpt1', '.html'), 'lpt1_.html');
  assert.equal(pagesave.buildSaveName('console', '.html'), 'console.html');
});

test('normalizeSavePath appends fallback extension', () => {
  assert.equal(pagesave.normalizeSavePath('a', ['.html', '.htm'], '.html'), 'a.html');
  assert.equal(pagesave.normalizeSavePath('a.htm', ['.html', '.htm'], '.html'), 'a.htm');
  assert.equal(pagesave.normalizeSavePath('a.HTML', ['.html'], '.html'), 'a.HTML');
  assert.equal(pagesave.normalizeSavePath('  ', ['.html'], '.html'), '');
});

test('classifySaveResult distinguishes cancel and failure', () => {
  assert.equal(pagesave.classifySaveResult(false, true), 'canceled');
  assert.equal(pagesave.classifySaveResult(true, false), 'saved');
  assert.equal(pagesave.classifySaveResult(false, false), 'failed');
});
