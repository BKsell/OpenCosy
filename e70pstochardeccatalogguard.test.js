'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PTDClassify, E70PTD_CLASS, E70PTD_BLOCK, E70PTD_WARN, E70PTD_ALLOW } = require('./e70pstochardeccatalogguard.js')

test('E70PTD block classification', () => {
  for (const v of E70PTD_BLOCK) assert.equal(E70PTDClassify(v), E70PTD_CLASS.BLOCK, v)
})

test('E70PTD warn classification', () => {
  for (const v of E70PTD_WARN) assert.equal(E70PTDClassify(v), E70PTD_CLASS.WARN, v)
})

test('E70PTD allow classification', () => {
  for (const v of E70PTD_ALLOW) assert.equal(E70PTDClassify(v), E70PTD_CLASS.ALLOW, v)
})

test('E70PTD unknown classification', () => {
  assert.equal(E70PTDClassify('zzz-not-in-any-e70-catalog-99'), E70PTD_CLASS.UNKNOWN)
})
