'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T46Classify, E70T46_CLASS, E70T46_BLOCK, E70T46_WARN, E70T46_ALLOW } = require('./e70blockelementscatalogguard.js')

test('E70T46 block classification', () => {
  for (const v of E70T46_BLOCK) assert.equal(E70T46Classify(v), E70T46_CLASS.BLOCK, v)
})

test('E70T46 warn classification', () => {
  for (const v of E70T46_WARN) assert.equal(E70T46Classify(v), E70T46_CLASS.WARN, v)
})

test('E70T46 allow classification', () => {
  for (const v of E70T46_ALLOW) assert.equal(E70T46Classify(v), E70T46_CLASS.ALLOW, v)
})

test('E70T46 unknown classification', () => {
  assert.equal(E70T46Classify('zzz-not-in-any-e70-catalog-99'), E70T46_CLASS.UNKNOWN)
})
