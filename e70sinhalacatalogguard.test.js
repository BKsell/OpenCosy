'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T18Classify, E70T18_CLASS, E70T18_BLOCK, E70T18_WARN, E70T18_ALLOW } = require('./e70sinhalacatalogguard.js')

test('E70T18 block classification', () => {
  for (const v of E70T18_BLOCK) assert.equal(E70T18Classify(v), E70T18_CLASS.BLOCK, v)
})

test('E70T18 warn classification', () => {
  for (const v of E70T18_WARN) assert.equal(E70T18Classify(v), E70T18_CLASS.WARN, v)
})

test('E70T18 allow classification', () => {
  for (const v of E70T18_ALLOW) assert.equal(E70T18Classify(v), E70T18_CLASS.ALLOW, v)
})

test('E70T18 unknown classification', () => {
  assert.equal(E70T18Classify('zzz-not-in-any-e70-catalog-99'), E70T18_CLASS.UNKNOWN)
})
