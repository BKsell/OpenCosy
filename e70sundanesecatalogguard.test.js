'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T30Classify, E70T30_CLASS, E70T30_BLOCK, E70T30_WARN, E70T30_ALLOW } = require('./e70sundanesecatalogguard.js')

test('E70T30 block classification', () => {
  for (const v of E70T30_BLOCK) assert.equal(E70T30Classify(v), E70T30_CLASS.BLOCK, v)
})

test('E70T30 warn classification', () => {
  for (const v of E70T30_WARN) assert.equal(E70T30Classify(v), E70T30_CLASS.WARN, v)
})

test('E70T30 allow classification', () => {
  for (const v of E70T30_ALLOW) assert.equal(E70T30Classify(v), E70T30_CLASS.ALLOW, v)
})

test('E70T30 unknown classification', () => {
  assert.equal(E70T30Classify('zzz-not-in-any-e70-catalog-99'), E70T30_CLASS.UNKNOWN)
})
