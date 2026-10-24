'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T51Classify, E70T51_CLASS, E70T51_BLOCK, E70T51_WARN, E70T51_ALLOW } = require('./e70glagoliticcatalogguard.js')

test('E70T51 block classification', () => {
  for (const v of E70T51_BLOCK) assert.equal(E70T51Classify(v), E70T51_CLASS.BLOCK, v)
})

test('E70T51 warn classification', () => {
  for (const v of E70T51_WARN) assert.equal(E70T51Classify(v), E70T51_CLASS.WARN, v)
})

test('E70T51 allow classification', () => {
  for (const v of E70T51_ALLOW) assert.equal(E70T51Classify(v), E70T51_CLASS.ALLOW, v)
})

test('E70T51 unknown classification', () => {
  assert.equal(E70T51Classify('zzz-not-in-any-e70-catalog-99'), E70T51_CLASS.UNKNOWN)
})
