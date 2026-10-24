'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HD6Classify, E70HD6_CLASS, E70HD6_BLOCK, E70HD6_WARN, E70HD6_ALLOW } = require('./e70htmldecpad6catalogguard.js')

test('E70HD6 block classification', () => {
  for (const v of E70HD6_BLOCK) assert.equal(E70HD6Classify(v), E70HD6_CLASS.BLOCK, v)
})

test('E70HD6 warn classification', () => {
  for (const v of E70HD6_WARN) assert.equal(E70HD6Classify(v), E70HD6_CLASS.WARN, v)
})

test('E70HD6 allow classification', () => {
  for (const v of E70HD6_ALLOW) assert.equal(E70HD6Classify(v), E70HD6_CLASS.ALLOW, v)
})

test('E70HD6 unknown classification', () => {
  assert.equal(E70HD6Classify('zzz-not-in-any-e70-catalog-99'), E70HD6_CLASS.UNKNOWN)
})
