'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T31Classify, E70T31_CLASS, E70T31_BLOCK, E70T31_WARN, E70T31_ALLOW } = require('./e70batakcatalogguard.js')

test('E70T31 block classification', () => {
  for (const v of E70T31_BLOCK) assert.equal(E70T31Classify(v), E70T31_CLASS.BLOCK, v)
})

test('E70T31 warn classification', () => {
  for (const v of E70T31_WARN) assert.equal(E70T31Classify(v), E70T31_CLASS.WARN, v)
})

test('E70T31 allow classification', () => {
  for (const v of E70T31_ALLOW) assert.equal(E70T31Classify(v), E70T31_CLASS.ALLOW, v)
})

test('E70T31 unknown classification', () => {
  assert.equal(E70T31Classify('zzz-not-in-any-e70-catalog-99'), E70T31_CLASS.UNKNOWN)
})
