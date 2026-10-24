'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T20Classify, E70T20_CLASS, E70T20_BLOCK, E70T20_WARN, E70T20_ALLOW } = require('./e70laocatalogguard.js')

test('E70T20 block classification', () => {
  for (const v of E70T20_BLOCK) assert.equal(E70T20Classify(v), E70T20_CLASS.BLOCK, v)
})

test('E70T20 warn classification', () => {
  for (const v of E70T20_WARN) assert.equal(E70T20Classify(v), E70T20_CLASS.WARN, v)
})

test('E70T20 allow classification', () => {
  for (const v of E70T20_ALLOW) assert.equal(E70T20Classify(v), E70T20_CLASS.ALLOW, v)
})

test('E70T20 unknown classification', () => {
  assert.equal(E70T20Classify('zzz-not-in-any-e70-catalog-99'), E70T20_CLASS.UNKNOWN)
})
