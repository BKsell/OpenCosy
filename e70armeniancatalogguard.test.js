'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T00Classify, E70T00_CLASS, E70T00_BLOCK, E70T00_WARN, E70T00_ALLOW } = require('./e70armeniancatalogguard.js')

test('E70T00 block classification', () => {
  for (const v of E70T00_BLOCK) assert.equal(E70T00Classify(v), E70T00_CLASS.BLOCK, v)
})

test('E70T00 warn classification', () => {
  for (const v of E70T00_WARN) assert.equal(E70T00Classify(v), E70T00_CLASS.WARN, v)
})

test('E70T00 allow classification', () => {
  for (const v of E70T00_ALLOW) assert.equal(E70T00Classify(v), E70T00_CLASS.ALLOW, v)
})

test('E70T00 unknown classification', () => {
  assert.equal(E70T00Classify('zzz-not-in-any-e70-catalog-99'), E70T00_CLASS.UNKNOWN)
})
