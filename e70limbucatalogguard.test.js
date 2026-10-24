'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T25Classify, E70T25_CLASS, E70T25_BLOCK, E70T25_WARN, E70T25_ALLOW } = require('./e70limbucatalogguard.js')

test('E70T25 block classification', () => {
  for (const v of E70T25_BLOCK) assert.equal(E70T25Classify(v), E70T25_CLASS.BLOCK, v)
})

test('E70T25 warn classification', () => {
  for (const v of E70T25_WARN) assert.equal(E70T25Classify(v), E70T25_CLASS.WARN, v)
})

test('E70T25 allow classification', () => {
  for (const v of E70T25_ALLOW) assert.equal(E70T25Classify(v), E70T25_CLASS.ALLOW, v)
})

test('E70T25 unknown classification', () => {
  assert.equal(E70T25Classify('zzz-not-in-any-e70-catalog-99'), E70T25_CLASS.UNKNOWN)
})
