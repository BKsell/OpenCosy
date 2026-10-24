'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T15Classify, E70T15_CLASS, E70T15_BLOCK, E70T15_WARN, E70T15_ALLOW } = require('./e70telugucatalogguard.js')

test('E70T15 block classification', () => {
  for (const v of E70T15_BLOCK) assert.equal(E70T15Classify(v), E70T15_CLASS.BLOCK, v)
})

test('E70T15 warn classification', () => {
  for (const v of E70T15_WARN) assert.equal(E70T15Classify(v), E70T15_CLASS.WARN, v)
})

test('E70T15 allow classification', () => {
  for (const v of E70T15_ALLOW) assert.equal(E70T15Classify(v), E70T15_CLASS.ALLOW, v)
})

test('E70T15 unknown classification', () => {
  assert.equal(E70T15Classify('zzz-not-in-any-e70-catalog-99'), E70T15_CLASS.UNKNOWN)
})
