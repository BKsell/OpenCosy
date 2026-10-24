'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T04Classify, E70T04_CLASS, E70T04_BLOCK, E70T04_WARN, E70T04_ALLOW } = require('./e70arabicsuppcatalogguard.js')

test('E70T04 block classification', () => {
  for (const v of E70T04_BLOCK) assert.equal(E70T04Classify(v), E70T04_CLASS.BLOCK, v)
})

test('E70T04 warn classification', () => {
  for (const v of E70T04_WARN) assert.equal(E70T04Classify(v), E70T04_CLASS.WARN, v)
})

test('E70T04 allow classification', () => {
  for (const v of E70T04_ALLOW) assert.equal(E70T04Classify(v), E70T04_CLASS.ALLOW, v)
})

test('E70T04 unknown classification', () => {
  assert.equal(E70T04Classify('zzz-not-in-any-e70-catalog-99'), E70T04_CLASS.UNKNOWN)
})
