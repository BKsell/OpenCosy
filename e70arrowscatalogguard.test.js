'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T40Classify, E70T40_CLASS, E70T40_BLOCK, E70T40_WARN, E70T40_ALLOW } = require('./e70arrowscatalogguard.js')

test('E70T40 block classification', () => {
  for (const v of E70T40_BLOCK) assert.equal(E70T40Classify(v), E70T40_CLASS.BLOCK, v)
})

test('E70T40 warn classification', () => {
  for (const v of E70T40_WARN) assert.equal(E70T40Classify(v), E70T40_CLASS.WARN, v)
})

test('E70T40 allow classification', () => {
  for (const v of E70T40_ALLOW) assert.equal(E70T40Classify(v), E70T40_CLASS.ALLOW, v)
})

test('E70T40 unknown classification', () => {
  assert.equal(E70T40Classify('zzz-not-in-any-e70-catalog-99'), E70T40_CLASS.UNKNOWN)
})
