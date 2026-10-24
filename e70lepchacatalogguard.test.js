'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T32Classify, E70T32_CLASS, E70T32_BLOCK, E70T32_WARN, E70T32_ALLOW } = require('./e70lepchacatalogguard.js')

test('E70T32 block classification', () => {
  for (const v of E70T32_BLOCK) assert.equal(E70T32Classify(v), E70T32_CLASS.BLOCK, v)
})

test('E70T32 warn classification', () => {
  for (const v of E70T32_WARN) assert.equal(E70T32Classify(v), E70T32_CLASS.WARN, v)
})

test('E70T32 allow classification', () => {
  for (const v of E70T32_ALLOW) assert.equal(E70T32Classify(v), E70T32_CLASS.ALLOW, v)
})

test('E70T32 unknown classification', () => {
  assert.equal(E70T32Classify('zzz-not-in-any-e70-catalog-99'), E70T32_CLASS.UNKNOWN)
})
