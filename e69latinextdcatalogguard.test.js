'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T32Classify, E69T32_CLASS, E69T32_BLOCK, E69T32_WARN, E69T32_ALLOW } = require('./e69latinextdcatalogguard.js')

test('E69T32 block classification', () => {
  for (const v of E69T32_BLOCK) assert.equal(E69T32Classify(v), E69T32_CLASS.BLOCK, v)
})

test('E69T32 warn classification', () => {
  for (const v of E69T32_WARN) assert.equal(E69T32Classify(v), E69T32_CLASS.WARN, v)
})

test('E69T32 allow classification', () => {
  for (const v of E69T32_ALLOW) assert.equal(E69T32Classify(v), E69T32_CLASS.ALLOW, v)
})

test('E69T32 unknown classification', () => {
  assert.equal(E69T32Classify('zzz-not-in-any-e69-catalog-88'), E69T32_CLASS.UNKNOWN)
})
