'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T40Classify, E69T40_CLASS, E69T40_BLOCK, E69T40_WARN, E69T40_ALLOW } = require('./e69variationselectorscatalogguard.js')

test('E69T40 block classification', () => {
  for (const v of E69T40_BLOCK) assert.equal(E69T40Classify(v), E69T40_CLASS.BLOCK, v)
})

test('E69T40 warn classification', () => {
  for (const v of E69T40_WARN) assert.equal(E69T40Classify(v), E69T40_CLASS.WARN, v)
})

test('E69T40 allow classification', () => {
  for (const v of E69T40_ALLOW) assert.equal(E69T40Classify(v), E69T40_CLASS.ALLOW, v)
})

test('E69T40 unknown classification', () => {
  assert.equal(E69T40Classify('zzz-not-in-any-e69-catalog-88'), E69T40_CLASS.UNKNOWN)
})
