'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T31Classify, E69T31_CLASS, E69T31_BLOCK, E69T31_WARN, E69T31_ALLOW } = require('./e69yijinghexagramcatalogguard.js')

test('E69T31 block classification', () => {
  for (const v of E69T31_BLOCK) assert.equal(E69T31Classify(v), E69T31_CLASS.BLOCK, v)
})

test('E69T31 warn classification', () => {
  for (const v of E69T31_WARN) assert.equal(E69T31Classify(v), E69T31_CLASS.WARN, v)
})

test('E69T31 allow classification', () => {
  for (const v of E69T31_ALLOW) assert.equal(E69T31Classify(v), E69T31_CLASS.ALLOW, v)
})

test('E69T31 unknown classification', () => {
  assert.equal(E69T31Classify('zzz-not-in-any-e69-catalog-88'), E69T31_CLASS.UNKNOWN)
})
