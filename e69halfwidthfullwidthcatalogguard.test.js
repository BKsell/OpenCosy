'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T36Classify, E69T36_CLASS, E69T36_BLOCK, E69T36_WARN, E69T36_ALLOW } = require('./e69halfwidthfullwidthcatalogguard.js')

test('E69T36 block classification', () => {
  for (const v of E69T36_BLOCK) assert.equal(E69T36Classify(v), E69T36_CLASS.BLOCK, v)
})

test('E69T36 warn classification', () => {
  for (const v of E69T36_WARN) assert.equal(E69T36Classify(v), E69T36_CLASS.WARN, v)
})

test('E69T36 allow classification', () => {
  for (const v of E69T36_ALLOW) assert.equal(E69T36Classify(v), E69T36_CLASS.ALLOW, v)
})

test('E69T36 unknown classification', () => {
  assert.equal(E69T36Classify('zzz-not-in-any-e69-catalog-88'), E69T36_CLASS.UNKNOWN)
})
