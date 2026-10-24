'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T14Classify, E69T14_CLASS, E69T14_BLOCK, E69T14_WARN, E69T14_ALLOW } = require('./e69mongoliancatalogguard.js')

test('E69T14 block classification', () => {
  for (const v of E69T14_BLOCK) assert.equal(E69T14Classify(v), E69T14_CLASS.BLOCK, v)
})

test('E69T14 warn classification', () => {
  for (const v of E69T14_WARN) assert.equal(E69T14Classify(v), E69T14_CLASS.WARN, v)
})

test('E69T14 allow classification', () => {
  for (const v of E69T14_ALLOW) assert.equal(E69T14Classify(v), E69T14_CLASS.ALLOW, v)
})

test('E69T14 unknown classification', () => {
  assert.equal(E69T14Classify('zzz-not-in-any-e69-catalog-88'), E69T14_CLASS.UNKNOWN)
})
