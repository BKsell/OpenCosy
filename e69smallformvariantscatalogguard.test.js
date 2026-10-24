'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T34Classify, E69T34_CLASS, E69T34_BLOCK, E69T34_WARN, E69T34_ALLOW } = require('./e69smallformvariantscatalogguard.js')

test('E69T34 block classification', () => {
  for (const v of E69T34_BLOCK) assert.equal(E69T34Classify(v), E69T34_CLASS.BLOCK, v)
})

test('E69T34 warn classification', () => {
  for (const v of E69T34_WARN) assert.equal(E69T34Classify(v), E69T34_CLASS.WARN, v)
})

test('E69T34 allow classification', () => {
  for (const v of E69T34_ALLOW) assert.equal(E69T34Classify(v), E69T34_CLASS.ALLOW, v)
})

test('E69T34 unknown classification', () => {
  assert.equal(E69T34Classify('zzz-not-in-any-e69-catalog-88'), E69T34_CLASS.UNKNOWN)
})
