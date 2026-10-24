'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T27Classify, E69T27_CLASS, E69T27_BLOCK, E69T27_WARN, E69T27_ALLOW } = require('./e69bopomofocatalogguard.js')

test('E69T27 block classification', () => {
  for (const v of E69T27_BLOCK) assert.equal(E69T27Classify(v), E69T27_CLASS.BLOCK, v)
})

test('E69T27 warn classification', () => {
  for (const v of E69T27_WARN) assert.equal(E69T27Classify(v), E69T27_CLASS.WARN, v)
})

test('E69T27 allow classification', () => {
  for (const v of E69T27_ALLOW) assert.equal(E69T27Classify(v), E69T27_CLASS.ALLOW, v)
})

test('E69T27 unknown classification', () => {
  assert.equal(E69T27Classify('zzz-not-in-any-e69-catalog-88'), E69T27_CLASS.UNKNOWN)
})
