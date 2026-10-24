'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T41Classify, E69T41_CLASS, E69T41_BLOCK, E69T41_WARN, E69T41_ALLOW } = require('./e69cjkcompatideographscatalogguard.js')

test('E69T41 block classification', () => {
  for (const v of E69T41_BLOCK) assert.equal(E69T41Classify(v), E69T41_CLASS.BLOCK, v)
})

test('E69T41 warn classification', () => {
  for (const v of E69T41_WARN) assert.equal(E69T41Classify(v), E69T41_CLASS.WARN, v)
})

test('E69T41 allow classification', () => {
  for (const v of E69T41_ALLOW) assert.equal(E69T41Classify(v), E69T41_CLASS.ALLOW, v)
})

test('E69T41 unknown classification', () => {
  assert.equal(E69T41Classify('zzz-not-in-any-e69-catalog-88'), E69T41_CLASS.UNKNOWN)
})
