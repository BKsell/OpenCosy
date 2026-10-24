'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T38Classify, E69T38_CLASS, E69T38_BLOCK, E69T38_WARN, E69T38_ALLOW } = require('./e69combiningsuppcatalogguard.js')

test('E69T38 block classification', () => {
  for (const v of E69T38_BLOCK) assert.equal(E69T38Classify(v), E69T38_CLASS.BLOCK, v)
})

test('E69T38 warn classification', () => {
  for (const v of E69T38_WARN) assert.equal(E69T38Classify(v), E69T38_CLASS.WARN, v)
})

test('E69T38 allow classification', () => {
  for (const v of E69T38_ALLOW) assert.equal(E69T38Classify(v), E69T38_CLASS.ALLOW, v)
})

test('E69T38 unknown classification', () => {
  assert.equal(E69T38Classify('zzz-not-in-any-e69-catalog-88'), E69T38_CLASS.UNKNOWN)
})
