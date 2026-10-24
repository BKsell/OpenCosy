'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T26Classify, E69T26_CLASS, E69T26_BLOCK, E69T26_WARN, E69T26_ALLOW } = require('./e69katakanacatalogguard.js')

test('E69T26 block classification', () => {
  for (const v of E69T26_BLOCK) assert.equal(E69T26Classify(v), E69T26_CLASS.BLOCK, v)
})

test('E69T26 warn classification', () => {
  for (const v of E69T26_WARN) assert.equal(E69T26Classify(v), E69T26_CLASS.WARN, v)
})

test('E69T26 allow classification', () => {
  for (const v of E69T26_ALLOW) assert.equal(E69T26Classify(v), E69T26_CLASS.ALLOW, v)
})

test('E69T26 unknown classification', () => {
  assert.equal(E69T26Classify('zzz-not-in-any-e69-catalog-88'), E69T26_CLASS.UNKNOWN)
})
