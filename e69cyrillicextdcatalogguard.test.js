'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T43Classify, E69T43_CLASS, E69T43_BLOCK, E69T43_WARN, E69T43_ALLOW } = require('./e69cyrillicextdcatalogguard.js')

test('E69T43 block classification', () => {
  for (const v of E69T43_BLOCK) assert.equal(E69T43Classify(v), E69T43_CLASS.BLOCK, v)
})

test('E69T43 warn classification', () => {
  for (const v of E69T43_WARN) assert.equal(E69T43Classify(v), E69T43_CLASS.WARN, v)
})

test('E69T43 allow classification', () => {
  for (const v of E69T43_ALLOW) assert.equal(E69T43Classify(v), E69T43_CLASS.ALLOW, v)
})

test('E69T43 unknown classification', () => {
  assert.equal(E69T43Classify('zzz-not-in-any-e69-catalog-88'), E69T43_CLASS.UNKNOWN)
})
