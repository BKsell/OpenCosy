'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T02Classify, E69T02_CLASS, E69T02_BLOCK, E69T02_WARN, E69T02_ALLOW } = require('./e69latinextbcatalogguard.js')

test('E69T02 block classification', () => {
  for (const v of E69T02_BLOCK) assert.equal(E69T02Classify(v), E69T02_CLASS.BLOCK, v)
})

test('E69T02 warn classification', () => {
  for (const v of E69T02_WARN) assert.equal(E69T02Classify(v), E69T02_CLASS.WARN, v)
})

test('E69T02 allow classification', () => {
  for (const v of E69T02_ALLOW) assert.equal(E69T02Classify(v), E69T02_CLASS.ALLOW, v)
})

test('E69T02 unknown classification', () => {
  assert.equal(E69T02Classify('zzz-not-in-any-e69-catalog-88'), E69T02_CLASS.UNKNOWN)
})
