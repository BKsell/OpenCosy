'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T01Classify, E69T01_CLASS, E69T01_BLOCK, E69T01_WARN, E69T01_ALLOW } = require('./e69latinextacatalogguard.js')

test('E69T01 block classification', () => {
  for (const v of E69T01_BLOCK) assert.equal(E69T01Classify(v), E69T01_CLASS.BLOCK, v)
})

test('E69T01 warn classification', () => {
  for (const v of E69T01_WARN) assert.equal(E69T01Classify(v), E69T01_CLASS.WARN, v)
})

test('E69T01 allow classification', () => {
  for (const v of E69T01_ALLOW) assert.equal(E69T01Classify(v), E69T01_CLASS.ALLOW, v)
})

test('E69T01 unknown classification', () => {
  assert.equal(E69T01Classify('zzz-not-in-any-e69-catalog-88'), E69T01_CLASS.UNKNOWN)
})
