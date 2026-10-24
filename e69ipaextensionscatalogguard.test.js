'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T03Classify, E69T03_CLASS, E69T03_BLOCK, E69T03_WARN, E69T03_ALLOW } = require('./e69ipaextensionscatalogguard.js')

test('E69T03 block classification', () => {
  for (const v of E69T03_BLOCK) assert.equal(E69T03Classify(v), E69T03_CLASS.BLOCK, v)
})

test('E69T03 warn classification', () => {
  for (const v of E69T03_WARN) assert.equal(E69T03Classify(v), E69T03_CLASS.WARN, v)
})

test('E69T03 allow classification', () => {
  for (const v of E69T03_ALLOW) assert.equal(E69T03Classify(v), E69T03_CLASS.ALLOW, v)
})

test('E69T03 unknown classification', () => {
  assert.equal(E69T03Classify('zzz-not-in-any-e69-catalog-88'), E69T03_CLASS.UNKNOWN)
})
