'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U03Classify, E69U03_CLASS, E69U03_BLOCK, E69U03_WARN, E69U03_ALLOW } = require('./e69chesssymbolscatalogguard.js')

test('E69U03 block classification', () => {
  for (const v of E69U03_BLOCK) assert.equal(E69U03Classify(v), E69U03_CLASS.BLOCK, v)
})

test('E69U03 warn classification', () => {
  for (const v of E69U03_WARN) assert.equal(E69U03Classify(v), E69U03_CLASS.WARN, v)
})

test('E69U03 allow classification', () => {
  for (const v of E69U03_ALLOW) assert.equal(E69U03Classify(v), E69U03_CLASS.ALLOW, v)
})

test('E69U03 unknown classification', () => {
  assert.equal(E69U03Classify('zzz-not-in-any-e69-catalog-88'), E69U03_CLASS.UNKNOWN)
})
