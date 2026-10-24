'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U05Classify, E69U05_CLASS, E69U05_BLOCK, E69U05_WARN, E69U05_ALLOW } = require('./e69pictographsextacatalogguard.js')

test('E69U05 block classification', () => {
  for (const v of E69U05_BLOCK) assert.equal(E69U05Classify(v), E69U05_CLASS.BLOCK, v)
})

test('E69U05 warn classification', () => {
  for (const v of E69U05_WARN) assert.equal(E69U05Classify(v), E69U05_CLASS.WARN, v)
})

test('E69U05 allow classification', () => {
  for (const v of E69U05_ALLOW) assert.equal(E69U05Classify(v), E69U05_CLASS.ALLOW, v)
})

test('E69U05 unknown classification', () => {
  assert.equal(E69U05Classify('zzz-not-in-any-e69-catalog-88'), E69U05_CLASS.UNKNOWN)
})
