'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U00Classify, E69U00_CLASS, E69U00_BLOCK, E69U00_WARN, E69U00_ALLOW } = require('./e69ornamentaldingbatscatalogguard.js')

test('E69U00 block classification', () => {
  for (const v of E69U00_BLOCK) assert.equal(E69U00Classify(v), E69U00_CLASS.BLOCK, v)
})

test('E69U00 warn classification', () => {
  for (const v of E69U00_WARN) assert.equal(E69U00Classify(v), E69U00_CLASS.WARN, v)
})

test('E69U00 allow classification', () => {
  for (const v of E69U00_ALLOW) assert.equal(E69U00Classify(v), E69U00_CLASS.ALLOW, v)
})

test('E69U00 unknown classification', () => {
  assert.equal(E69U00Classify('zzz-not-in-any-e69-catalog-88'), E69U00_CLASS.UNKNOWN)
})
