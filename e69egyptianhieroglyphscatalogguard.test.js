'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U09Classify, E69U09_CLASS, E69U09_BLOCK, E69U09_WARN, E69U09_ALLOW } = require('./e69egyptianhieroglyphscatalogguard.js')

test('E69U09 block classification', () => {
  for (const v of E69U09_BLOCK) assert.equal(E69U09Classify(v), E69U09_CLASS.BLOCK, v)
})

test('E69U09 warn classification', () => {
  for (const v of E69U09_WARN) assert.equal(E69U09Classify(v), E69U09_CLASS.WARN, v)
})

test('E69U09 allow classification', () => {
  for (const v of E69U09_ALLOW) assert.equal(E69U09Classify(v), E69U09_CLASS.ALLOW, v)
})

test('E69U09 unknown classification', () => {
  assert.equal(E69U09Classify('zzz-not-in-any-e69-catalog-88'), E69U09_CLASS.UNKNOWN)
})
