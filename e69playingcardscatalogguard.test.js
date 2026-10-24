'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U12Classify, E69U12_CLASS, E69U12_BLOCK, E69U12_WARN, E69U12_ALLOW } = require('./e69playingcardscatalogguard.js')

test('E69U12 block classification', () => {
  for (const v of E69U12_BLOCK) assert.equal(E69U12Classify(v), E69U12_CLASS.BLOCK, v)
})

test('E69U12 warn classification', () => {
  for (const v of E69U12_WARN) assert.equal(E69U12Classify(v), E69U12_CLASS.WARN, v)
})

test('E69U12 allow classification', () => {
  for (const v of E69U12_ALLOW) assert.equal(E69U12Classify(v), E69U12_CLASS.ALLOW, v)
})

test('E69U12 unknown classification', () => {
  assert.equal(E69U12Classify('zzz-not-in-any-e69-catalog-88'), E69U12_CLASS.UNKNOWN)
})
