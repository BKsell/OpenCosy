'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U07Classify, E69U07_CLASS, E69U07_BLOCK, E69U07_WARN, E69U07_ALLOW } = require('./e69variationsupplementcatalogguard.js')

test('E69U07 block classification', () => {
  for (const v of E69U07_BLOCK) assert.equal(E69U07Classify(v), E69U07_CLASS.BLOCK, v)
})

test('E69U07 warn classification', () => {
  for (const v of E69U07_WARN) assert.equal(E69U07Classify(v), E69U07_CLASS.WARN, v)
})

test('E69U07 allow classification', () => {
  for (const v of E69U07_ALLOW) assert.equal(E69U07Classify(v), E69U07_CLASS.ALLOW, v)
})

test('E69U07 unknown classification', () => {
  assert.equal(E69U07Classify('zzz-not-in-any-e69-catalog-88'), E69U07_CLASS.UNKNOWN)
})
