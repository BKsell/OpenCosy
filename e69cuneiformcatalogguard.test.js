'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U08Classify, E69U08_CLASS, E69U08_BLOCK, E69U08_WARN, E69U08_ALLOW } = require('./e69cuneiformcatalogguard.js')

test('E69U08 block classification', () => {
  for (const v of E69U08_BLOCK) assert.equal(E69U08Classify(v), E69U08_CLASS.BLOCK, v)
})

test('E69U08 warn classification', () => {
  for (const v of E69U08_WARN) assert.equal(E69U08Classify(v), E69U08_CLASS.WARN, v)
})

test('E69U08 allow classification', () => {
  for (const v of E69U08_ALLOW) assert.equal(E69U08Classify(v), E69U08_CLASS.ALLOW, v)
})

test('E69U08 unknown classification', () => {
  assert.equal(E69U08Classify('zzz-not-in-any-e69-catalog-88'), E69U08_CLASS.UNKNOWN)
})
