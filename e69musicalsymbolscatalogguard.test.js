'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U10Classify, E69U10_CLASS, E69U10_BLOCK, E69U10_WARN, E69U10_ALLOW } = require('./e69musicalsymbolscatalogguard.js')

test('E69U10 block classification', () => {
  for (const v of E69U10_BLOCK) assert.equal(E69U10Classify(v), E69U10_CLASS.BLOCK, v)
})

test('E69U10 warn classification', () => {
  for (const v of E69U10_WARN) assert.equal(E69U10Classify(v), E69U10_CLASS.WARN, v)
})

test('E69U10 allow classification', () => {
  for (const v of E69U10_ALLOW) assert.equal(E69U10Classify(v), E69U10_CLASS.ALLOW, v)
})

test('E69U10 unknown classification', () => {
  assert.equal(E69U10Classify('zzz-not-in-any-e69-catalog-88'), E69U10_CLASS.UNKNOWN)
})
