'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U13Classify, E69U13_CLASS, E69U13_BLOCK, E69U13_WARN, E69U13_ALLOW } = require('./e69mayanumeralscatalogguard.js')

test('E69U13 block classification', () => {
  for (const v of E69U13_BLOCK) assert.equal(E69U13Classify(v), E69U13_CLASS.BLOCK, v)
})

test('E69U13 warn classification', () => {
  for (const v of E69U13_WARN) assert.equal(E69U13Classify(v), E69U13_CLASS.WARN, v)
})

test('E69U13 allow classification', () => {
  for (const v of E69U13_ALLOW) assert.equal(E69U13Classify(v), E69U13_CLASS.ALLOW, v)
})

test('E69U13 unknown classification', () => {
  assert.equal(E69U13Classify('zzz-not-in-any-e69-catalog-88'), E69U13_CLASS.UNKNOWN)
})
