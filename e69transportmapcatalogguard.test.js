'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U01Classify, E69U01_CLASS, E69U01_BLOCK, E69U01_WARN, E69U01_ALLOW } = require('./e69transportmapcatalogguard.js')

test('E69U01 block classification', () => {
  for (const v of E69U01_BLOCK) assert.equal(E69U01Classify(v), E69U01_CLASS.BLOCK, v)
})

test('E69U01 warn classification', () => {
  for (const v of E69U01_WARN) assert.equal(E69U01Classify(v), E69U01_CLASS.WARN, v)
})

test('E69U01 allow classification', () => {
  for (const v of E69U01_ALLOW) assert.equal(E69U01Classify(v), E69U01_CLASS.ALLOW, v)
})

test('E69U01 unknown classification', () => {
  assert.equal(E69U01Classify('zzz-not-in-any-e69-catalog-88'), E69U01_CLASS.UNKNOWN)
})
