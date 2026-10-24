'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U11Classify, E69U11_CLASS, E69U11_BLOCK, E69U11_WARN, E69U11_ALLOW } = require('./e69mahjongdominocatalogguard.js')

test('E69U11 block classification', () => {
  for (const v of E69U11_BLOCK) assert.equal(E69U11Classify(v), E69U11_CLASS.BLOCK, v)
})

test('E69U11 warn classification', () => {
  for (const v of E69U11_WARN) assert.equal(E69U11Classify(v), E69U11_CLASS.WARN, v)
})

test('E69U11 allow classification', () => {
  for (const v of E69U11_ALLOW) assert.equal(E69U11Classify(v), E69U11_CLASS.ALLOW, v)
})

test('E69U11 unknown classification', () => {
  assert.equal(E69U11Classify('zzz-not-in-any-e69-catalog-88'), E69U11_CLASS.UNKNOWN)
})
