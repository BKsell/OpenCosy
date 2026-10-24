'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69ULEClassify, E69ULE_CLASS, E69ULE_BLOCK, E69ULE_WARN, E69ULE_ALLOW } = require('./e69utf16lepctcatalogguard.js')

test('E69ULE block classification', () => {
  for (const v of E69ULE_BLOCK) assert.equal(E69ULEClassify(v), E69ULE_CLASS.BLOCK, v)
})

test('E69ULE warn classification', () => {
  for (const v of E69ULE_WARN) assert.equal(E69ULEClassify(v), E69ULE_CLASS.WARN, v)
})

test('E69ULE allow classification', () => {
  for (const v of E69ULE_ALLOW) assert.equal(E69ULEClassify(v), E69ULE_CLASS.ALLOW, v)
})

test('E69ULE unknown classification', () => {
  assert.equal(E69ULEClassify('zzz-not-in-any-e69-catalog-88'), E69ULE_CLASS.UNKNOWN)
})
