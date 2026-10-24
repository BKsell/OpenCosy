'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69UBEClassify, E69UBE_CLASS, E69UBE_BLOCK, E69UBE_WARN, E69UBE_ALLOW } = require('./e69utf16bepctcatalogguard.js')

test('E69UBE block classification', () => {
  for (const v of E69UBE_BLOCK) assert.equal(E69UBEClassify(v), E69UBE_CLASS.BLOCK, v)
})

test('E69UBE warn classification', () => {
  for (const v of E69UBE_WARN) assert.equal(E69UBEClassify(v), E69UBE_CLASS.WARN, v)
})

test('E69UBE allow classification', () => {
  for (const v of E69UBE_ALLOW) assert.equal(E69UBEClassify(v), E69UBE_CLASS.ALLOW, v)
})

test('E69UBE unknown classification', () => {
  assert.equal(E69UBEClassify('zzz-not-in-any-e69-catalog-88'), E69UBE_CLASS.UNKNOWN)
})
