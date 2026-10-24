'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69CNEClassify, E69CNE_CLASS, E69CNE_BLOCK, E69CNE_WARN, E69CNE_ALLOW } = require('./e69cnamedescapescatalogguard.js')

test('E69CNE block classification', () => {
  for (const v of E69CNE_BLOCK) assert.equal(E69CNEClassify(v), E69CNE_CLASS.BLOCK, v)
})

test('E69CNE warn classification', () => {
  for (const v of E69CNE_WARN) assert.equal(E69CNEClassify(v), E69CNE_CLASS.WARN, v)
})

test('E69CNE allow classification', () => {
  for (const v of E69CNE_ALLOW) assert.equal(E69CNEClassify(v), E69CNE_CLASS.ALLOW, v)
})

test('E69CNE unknown classification', () => {
  assert.equal(E69CNEClassify('zzz-not-in-any-e69-catalog-88'), E69CNE_CLASS.UNKNOWN)
})
