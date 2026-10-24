'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69C6UClassify, E69C6U_CLASS, E69C6U_BLOCK, E69C6U_WARN, E69C6U_ALLOW } = require('./e69csssixuppercatalogguard.js')

test('E69C6U block classification', () => {
  for (const v of E69C6U_BLOCK) assert.equal(E69C6UClassify(v), E69C6U_CLASS.BLOCK, v)
})

test('E69C6U warn classification', () => {
  for (const v of E69C6U_WARN) assert.equal(E69C6UClassify(v), E69C6U_CLASS.WARN, v)
})

test('E69C6U allow classification', () => {
  for (const v of E69C6U_ALLOW) assert.equal(E69C6UClassify(v), E69C6U_CLASS.ALLOW, v)
})

test('E69C6U unknown classification', () => {
  assert.equal(E69C6UClassify('zzz-not-in-any-e69-catalog-88'), E69C6U_CLASS.UNKNOWN)
})
