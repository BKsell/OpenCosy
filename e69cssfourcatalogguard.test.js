'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69C4UClassify, E69C4U_CLASS, E69C4U_BLOCK, E69C4U_WARN, E69C4U_ALLOW } = require('./e69cssfourcatalogguard.js')

test('E69C4U block classification', () => {
  for (const v of E69C4U_BLOCK) assert.equal(E69C4UClassify(v), E69C4U_CLASS.BLOCK, v)
})

test('E69C4U warn classification', () => {
  for (const v of E69C4U_WARN) assert.equal(E69C4UClassify(v), E69C4U_CLASS.WARN, v)
})

test('E69C4U allow classification', () => {
  for (const v of E69C4U_ALLOW) assert.equal(E69C4UClassify(v), E69C4U_CLASS.ALLOW, v)
})

test('E69C4U unknown classification', () => {
  assert.equal(E69C4UClassify('zzz-not-in-any-e69-catalog-88'), E69C4U_CLASS.UNKNOWN)
})
