'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69SCLClassify, E69SCL_CLASS, E69SCL_BLOCK, E69SCL_WARN, E69SCL_ALLOW } = require('./e69sqlcharlowercatalogguard.js')

test('E69SCL block classification', () => {
  for (const v of E69SCL_BLOCK) assert.equal(E69SCLClassify(v), E69SCL_CLASS.BLOCK, v)
})

test('E69SCL warn classification', () => {
  for (const v of E69SCL_WARN) assert.equal(E69SCLClassify(v), E69SCL_CLASS.WARN, v)
})

test('E69SCL allow classification', () => {
  for (const v of E69SCL_ALLOW) assert.equal(E69SCLClassify(v), E69SCL_CLASS.ALLOW, v)
})

test('E69SCL unknown classification', () => {
  assert.equal(E69SCLClassify('zzz-not-in-any-e69-catalog-88'), E69SCL_CLASS.UNKNOWN)
})
