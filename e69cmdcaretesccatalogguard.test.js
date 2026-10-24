'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69CMCClassify, E69CMC_CLASS, E69CMC_BLOCK, E69CMC_WARN, E69CMC_ALLOW } = require('./e69cmdcaretesccatalogguard.js')

test('E69CMC block classification', () => {
  for (const v of E69CMC_BLOCK) assert.equal(E69CMCClassify(v), E69CMC_CLASS.BLOCK, v)
})

test('E69CMC warn classification', () => {
  for (const v of E69CMC_WARN) assert.equal(E69CMCClassify(v), E69CMC_CLASS.WARN, v)
})

test('E69CMC allow classification', () => {
  for (const v of E69CMC_ALLOW) assert.equal(E69CMCClassify(v), E69CMC_CLASS.ALLOW, v)
})

test('E69CMC unknown classification', () => {
  assert.equal(E69CMCClassify('zzz-not-in-any-e69-catalog-88'), E69CMC_CLASS.UNKNOWN)
})
