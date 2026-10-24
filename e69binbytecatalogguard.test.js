'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69BINClassify, E69BIN_CLASS, E69BIN_BLOCK, E69BIN_WARN, E69BIN_ALLOW } = require('./e69binbytecatalogguard.js')

test('E69BIN block classification', () => {
  for (const v of E69BIN_BLOCK) assert.equal(E69BINClassify(v), E69BIN_CLASS.BLOCK, v)
})

test('E69BIN warn classification', () => {
  for (const v of E69BIN_WARN) assert.equal(E69BINClassify(v), E69BIN_CLASS.WARN, v)
})

test('E69BIN allow classification', () => {
  for (const v of E69BIN_ALLOW) assert.equal(E69BINClassify(v), E69BIN_CLASS.ALLOW, v)
})

test('E69BIN unknown classification', () => {
  assert.equal(E69BINClassify('zzz-not-in-any-e69-catalog-88'), E69BIN_CLASS.UNKNOWN)
})
