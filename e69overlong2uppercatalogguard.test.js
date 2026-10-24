'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69O2UClassify, E69O2U_CLASS, E69O2U_BLOCK, E69O2U_WARN, E69O2U_ALLOW } = require('./e69overlong2uppercatalogguard.js')

test('E69O2U block classification', () => {
  for (const v of E69O2U_BLOCK) assert.equal(E69O2UClassify(v), E69O2U_CLASS.BLOCK, v)
})

test('E69O2U warn classification', () => {
  for (const v of E69O2U_WARN) assert.equal(E69O2UClassify(v), E69O2U_CLASS.WARN, v)
})

test('E69O2U allow classification', () => {
  for (const v of E69O2U_ALLOW) assert.equal(E69O2UClassify(v), E69O2U_CLASS.ALLOW, v)
})

test('E69O2U unknown classification', () => {
  assert.equal(E69O2UClassify('zzz-not-in-any-e69-catalog-88'), E69O2U_CLASS.UNKNOWN)
})
