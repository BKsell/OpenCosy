'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69OXBClassify, E69OXB_CLASS, E69OXB_BLOCK, E69OXB_WARN, E69OXB_ALLOW } = require('./e69hexbig0Xcatalogguard.js')

test('E69OXB block classification', () => {
  for (const v of E69OXB_BLOCK) assert.equal(E69OXBClassify(v), E69OXB_CLASS.BLOCK, v)
})

test('E69OXB warn classification', () => {
  for (const v of E69OXB_WARN) assert.equal(E69OXBClassify(v), E69OXB_CLASS.WARN, v)
})

test('E69OXB allow classification', () => {
  for (const v of E69OXB_ALLOW) assert.equal(E69OXBClassify(v), E69OXB_CLASS.ALLOW, v)
})

test('E69OXB unknown classification', () => {
  assert.equal(E69OXBClassify('zzz-not-in-any-e69-catalog-88'), E69OXB_CLASS.UNKNOWN)
})
