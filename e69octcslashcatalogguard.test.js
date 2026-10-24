'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69OCSClassify, E69OCS_CLASS, E69OCS_BLOCK, E69OCS_WARN, E69OCS_ALLOW } = require('./e69octcslashcatalogguard.js')

test('E69OCS block classification', () => {
  for (const v of E69OCS_BLOCK) assert.equal(E69OCSClassify(v), E69OCS_CLASS.BLOCK, v)
})

test('E69OCS warn classification', () => {
  for (const v of E69OCS_WARN) assert.equal(E69OCSClassify(v), E69OCS_CLASS.WARN, v)
})

test('E69OCS allow classification', () => {
  for (const v of E69OCS_ALLOW) assert.equal(E69OCSClassify(v), E69OCS_CLASS.ALLOW, v)
})

test('E69OCS unknown classification', () => {
  assert.equal(E69OCSClassify('zzz-not-in-any-e69-catalog-88'), E69OCS_CLASS.UNKNOWN)
})
