'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69CASClassify, E69CAS_CLASS, E69CAS_BLOCK, E69CAS_WARN, E69CAS_ALLOW } = require('./e69castcharcatalogguard.js')

test('E69CAS block classification', () => {
  for (const v of E69CAS_BLOCK) assert.equal(E69CASClassify(v), E69CAS_CLASS.BLOCK, v)
})

test('E69CAS warn classification', () => {
  for (const v of E69CAS_WARN) assert.equal(E69CASClassify(v), E69CAS_CLASS.WARN, v)
})

test('E69CAS allow classification', () => {
  for (const v of E69CAS_ALLOW) assert.equal(E69CASClassify(v), E69CAS_CLASS.ALLOW, v)
})

test('E69CAS unknown classification', () => {
  assert.equal(E69CASClassify('zzz-not-in-any-e69-catalog-88'), E69CAS_CLASS.UNKNOWN)
})
