'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69O2LClassify, E69O2L_CLASS, E69O2L_BLOCK, E69O2L_WARN, E69O2L_ALLOW } = require('./e69overlong2lowercatalogguard.js')

test('E69O2L block classification', () => {
  for (const v of E69O2L_BLOCK) assert.equal(E69O2LClassify(v), E69O2L_CLASS.BLOCK, v)
})

test('E69O2L warn classification', () => {
  for (const v of E69O2L_WARN) assert.equal(E69O2LClassify(v), E69O2L_CLASS.WARN, v)
})

test('E69O2L allow classification', () => {
  for (const v of E69O2L_ALLOW) assert.equal(E69O2LClassify(v), E69O2L_CLASS.ALLOW, v)
})

test('E69O2L unknown classification', () => {
  assert.equal(E69O2LClassify('zzz-not-in-any-e69-catalog-88'), E69O2L_CLASS.UNKNOWN)
})
