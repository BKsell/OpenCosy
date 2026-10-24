'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T06Classify, E69T06_CLASS, E69T06_BLOCK, E69T06_WARN, E69T06_ALLOW } = require('./e69greekcopticcatalogguard.js')

test('E69T06 block classification', () => {
  for (const v of E69T06_BLOCK) assert.equal(E69T06Classify(v), E69T06_CLASS.BLOCK, v)
})

test('E69T06 warn classification', () => {
  for (const v of E69T06_WARN) assert.equal(E69T06Classify(v), E69T06_CLASS.WARN, v)
})

test('E69T06 allow classification', () => {
  for (const v of E69T06_ALLOW) assert.equal(E69T06Classify(v), E69T06_CLASS.ALLOW, v)
})

test('E69T06 unknown classification', () => {
  assert.equal(E69T06Classify('zzz-not-in-any-e69-catalog-88'), E69T06_CLASS.UNKNOWN)
})
