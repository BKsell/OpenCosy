'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T13Classify, E69T13_CLASS, E69T13_BLOCK, E69T13_WARN, E69T13_ALLOW } = require('./e69philippinetagalogcatalogguard.js')

test('E69T13 block classification', () => {
  for (const v of E69T13_BLOCK) assert.equal(E69T13Classify(v), E69T13_CLASS.BLOCK, v)
})

test('E69T13 warn classification', () => {
  for (const v of E69T13_WARN) assert.equal(E69T13Classify(v), E69T13_CLASS.WARN, v)
})

test('E69T13 allow classification', () => {
  for (const v of E69T13_ALLOW) assert.equal(E69T13Classify(v), E69T13_CLASS.ALLOW, v)
})

test('E69T13 unknown classification', () => {
  assert.equal(E69T13Classify('zzz-not-in-any-e69-catalog-88'), E69T13_CLASS.UNKNOWN)
})
