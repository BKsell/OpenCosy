'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T19Classify, E69T19_CLASS, E69T19_BLOCK, E69T19_WARN, E69T19_ALLOW } = require('./e69cjkradicalssuppcatalogguard.js')

test('E69T19 block classification', () => {
  for (const v of E69T19_BLOCK) assert.equal(E69T19Classify(v), E69T19_CLASS.BLOCK, v)
})

test('E69T19 warn classification', () => {
  for (const v of E69T19_WARN) assert.equal(E69T19Classify(v), E69T19_CLASS.WARN, v)
})

test('E69T19 allow classification', () => {
  for (const v of E69T19_ALLOW) assert.equal(E69T19Classify(v), E69T19_CLASS.ALLOW, v)
})

test('E69T19 unknown classification', () => {
  assert.equal(E69T19Classify('zzz-not-in-any-e69-catalog-88'), E69T19_CLASS.UNKNOWN)
})
