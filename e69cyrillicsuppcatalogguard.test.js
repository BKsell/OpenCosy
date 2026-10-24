'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T08Classify, E69T08_CLASS, E69T08_BLOCK, E69T08_WARN, E69T08_ALLOW } = require('./e69cyrillicsuppcatalogguard.js')

test('E69T08 block classification', () => {
  for (const v of E69T08_BLOCK) assert.equal(E69T08Classify(v), E69T08_CLASS.BLOCK, v)
})

test('E69T08 warn classification', () => {
  for (const v of E69T08_WARN) assert.equal(E69T08Classify(v), E69T08_CLASS.WARN, v)
})

test('E69T08 allow classification', () => {
  for (const v of E69T08_ALLOW) assert.equal(E69T08Classify(v), E69T08_CLASS.ALLOW, v)
})

test('E69T08 unknown classification', () => {
  assert.equal(E69T08Classify('zzz-not-in-any-e69-catalog-88'), E69T08_CLASS.UNKNOWN)
})
