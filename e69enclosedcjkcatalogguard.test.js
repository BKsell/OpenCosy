'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T29Classify, E69T29_CLASS, E69T29_BLOCK, E69T29_WARN, E69T29_ALLOW } = require('./e69enclosedcjkcatalogguard.js')

test('E69T29 block classification', () => {
  for (const v of E69T29_BLOCK) assert.equal(E69T29Classify(v), E69T29_CLASS.BLOCK, v)
})

test('E69T29 warn classification', () => {
  for (const v of E69T29_WARN) assert.equal(E69T29Classify(v), E69T29_CLASS.WARN, v)
})

test('E69T29 allow classification', () => {
  for (const v of E69T29_ALLOW) assert.equal(E69T29Classify(v), E69T29_CLASS.ALLOW, v)
})

test('E69T29 unknown classification', () => {
  assert.equal(E69T29Classify('zzz-not-in-any-e69-catalog-88'), E69T29_CLASS.UNKNOWN)
})
