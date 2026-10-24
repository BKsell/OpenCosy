'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T24Classify, E69T24_CLASS, E69T24_BLOCK, E69T24_WARN, E69T24_ALLOW } = require('./e69cjksymbolspunctcatalogguard.js')

test('E69T24 block classification', () => {
  for (const v of E69T24_BLOCK) assert.equal(E69T24Classify(v), E69T24_CLASS.BLOCK, v)
})

test('E69T24 warn classification', () => {
  for (const v of E69T24_WARN) assert.equal(E69T24Classify(v), E69T24_CLASS.WARN, v)
})

test('E69T24 allow classification', () => {
  for (const v of E69T24_ALLOW) assert.equal(E69T24Classify(v), E69T24_CLASS.ALLOW, v)
})

test('E69T24 unknown classification', () => {
  assert.equal(E69T24Classify('zzz-not-in-any-e69-catalog-88'), E69T24_CLASS.UNKNOWN)
})
