'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T35Classify, E69T35_CLASS, E69T35_BLOCK, E69T35_WARN, E69T35_ALLOW } = require('./e69arabicpresbcatalogguard.js')

test('E69T35 block classification', () => {
  for (const v of E69T35_BLOCK) assert.equal(E69T35Classify(v), E69T35_CLASS.BLOCK, v)
})

test('E69T35 warn classification', () => {
  for (const v of E69T35_WARN) assert.equal(E69T35Classify(v), E69T35_CLASS.WARN, v)
})

test('E69T35 allow classification', () => {
  for (const v of E69T35_ALLOW) assert.equal(E69T35Classify(v), E69T35_CLASS.ALLOW, v)
})

test('E69T35 unknown classification', () => {
  assert.equal(E69T35Classify('zzz-not-in-any-e69-catalog-88'), E69T35_CLASS.UNKNOWN)
})
