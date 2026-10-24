'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T23Classify, E69T23_CLASS, E69T23_BLOCK, E69T23_WARN, E69T23_ALLOW } = require('./e69combiningmarksymbolscatalogguard.js')

test('E69T23 block classification', () => {
  for (const v of E69T23_BLOCK) assert.equal(E69T23Classify(v), E69T23_CLASS.BLOCK, v)
})

test('E69T23 warn classification', () => {
  for (const v of E69T23_WARN) assert.equal(E69T23Classify(v), E69T23_CLASS.WARN, v)
})

test('E69T23 allow classification', () => {
  for (const v of E69T23_ALLOW) assert.equal(E69T23Classify(v), E69T23_CLASS.ALLOW, v)
})

test('E69T23 unknown classification', () => {
  assert.equal(E69T23Classify('zzz-not-in-any-e69-catalog-88'), E69T23_CLASS.UNKNOWN)
})
