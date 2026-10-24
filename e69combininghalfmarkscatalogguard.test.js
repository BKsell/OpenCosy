'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T39Classify, E69T39_CLASS, E69T39_BLOCK, E69T39_WARN, E69T39_ALLOW } = require('./e69combininghalfmarkscatalogguard.js')

test('E69T39 block classification', () => {
  for (const v of E69T39_BLOCK) assert.equal(E69T39Classify(v), E69T39_CLASS.BLOCK, v)
})

test('E69T39 warn classification', () => {
  for (const v of E69T39_WARN) assert.equal(E69T39Classify(v), E69T39_CLASS.WARN, v)
})

test('E69T39 allow classification', () => {
  for (const v of E69T39_ALLOW) assert.equal(E69T39Classify(v), E69T39_CLASS.ALLOW, v)
})

test('E69T39 unknown classification', () => {
  assert.equal(E69T39Classify('zzz-not-in-any-e69-catalog-88'), E69T39_CLASS.UNKNOWN)
})
