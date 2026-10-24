'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T09Classify, E69T09_CLASS, E69T09_BLOCK, E69T09_WARN, E69T09_ALLOW } = require('./e69ethiopiccatalogguard.js')

test('E69T09 block classification', () => {
  for (const v of E69T09_BLOCK) assert.equal(E69T09Classify(v), E69T09_CLASS.BLOCK, v)
})

test('E69T09 warn classification', () => {
  for (const v of E69T09_WARN) assert.equal(E69T09Classify(v), E69T09_CLASS.WARN, v)
})

test('E69T09 allow classification', () => {
  for (const v of E69T09_ALLOW) assert.equal(E69T09Classify(v), E69T09_CLASS.ALLOW, v)
})

test('E69T09 unknown classification', () => {
  assert.equal(E69T09Classify('zzz-not-in-any-e69-catalog-88'), E69T09_CLASS.UNKNOWN)
})
