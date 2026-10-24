'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U02Classify, E69U02_CLASS, E69U02_BLOCK, E69U02_WARN, E69U02_ALLOW } = require('./e69supplementalpictographscatalogguard.js')

test('E69U02 block classification', () => {
  for (const v of E69U02_BLOCK) assert.equal(E69U02Classify(v), E69U02_CLASS.BLOCK, v)
})

test('E69U02 warn classification', () => {
  for (const v of E69U02_WARN) assert.equal(E69U02Classify(v), E69U02_CLASS.WARN, v)
})

test('E69U02 allow classification', () => {
  for (const v of E69U02_ALLOW) assert.equal(E69U02Classify(v), E69U02_CLASS.ALLOW, v)
})

test('E69U02 unknown classification', () => {
  assert.equal(E69U02Classify('zzz-not-in-any-e69-catalog-88'), E69U02_CLASS.UNKNOWN)
})
