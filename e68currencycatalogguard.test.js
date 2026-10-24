'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R23Classify, E68R23_CLASS, E68R23_BLOCK, E68R23_WARN, E68R23_ALLOW } = require('./e68currencycatalogguard.js')

test('E68R23 block classification', () => {
  for (const v of E68R23_BLOCK) assert.equal(E68R23Classify(v), E68R23_CLASS.BLOCK, v)
})

test('E68R23 warn classification', () => {
  for (const v of E68R23_WARN) assert.equal(E68R23Classify(v), E68R23_CLASS.WARN, v)
})

test('E68R23 allow classification', () => {
  for (const v of E68R23_ALLOW) assert.equal(E68R23Classify(v), E68R23_CLASS.ALLOW, v)
})

test('E68R23 unknown classification', () => {
  assert.equal(E68R23Classify('zzz-not-in-any-e68-catalog-77'), E68R23_CLASS.UNKNOWN)
})
