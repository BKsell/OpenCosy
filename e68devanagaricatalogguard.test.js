'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R05Classify, E68R05_CLASS, E68R05_BLOCK, E68R05_WARN, E68R05_ALLOW } = require('./e68devanagaricatalogguard.js')

test('E68R05 block classification', () => {
  for (const v of E68R05_BLOCK) assert.equal(E68R05Classify(v), E68R05_CLASS.BLOCK, v)
})

test('E68R05 warn classification', () => {
  for (const v of E68R05_WARN) assert.equal(E68R05Classify(v), E68R05_CLASS.WARN, v)
})

test('E68R05 allow classification', () => {
  for (const v of E68R05_ALLOW) assert.equal(E68R05Classify(v), E68R05_CLASS.ALLOW, v)
})

test('E68R05 unknown classification', () => {
  assert.equal(E68R05Classify('zzz-not-in-any-e68-catalog-77'), E68R05_CLASS.UNKNOWN)
})
