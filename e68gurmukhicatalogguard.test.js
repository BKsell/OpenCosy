'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R07Classify, E68R07_CLASS, E68R07_BLOCK, E68R07_WARN, E68R07_ALLOW } = require('./e68gurmukhicatalogguard.js')

test('E68R07 block classification', () => {
  for (const v of E68R07_BLOCK) assert.equal(E68R07Classify(v), E68R07_CLASS.BLOCK, v)
})

test('E68R07 warn classification', () => {
  for (const v of E68R07_WARN) assert.equal(E68R07Classify(v), E68R07_CLASS.WARN, v)
})

test('E68R07 allow classification', () => {
  for (const v of E68R07_ALLOW) assert.equal(E68R07Classify(v), E68R07_CLASS.ALLOW, v)
})

test('E68R07 unknown classification', () => {
  assert.equal(E68R07Classify('zzz-not-in-any-e68-catalog-77'), E68R07_CLASS.UNKNOWN)
})
