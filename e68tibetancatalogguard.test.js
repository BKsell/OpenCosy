'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R17Classify, E68R17_CLASS, E68R17_BLOCK, E68R17_WARN, E68R17_ALLOW } = require('./e68tibetancatalogguard.js')

test('E68R17 block classification', () => {
  for (const v of E68R17_BLOCK) assert.equal(E68R17Classify(v), E68R17_CLASS.BLOCK, v)
})

test('E68R17 warn classification', () => {
  for (const v of E68R17_WARN) assert.equal(E68R17Classify(v), E68R17_CLASS.WARN, v)
})

test('E68R17 allow classification', () => {
  for (const v of E68R17_ALLOW) assert.equal(E68R17Classify(v), E68R17_CLASS.ALLOW, v)
})

test('E68R17 unknown classification', () => {
  assert.equal(E68R17Classify('zzz-not-in-any-e68-catalog-77'), E68R17_CLASS.UNKNOWN)
})
