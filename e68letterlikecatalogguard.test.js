'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R24Classify, E68R24_CLASS, E68R24_BLOCK, E68R24_WARN, E68R24_ALLOW } = require('./e68letterlikecatalogguard.js')

test('E68R24 block classification', () => {
  for (const v of E68R24_BLOCK) assert.equal(E68R24Classify(v), E68R24_CLASS.BLOCK, v)
})

test('E68R24 warn classification', () => {
  for (const v of E68R24_WARN) assert.equal(E68R24Classify(v), E68R24_CLASS.WARN, v)
})

test('E68R24 allow classification', () => {
  for (const v of E68R24_ALLOW) assert.equal(E68R24Classify(v), E68R24_CLASS.ALLOW, v)
})

test('E68R24 unknown classification', () => {
  assert.equal(E68R24Classify('zzz-not-in-any-e68-catalog-77'), E68R24_CLASS.UNKNOWN)
})
