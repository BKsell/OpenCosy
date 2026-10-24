'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T24Classify, E70T24_CLASS, E70T24_BLOCK, E70T24_WARN, E70T24_ALLOW } = require('./e70canadianaboriginalcatalogguard.js')

test('E70T24 block classification', () => {
  for (const v of E70T24_BLOCK) assert.equal(E70T24Classify(v), E70T24_CLASS.BLOCK, v)
})

test('E70T24 warn classification', () => {
  for (const v of E70T24_WARN) assert.equal(E70T24Classify(v), E70T24_CLASS.WARN, v)
})

test('E70T24 allow classification', () => {
  for (const v of E70T24_ALLOW) assert.equal(E70T24Classify(v), E70T24_CLASS.ALLOW, v)
})

test('E70T24 unknown classification', () => {
  assert.equal(E70T24Classify('zzz-not-in-any-e70-catalog-99'), E70T24_CLASS.UNKNOWN)
})
