'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U03Classify, E70U03_CLASS, E70U03_BLOCK, E70U03_WARN, E70U03_ALLOW } = require('./e70gothiccatalogguard.js')

test('E70U03 block classification', () => {
  for (const v of E70U03_BLOCK) assert.equal(E70U03Classify(v), E70U03_CLASS.BLOCK, v)
})

test('E70U03 warn classification', () => {
  for (const v of E70U03_WARN) assert.equal(E70U03Classify(v), E70U03_CLASS.WARN, v)
})

test('E70U03 allow classification', () => {
  for (const v of E70U03_ALLOW) assert.equal(E70U03Classify(v), E70U03_CLASS.ALLOW, v)
})

test('E70U03 unknown classification', () => {
  assert.equal(E70U03Classify('zzz-not-in-any-e70-catalog-99'), E70U03_CLASS.UNKNOWN)
})
