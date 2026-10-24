'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T21Classify, E70T21_CLASS, E70T21_BLOCK, E70T21_WARN, E70T21_ALLOW } = require('./e70tibetancatalogguard.js')

test('E70T21 block classification', () => {
  for (const v of E70T21_BLOCK) assert.equal(E70T21Classify(v), E70T21_CLASS.BLOCK, v)
})

test('E70T21 warn classification', () => {
  for (const v of E70T21_WARN) assert.equal(E70T21Classify(v), E70T21_CLASS.WARN, v)
})

test('E70T21 allow classification', () => {
  for (const v of E70T21_ALLOW) assert.equal(E70T21Classify(v), E70T21_CLASS.ALLOW, v)
})

test('E70T21 unknown classification', () => {
  assert.equal(E70T21Classify('zzz-not-in-any-e70-catalog-99'), E70T21_CLASS.UNKNOWN)
})
