'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U00Classify, E70U00_CLASS, E70U00_BLOCK, E70U00_WARN, E70U00_ALLOW } = require('./e70linearbcatalogguard.js')

test('E70U00 block classification', () => {
  for (const v of E70U00_BLOCK) assert.equal(E70U00Classify(v), E70U00_CLASS.BLOCK, v)
})

test('E70U00 warn classification', () => {
  for (const v of E70U00_WARN) assert.equal(E70U00Classify(v), E70U00_CLASS.WARN, v)
})

test('E70U00 allow classification', () => {
  for (const v of E70U00_ALLOW) assert.equal(E70U00Classify(v), E70U00_CLASS.ALLOW, v)
})

test('E70U00 unknown classification', () => {
  assert.equal(E70U00Classify('zzz-not-in-any-e70-catalog-99'), E70U00_CLASS.UNKNOWN)
})
