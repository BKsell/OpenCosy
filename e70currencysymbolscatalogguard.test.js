'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T37Classify, E70T37_CLASS, E70T37_BLOCK, E70T37_WARN, E70T37_ALLOW } = require('./e70currencysymbolscatalogguard.js')

test('E70T37 block classification', () => {
  for (const v of E70T37_BLOCK) assert.equal(E70T37Classify(v), E70T37_CLASS.BLOCK, v)
})

test('E70T37 warn classification', () => {
  for (const v of E70T37_WARN) assert.equal(E70T37Classify(v), E70T37_CLASS.WARN, v)
})

test('E70T37 allow classification', () => {
  for (const v of E70T37_ALLOW) assert.equal(E70T37Classify(v), E70T37_CLASS.ALLOW, v)
})

test('E70T37 unknown classification', () => {
  assert.equal(E70T37Classify('zzz-not-in-any-e70-catalog-99'), E70T37_CLASS.UNKNOWN)
})
