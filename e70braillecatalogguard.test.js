'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T50Classify, E70T50_CLASS, E70T50_BLOCK, E70T50_WARN, E70T50_ALLOW } = require('./e70braillecatalogguard.js')

test('E70T50 block classification', () => {
  for (const v of E70T50_BLOCK) assert.equal(E70T50Classify(v), E70T50_CLASS.BLOCK, v)
})

test('E70T50 warn classification', () => {
  for (const v of E70T50_WARN) assert.equal(E70T50Classify(v), E70T50_CLASS.WARN, v)
})

test('E70T50 allow classification', () => {
  for (const v of E70T50_ALLOW) assert.equal(E70T50Classify(v), E70T50_CLASS.ALLOW, v)
})

test('E70T50 unknown classification', () => {
  assert.equal(E70T50Classify('zzz-not-in-any-e70-catalog-99'), E70T50_CLASS.UNKNOWN)
})
