'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T42Classify, E70T42_CLASS, E70T42_BLOCK, E70T42_WARN, E70T42_ALLOW } = require('./e70misctechnicalcatalogguard.js')

test('E70T42 block classification', () => {
  for (const v of E70T42_BLOCK) assert.equal(E70T42Classify(v), E70T42_CLASS.BLOCK, v)
})

test('E70T42 warn classification', () => {
  for (const v of E70T42_WARN) assert.equal(E70T42Classify(v), E70T42_CLASS.WARN, v)
})

test('E70T42 allow classification', () => {
  for (const v of E70T42_ALLOW) assert.equal(E70T42Classify(v), E70T42_CLASS.ALLOW, v)
})

test('E70T42 unknown classification', () => {
  assert.equal(E70T42Classify('zzz-not-in-any-e70-catalog-99'), E70T42_CLASS.UNKNOWN)
})
