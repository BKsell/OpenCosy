'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T22Classify, E70T22_CLASS, E70T22_BLOCK, E70T22_WARN, E70T22_ALLOW } = require('./e70myanmarcatalogguard.js')

test('E70T22 block classification', () => {
  for (const v of E70T22_BLOCK) assert.equal(E70T22Classify(v), E70T22_CLASS.BLOCK, v)
})

test('E70T22 warn classification', () => {
  for (const v of E70T22_WARN) assert.equal(E70T22Classify(v), E70T22_CLASS.WARN, v)
})

test('E70T22 allow classification', () => {
  for (const v of E70T22_ALLOW) assert.equal(E70T22Classify(v), E70T22_CLASS.ALLOW, v)
})

test('E70T22 unknown classification', () => {
  assert.equal(E70T22Classify('zzz-not-in-any-e70-catalog-99'), E70T22_CLASS.UNKNOWN)
})
