'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T13Classify, E70T13_CLASS, E70T13_BLOCK, E70T13_WARN, E70T13_ALLOW } = require('./e70oriyacatalogguard.js')

test('E70T13 block classification', () => {
  for (const v of E70T13_BLOCK) assert.equal(E70T13Classify(v), E70T13_CLASS.BLOCK, v)
})

test('E70T13 warn classification', () => {
  for (const v of E70T13_WARN) assert.equal(E70T13Classify(v), E70T13_CLASS.WARN, v)
})

test('E70T13 allow classification', () => {
  for (const v of E70T13_ALLOW) assert.equal(E70T13Classify(v), E70T13_CLASS.ALLOW, v)
})

test('E70T13 unknown classification', () => {
  assert.equal(E70T13Classify('zzz-not-in-any-e70-catalog-99'), E70T13_CLASS.UNKNOWN)
})
