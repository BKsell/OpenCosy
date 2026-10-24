'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T17Classify, E70T17_CLASS, E70T17_BLOCK, E70T17_WARN, E70T17_ALLOW } = require('./e70malayalamcatalogguard.js')

test('E70T17 block classification', () => {
  for (const v of E70T17_BLOCK) assert.equal(E70T17Classify(v), E70T17_CLASS.BLOCK, v)
})

test('E70T17 warn classification', () => {
  for (const v of E70T17_WARN) assert.equal(E70T17Classify(v), E70T17_CLASS.WARN, v)
})

test('E70T17 allow classification', () => {
  for (const v of E70T17_ALLOW) assert.equal(E70T17Classify(v), E70T17_CLASS.ALLOW, v)
})

test('E70T17 unknown classification', () => {
  assert.equal(E70T17Classify('zzz-not-in-any-e70-catalog-99'), E70T17_CLASS.UNKNOWN)
})
