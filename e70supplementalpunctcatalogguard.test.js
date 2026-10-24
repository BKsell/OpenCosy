'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T55Classify, E70T55_CLASS, E70T55_BLOCK, E70T55_WARN, E70T55_ALLOW } = require('./e70supplementalpunctcatalogguard.js')

test('E70T55 block classification', () => {
  for (const v of E70T55_BLOCK) assert.equal(E70T55Classify(v), E70T55_CLASS.BLOCK, v)
})

test('E70T55 warn classification', () => {
  for (const v of E70T55_WARN) assert.equal(E70T55Classify(v), E70T55_CLASS.WARN, v)
})

test('E70T55 allow classification', () => {
  for (const v of E70T55_ALLOW) assert.equal(E70T55Classify(v), E70T55_CLASS.ALLOW, v)
})

test('E70T55 unknown classification', () => {
  assert.equal(E70T55Classify('zzz-not-in-any-e70-catalog-99'), E70T55_CLASS.UNKNOWN)
})
