'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T05Classify, E70T05_CLASS, E70T05_BLOCK, E70T05_WARN, E70T05_ALLOW } = require('./e70thaanacatalogguard.js')

test('E70T05 block classification', () => {
  for (const v of E70T05_BLOCK) assert.equal(E70T05Classify(v), E70T05_CLASS.BLOCK, v)
})

test('E70T05 warn classification', () => {
  for (const v of E70T05_WARN) assert.equal(E70T05Classify(v), E70T05_CLASS.WARN, v)
})

test('E70T05 allow classification', () => {
  for (const v of E70T05_ALLOW) assert.equal(E70T05Classify(v), E70T05_CLASS.ALLOW, v)
})

test('E70T05 unknown classification', () => {
  assert.equal(E70T05Classify('zzz-not-in-any-e70-catalog-99'), E70T05_CLASS.UNKNOWN)
})
