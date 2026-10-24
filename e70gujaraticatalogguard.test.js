'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T12Classify, E70T12_CLASS, E70T12_BLOCK, E70T12_WARN, E70T12_ALLOW } = require('./e70gujaraticatalogguard.js')

test('E70T12 block classification', () => {
  for (const v of E70T12_BLOCK) assert.equal(E70T12Classify(v), E70T12_CLASS.BLOCK, v)
})

test('E70T12 warn classification', () => {
  for (const v of E70T12_WARN) assert.equal(E70T12Classify(v), E70T12_CLASS.WARN, v)
})

test('E70T12 allow classification', () => {
  for (const v of E70T12_ALLOW) assert.equal(E70T12Classify(v), E70T12_CLASS.ALLOW, v)
})

test('E70T12 unknown classification', () => {
  assert.equal(E70T12Classify('zzz-not-in-any-e70-catalog-99'), E70T12_CLASS.UNKNOWN)
})
