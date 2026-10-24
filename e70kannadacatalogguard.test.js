'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T16Classify, E70T16_CLASS, E70T16_BLOCK, E70T16_WARN, E70T16_ALLOW } = require('./e70kannadacatalogguard.js')

test('E70T16 block classification', () => {
  for (const v of E70T16_BLOCK) assert.equal(E70T16Classify(v), E70T16_CLASS.BLOCK, v)
})

test('E70T16 warn classification', () => {
  for (const v of E70T16_WARN) assert.equal(E70T16Classify(v), E70T16_CLASS.WARN, v)
})

test('E70T16 allow classification', () => {
  for (const v of E70T16_ALLOW) assert.equal(E70T16Classify(v), E70T16_CLASS.ALLOW, v)
})

test('E70T16 unknown classification', () => {
  assert.equal(E70T16Classify('zzz-not-in-any-e70-catalog-99'), E70T16_CLASS.UNKNOWN)
})
