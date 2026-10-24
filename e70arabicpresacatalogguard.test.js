'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T62Classify, E70T62_CLASS, E70T62_BLOCK, E70T62_WARN, E70T62_ALLOW } = require('./e70arabicpresacatalogguard.js')

test('E70T62 block classification', () => {
  for (const v of E70T62_BLOCK) assert.equal(E70T62Classify(v), E70T62_CLASS.BLOCK, v)
})

test('E70T62 warn classification', () => {
  for (const v of E70T62_WARN) assert.equal(E70T62Classify(v), E70T62_CLASS.WARN, v)
})

test('E70T62 allow classification', () => {
  for (const v of E70T62_ALLOW) assert.equal(E70T62Classify(v), E70T62_CLASS.ALLOW, v)
})

test('E70T62 unknown classification', () => {
  assert.equal(E70T62Classify('zzz-not-in-any-e70-catalog-99'), E70T62_CLASS.UNKNOWN)
})
