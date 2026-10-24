'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T43Classify, E70T43_CLASS, E70T43_BLOCK, E70T43_WARN, E70T43_ALLOW } = require('./e70controlpicturescatalogguard.js')

test('E70T43 block classification', () => {
  for (const v of E70T43_BLOCK) assert.equal(E70T43Classify(v), E70T43_CLASS.BLOCK, v)
})

test('E70T43 warn classification', () => {
  for (const v of E70T43_WARN) assert.equal(E70T43Classify(v), E70T43_CLASS.WARN, v)
})

test('E70T43 allow classification', () => {
  for (const v of E70T43_ALLOW) assert.equal(E70T43Classify(v), E70T43_CLASS.ALLOW, v)
})

test('E70T43 unknown classification', () => {
  assert.equal(E70T43Classify('zzz-not-in-any-e70-catalog-99'), E70T43_CLASS.UNKNOWN)
})
