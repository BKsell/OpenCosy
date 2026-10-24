'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T26Classify, E70T26_CLASS, E70T26_BLOCK, E70T26_WARN, E70T26_ALLOW } = require('./e70tailecatalogguard.js')

test('E70T26 block classification', () => {
  for (const v of E70T26_BLOCK) assert.equal(E70T26Classify(v), E70T26_CLASS.BLOCK, v)
})

test('E70T26 warn classification', () => {
  for (const v of E70T26_WARN) assert.equal(E70T26Classify(v), E70T26_CLASS.WARN, v)
})

test('E70T26 allow classification', () => {
  for (const v of E70T26_ALLOW) assert.equal(E70T26Classify(v), E70T26_CLASS.ALLOW, v)
})

test('E70T26 unknown classification', () => {
  assert.equal(E70T26Classify('zzz-not-in-any-e70-catalog-99'), E70T26_CLASS.UNKNOWN)
})
