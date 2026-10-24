'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T58Classify, E70T58_CLASS, E70T58_BLOCK, E70T58_WARN, E70T58_ALLOW } = require('./e70cyrillicextbcatalogguard.js')

test('E70T58 block classification', () => {
  for (const v of E70T58_BLOCK) assert.equal(E70T58Classify(v), E70T58_CLASS.BLOCK, v)
})

test('E70T58 warn classification', () => {
  for (const v of E70T58_WARN) assert.equal(E70T58Classify(v), E70T58_CLASS.WARN, v)
})

test('E70T58 allow classification', () => {
  for (const v of E70T58_ALLOW) assert.equal(E70T58Classify(v), E70T58_CLASS.ALLOW, v)
})

test('E70T58 unknown classification', () => {
  assert.equal(E70T58Classify('zzz-not-in-any-e70-catalog-99'), E70T58_CLASS.UNKNOWN)
})
