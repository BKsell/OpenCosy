'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T59Classify, E70T59_CLASS, E70T59_BLOCK, E70T59_WARN, E70T59_ALLOW } = require('./e70modifiertonecatalogguard.js')

test('E70T59 block classification', () => {
  for (const v of E70T59_BLOCK) assert.equal(E70T59Classify(v), E70T59_CLASS.BLOCK, v)
})

test('E70T59 warn classification', () => {
  for (const v of E70T59_WARN) assert.equal(E70T59Classify(v), E70T59_CLASS.WARN, v)
})

test('E70T59 allow classification', () => {
  for (const v of E70T59_ALLOW) assert.equal(E70T59Classify(v), E70T59_CLASS.ALLOW, v)
})

test('E70T59 unknown classification', () => {
  assert.equal(E70T59Classify('zzz-not-in-any-e70-catalog-99'), E70T59_CLASS.UNKNOWN)
})
