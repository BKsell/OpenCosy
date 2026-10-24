'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T38Classify, E70T38_CLASS, E70T38_BLOCK, E70T38_WARN, E70T38_ALLOW } = require('./e70letterlikecatalogguard.js')

test('E70T38 block classification', () => {
  for (const v of E70T38_BLOCK) assert.equal(E70T38Classify(v), E70T38_CLASS.BLOCK, v)
})

test('E70T38 warn classification', () => {
  for (const v of E70T38_WARN) assert.equal(E70T38Classify(v), E70T38_CLASS.WARN, v)
})

test('E70T38 allow classification', () => {
  for (const v of E70T38_ALLOW) assert.equal(E70T38Classify(v), E70T38_CLASS.ALLOW, v)
})

test('E70T38 unknown classification', () => {
  assert.equal(E70T38Classify('zzz-not-in-any-e70-catalog-99'), E70T38_CLASS.UNKNOWN)
})
