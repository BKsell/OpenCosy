'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T28Classify, E70T28_CLASS, E70T28_BLOCK, E70T28_WARN, E70T28_ALLOW } = require('./e70buginesecatalogguard.js')

test('E70T28 block classification', () => {
  for (const v of E70T28_BLOCK) assert.equal(E70T28Classify(v), E70T28_CLASS.BLOCK, v)
})

test('E70T28 warn classification', () => {
  for (const v of E70T28_WARN) assert.equal(E70T28Classify(v), E70T28_CLASS.WARN, v)
})

test('E70T28 allow classification', () => {
  for (const v of E70T28_ALLOW) assert.equal(E70T28Classify(v), E70T28_CLASS.ALLOW, v)
})

test('E70T28 unknown classification', () => {
  assert.equal(E70T28Classify('zzz-not-in-any-e70-catalog-99'), E70T28_CLASS.UNKNOWN)
})
