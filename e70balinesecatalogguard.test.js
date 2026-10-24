'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T29Classify, E70T29_CLASS, E70T29_BLOCK, E70T29_WARN, E70T29_ALLOW } = require('./e70balinesecatalogguard.js')

test('E70T29 block classification', () => {
  for (const v of E70T29_BLOCK) assert.equal(E70T29Classify(v), E70T29_CLASS.BLOCK, v)
})

test('E70T29 warn classification', () => {
  for (const v of E70T29_WARN) assert.equal(E70T29Classify(v), E70T29_CLASS.WARN, v)
})

test('E70T29 allow classification', () => {
  for (const v of E70T29_ALLOW) assert.equal(E70T29Classify(v), E70T29_CLASS.ALLOW, v)
})

test('E70T29 unknown classification', () => {
  assert.equal(E70T29Classify('zzz-not-in-any-e70-catalog-99'), E70T29_CLASS.UNKNOWN)
})
