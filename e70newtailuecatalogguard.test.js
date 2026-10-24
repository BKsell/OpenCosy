'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T27Classify, E70T27_CLASS, E70T27_BLOCK, E70T27_WARN, E70T27_ALLOW } = require('./e70newtailuecatalogguard.js')

test('E70T27 block classification', () => {
  for (const v of E70T27_BLOCK) assert.equal(E70T27Classify(v), E70T27_CLASS.BLOCK, v)
})

test('E70T27 warn classification', () => {
  for (const v of E70T27_WARN) assert.equal(E70T27Classify(v), E70T27_CLASS.WARN, v)
})

test('E70T27 allow classification', () => {
  for (const v of E70T27_ALLOW) assert.equal(E70T27Classify(v), E70T27_CLASS.ALLOW, v)
})

test('E70T27 unknown classification', () => {
  assert.equal(E70T27Classify('zzz-not-in-any-e70-catalog-99'), E70T27_CLASS.UNKNOWN)
})
