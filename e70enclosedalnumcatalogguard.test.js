'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T44Classify, E70T44_CLASS, E70T44_BLOCK, E70T44_WARN, E70T44_ALLOW } = require('./e70enclosedalnumcatalogguard.js')

test('E70T44 block classification', () => {
  for (const v of E70T44_BLOCK) assert.equal(E70T44Classify(v), E70T44_CLASS.BLOCK, v)
})

test('E70T44 warn classification', () => {
  for (const v of E70T44_WARN) assert.equal(E70T44Classify(v), E70T44_CLASS.WARN, v)
})

test('E70T44 allow classification', () => {
  for (const v of E70T44_ALLOW) assert.equal(E70T44Classify(v), E70T44_CLASS.ALLOW, v)
})

test('E70T44 unknown classification', () => {
  assert.equal(E70T44Classify('zzz-not-in-any-e70-catalog-99'), E70T44_CLASS.UNKNOWN)
})
