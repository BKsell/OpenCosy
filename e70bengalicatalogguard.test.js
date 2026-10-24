'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T10Classify, E70T10_CLASS, E70T10_BLOCK, E70T10_WARN, E70T10_ALLOW } = require('./e70bengalicatalogguard.js')

test('E70T10 block classification', () => {
  for (const v of E70T10_BLOCK) assert.equal(E70T10Classify(v), E70T10_CLASS.BLOCK, v)
})

test('E70T10 warn classification', () => {
  for (const v of E70T10_WARN) assert.equal(E70T10Classify(v), E70T10_CLASS.WARN, v)
})

test('E70T10 allow classification', () => {
  for (const v of E70T10_ALLOW) assert.equal(E70T10Classify(v), E70T10_CLASS.ALLOW, v)
})

test('E70T10 unknown classification', () => {
  assert.equal(E70T10Classify('zzz-not-in-any-e70-catalog-99'), E70T10_CLASS.UNKNOWN)
})
