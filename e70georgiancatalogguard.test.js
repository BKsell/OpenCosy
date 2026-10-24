'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T23Classify, E70T23_CLASS, E70T23_BLOCK, E70T23_WARN, E70T23_ALLOW } = require('./e70georgiancatalogguard.js')

test('E70T23 block classification', () => {
  for (const v of E70T23_BLOCK) assert.equal(E70T23Classify(v), E70T23_CLASS.BLOCK, v)
})

test('E70T23 warn classification', () => {
  for (const v of E70T23_WARN) assert.equal(E70T23Classify(v), E70T23_CLASS.WARN, v)
})

test('E70T23 allow classification', () => {
  for (const v of E70T23_ALLOW) assert.equal(E70T23Classify(v), E70T23_CLASS.ALLOW, v)
})

test('E70T23 unknown classification', () => {
  assert.equal(E70T23Classify('zzz-not-in-any-e70-catalog-99'), E70T23_CLASS.UNKNOWN)
})
