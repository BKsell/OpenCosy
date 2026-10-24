'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T07Classify, E70T07_CLASS, E70T07_BLOCK, E70T07_WARN, E70T07_ALLOW } = require('./e70samaritancatalogguard.js')

test('E70T07 block classification', () => {
  for (const v of E70T07_BLOCK) assert.equal(E70T07Classify(v), E70T07_CLASS.BLOCK, v)
})

test('E70T07 warn classification', () => {
  for (const v of E70T07_WARN) assert.equal(E70T07Classify(v), E70T07_CLASS.WARN, v)
})

test('E70T07 allow classification', () => {
  for (const v of E70T07_ALLOW) assert.equal(E70T07Classify(v), E70T07_CLASS.ALLOW, v)
})

test('E70T07 unknown classification', () => {
  assert.equal(E70T07Classify('zzz-not-in-any-e70-catalog-99'), E70T07_CLASS.UNKNOWN)
})
