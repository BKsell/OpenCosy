'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T36Classify, E70T36_CLASS, E70T36_BLOCK, E70T36_WARN, E70T36_ALLOW } = require('./e70greekextendedcatalogguard.js')

test('E70T36 block classification', () => {
  for (const v of E70T36_BLOCK) assert.equal(E70T36Classify(v), E70T36_CLASS.BLOCK, v)
})

test('E70T36 warn classification', () => {
  for (const v of E70T36_WARN) assert.equal(E70T36Classify(v), E70T36_CLASS.WARN, v)
})

test('E70T36 allow classification', () => {
  for (const v of E70T36_ALLOW) assert.equal(E70T36Classify(v), E70T36_CLASS.ALLOW, v)
})

test('E70T36 unknown classification', () => {
  assert.equal(E70T36Classify('zzz-not-in-any-e70-catalog-99'), E70T36_CLASS.UNKNOWN)
})
