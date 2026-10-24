'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T06Classify, E70T06_CLASS, E70T06_BLOCK, E70T06_WARN, E70T06_ALLOW } = require('./e70nkocatalogguard.js')

test('E70T06 block classification', () => {
  for (const v of E70T06_BLOCK) assert.equal(E70T06Classify(v), E70T06_CLASS.BLOCK, v)
})

test('E70T06 warn classification', () => {
  for (const v of E70T06_WARN) assert.equal(E70T06Classify(v), E70T06_CLASS.WARN, v)
})

test('E70T06 allow classification', () => {
  for (const v of E70T06_ALLOW) assert.equal(E70T06Classify(v), E70T06_CLASS.ALLOW, v)
})

test('E70T06 unknown classification', () => {
  assert.equal(E70T06Classify('zzz-not-in-any-e70-catalog-99'), E70T06_CLASS.UNKNOWN)
})
