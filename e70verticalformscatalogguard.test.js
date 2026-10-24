'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T60Classify, E70T60_CLASS, E70T60_BLOCK, E70T60_WARN, E70T60_ALLOW } = require('./e70verticalformscatalogguard.js')

test('E70T60 block classification', () => {
  for (const v of E70T60_BLOCK) assert.equal(E70T60Classify(v), E70T60_CLASS.BLOCK, v)
})

test('E70T60 warn classification', () => {
  for (const v of E70T60_WARN) assert.equal(E70T60Classify(v), E70T60_CLASS.WARN, v)
})

test('E70T60 allow classification', () => {
  for (const v of E70T60_ALLOW) assert.equal(E70T60Classify(v), E70T60_CLASS.ALLOW, v)
})

test('E70T60 unknown classification', () => {
  assert.equal(E70T60Classify('zzz-not-in-any-e70-catalog-99'), E70T60_CLASS.UNKNOWN)
})
