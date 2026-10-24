'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T14Classify, E70T14_CLASS, E70T14_BLOCK, E70T14_WARN, E70T14_ALLOW } = require('./e70tamilcatalogguard.js')

test('E70T14 block classification', () => {
  for (const v of E70T14_BLOCK) assert.equal(E70T14Classify(v), E70T14_CLASS.BLOCK, v)
})

test('E70T14 warn classification', () => {
  for (const v of E70T14_WARN) assert.equal(E70T14Classify(v), E70T14_CLASS.WARN, v)
})

test('E70T14 allow classification', () => {
  for (const v of E70T14_ALLOW) assert.equal(E70T14Classify(v), E70T14_CLASS.ALLOW, v)
})

test('E70T14 unknown classification', () => {
  assert.equal(E70T14Classify('zzz-not-in-any-e70-catalog-99'), E70T14_CLASS.UNKNOWN)
})
