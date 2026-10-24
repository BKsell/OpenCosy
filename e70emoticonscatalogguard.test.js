'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U14Classify, E70U14_CLASS, E70U14_BLOCK, E70U14_WARN, E70U14_ALLOW } = require('./e70emoticonscatalogguard.js')

test('E70U14 block classification', () => {
  for (const v of E70U14_BLOCK) assert.equal(E70U14Classify(v), E70U14_CLASS.BLOCK, v)
})

test('E70U14 warn classification', () => {
  for (const v of E70U14_WARN) assert.equal(E70U14Classify(v), E70U14_CLASS.WARN, v)
})

test('E70U14 allow classification', () => {
  for (const v of E70U14_ALLOW) assert.equal(E70U14Classify(v), E70U14_CLASS.ALLOW, v)
})

test('E70U14 unknown classification', () => {
  assert.equal(E70U14Classify('zzz-not-in-any-e70-catalog-99'), E70U14_CLASS.UNKNOWN)
})
