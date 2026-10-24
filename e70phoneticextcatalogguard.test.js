'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T34Classify, E70T34_CLASS, E70T34_BLOCK, E70T34_WARN, E70T34_ALLOW } = require('./e70phoneticextcatalogguard.js')

test('E70T34 block classification', () => {
  for (const v of E70T34_BLOCK) assert.equal(E70T34Classify(v), E70T34_CLASS.BLOCK, v)
})

test('E70T34 warn classification', () => {
  for (const v of E70T34_WARN) assert.equal(E70T34Classify(v), E70T34_CLASS.WARN, v)
})

test('E70T34 allow classification', () => {
  for (const v of E70T34_ALLOW) assert.equal(E70T34Classify(v), E70T34_CLASS.ALLOW, v)
})

test('E70T34 unknown classification', () => {
  assert.equal(E70T34Classify('zzz-not-in-any-e70-catalog-99'), E70T34_CLASS.UNKNOWN)
})
