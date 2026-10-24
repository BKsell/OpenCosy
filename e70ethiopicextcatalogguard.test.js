'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T54Classify, E70T54_CLASS, E70T54_BLOCK, E70T54_WARN, E70T54_ALLOW } = require('./e70ethiopicextcatalogguard.js')

test('E70T54 block classification', () => {
  for (const v of E70T54_BLOCK) assert.equal(E70T54Classify(v), E70T54_CLASS.BLOCK, v)
})

test('E70T54 warn classification', () => {
  for (const v of E70T54_WARN) assert.equal(E70T54Classify(v), E70T54_CLASS.WARN, v)
})

test('E70T54 allow classification', () => {
  for (const v of E70T54_ALLOW) assert.equal(E70T54Classify(v), E70T54_CLASS.ALLOW, v)
})

test('E70T54 unknown classification', () => {
  assert.equal(E70T54Classify('zzz-not-in-any-e70-catalog-99'), E70T54_CLASS.UNKNOWN)
})
