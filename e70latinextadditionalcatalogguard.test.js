'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T35Classify, E70T35_CLASS, E70T35_BLOCK, E70T35_WARN, E70T35_ALLOW } = require('./e70latinextadditionalcatalogguard.js')

test('E70T35 block classification', () => {
  for (const v of E70T35_BLOCK) assert.equal(E70T35Classify(v), E70T35_CLASS.BLOCK, v)
})

test('E70T35 warn classification', () => {
  for (const v of E70T35_WARN) assert.equal(E70T35Classify(v), E70T35_CLASS.WARN, v)
})

test('E70T35 allow classification', () => {
  for (const v of E70T35_ALLOW) assert.equal(E70T35Classify(v), E70T35_CLASS.ALLOW, v)
})

test('E70T35 unknown classification', () => {
  assert.equal(E70T35Classify('zzz-not-in-any-e70-catalog-99'), E70T35_CLASS.UNKNOWN)
})
