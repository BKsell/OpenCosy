'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T01Classify, E70T01_CLASS, E70T01_BLOCK, E70T01_WARN, E70T01_ALLOW } = require('./e70hebrewcatalogguard.js')

test('E70T01 block classification', () => {
  for (const v of E70T01_BLOCK) assert.equal(E70T01Classify(v), E70T01_CLASS.BLOCK, v)
})

test('E70T01 warn classification', () => {
  for (const v of E70T01_WARN) assert.equal(E70T01Classify(v), E70T01_CLASS.WARN, v)
})

test('E70T01 allow classification', () => {
  for (const v of E70T01_ALLOW) assert.equal(E70T01Classify(v), E70T01_CLASS.ALLOW, v)
})

test('E70T01 unknown classification', () => {
  assert.equal(E70T01Classify('zzz-not-in-any-e70-catalog-99'), E70T01_CLASS.UNKNOWN)
})
