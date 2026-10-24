'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U01Classify, E70U01_CLASS, E70U01_BLOCK, E70U01_WARN, E70U01_ALLOW } = require('./e70lyciancatalogguard.js')

test('E70U01 block classification', () => {
  for (const v of E70U01_BLOCK) assert.equal(E70U01Classify(v), E70U01_CLASS.BLOCK, v)
})

test('E70U01 warn classification', () => {
  for (const v of E70U01_WARN) assert.equal(E70U01Classify(v), E70U01_CLASS.WARN, v)
})

test('E70U01 allow classification', () => {
  for (const v of E70U01_ALLOW) assert.equal(E70U01Classify(v), E70U01_CLASS.ALLOW, v)
})

test('E70U01 unknown classification', () => {
  assert.equal(E70U01Classify('zzz-not-in-any-e70-catalog-99'), E70U01_CLASS.UNKNOWN)
})
