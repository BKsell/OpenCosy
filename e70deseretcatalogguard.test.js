'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U05Classify, E70U05_CLASS, E70U05_BLOCK, E70U05_WARN, E70U05_ALLOW } = require('./e70deseretcatalogguard.js')

test('E70U05 block classification', () => {
  for (const v of E70U05_BLOCK) assert.equal(E70U05Classify(v), E70U05_CLASS.BLOCK, v)
})

test('E70U05 warn classification', () => {
  for (const v of E70U05_WARN) assert.equal(E70U05Classify(v), E70U05_CLASS.WARN, v)
})

test('E70U05 allow classification', () => {
  for (const v of E70U05_ALLOW) assert.equal(E70U05Classify(v), E70U05_CLASS.ALLOW, v)
})

test('E70U05 unknown classification', () => {
  assert.equal(E70U05Classify('zzz-not-in-any-e70-catalog-99'), E70U05_CLASS.UNKNOWN)
})
