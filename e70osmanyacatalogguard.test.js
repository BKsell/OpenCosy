'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U07Classify, E70U07_CLASS, E70U07_BLOCK, E70U07_WARN, E70U07_ALLOW } = require('./e70osmanyacatalogguard.js')

test('E70U07 block classification', () => {
  for (const v of E70U07_BLOCK) assert.equal(E70U07Classify(v), E70U07_CLASS.BLOCK, v)
})

test('E70U07 warn classification', () => {
  for (const v of E70U07_WARN) assert.equal(E70U07Classify(v), E70U07_CLASS.WARN, v)
})

test('E70U07 allow classification', () => {
  for (const v of E70U07_ALLOW) assert.equal(E70U07Classify(v), E70U07_CLASS.ALLOW, v)
})

test('E70U07 unknown classification', () => {
  assert.equal(E70U07Classify('zzz-not-in-any-e70-catalog-99'), E70U07_CLASS.UNKNOWN)
})
