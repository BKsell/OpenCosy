'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U13Classify, E70U13_CLASS, E70U13_BLOCK, E70U13_WARN, E70U13_ALLOW } = require('./e70enclosedideographsuppcatalogguard.js')

test('E70U13 block classification', () => {
  for (const v of E70U13_BLOCK) assert.equal(E70U13Classify(v), E70U13_CLASS.BLOCK, v)
})

test('E70U13 warn classification', () => {
  for (const v of E70U13_WARN) assert.equal(E70U13Classify(v), E70U13_CLASS.WARN, v)
})

test('E70U13 allow classification', () => {
  for (const v of E70U13_ALLOW) assert.equal(E70U13Classify(v), E70U13_CLASS.ALLOW, v)
})

test('E70U13 unknown classification', () => {
  assert.equal(E70U13Classify('zzz-not-in-any-e70-catalog-99'), E70U13_CLASS.UNKNOWN)
})
