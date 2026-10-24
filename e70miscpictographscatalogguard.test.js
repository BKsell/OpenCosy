'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U15Classify, E70U15_CLASS, E70U15_BLOCK, E70U15_WARN, E70U15_ALLOW } = require('./e70miscpictographscatalogguard.js')

test('E70U15 block classification', () => {
  for (const v of E70U15_BLOCK) assert.equal(E70U15Classify(v), E70U15_CLASS.BLOCK, v)
})

test('E70U15 warn classification', () => {
  for (const v of E70U15_WARN) assert.equal(E70U15Classify(v), E70U15_CLASS.WARN, v)
})

test('E70U15 allow classification', () => {
  for (const v of E70U15_ALLOW) assert.equal(E70U15Classify(v), E70U15_CLASS.ALLOW, v)
})

test('E70U15 unknown classification', () => {
  assert.equal(E70U15Classify('zzz-not-in-any-e70-catalog-99'), E70U15_CLASS.UNKNOWN)
})
