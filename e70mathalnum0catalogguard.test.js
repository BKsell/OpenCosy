'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U09Classify, E70U09_CLASS, E70U09_BLOCK, E70U09_WARN, E70U09_ALLOW } = require('./e70mathalnum0catalogguard.js')

test('E70U09 block classification', () => {
  for (const v of E70U09_BLOCK) assert.equal(E70U09Classify(v), E70U09_CLASS.BLOCK, v)
})

test('E70U09 warn classification', () => {
  for (const v of E70U09_WARN) assert.equal(E70U09Classify(v), E70U09_CLASS.WARN, v)
})

test('E70U09 allow classification', () => {
  for (const v of E70U09_ALLOW) assert.equal(E70U09Classify(v), E70U09_CLASS.ALLOW, v)
})

test('E70U09 unknown classification', () => {
  assert.equal(E70U09Classify('zzz-not-in-any-e70-catalog-99'), E70U09_CLASS.UNKNOWN)
})
