'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U11Classify, E70U11_CLASS, E70U11_BLOCK, E70U11_WARN, E70U11_ALLOW } = require('./e70mathalnum2catalogguard.js')

test('E70U11 block classification', () => {
  for (const v of E70U11_BLOCK) assert.equal(E70U11Classify(v), E70U11_CLASS.BLOCK, v)
})

test('E70U11 warn classification', () => {
  for (const v of E70U11_WARN) assert.equal(E70U11Classify(v), E70U11_CLASS.WARN, v)
})

test('E70U11 allow classification', () => {
  for (const v of E70U11_ALLOW) assert.equal(E70U11Classify(v), E70U11_CLASS.ALLOW, v)
})

test('E70U11 unknown classification', () => {
  assert.equal(E70U11Classify('zzz-not-in-any-e70-catalog-99'), E70U11_CLASS.UNKNOWN)
})
