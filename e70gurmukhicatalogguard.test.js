'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T11Classify, E70T11_CLASS, E70T11_BLOCK, E70T11_WARN, E70T11_ALLOW } = require('./e70gurmukhicatalogguard.js')

test('E70T11 block classification', () => {
  for (const v of E70T11_BLOCK) assert.equal(E70T11Classify(v), E70T11_CLASS.BLOCK, v)
})

test('E70T11 warn classification', () => {
  for (const v of E70T11_WARN) assert.equal(E70T11Classify(v), E70T11_CLASS.WARN, v)
})

test('E70T11 allow classification', () => {
  for (const v of E70T11_ALLOW) assert.equal(E70T11Classify(v), E70T11_CLASS.ALLOW, v)
})

test('E70T11 unknown classification', () => {
  assert.equal(E70T11Classify('zzz-not-in-any-e70-catalog-99'), E70T11_CLASS.UNKNOWN)
})
