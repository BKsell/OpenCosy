'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T03Classify, E70T03_CLASS, E70T03_BLOCK, E70T03_WARN, E70T03_ALLOW } = require('./e70syriaccatalogguard.js')

test('E70T03 block classification', () => {
  for (const v of E70T03_BLOCK) assert.equal(E70T03Classify(v), E70T03_CLASS.BLOCK, v)
})

test('E70T03 warn classification', () => {
  for (const v of E70T03_WARN) assert.equal(E70T03Classify(v), E70T03_CLASS.WARN, v)
})

test('E70T03 allow classification', () => {
  for (const v of E70T03_ALLOW) assert.equal(E70T03Classify(v), E70T03_CLASS.ALLOW, v)
})

test('E70T03 unknown classification', () => {
  assert.equal(E70T03Classify('zzz-not-in-any-e70-catalog-99'), E70T03_CLASS.UNKNOWN)
})
