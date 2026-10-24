'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T19Classify, E70T19_CLASS, E70T19_BLOCK, E70T19_WARN, E70T19_ALLOW } = require('./e70thaicatalogguard.js')

test('E70T19 block classification', () => {
  for (const v of E70T19_BLOCK) assert.equal(E70T19Classify(v), E70T19_CLASS.BLOCK, v)
})

test('E70T19 warn classification', () => {
  for (const v of E70T19_WARN) assert.equal(E70T19Classify(v), E70T19_CLASS.WARN, v)
})

test('E70T19 allow classification', () => {
  for (const v of E70T19_ALLOW) assert.equal(E70T19Classify(v), E70T19_CLASS.ALLOW, v)
})

test('E70T19 unknown classification', () => {
  assert.equal(E70T19Classify('zzz-not-in-any-e70-catalog-99'), E70T19_CLASS.UNKNOWN)
})
