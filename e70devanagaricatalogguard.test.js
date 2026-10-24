'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T09Classify, E70T09_CLASS, E70T09_BLOCK, E70T09_WARN, E70T09_ALLOW } = require('./e70devanagaricatalogguard.js')

test('E70T09 block classification', () => {
  for (const v of E70T09_BLOCK) assert.equal(E70T09Classify(v), E70T09_CLASS.BLOCK, v)
})

test('E70T09 warn classification', () => {
  for (const v of E70T09_WARN) assert.equal(E70T09Classify(v), E70T09_CLASS.WARN, v)
})

test('E70T09 allow classification', () => {
  for (const v of E70T09_ALLOW) assert.equal(E70T09Classify(v), E70T09_CLASS.ALLOW, v)
})

test('E70T09 unknown classification', () => {
  assert.equal(E70T09Classify('zzz-not-in-any-e70-catalog-99'), E70T09_CLASS.UNKNOWN)
})
