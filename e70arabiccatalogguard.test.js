'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T02Classify, E70T02_CLASS, E70T02_BLOCK, E70T02_WARN, E70T02_ALLOW } = require('./e70arabiccatalogguard.js')

test('E70T02 block classification', () => {
  for (const v of E70T02_BLOCK) assert.equal(E70T02Classify(v), E70T02_CLASS.BLOCK, v)
})

test('E70T02 warn classification', () => {
  for (const v of E70T02_WARN) assert.equal(E70T02Classify(v), E70T02_CLASS.WARN, v)
})

test('E70T02 allow classification', () => {
  for (const v of E70T02_ALLOW) assert.equal(E70T02Classify(v), E70T02_CLASS.ALLOW, v)
})

test('E70T02 unknown classification', () => {
  assert.equal(E70T02Classify('zzz-not-in-any-e70-catalog-99'), E70T02_CLASS.UNKNOWN)
})
