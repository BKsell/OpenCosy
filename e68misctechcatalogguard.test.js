'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R28Classify, E68R28_CLASS, E68R28_BLOCK, E68R28_WARN, E68R28_ALLOW } = require('./e68misctechcatalogguard.js')

test('E68R28 block classification', () => {
  for (const v of E68R28_BLOCK) assert.equal(E68R28Classify(v), E68R28_CLASS.BLOCK, v)
})

test('E68R28 warn classification', () => {
  for (const v of E68R28_WARN) assert.equal(E68R28Classify(v), E68R28_CLASS.WARN, v)
})

test('E68R28 allow classification', () => {
  for (const v of E68R28_ALLOW) assert.equal(E68R28Classify(v), E68R28_CLASS.ALLOW, v)
})

test('E68R28 unknown classification', () => {
  assert.equal(E68R28Classify('zzz-not-in-any-e68-catalog-77'), E68R28_CLASS.UNKNOWN)
})
