'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R15Classify, E68R15_CLASS, E68R15_BLOCK, E68R15_WARN, E68R15_ALLOW } = require('./e68thaicatalogguard.js')

test('E68R15 block classification', () => {
  for (const v of E68R15_BLOCK) assert.equal(E68R15Classify(v), E68R15_CLASS.BLOCK, v)
})

test('E68R15 warn classification', () => {
  for (const v of E68R15_WARN) assert.equal(E68R15Classify(v), E68R15_CLASS.WARN, v)
})

test('E68R15 allow classification', () => {
  for (const v of E68R15_ALLOW) assert.equal(E68R15Classify(v), E68R15_CLASS.ALLOW, v)
})

test('E68R15 unknown classification', () => {
  assert.equal(E68R15Classify('zzz-not-in-any-e68-catalog-77'), E68R15_CLASS.UNKNOWN)
})
