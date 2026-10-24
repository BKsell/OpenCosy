'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R11Classify, E68R11_CLASS, E68R11_BLOCK, E68R11_WARN, E68R11_ALLOW } = require('./e68telugucatalogguard.js')

test('E68R11 block classification', () => {
  for (const v of E68R11_BLOCK) assert.equal(E68R11Classify(v), E68R11_CLASS.BLOCK, v)
})

test('E68R11 warn classification', () => {
  for (const v of E68R11_WARN) assert.equal(E68R11Classify(v), E68R11_CLASS.WARN, v)
})

test('E68R11 allow classification', () => {
  for (const v of E68R11_ALLOW) assert.equal(E68R11Classify(v), E68R11_CLASS.ALLOW, v)
})

test('E68R11 unknown classification', () => {
  assert.equal(E68R11Classify('zzz-not-in-any-e68-catalog-77'), E68R11_CLASS.UNKNOWN)
})
