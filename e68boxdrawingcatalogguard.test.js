'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R31Classify, E68R31_CLASS, E68R31_BLOCK, E68R31_WARN, E68R31_ALLOW } = require('./e68boxdrawingcatalogguard.js')

test('E68R31 block classification', () => {
  for (const v of E68R31_BLOCK) assert.equal(E68R31Classify(v), E68R31_CLASS.BLOCK, v)
})

test('E68R31 warn classification', () => {
  for (const v of E68R31_WARN) assert.equal(E68R31Classify(v), E68R31_CLASS.WARN, v)
})

test('E68R31 allow classification', () => {
  for (const v of E68R31_ALLOW) assert.equal(E68R31Classify(v), E68R31_CLASS.ALLOW, v)
})

test('E68R31 unknown classification', () => {
  assert.equal(E68R31Classify('zzz-not-in-any-e68-catalog-77'), E68R31_CLASS.UNKNOWN)
})
