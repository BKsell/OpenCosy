'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R13Classify, E68R13_CLASS, E68R13_BLOCK, E68R13_WARN, E68R13_ALLOW } = require('./e68malayalamcatalogguard.js')

test('E68R13 block classification', () => {
  for (const v of E68R13_BLOCK) assert.equal(E68R13Classify(v), E68R13_CLASS.BLOCK, v)
})

test('E68R13 warn classification', () => {
  for (const v of E68R13_WARN) assert.equal(E68R13Classify(v), E68R13_CLASS.WARN, v)
})

test('E68R13 allow classification', () => {
  for (const v of E68R13_ALLOW) assert.equal(E68R13Classify(v), E68R13_CLASS.ALLOW, v)
})

test('E68R13 unknown classification', () => {
  assert.equal(E68R13Classify('zzz-not-in-any-e68-catalog-77'), E68R13_CLASS.UNKNOWN)
})
