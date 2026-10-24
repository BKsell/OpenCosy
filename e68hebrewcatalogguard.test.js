'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R01Classify, E68R01_CLASS, E68R01_BLOCK, E68R01_WARN, E68R01_ALLOW } = require('./e68hebrewcatalogguard.js')

test('E68R01 block classification', () => {
  for (const v of E68R01_BLOCK) assert.equal(E68R01Classify(v), E68R01_CLASS.BLOCK, v)
})

test('E68R01 warn classification', () => {
  for (const v of E68R01_WARN) assert.equal(E68R01Classify(v), E68R01_CLASS.WARN, v)
})

test('E68R01 allow classification', () => {
  for (const v of E68R01_ALLOW) assert.equal(E68R01Classify(v), E68R01_CLASS.ALLOW, v)
})

test('E68R01 unknown classification', () => {
  assert.equal(E68R01Classify('zzz-not-in-any-e68-catalog-77'), E68R01_CLASS.UNKNOWN)
})
