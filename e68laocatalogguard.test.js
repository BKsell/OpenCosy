'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R16Classify, E68R16_CLASS, E68R16_BLOCK, E68R16_WARN, E68R16_ALLOW } = require('./e68laocatalogguard.js')

test('E68R16 block classification', () => {
  for (const v of E68R16_BLOCK) assert.equal(E68R16Classify(v), E68R16_CLASS.BLOCK, v)
})

test('E68R16 warn classification', () => {
  for (const v of E68R16_WARN) assert.equal(E68R16Classify(v), E68R16_CLASS.WARN, v)
})

test('E68R16 allow classification', () => {
  for (const v of E68R16_ALLOW) assert.equal(E68R16Classify(v), E68R16_CLASS.ALLOW, v)
})

test('E68R16 unknown classification', () => {
  assert.equal(E68R16Classify('zzz-not-in-any-e68-catalog-77'), E68R16_CLASS.UNKNOWN)
})
