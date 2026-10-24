'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R32Classify, E68R32_CLASS, E68R32_BLOCK, E68R32_WARN, E68R32_ALLOW } = require('./e68blockelementscatalogguard.js')

test('E68R32 block classification', () => {
  for (const v of E68R32_BLOCK) assert.equal(E68R32Classify(v), E68R32_CLASS.BLOCK, v)
})

test('E68R32 warn classification', () => {
  for (const v of E68R32_WARN) assert.equal(E68R32Classify(v), E68R32_CLASS.WARN, v)
})

test('E68R32 allow classification', () => {
  for (const v of E68R32_ALLOW) assert.equal(E68R32Classify(v), E68R32_CLASS.ALLOW, v)
})

test('E68R32 unknown classification', () => {
  assert.equal(E68R32Classify('zzz-not-in-any-e68-catalog-77'), E68R32_CLASS.UNKNOWN)
})
