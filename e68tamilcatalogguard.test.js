'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R10Classify, E68R10_CLASS, E68R10_BLOCK, E68R10_WARN, E68R10_ALLOW } = require('./e68tamilcatalogguard.js')

test('E68R10 block classification', () => {
  for (const v of E68R10_BLOCK) assert.equal(E68R10Classify(v), E68R10_CLASS.BLOCK, v)
})

test('E68R10 warn classification', () => {
  for (const v of E68R10_WARN) assert.equal(E68R10Classify(v), E68R10_CLASS.WARN, v)
})

test('E68R10 allow classification', () => {
  for (const v of E68R10_ALLOW) assert.equal(E68R10Classify(v), E68R10_CLASS.ALLOW, v)
})

test('E68R10 unknown classification', () => {
  assert.equal(E68R10Classify('zzz-not-in-any-e68-catalog-77'), E68R10_CLASS.UNKNOWN)
})
