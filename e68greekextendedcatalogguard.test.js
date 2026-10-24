'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R22Classify, E68R22_CLASS, E68R22_BLOCK, E68R22_WARN, E68R22_ALLOW } = require('./e68greekextendedcatalogguard.js')

test('E68R22 block classification', () => {
  for (const v of E68R22_BLOCK) assert.equal(E68R22Classify(v), E68R22_CLASS.BLOCK, v)
})

test('E68R22 warn classification', () => {
  for (const v of E68R22_WARN) assert.equal(E68R22Classify(v), E68R22_CLASS.WARN, v)
})

test('E68R22 allow classification', () => {
  for (const v of E68R22_ALLOW) assert.equal(E68R22Classify(v), E68R22_CLASS.ALLOW, v)
})

test('E68R22 unknown classification', () => {
  assert.equal(E68R22Classify('zzz-not-in-any-e68-catalog-77'), E68R22_CLASS.UNKNOWN)
})
