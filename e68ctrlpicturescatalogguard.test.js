'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R29Classify, E68R29_CLASS, E68R29_BLOCK, E68R29_WARN, E68R29_ALLOW } = require('./e68ctrlpicturescatalogguard.js')

test('E68R29 block classification', () => {
  for (const v of E68R29_BLOCK) assert.equal(E68R29Classify(v), E68R29_CLASS.BLOCK, v)
})

test('E68R29 warn classification', () => {
  for (const v of E68R29_WARN) assert.equal(E68R29Classify(v), E68R29_CLASS.WARN, v)
})

test('E68R29 allow classification', () => {
  for (const v of E68R29_ALLOW) assert.equal(E68R29Classify(v), E68R29_CLASS.ALLOW, v)
})

test('E68R29 unknown classification', () => {
  assert.equal(E68R29Classify('zzz-not-in-any-e68-catalog-77'), E68R29_CLASS.UNKNOWN)
})
