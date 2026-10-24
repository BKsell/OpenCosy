'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R33Classify, E68R33_CLASS, E68R33_BLOCK, E68R33_WARN, E68R33_ALLOW } = require('./e68geometriccatalogguard.js')

test('E68R33 block classification', () => {
  for (const v of E68R33_BLOCK) assert.equal(E68R33Classify(v), E68R33_CLASS.BLOCK, v)
})

test('E68R33 warn classification', () => {
  for (const v of E68R33_WARN) assert.equal(E68R33Classify(v), E68R33_CLASS.WARN, v)
})

test('E68R33 allow classification', () => {
  for (const v of E68R33_ALLOW) assert.equal(E68R33Classify(v), E68R33_CLASS.ALLOW, v)
})

test('E68R33 unknown classification', () => {
  assert.equal(E68R33Classify('zzz-not-in-any-e68-catalog-77'), E68R33_CLASS.UNKNOWN)
})
