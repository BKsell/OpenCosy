'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R21Classify, E68R21_CLASS, E68R21_BLOCK, E68R21_WARN, E68R21_ALLOW } = require('./e68latinextadditionalcatalogguard.js')

test('E68R21 block classification', () => {
  for (const v of E68R21_BLOCK) assert.equal(E68R21Classify(v), E68R21_CLASS.BLOCK, v)
})

test('E68R21 warn classification', () => {
  for (const v of E68R21_WARN) assert.equal(E68R21Classify(v), E68R21_CLASS.WARN, v)
})

test('E68R21 allow classification', () => {
  for (const v of E68R21_ALLOW) assert.equal(E68R21Classify(v), E68R21_CLASS.ALLOW, v)
})

test('E68R21 unknown classification', () => {
  assert.equal(E68R21Classify('zzz-not-in-any-e68-catalog-77'), E68R21_CLASS.UNKNOWN)
})
