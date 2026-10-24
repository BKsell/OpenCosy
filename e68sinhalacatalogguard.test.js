'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R14Classify, E68R14_CLASS, E68R14_BLOCK, E68R14_WARN, E68R14_ALLOW } = require('./e68sinhalacatalogguard.js')

test('E68R14 block classification', () => {
  for (const v of E68R14_BLOCK) assert.equal(E68R14Classify(v), E68R14_CLASS.BLOCK, v)
})

test('E68R14 warn classification', () => {
  for (const v of E68R14_WARN) assert.equal(E68R14Classify(v), E68R14_CLASS.WARN, v)
})

test('E68R14 allow classification', () => {
  for (const v of E68R14_ALLOW) assert.equal(E68R14Classify(v), E68R14_CLASS.ALLOW, v)
})

test('E68R14 unknown classification', () => {
  assert.equal(E68R14Classify('zzz-not-in-any-e68-catalog-77'), E68R14_CLASS.UNKNOWN)
})
