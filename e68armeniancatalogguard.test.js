'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R00Classify, E68R00_CLASS, E68R00_BLOCK, E68R00_WARN, E68R00_ALLOW } = require('./e68armeniancatalogguard.js')

test('E68R00 block classification', () => {
  for (const v of E68R00_BLOCK) assert.equal(E68R00Classify(v), E68R00_CLASS.BLOCK, v)
})

test('E68R00 warn classification', () => {
  for (const v of E68R00_WARN) assert.equal(E68R00Classify(v), E68R00_CLASS.WARN, v)
})

test('E68R00 allow classification', () => {
  for (const v of E68R00_ALLOW) assert.equal(E68R00Classify(v), E68R00_CLASS.ALLOW, v)
})

test('E68R00 unknown classification', () => {
  assert.equal(E68R00Classify('zzz-not-in-any-e68-catalog-77'), E68R00_CLASS.UNKNOWN)
})
