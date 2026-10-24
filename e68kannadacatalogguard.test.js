'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R12Classify, E68R12_CLASS, E68R12_BLOCK, E68R12_WARN, E68R12_ALLOW } = require('./e68kannadacatalogguard.js')

test('E68R12 block classification', () => {
  for (const v of E68R12_BLOCK) assert.equal(E68R12Classify(v), E68R12_CLASS.BLOCK, v)
})

test('E68R12 warn classification', () => {
  for (const v of E68R12_WARN) assert.equal(E68R12Classify(v), E68R12_CLASS.WARN, v)
})

test('E68R12 allow classification', () => {
  for (const v of E68R12_ALLOW) assert.equal(E68R12Classify(v), E68R12_CLASS.ALLOW, v)
})

test('E68R12 unknown classification', () => {
  assert.equal(E68R12Classify('zzz-not-in-any-e68-catalog-77'), E68R12_CLASS.UNKNOWN)
})
