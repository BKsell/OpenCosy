'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R20Classify, E68R20_CLASS, E68R20_BLOCK, E68R20_WARN, E68R20_ALLOW } = require('./e68hanguljamocatalogguard.js')

test('E68R20 block classification', () => {
  for (const v of E68R20_BLOCK) assert.equal(E68R20Classify(v), E68R20_CLASS.BLOCK, v)
})

test('E68R20 warn classification', () => {
  for (const v of E68R20_WARN) assert.equal(E68R20Classify(v), E68R20_CLASS.WARN, v)
})

test('E68R20 allow classification', () => {
  for (const v of E68R20_ALLOW) assert.equal(E68R20Classify(v), E68R20_CLASS.ALLOW, v)
})

test('E68R20 unknown classification', () => {
  assert.equal(E68R20Classify('zzz-not-in-any-e68-catalog-77'), E68R20_CLASS.UNKNOWN)
})
