'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68D03Classify, E68D03_CLASS, E68D03_BLOCK, E68D03_WARN, E68D03_ALLOW } = require('./e68dec3padcatalogguard.js')

test('E68D03 block classification', () => {
  for (const v of E68D03_BLOCK) assert.equal(E68D03Classify(v), E68D03_CLASS.BLOCK, v)
})

test('E68D03 warn classification', () => {
  for (const v of E68D03_WARN) assert.equal(E68D03Classify(v), E68D03_CLASS.WARN, v)
})

test('E68D03 allow classification', () => {
  for (const v of E68D03_ALLOW) assert.equal(E68D03Classify(v), E68D03_CLASS.ALLOW, v)
})

test('E68D03 unknown classification', () => {
  assert.equal(E68D03Classify('zzz-not-in-any-e68-catalog-77'), E68D03_CLASS.UNKNOWN)
})
