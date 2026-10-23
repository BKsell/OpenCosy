'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HD2Classify, HD2_CLASS, HD2_BLOCK, HD2_WARN, HD2_ALLOW } = require('./htmldecimalentitycatalogguard.js')

test('HD2 block classification', () => {
  for (const v of HD2_BLOCK) assert.equal(HD2Classify(v), HD2_CLASS.BLOCK, v)
})

test('HD2 warn classification', () => {
  for (const v of HD2_WARN) assert.equal(HD2Classify(v), HD2_CLASS.WARN, v)
})

test('HD2 allow classification', () => {
  for (const v of HD2_ALLOW) assert.equal(HD2Classify(v), HD2_CLASS.ALLOW, v)
})

test('HD2 unknown classification', () => {
  assert.equal(HD2Classify('zzz-not-in-catalog-11'), HD2_CLASS.UNKNOWN)
})
