'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HB2Classify, HB2_CLASS, HB2_BLOCK, HB2_WARN, HB2_ALLOW } = require('./hexescbytecatalogguard.js')

test('HB2 block classification', () => {
  for (const v of HB2_BLOCK) assert.equal(HB2Classify(v), HB2_CLASS.BLOCK, v)
})

test('HB2 warn classification', () => {
  for (const v of HB2_WARN) assert.equal(HB2Classify(v), HB2_CLASS.WARN, v)
})

test('HB2 allow classification', () => {
  for (const v of HB2_ALLOW) assert.equal(HB2Classify(v), HB2_CLASS.ALLOW, v)
})

test('HB2 unknown classification', () => {
  assert.equal(HB2Classify('zzz-not-in-catalog-11'), HB2_CLASS.UNKNOWN)
})
