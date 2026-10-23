'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { GG2Classify, GG2_CLASS, GG2_BLOCK, GG2_WARN, GG2_ALLOW } = require('./greekhomoglyphcatalogguard.js')

test('GG2 block classification', () => {
  for (const v of GG2_BLOCK) assert.equal(GG2Classify(v), GG2_CLASS.BLOCK, v)
})

test('GG2 warn classification', () => {
  for (const v of GG2_WARN) assert.equal(GG2Classify(v), GG2_CLASS.WARN, v)
})

test('GG2 allow classification', () => {
  for (const v of GG2_ALLOW) assert.equal(GG2Classify(v), GG2_CLASS.ALLOW, v)
})

test('GG2 unknown classification', () => {
  assert.equal(GG2Classify('zzz-not-in-catalog-11'), GG2_CLASS.UNKNOWN)
})
