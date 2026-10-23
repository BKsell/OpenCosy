'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HB3Classify, HB3_CLASS, HB3_BLOCK, HB3_WARN, HB3_ALLOW } = require('./highsurrogatebcatalogguard.js')

test('HB3 block classification', () => {
  for (const v of HB3_BLOCK) assert.equal(HB3Classify(v), HB3_CLASS.BLOCK, v)
})

test('HB3 warn classification', () => {
  for (const v of HB3_WARN) assert.equal(HB3Classify(v), HB3_CLASS.WARN, v)
})

test('HB3 allow classification', () => {
  for (const v of HB3_ALLOW) assert.equal(HB3Classify(v), HB3_CLASS.ALLOW, v)
})

test('HB3 unknown classification', () => {
  assert.equal(HB3Classify('zzz-not-in-catalog-11'), HB3_CLASS.UNKNOWN)
})
