'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HX2Classify, HX2_CLASS, HX2_BLOCK, HX2_WARN, HX2_ALLOW } = require('./htmlhexentitycatalogguard.js')

test('HX2 block classification', () => {
  for (const v of HX2_BLOCK) assert.equal(HX2Classify(v), HX2_CLASS.BLOCK, v)
})

test('HX2 warn classification', () => {
  for (const v of HX2_WARN) assert.equal(HX2Classify(v), HX2_CLASS.WARN, v)
})

test('HX2 allow classification', () => {
  for (const v of HX2_ALLOW) assert.equal(HX2Classify(v), HX2_CLASS.ALLOW, v)
})

test('HX2 unknown classification', () => {
  assert.equal(HX2Classify('zzz-not-in-catalog-11'), HX2_CLASS.UNKNOWN)
})
