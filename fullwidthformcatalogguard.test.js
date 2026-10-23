'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FW2Classify, FW2_CLASS, FW2_BLOCK, FW2_WARN, FW2_ALLOW } = require('./fullwidthformcatalogguard.js')

test('FW2 block classification', () => {
  for (const v of FW2_BLOCK) assert.equal(FW2Classify(v), FW2_CLASS.BLOCK, v)
})

test('FW2 warn classification', () => {
  for (const v of FW2_WARN) assert.equal(FW2Classify(v), FW2_CLASS.WARN, v)
})

test('FW2 allow classification', () => {
  for (const v of FW2_ALLOW) assert.equal(FW2Classify(v), FW2_CLASS.ALLOW, v)
})

test('FW2 unknown classification', () => {
  assert.equal(FW2Classify('zzz-not-in-catalog-11'), FW2_CLASS.UNKNOWN)
})
