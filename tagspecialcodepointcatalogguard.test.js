'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TS2Classify, TS2_CLASS, TS2_BLOCK, TS2_WARN, TS2_ALLOW } = require('./tagspecialcodepointcatalogguard.js')

test('TS2 block classification', () => {
  for (const v of TS2_BLOCK) assert.equal(TS2Classify(v), TS2_CLASS.BLOCK, v)
})

test('TS2 warn classification', () => {
  for (const v of TS2_WARN) assert.equal(TS2Classify(v), TS2_CLASS.WARN, v)
})

test('TS2 allow classification', () => {
  for (const v of TS2_ALLOW) assert.equal(TS2Classify(v), TS2_CLASS.ALLOW, v)
})

test('TS2 unknown classification', () => {
  assert.equal(TS2Classify('zzz-not-in-catalog-11'), TS2_CLASS.UNKNOWN)
})
