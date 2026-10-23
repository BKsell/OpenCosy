'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PB2Classify, PB2_CLASS, PB2_BLOCK, PB2_WARN, PB2_ALLOW } = require('./pctbyteencodingcatalogguard.js')

test('PB2 block classification', () => {
  for (const v of PB2_BLOCK) assert.equal(PB2Classify(v), PB2_CLASS.BLOCK, v)
})

test('PB2 warn classification', () => {
  for (const v of PB2_WARN) assert.equal(PB2Classify(v), PB2_CLASS.WARN, v)
})

test('PB2 allow classification', () => {
  for (const v of PB2_ALLOW) assert.equal(PB2Classify(v), PB2_CLASS.ALLOW, v)
})

test('PB2 unknown classification', () => {
  assert.equal(PB2Classify('zzz-not-in-catalog-11'), PB2_CLASS.UNKNOWN)
})
