'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { VS2Classify, VS2_CLASS, VS2_BLOCK, VS2_WARN, VS2_ALLOW } = require('./variationselectorcodepointcatalogguard.js')

test('VS2 block classification', () => {
  for (const v of VS2_BLOCK) assert.equal(VS2Classify(v), VS2_CLASS.BLOCK, v)
})

test('VS2 warn classification', () => {
  for (const v of VS2_WARN) assert.equal(VS2Classify(v), VS2_CLASS.WARN, v)
})

test('VS2 allow classification', () => {
  for (const v of VS2_ALLOW) assert.equal(VS2Classify(v), VS2_CLASS.ALLOW, v)
})

test('VS2 unknown classification', () => {
  assert.equal(VS2Classify('zzz-not-in-catalog-11'), VS2_CLASS.UNKNOWN)
})
