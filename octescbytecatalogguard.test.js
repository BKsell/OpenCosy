'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OB2Classify, OB2_CLASS, OB2_BLOCK, OB2_WARN, OB2_ALLOW } = require('./octescbytecatalogguard.js')

test('OB2 block classification', () => {
  for (const v of OB2_BLOCK) assert.equal(OB2Classify(v), OB2_CLASS.BLOCK, v)
})

test('OB2 warn classification', () => {
  for (const v of OB2_WARN) assert.equal(OB2Classify(v), OB2_CLASS.WARN, v)
})

test('OB2 allow classification', () => {
  for (const v of OB2_ALLOW) assert.equal(OB2Classify(v), OB2_CLASS.ALLOW, v)
})

test('OB2 unknown classification', () => {
  assert.equal(OB2Classify('zzz-not-in-catalog-11'), OB2_CLASS.UNKNOWN)
})
