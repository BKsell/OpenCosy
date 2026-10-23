'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CG2Classify, CG2_CLASS, CG2_BLOCK, CG2_WARN, CG2_ALLOW } = require('./cyrillichomoglyphcatalogguard.js')

test('CG2 block classification', () => {
  for (const v of CG2_BLOCK) assert.equal(CG2Classify(v), CG2_CLASS.BLOCK, v)
})

test('CG2 warn classification', () => {
  for (const v of CG2_WARN) assert.equal(CG2Classify(v), CG2_CLASS.WARN, v)
})

test('CG2 allow classification', () => {
  for (const v of CG2_ALLOW) assert.equal(CG2Classify(v), CG2_CLASS.ALLOW, v)
})

test('CG2 unknown classification', () => {
  assert.equal(CG2Classify('zzz-not-in-catalog-11'), CG2_CLASS.UNKNOWN)
})
