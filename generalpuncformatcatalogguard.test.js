'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { GF2Classify, GF2_CLASS, GF2_BLOCK, GF2_WARN, GF2_ALLOW } = require('./generalpuncformatcatalogguard.js')

test('GF2 block classification', () => {
  for (const v of GF2_BLOCK) assert.equal(GF2Classify(v), GF2_CLASS.BLOCK, v)
})

test('GF2 warn classification', () => {
  for (const v of GF2_WARN) assert.equal(GF2Classify(v), GF2_CLASS.WARN, v)
})

test('GF2 allow classification', () => {
  for (const v of GF2_ALLOW) assert.equal(GF2Classify(v), GF2_CLASS.ALLOW, v)
})

test('GF2 unknown classification', () => {
  assert.equal(GF2Classify('zzz-not-in-catalog-11'), GF2_CLASS.UNKNOWN)
})
