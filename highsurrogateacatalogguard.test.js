'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HA2Classify, HA2_CLASS, HA2_BLOCK, HA2_WARN, HA2_ALLOW } = require('./highsurrogateacatalogguard.js')

test('HA2 block classification', () => {
  for (const v of HA2_BLOCK) assert.equal(HA2Classify(v), HA2_CLASS.BLOCK, v)
})

test('HA2 warn classification', () => {
  for (const v of HA2_WARN) assert.equal(HA2Classify(v), HA2_CLASS.WARN, v)
})

test('HA2 allow classification', () => {
  for (const v of HA2_ALLOW) assert.equal(HA2Classify(v), HA2_CLASS.ALLOW, v)
})

test('HA2 unknown classification', () => {
  assert.equal(HA2Classify('zzz-not-in-catalog-11'), HA2_CLASS.UNKNOWN)
})
