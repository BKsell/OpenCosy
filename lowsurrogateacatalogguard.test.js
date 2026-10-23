'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LA2Classify, LA2_CLASS, LA2_BLOCK, LA2_WARN, LA2_ALLOW } = require('./lowsurrogateacatalogguard.js')

test('LA2 block classification', () => {
  for (const v of LA2_BLOCK) assert.equal(LA2Classify(v), LA2_CLASS.BLOCK, v)
})

test('LA2 warn classification', () => {
  for (const v of LA2_WARN) assert.equal(LA2Classify(v), LA2_CLASS.WARN, v)
})

test('LA2 allow classification', () => {
  for (const v of LA2_ALLOW) assert.equal(LA2Classify(v), LA2_CLASS.ALLOW, v)
})

test('LA2 unknown classification', () => {
  assert.equal(LA2Classify('zzz-not-in-catalog-11'), LA2_CLASS.UNKNOWN)
})
