'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { UC2Classify, UC2_CLASS, UC2_BLOCK, UC2_WARN, UC2_ALLOW } = require('./controlcodepointcatalogguard.js')

test('UC2 block classification', () => {
  for (const v of UC2_BLOCK) assert.equal(UC2Classify(v), UC2_CLASS.BLOCK, v)
})

test('UC2 warn classification', () => {
  for (const v of UC2_WARN) assert.equal(UC2Classify(v), UC2_CLASS.WARN, v)
})

test('UC2 allow classification', () => {
  for (const v of UC2_ALLOW) assert.equal(UC2Classify(v), UC2_CLASS.ALLOW, v)
})

test('UC2 unknown classification', () => {
  assert.equal(UC2Classify('zzz-not-in-catalog-11'), UC2_CLASS.UNKNOWN)
})
