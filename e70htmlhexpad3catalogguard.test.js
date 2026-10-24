'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HX3Classify, E70HX3_CLASS, E70HX3_BLOCK, E70HX3_WARN, E70HX3_ALLOW } = require('./e70htmlhexpad3catalogguard.js')

test('E70HX3 block classification', () => {
  for (const v of E70HX3_BLOCK) assert.equal(E70HX3Classify(v), E70HX3_CLASS.BLOCK, v)
})

test('E70HX3 warn classification', () => {
  for (const v of E70HX3_WARN) assert.equal(E70HX3Classify(v), E70HX3_CLASS.WARN, v)
})

test('E70HX3 allow classification', () => {
  for (const v of E70HX3_ALLOW) assert.equal(E70HX3Classify(v), E70HX3_CLASS.ALLOW, v)
})

test('E70HX3 unknown classification', () => {
  assert.equal(E70HX3Classify('zzz-not-in-any-e70-catalog-99'), E70HX3_CLASS.UNKNOWN)
})
