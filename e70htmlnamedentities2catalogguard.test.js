'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HN2Classify, E70HN2_CLASS, E70HN2_BLOCK, E70HN2_WARN, E70HN2_ALLOW } = require('./e70htmlnamedentities2catalogguard.js')

test('E70HN2 block classification', () => {
  for (const v of E70HN2_BLOCK) assert.equal(E70HN2Classify(v), E70HN2_CLASS.BLOCK, v)
})

test('E70HN2 warn classification', () => {
  for (const v of E70HN2_WARN) assert.equal(E70HN2Classify(v), E70HN2_CLASS.WARN, v)
})

test('E70HN2 allow classification', () => {
  for (const v of E70HN2_ALLOW) assert.equal(E70HN2Classify(v), E70HN2_CLASS.ALLOW, v)
})

test('E70HN2 unknown classification', () => {
  assert.equal(E70HN2Classify('zzz-not-in-any-e70-catalog-99'), E70HN2_CLASS.UNKNOWN)
})
