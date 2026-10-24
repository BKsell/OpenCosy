'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T56Classify, E70T56_CLASS, E70T56_BLOCK, E70T56_WARN, E70T56_ALLOW } = require('./e70cjkstrokescatalogguard.js')

test('E70T56 block classification', () => {
  for (const v of E70T56_BLOCK) assert.equal(E70T56Classify(v), E70T56_CLASS.BLOCK, v)
})

test('E70T56 warn classification', () => {
  for (const v of E70T56_WARN) assert.equal(E70T56Classify(v), E70T56_CLASS.WARN, v)
})

test('E70T56 allow classification', () => {
  for (const v of E70T56_ALLOW) assert.equal(E70T56Classify(v), E70T56_CLASS.ALLOW, v)
})

test('E70T56 unknown classification', () => {
  assert.equal(E70T56Classify('zzz-not-in-any-e70-catalog-99'), E70T56_CLASS.UNKNOWN)
})
