'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T52Classify, E70T52_CLASS, E70T52_BLOCK, E70T52_WARN, E70T52_ALLOW } = require('./e70latinextccatalogguard.js')

test('E70T52 block classification', () => {
  for (const v of E70T52_BLOCK) assert.equal(E70T52Classify(v), E70T52_CLASS.BLOCK, v)
})

test('E70T52 warn classification', () => {
  for (const v of E70T52_WARN) assert.equal(E70T52Classify(v), E70T52_CLASS.WARN, v)
})

test('E70T52 allow classification', () => {
  for (const v of E70T52_ALLOW) assert.equal(E70T52Classify(v), E70T52_CLASS.ALLOW, v)
})

test('E70T52 unknown classification', () => {
  assert.equal(E70T52Classify('zzz-not-in-any-e70-catalog-99'), E70T52_CLASS.UNKNOWN)
})
