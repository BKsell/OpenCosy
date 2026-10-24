'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T53Classify, E70T53_CLASS, E70T53_BLOCK, E70T53_WARN, E70T53_ALLOW } = require('./e70georgiansuppcatalogguard.js')

test('E70T53 block classification', () => {
  for (const v of E70T53_BLOCK) assert.equal(E70T53Classify(v), E70T53_CLASS.BLOCK, v)
})

test('E70T53 warn classification', () => {
  for (const v of E70T53_WARN) assert.equal(E70T53Classify(v), E70T53_CLASS.WARN, v)
})

test('E70T53 allow classification', () => {
  for (const v of E70T53_ALLOW) assert.equal(E70T53Classify(v), E70T53_CLASS.ALLOW, v)
})

test('E70T53 unknown classification', () => {
  assert.equal(E70T53Classify('zzz-not-in-any-e70-catalog-99'), E70T53_CLASS.UNKNOWN)
})
