'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T08Classify, E70T08_CLASS, E70T08_BLOCK, E70T08_WARN, E70T08_ALLOW } = require('./e70mandaiccatalogguard.js')

test('E70T08 block classification', () => {
  for (const v of E70T08_BLOCK) assert.equal(E70T08Classify(v), E70T08_CLASS.BLOCK, v)
})

test('E70T08 warn classification', () => {
  for (const v of E70T08_WARN) assert.equal(E70T08Classify(v), E70T08_CLASS.WARN, v)
})

test('E70T08 allow classification', () => {
  for (const v of E70T08_ALLOW) assert.equal(E70T08Classify(v), E70T08_CLASS.ALLOW, v)
})

test('E70T08 unknown classification', () => {
  assert.equal(E70T08Classify('zzz-not-in-any-e70-catalog-99'), E70T08_CLASS.UNKNOWN)
})
