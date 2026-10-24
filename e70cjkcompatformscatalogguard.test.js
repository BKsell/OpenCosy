'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T61Classify, E70T61_CLASS, E70T61_BLOCK, E70T61_WARN, E70T61_ALLOW } = require('./e70cjkcompatformscatalogguard.js')

test('E70T61 block classification', () => {
  for (const v of E70T61_BLOCK) assert.equal(E70T61Classify(v), E70T61_CLASS.BLOCK, v)
})

test('E70T61 warn classification', () => {
  for (const v of E70T61_WARN) assert.equal(E70T61Classify(v), E70T61_CLASS.WARN, v)
})

test('E70T61 allow classification', () => {
  for (const v of E70T61_ALLOW) assert.equal(E70T61Classify(v), E70T61_CLASS.ALLOW, v)
})

test('E70T61 unknown classification', () => {
  assert.equal(E70T61Classify('zzz-not-in-any-e70-catalog-99'), E70T61_CLASS.UNKNOWN)
})
