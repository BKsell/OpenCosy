'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T48Classify, E70T48_CLASS, E70T48_BLOCK, E70T48_WARN, E70T48_ALLOW } = require('./e70miscsymbolscatalogguard.js')

test('E70T48 block classification', () => {
  for (const v of E70T48_BLOCK) assert.equal(E70T48Classify(v), E70T48_CLASS.BLOCK, v)
})

test('E70T48 warn classification', () => {
  for (const v of E70T48_WARN) assert.equal(E70T48Classify(v), E70T48_CLASS.WARN, v)
})

test('E70T48 allow classification', () => {
  for (const v of E70T48_ALLOW) assert.equal(E70T48Classify(v), E70T48_CLASS.ALLOW, v)
})

test('E70T48 unknown classification', () => {
  assert.equal(E70T48Classify('zzz-not-in-any-e70-catalog-99'), E70T48_CLASS.UNKNOWN)
})
