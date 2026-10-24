'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T57Classify, E70T57_CLASS, E70T57_BLOCK, E70T57_WARN, E70T57_ALLOW } = require('./e70katakanaphoneticcatalogguard.js')

test('E70T57 block classification', () => {
  for (const v of E70T57_BLOCK) assert.equal(E70T57Classify(v), E70T57_CLASS.BLOCK, v)
})

test('E70T57 warn classification', () => {
  for (const v of E70T57_WARN) assert.equal(E70T57Classify(v), E70T57_CLASS.WARN, v)
})

test('E70T57 allow classification', () => {
  for (const v of E70T57_ALLOW) assert.equal(E70T57Classify(v), E70T57_CLASS.ALLOW, v)
})

test('E70T57 unknown classification', () => {
  assert.equal(E70T57Classify('zzz-not-in-any-e70-catalog-99'), E70T57_CLASS.UNKNOWN)
})
