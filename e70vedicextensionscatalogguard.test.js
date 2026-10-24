'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T33Classify, E70T33_CLASS, E70T33_BLOCK, E70T33_WARN, E70T33_ALLOW } = require('./e70vedicextensionscatalogguard.js')

test('E70T33 block classification', () => {
  for (const v of E70T33_BLOCK) assert.equal(E70T33Classify(v), E70T33_CLASS.BLOCK, v)
})

test('E70T33 warn classification', () => {
  for (const v of E70T33_WARN) assert.equal(E70T33Classify(v), E70T33_CLASS.WARN, v)
})

test('E70T33 allow classification', () => {
  for (const v of E70T33_ALLOW) assert.equal(E70T33Classify(v), E70T33_CLASS.ALLOW, v)
})

test('E70T33 unknown classification', () => {
  assert.equal(E70T33Classify('zzz-not-in-any-e70-catalog-99'), E70T33_CLASS.UNKNOWN)
})
