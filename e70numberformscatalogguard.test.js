'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T39Classify, E70T39_CLASS, E70T39_BLOCK, E70T39_WARN, E70T39_ALLOW } = require('./e70numberformscatalogguard.js')

test('E70T39 block classification', () => {
  for (const v of E70T39_BLOCK) assert.equal(E70T39Classify(v), E70T39_CLASS.BLOCK, v)
})

test('E70T39 warn classification', () => {
  for (const v of E70T39_WARN) assert.equal(E70T39Classify(v), E70T39_CLASS.WARN, v)
})

test('E70T39 allow classification', () => {
  for (const v of E70T39_ALLOW) assert.equal(E70T39Classify(v), E70T39_CLASS.ALLOW, v)
})

test('E70T39 unknown classification', () => {
  assert.equal(E70T39Classify('zzz-not-in-any-e70-catalog-99'), E70T39_CLASS.UNKNOWN)
})
