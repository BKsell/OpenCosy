'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T49Classify, E70T49_CLASS, E70T49_BLOCK, E70T49_WARN, E70T49_ALLOW } = require('./e70dingbatscatalogguard.js')

test('E70T49 block classification', () => {
  for (const v of E70T49_BLOCK) assert.equal(E70T49Classify(v), E70T49_CLASS.BLOCK, v)
})

test('E70T49 warn classification', () => {
  for (const v of E70T49_WARN) assert.equal(E70T49Classify(v), E70T49_CLASS.WARN, v)
})

test('E70T49 allow classification', () => {
  for (const v of E70T49_ALLOW) assert.equal(E70T49Classify(v), E70T49_CLASS.ALLOW, v)
})

test('E70T49 unknown classification', () => {
  assert.equal(E70T49Classify('zzz-not-in-any-e70-catalog-99'), E70T49_CLASS.UNKNOWN)
})
