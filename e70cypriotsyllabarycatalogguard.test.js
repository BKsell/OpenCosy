'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U08Classify, E70U08_CLASS, E70U08_BLOCK, E70U08_WARN, E70U08_ALLOW } = require('./e70cypriotsyllabarycatalogguard.js')

test('E70U08 block classification', () => {
  for (const v of E70U08_BLOCK) assert.equal(E70U08Classify(v), E70U08_CLASS.BLOCK, v)
})

test('E70U08 warn classification', () => {
  for (const v of E70U08_WARN) assert.equal(E70U08Classify(v), E70U08_CLASS.WARN, v)
})

test('E70U08 allow classification', () => {
  for (const v of E70U08_ALLOW) assert.equal(E70U08Classify(v), E70U08_CLASS.ALLOW, v)
})

test('E70U08 unknown classification', () => {
  assert.equal(E70U08Classify('zzz-not-in-any-e70-catalog-99'), E70U08_CLASS.UNKNOWN)
})
