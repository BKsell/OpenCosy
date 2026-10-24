'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U02Classify, E70U02_CLASS, E70U02_BLOCK, E70U02_WARN, E70U02_ALLOW } = require('./e70olditaliccatalogguard.js')

test('E70U02 block classification', () => {
  for (const v of E70U02_BLOCK) assert.equal(E70U02Classify(v), E70U02_CLASS.BLOCK, v)
})

test('E70U02 warn classification', () => {
  for (const v of E70U02_WARN) assert.equal(E70U02Classify(v), E70U02_CLASS.WARN, v)
})

test('E70U02 allow classification', () => {
  for (const v of E70U02_ALLOW) assert.equal(E70U02Classify(v), E70U02_CLASS.ALLOW, v)
})

test('E70U02 unknown classification', () => {
  assert.equal(E70U02Classify('zzz-not-in-any-e70-catalog-99'), E70U02_CLASS.UNKNOWN)
})
