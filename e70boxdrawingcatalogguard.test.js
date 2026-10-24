'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T45Classify, E70T45_CLASS, E70T45_BLOCK, E70T45_WARN, E70T45_ALLOW } = require('./e70boxdrawingcatalogguard.js')

test('E70T45 block classification', () => {
  for (const v of E70T45_BLOCK) assert.equal(E70T45Classify(v), E70T45_CLASS.BLOCK, v)
})

test('E70T45 warn classification', () => {
  for (const v of E70T45_WARN) assert.equal(E70T45Classify(v), E70T45_CLASS.WARN, v)
})

test('E70T45 allow classification', () => {
  for (const v of E70T45_ALLOW) assert.equal(E70T45Classify(v), E70T45_CLASS.ALLOW, v)
})

test('E70T45 unknown classification', () => {
  assert.equal(E70T45Classify('zzz-not-in-any-e70-catalog-99'), E70T45_CLASS.UNKNOWN)
})
