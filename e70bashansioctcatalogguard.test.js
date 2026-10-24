'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70BAOClassify, E70BAO_CLASS, E70BAO_BLOCK, E70BAO_WARN, E70BAO_ALLOW } = require('./e70bashansioctcatalogguard.js')

test('E70BAO block classification', () => {
  for (const v of E70BAO_BLOCK) assert.equal(E70BAOClassify(v), E70BAO_CLASS.BLOCK, v)
})

test('E70BAO warn classification', () => {
  for (const v of E70BAO_WARN) assert.equal(E70BAOClassify(v), E70BAO_CLASS.WARN, v)
})

test('E70BAO allow classification', () => {
  for (const v of E70BAO_ALLOW) assert.equal(E70BAOClassify(v), E70BAO_CLASS.ALLOW, v)
})

test('E70BAO unknown classification', () => {
  assert.equal(E70BAOClassify('zzz-not-in-any-e70-catalog-99'), E70BAO_CLASS.UNKNOWN)
})
