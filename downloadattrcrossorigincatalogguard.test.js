'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DLAClassify, DLA_CLASS, DLA_BLOCK, DLA_WARN, DLA_ALLOW } = require('./downloadattrcrossorigincatalogguard.js')

test('DLA block classification', () => {
  for (const v of DLA_BLOCK) assert.equal(DLAClassify(v), DLA_CLASS.BLOCK, v)
})

test('DLA warn classification', () => {
  for (const v of DLA_WARN) assert.equal(DLAClassify(v), DLA_CLASS.WARN, v)
})

test('DLA allow classification', () => {
  for (const v of DLA_ALLOW) assert.equal(DLAClassify(v), DLA_CLASS.ALLOW, v)
})

test('DLA unknown classification', () => {
  assert.equal(DLAClassify('zzz-not-in-catalog-7'), DLA_CLASS.UNKNOWN)
})
