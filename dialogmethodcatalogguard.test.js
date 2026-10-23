'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DLGClassify, DLG_CLASS, DLG_BLOCK, DLG_WARN, DLG_ALLOW } = require('./dialogmethodcatalogguard.js')

test('DLG block classification', () => {
  for (const v of DLG_BLOCK) assert.equal(DLGClassify(v), DLG_CLASS.BLOCK, v)
})

test('DLG warn classification', () => {
  for (const v of DLG_WARN) assert.equal(DLGClassify(v), DLG_CLASS.WARN, v)
})

test('DLG allow classification', () => {
  for (const v of DLG_ALLOW) assert.equal(DLGClassify(v), DLG_CLASS.ALLOW, v)
})

test('DLG unknown classification', () => {
  assert.equal(DLGClassify('zzz-not-in-catalog-7'), DLG_CLASS.UNKNOWN)
})
