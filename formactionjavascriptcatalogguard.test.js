'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FASClassify, FAS_CLASS, FAS_BLOCK, FAS_WARN, FAS_ALLOW } = require('./formactionjavascriptcatalogguard.js')

test('FAS block classification', () => {
  for (const v of FAS_BLOCK) assert.equal(FASClassify(v), FAS_CLASS.BLOCK, v)
})

test('FAS warn classification', () => {
  for (const v of FAS_WARN) assert.equal(FASClassify(v), FAS_CLASS.WARN, v)
})

test('FAS allow classification', () => {
  for (const v of FAS_ALLOW) assert.equal(FASClassify(v), FAS_CLASS.ALLOW, v)
})

test('FAS unknown classification', () => {
  assert.equal(FASClassify('zzz-not-in-catalog-7'), FAS_CLASS.UNKNOWN)
})
