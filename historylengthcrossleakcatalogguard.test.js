'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HLEClassify, HLE_CLASS, HLE_BLOCK, HLE_WARN, HLE_ALLOW } = require('./historylengthcrossleakcatalogguard.js')

test('HLE block classification', () => {
  for (const v of HLE_BLOCK) assert.equal(HLEClassify(v), HLE_CLASS.BLOCK, v)
})

test('HLE warn classification', () => {
  for (const v of HLE_WARN) assert.equal(HLEClassify(v), HLE_CLASS.WARN, v)
})

test('HLE allow classification', () => {
  for (const v of HLE_ALLOW) assert.equal(HLEClassify(v), HLE_CLASS.ALLOW, v)
})

test('HLE unknown classification', () => {
  assert.equal(HLEClassify('zzz-not-in-catalog-7'), HLE_CLASS.UNKNOWN)
})
