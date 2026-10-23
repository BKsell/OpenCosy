'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SHWClassify, SHW_CLASS, SHW_BLOCK, SHW_WARN, SHW_ALLOW } = require('./sharedworkerendpointcatalogguard.js')

test('SHW block classification', () => {
  for (const v of SHW_BLOCK) assert.equal(SHWClassify(v), SHW_CLASS.BLOCK, v)
})

test('SHW warn classification', () => {
  for (const v of SHW_WARN) assert.equal(SHWClassify(v), SHW_CLASS.WARN, v)
})

test('SHW allow classification', () => {
  for (const v of SHW_ALLOW) assert.equal(SHWClassify(v), SHW_CLASS.ALLOW, v)
})

test('SHW unknown classification', () => {
  assert.equal(SHWClassify('zzz-not-in-catalog-7'), SHW_CLASS.UNKNOWN)
})
