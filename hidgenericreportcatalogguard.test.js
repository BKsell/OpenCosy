'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HDRClassify, HDR_CLASS, HDR_BLOCK, HDR_WARN, HDR_ALLOW } = require('./hidgenericreportcatalogguard.js')

test('HDR block classification', () => {
  for (const v of HDR_BLOCK) assert.equal(HDRClassify(v), HDR_CLASS.BLOCK, v)
})

test('HDR warn classification', () => {
  for (const v of HDR_WARN) assert.equal(HDRClassify(v), HDR_CLASS.WARN, v)
})

test('HDR allow classification', () => {
  for (const v of HDR_ALLOW) assert.equal(HDRClassify(v), HDR_CLASS.ALLOW, v)
})

test('HDR unknown classification', () => {
  assert.equal(HDRClassify('zzz-not-in-catalog-7'), HDR_CLASS.UNKNOWN)
})
