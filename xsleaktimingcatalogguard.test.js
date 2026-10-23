'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XLTClassify, XLT_CLASS, XLT_BLOCK, XLT_WARN, XLT_ALLOW } = require('./xsleaktimingcatalogguard.js')

test('XLT block classification', () => {
  for (const v of XLT_BLOCK) assert.equal(XLTClassify(v), XLT_CLASS.BLOCK, v)
})

test('XLT warn classification', () => {
  for (const v of XLT_WARN) assert.equal(XLTClassify(v), XLT_CLASS.WARN, v)
})

test('XLT allow classification', () => {
  for (const v of XLT_ALLOW) assert.equal(XLTClassify(v), XLT_CLASS.ALLOW, v)
})

test('XLT unknown classification', () => {
  assert.equal(XLTClassify('zzz-not-in-catalog-7'), XLT_CLASS.UNKNOWN)
})
