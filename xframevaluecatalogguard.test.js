'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XFVClassify, XFV_CLASS, XFV_BLOCK, XFV_WARN, XFV_ALLOW } = require('./xframevaluecatalogguard.js')

test('XFV block classification', () => {
  for (const v of XFV_BLOCK) assert.equal(XFVClassify(v), XFV_CLASS.BLOCK, v)
})

test('XFV warn classification', () => {
  for (const v of XFV_WARN) assert.equal(XFVClassify(v), XFV_CLASS.WARN, v)
})

test('XFV allow classification', () => {
  for (const v of XFV_ALLOW) assert.equal(XFVClassify(v), XFV_CLASS.ALLOW, v)
})

test('XFV unknown classification', () => {
  assert.equal(XFVClassify('zzz-not-in-catalog-7'), XFV_CLASS.UNKNOWN)
})
