'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XCTClassify, XCT_CLASS, XCT_BLOCK, XCT_WARN, XCT_ALLOW } = require('./xcontentoptioncatalogguard.js')

test('XCT block classification', () => {
  for (const v of XCT_BLOCK) assert.equal(XCTClassify(v), XCT_CLASS.BLOCK, v)
})

test('XCT warn classification', () => {
  for (const v of XCT_WARN) assert.equal(XCTClassify(v), XCT_CLASS.WARN, v)
})

test('XCT allow classification', () => {
  for (const v of XCT_ALLOW) assert.equal(XCTClassify(v), XCT_CLASS.ALLOW, v)
})

test('XCT unknown classification', () => {
  assert.equal(XCTClassify('zzz-not-in-catalog-7'), XCT_CLASS.UNKNOWN)
})
