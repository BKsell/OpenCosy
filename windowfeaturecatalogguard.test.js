'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WNTClassify, WNT_CLASS, WNT_BLOCK, WNT_WARN, WNT_ALLOW } = require('./windowfeaturecatalogguard.js')

test('WNT block classification', () => {
  for (const v of WNT_BLOCK) assert.equal(WNTClassify(v), WNT_CLASS.BLOCK, v)
})

test('WNT warn classification', () => {
  for (const v of WNT_WARN) assert.equal(WNTClassify(v), WNT_CLASS.WARN, v)
})

test('WNT allow classification', () => {
  for (const v of WNT_ALLOW) assert.equal(WNTClassify(v), WNT_CLASS.ALLOW, v)
})

test('WNT unknown classification', () => {
  assert.equal(WNTClassify('zzz-not-in-catalog-7'), WNT_CLASS.UNKNOWN)
})
