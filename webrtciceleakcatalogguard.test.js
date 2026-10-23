'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WICClassify, WIC_CLASS, WIC_BLOCK, WIC_WARN, WIC_ALLOW } = require('./webrtciceleakcatalogguard.js')

test('WIC block classification', () => {
  for (const v of WIC_BLOCK) assert.equal(WICClassify(v), WIC_CLASS.BLOCK, v)
})

test('WIC warn classification', () => {
  for (const v of WIC_WARN) assert.equal(WICClassify(v), WIC_CLASS.WARN, v)
})

test('WIC allow classification', () => {
  for (const v of WIC_ALLOW) assert.equal(WICClassify(v), WIC_CLASS.ALLOW, v)
})

test('WIC unknown classification', () => {
  assert.equal(WICClassify('zzz-not-in-catalog-7'), WIC_CLASS.UNKNOWN)
})
