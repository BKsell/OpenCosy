'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WGFClassify, WGF_CLASS, WGF_BLOCK, WGF_WARN, WGF_ALLOW } = require('./webglparameterfingerprintcatalogguard.js')

test('WGF block classification', () => {
  for (const v of WGF_BLOCK) assert.equal(WGFClassify(v), WGF_CLASS.BLOCK, v)
})

test('WGF warn classification', () => {
  for (const v of WGF_WARN) assert.equal(WGFClassify(v), WGF_CLASS.WARN, v)
})

test('WGF allow classification', () => {
  for (const v of WGF_ALLOW) assert.equal(WGFClassify(v), WGF_CLASS.ALLOW, v)
})

test('WGF unknown classification', () => {
  assert.equal(WGFClassify('zzz-not-in-catalog-7'), WGF_CLASS.UNKNOWN)
})
