'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WKSClassify, WKS_CLASS, WKS_BLOCK, WKS_WARN, WKS_ALLOW } = require('./workerbloburlcatalogguard.js')

test('WKS block classification', () => {
  for (const v of WKS_BLOCK) assert.equal(WKSClassify(v), WKS_CLASS.BLOCK, v)
})

test('WKS warn classification', () => {
  for (const v of WKS_WARN) assert.equal(WKSClassify(v), WKS_CLASS.WARN, v)
})

test('WKS allow classification', () => {
  for (const v of WKS_ALLOW) assert.equal(WKSClassify(v), WKS_CLASS.ALLOW, v)
})

test('WKS unknown classification', () => {
  assert.equal(WKSClassify('zzz-not-in-catalog-7'), WKS_CLASS.UNKNOWN)
})
