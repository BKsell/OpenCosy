'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { GCTClassify, GCT_CLASS, GCT_BLOCK, GCT_WARN, GCT_ALLOW } = require('./geolocationcontinuoustrackcatalogguard.js')

test('GCT block classification', () => {
  for (const v of GCT_BLOCK) assert.equal(GCTClassify(v), GCT_CLASS.BLOCK, v)
})

test('GCT warn classification', () => {
  for (const v of GCT_WARN) assert.equal(GCTClassify(v), GCT_CLASS.WARN, v)
})

test('GCT allow classification', () => {
  for (const v of GCT_ALLOW) assert.equal(GCTClassify(v), GCT_CLASS.ALLOW, v)
})

test('GCT unknown classification', () => {
  assert.equal(GCTClassify('zzz-not-in-catalog-7'), GCT_CLASS.UNKNOWN)
})
