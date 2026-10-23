'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CDVClassify, CDV_CLASS, CDV_BLOCK, CDV_WARN, CDV_ALLOW } = require('./cspdirectiveweakvaluecatalogguard.js')

test('CDV block classification', () => {
  for (const v of CDV_BLOCK) assert.equal(CDVClassify(v), CDV_CLASS.BLOCK, v)
})

test('CDV warn classification', () => {
  for (const v of CDV_WARN) assert.equal(CDVClassify(v), CDV_CLASS.WARN, v)
})

test('CDV allow classification', () => {
  for (const v of CDV_ALLOW) assert.equal(CDVClassify(v), CDV_CLASS.ALLOW, v)
})

test('CDV unknown classification', () => {
  assert.equal(CDVClassify('zzz-not-in-catalog-7'), CDV_CLASS.UNKNOWN)
})
