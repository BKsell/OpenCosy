'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { NCEClassify, NCE_CLASS, NCE_BLOCK, NCE_WARN, NCE_ALLOW } = require('./noncereusemisconfigcatalogguard.js')

test('NCE block classification', () => {
  for (const v of NCE_BLOCK) assert.equal(NCEClassify(v), NCE_CLASS.BLOCK, v)
})

test('NCE warn classification', () => {
  for (const v of NCE_WARN) assert.equal(NCEClassify(v), NCE_CLASS.WARN, v)
})

test('NCE allow classification', () => {
  for (const v of NCE_ALLOW) assert.equal(NCEClassify(v), NCE_CLASS.ALLOW, v)
})

test('NCE unknown classification', () => {
  assert.equal(NCEClassify('zzz-not-in-catalog-7'), NCE_CLASS.UNKNOWN)
})
