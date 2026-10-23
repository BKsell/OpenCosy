'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FESClassify, FES_CLASS, FES_BLOCK, FES_WARN, FES_ALLOW } = require('./fetchcrosscredentialcatalogguard.js')

test('FES block classification', () => {
  for (const v of FES_BLOCK) assert.equal(FESClassify(v), FES_CLASS.BLOCK, v)
})

test('FES warn classification', () => {
  for (const v of FES_WARN) assert.equal(FESClassify(v), FES_CLASS.WARN, v)
})

test('FES allow classification', () => {
  for (const v of FES_ALLOW) assert.equal(FESClassify(v), FES_CLASS.ALLOW, v)
})

test('FES unknown classification', () => {
  assert.equal(FESClassify('zzz-not-in-catalog-7'), FES_CLASS.UNKNOWN)
})
