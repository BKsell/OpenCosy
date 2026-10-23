'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OESClassify, OES_CLASS, OES_BLOCK, OES_WARN, OES_ALLOW } = require('./objectembedplugincatalogguard.js')

test('OES block classification', () => {
  for (const v of OES_BLOCK) assert.equal(OESClassify(v), OES_CLASS.BLOCK, v)
})

test('OES warn classification', () => {
  for (const v of OES_WARN) assert.equal(OESClassify(v), OES_CLASS.WARN, v)
})

test('OES allow classification', () => {
  for (const v of OES_ALLOW) assert.equal(OESClassify(v), OES_CLASS.ALLOW, v)
})

test('OES unknown classification', () => {
  assert.equal(OESClassify('zzz-not-in-catalog-7'), OES_CLASS.UNKNOWN)
})
