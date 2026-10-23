'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SWSClassify, SWS_CLASS, SWS_BLOCK, SWS_WARN, SWS_ALLOW } = require('./serviceworkerscopecatalogguard.js')

test('SWS block classification', () => {
  for (const v of SWS_BLOCK) assert.equal(SWSClassify(v), SWS_CLASS.BLOCK, v)
})

test('SWS warn classification', () => {
  for (const v of SWS_WARN) assert.equal(SWSClassify(v), SWS_CLASS.WARN, v)
})

test('SWS allow classification', () => {
  for (const v of SWS_ALLOW) assert.equal(SWSClassify(v), SWS_CLASS.ALLOW, v)
})

test('SWS unknown classification', () => {
  assert.equal(SWSClassify('zzz-not-in-catalog-7'), SWS_CLASS.UNKNOWN)
})
