'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WGEClassify, WGE_CLASS, WGE_BLOCK, WGE_WARN, WGE_ALLOW } = require('./webglextensiondirectoryguard.js')

test('WGE block classification', () => {
  for (const v of WGE_BLOCK) assert.equal(WGEClassify(v), WGE_CLASS.BLOCK, v)
})

test('WGE warn classification', () => {
  for (const v of WGE_WARN) assert.equal(WGEClassify(v), WGE_CLASS.WARN, v)
})

test('WGE allow classification', () => {
  for (const v of WGE_ALLOW) assert.equal(WGEClassify(v), WGE_CLASS.ALLOW, v)
})

test('WGE unknown classification', () => {
  assert.equal(WGEClassify('zzz-not-in-catalog-7'), WGE_CLASS.UNKNOWN)
})
