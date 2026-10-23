'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FSEClassify, FSE_CLASS, FSE_BLOCK, FSE_WARN, FSE_ALLOW } = require('./fullscreenuntrustedoverlaycatalogguard.js')

test('FSE block classification', () => {
  for (const v of FSE_BLOCK) assert.equal(FSEClassify(v), FSE_CLASS.BLOCK, v)
})

test('FSE warn classification', () => {
  for (const v of FSE_WARN) assert.equal(FSEClassify(v), FSE_CLASS.WARN, v)
})

test('FSE allow classification', () => {
  for (const v of FSE_ALLOW) assert.equal(FSEClassify(v), FSE_CLASS.ALLOW, v)
})

test('FSE unknown classification', () => {
  assert.equal(FSEClassify('zzz-not-in-catalog-7'), FSE_CLASS.UNKNOWN)
})
