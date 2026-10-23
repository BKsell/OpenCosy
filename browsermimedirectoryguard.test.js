'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MMDClassify, MMD_CLASS, MMD_BLOCK, MMD_WARN, MMD_ALLOW } = require('./browsermimedirectoryguard.js')

test('MMD block classification', () => {
  for (const v of MMD_BLOCK) assert.equal(MMDClassify(v), MMD_CLASS.BLOCK, v)
})

test('MMD warn classification', () => {
  for (const v of MMD_WARN) assert.equal(MMDClassify(v), MMD_CLASS.WARN, v)
})

test('MMD allow classification', () => {
  for (const v of MMD_ALLOW) assert.equal(MMDClassify(v), MMD_CLASS.ALLOW, v)
})

test('MMD unknown classification', () => {
  assert.equal(MMDClassify('zzz-not-in-catalog-7'), MMD_CLASS.UNKNOWN)
})
