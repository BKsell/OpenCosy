'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CCTClassify, CCT_CLASS, CCT_BLOCK, CCT_WARN, CCT_ALLOW } = require('./cachecontroltokendirectoryguard.js')

test('CCT block classification', () => {
  for (const v of CCT_BLOCK) assert.equal(CCTClassify(v), CCT_CLASS.BLOCK, v)
})

test('CCT warn classification', () => {
  for (const v of CCT_WARN) assert.equal(CCTClassify(v), CCT_CLASS.WARN, v)
})

test('CCT allow classification', () => {
  for (const v of CCT_ALLOW) assert.equal(CCTClassify(v), CCT_CLASS.ALLOW, v)
})

test('CCT unknown classification', () => {
  assert.equal(CCTClassify('zzz-not-in-catalog-7'), CCT_CLASS.UNKNOWN)
})
