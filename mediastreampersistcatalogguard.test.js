'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MSTClassify, MST_CLASS, MST_BLOCK, MST_WARN, MST_ALLOW } = require('./mediastreampersistcatalogguard.js')

test('MST block classification', () => {
  for (const v of MST_BLOCK) assert.equal(MSTClassify(v), MST_CLASS.BLOCK, v)
})

test('MST warn classification', () => {
  for (const v of MST_WARN) assert.equal(MSTClassify(v), MST_CLASS.WARN, v)
})

test('MST allow classification', () => {
  for (const v of MST_ALLOW) assert.equal(MSTClassify(v), MST_CLASS.ALLOW, v)
})

test('MST unknown classification', () => {
  assert.equal(MSTClassify('zzz-not-in-catalog-7'), MST_CLASS.UNKNOWN)
})
