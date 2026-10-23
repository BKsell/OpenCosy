'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { UBTClassify, UBT_CLASS, UBT_BLOCK, UBT_WARN, UBT_ALLOW } = require('./usbarbitrarytransfercatalogguard.js')

test('UBT block classification', () => {
  for (const v of UBT_BLOCK) assert.equal(UBTClassify(v), UBT_CLASS.BLOCK, v)
})

test('UBT warn classification', () => {
  for (const v of UBT_WARN) assert.equal(UBTClassify(v), UBT_CLASS.WARN, v)
})

test('UBT allow classification', () => {
  for (const v of UBT_ALLOW) assert.equal(UBTClassify(v), UBT_CLASS.ALLOW, v)
})

test('UBT unknown classification', () => {
  assert.equal(UBTClassify('zzz-not-in-catalog-7'), UBT_CLASS.UNKNOWN)
})
