'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TTPClassify, TTP_CLASS, TTP_BLOCK, TTP_WARN, TTP_ALLOW } = require('./trustedtypespolicydirectoryguard.js')

test('TTP block classification', () => {
  for (const v of TTP_BLOCK) assert.equal(TTPClassify(v), TTP_CLASS.BLOCK, v)
})

test('TTP warn classification', () => {
  for (const v of TTP_WARN) assert.equal(TTPClassify(v), TTP_CLASS.WARN, v)
})

test('TTP allow classification', () => {
  for (const v of TTP_ALLOW) assert.equal(TTPClassify(v), TTP_CLASS.ALLOW, v)
})

test('TTP unknown classification', () => {
  assert.equal(TTPClassify('zzz-not-in-catalog-7'), TTP_CLASS.UNKNOWN)
})
