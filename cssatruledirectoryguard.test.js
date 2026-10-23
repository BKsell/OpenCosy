'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CARClassify, CAR_CLASS, CAR_BLOCK, CAR_WARN, CAR_ALLOW } = require('./cssatruledirectoryguard.js')

test('CAR block classification', () => {
  for (const v of CAR_BLOCK) assert.equal(CARClassify(v), CAR_CLASS.BLOCK, v)
})

test('CAR warn classification', () => {
  for (const v of CAR_WARN) assert.equal(CARClassify(v), CAR_CLASS.WARN, v)
})

test('CAR allow classification', () => {
  for (const v of CAR_ALLOW) assert.equal(CARClassify(v), CAR_CLASS.ALLOW, v)
})

test('CAR unknown classification', () => {
  assert.equal(CARClassify('zzz-not-in-catalog-7'), CAR_CLASS.UNKNOWN)
})
