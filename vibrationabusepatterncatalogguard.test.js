'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { VIBClassify, VIB_CLASS, VIB_BLOCK, VIB_WARN, VIB_ALLOW } = require('./vibrationabusepatterncatalogguard.js')

test('VIB block classification', () => {
  for (const v of VIB_BLOCK) assert.equal(VIBClassify(v), VIB_CLASS.BLOCK, v)
})

test('VIB warn classification', () => {
  for (const v of VIB_WARN) assert.equal(VIBClassify(v), VIB_CLASS.WARN, v)
})

test('VIB allow classification', () => {
  for (const v of VIB_ALLOW) assert.equal(VIBClassify(v), VIB_CLASS.ALLOW, v)
})

test('VIB unknown classification', () => {
  assert.equal(VIBClassify('zzz-not-in-catalog-7'), VIB_CLASS.UNKNOWN)
})
