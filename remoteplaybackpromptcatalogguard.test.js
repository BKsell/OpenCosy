'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RPBClassify, RPB_CLASS, RPB_BLOCK, RPB_WARN, RPB_ALLOW } = require('./remoteplaybackpromptcatalogguard.js')

test('RPB block classification', () => {
  for (const v of RPB_BLOCK) assert.equal(RPBClassify(v), RPB_CLASS.BLOCK, v)
})

test('RPB warn classification', () => {
  for (const v of RPB_WARN) assert.equal(RPBClassify(v), RPB_CLASS.WARN, v)
})

test('RPB allow classification', () => {
  for (const v of RPB_ALLOW) assert.equal(RPBClassify(v), RPB_CLASS.ALLOW, v)
})

test('RPB unknown classification', () => {
  assert.equal(RPBClassify('zzz-not-in-catalog-7'), RPB_CLASS.UNKNOWN)
})
