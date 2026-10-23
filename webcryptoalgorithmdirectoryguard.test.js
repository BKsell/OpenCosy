'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WCAClassify, WCA_CLASS, WCA_BLOCK, WCA_WARN, WCA_ALLOW } = require('./webcryptoalgorithmdirectoryguard.js')

test('WCA block classification', () => {
  for (const v of WCA_BLOCK) assert.equal(WCAClassify(v), WCA_CLASS.BLOCK, v)
})

test('WCA warn classification', () => {
  for (const v of WCA_WARN) assert.equal(WCAClassify(v), WCA_CLASS.WARN, v)
})

test('WCA allow classification', () => {
  for (const v of WCA_ALLOW) assert.equal(WCAClassify(v), WCA_CLASS.ALLOW, v)
})

test('WCA unknown classification', () => {
  assert.equal(WCAClassify('zzz-not-in-catalog-7'), WCA_CLASS.UNKNOWN)
})
