'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CFNClassify, CFN_CLASS, CFN_BLOCK, CFN_WARN, CFN_ALLOW } = require('./cssfunctiondirectoryguard.js')

test('CFN block classification', () => {
  for (const v of CFN_BLOCK) assert.equal(CFNClassify(v), CFN_CLASS.BLOCK, v)
})

test('CFN warn classification', () => {
  for (const v of CFN_WARN) assert.equal(CFNClassify(v), CFN_CLASS.WARN, v)
})

test('CFN allow classification', () => {
  for (const v of CFN_ALLOW) assert.equal(CFNClassify(v), CFN_CLASS.ALLOW, v)
})

test('CFN unknown classification', () => {
  assert.equal(CFNClassify('zzz-not-in-catalog-7'), CFN_CLASS.UNKNOWN)
})
