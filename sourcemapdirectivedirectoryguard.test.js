'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SMDClassify, SMD_CLASS, SMD_BLOCK, SMD_WARN, SMD_ALLOW } = require('./sourcemapdirectivedirectoryguard.js')

test('SMD block classification', () => {
  for (const v of SMD_BLOCK) assert.equal(SMDClassify(v), SMD_CLASS.BLOCK, v)
})

test('SMD warn classification', () => {
  for (const v of SMD_WARN) assert.equal(SMDClassify(v), SMD_CLASS.WARN, v)
})

test('SMD allow classification', () => {
  for (const v of SMD_ALLOW) assert.equal(SMDClassify(v), SMD_CLASS.ALLOW, v)
})

test('SMD unknown classification', () => {
  assert.equal(SMDClassify('zzz-not-in-catalog-7'), SMD_CLASS.UNKNOWN)
})
