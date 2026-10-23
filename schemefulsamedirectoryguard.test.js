'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SSCClassify, SSC_CLASS, SSC_BLOCK, SSC_WARN, SSC_ALLOW } = require('./schemefulsamedirectoryguard.js')

test('SSC block classification', () => {
  for (const v of SSC_BLOCK) assert.equal(SSCClassify(v), SSC_CLASS.BLOCK, v)
})

test('SSC warn classification', () => {
  for (const v of SSC_WARN) assert.equal(SSCClassify(v), SSC_CLASS.WARN, v)
})

test('SSC allow classification', () => {
  for (const v of SSC_ALLOW) assert.equal(SSCClassify(v), SSC_CLASS.ALLOW, v)
})

test('SSC unknown classification', () => {
  assert.equal(SSCClassify('zzz-not-in-catalog-7'), SSC_CLASS.UNKNOWN)
})
