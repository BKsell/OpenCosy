'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CCDClassify, CCD_CLASS, CCD_BLOCK, CCD_WARN, CCD_ALLOW } = require('./cookieattributedirectoryguard.js')

test('CCD block classification', () => {
  for (const v of CCD_BLOCK) assert.equal(CCDClassify(v), CCD_CLASS.BLOCK, v)
})

test('CCD warn classification', () => {
  for (const v of CCD_WARN) assert.equal(CCDClassify(v), CCD_CLASS.WARN, v)
})

test('CCD allow classification', () => {
  for (const v of CCD_ALLOW) assert.equal(CCDClassify(v), CCD_CLASS.ALLOW, v)
})

test('CCD unknown classification', () => {
  assert.equal(CCDClassify('zzz-not-in-catalog-7'), CCD_CLASS.UNKNOWN)
})
