'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SCDClassify, SCD_CLASS, SCD_BLOCK, SCD_WARN, SCD_ALLOW } = require('./speakercaptchadomcatalogguard.js')

test('SCD block classification', () => {
  for (const v of SCD_BLOCK) assert.equal(SCDClassify(v), SCD_CLASS.BLOCK, v)
})

test('SCD warn classification', () => {
  for (const v of SCD_WARN) assert.equal(SCDClassify(v), SCD_CLASS.WARN, v)
})

test('SCD allow classification', () => {
  for (const v of SCD_ALLOW) assert.equal(SCDClassify(v), SCD_CLASS.ALLOW, v)
})

test('SCD unknown classification', () => {
  assert.equal(SCDClassify('zzz-not-in-catalog-7'), SCD_CLASS.UNKNOWN)
})
