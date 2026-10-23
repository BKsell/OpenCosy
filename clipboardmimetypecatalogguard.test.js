'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CLMClassify, CLM_CLASS, CLM_BLOCK, CLM_WARN, CLM_ALLOW } = require('./clipboardmimetypecatalogguard.js')

test('CLM block classification', () => {
  for (const v of CLM_BLOCK) assert.equal(CLMClassify(v), CLM_CLASS.BLOCK, v)
})

test('CLM warn classification', () => {
  for (const v of CLM_WARN) assert.equal(CLMClassify(v), CLM_CLASS.WARN, v)
})

test('CLM allow classification', () => {
  for (const v of CLM_ALLOW) assert.equal(CLMClassify(v), CLM_CLASS.ALLOW, v)
})

test('CLM unknown classification', () => {
  assert.equal(CLMClassify('zzz-not-in-catalog-7'), CLM_CLASS.UNKNOWN)
})
