'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OITClassify, OIT_CLASS, OIT_BLOCK, OIT_WARN, OIT_ALLOW } = require('./originisolationtokendirectoryguard.js')

test('OIT block classification', () => {
  for (const v of OIT_BLOCK) assert.equal(OITClassify(v), OIT_CLASS.BLOCK, v)
})

test('OIT warn classification', () => {
  for (const v of OIT_WARN) assert.equal(OITClassify(v), OIT_CLASS.WARN, v)
})

test('OIT allow classification', () => {
  for (const v of OIT_ALLOW) assert.equal(OITClassify(v), OIT_CLASS.ALLOW, v)
})

test('OIT unknown classification', () => {
  assert.equal(OITClassify('zzz-not-in-catalog-7'), OIT_CLASS.UNKNOWN)
})
