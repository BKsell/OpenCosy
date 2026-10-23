'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HSTClassify, HST_CLASS, HST_BLOCK, HST_WARN, HST_ALLOW } = require('./hstsdirectivecatalogguard.js')

test('HST block classification', () => {
  for (const v of HST_BLOCK) assert.equal(HSTClassify(v), HST_CLASS.BLOCK, v)
})

test('HST warn classification', () => {
  for (const v of HST_WARN) assert.equal(HSTClassify(v), HST_CLASS.WARN, v)
})

test('HST allow classification', () => {
  for (const v of HST_ALLOW) assert.equal(HSTClassify(v), HST_CLASS.ALLOW, v)
})

test('HST unknown classification', () => {
  assert.equal(HSTClassify('zzz-not-in-catalog-7'), HST_CLASS.UNKNOWN)
})
