'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BSDClassify, BSD_CLASS, BSD_BLOCK, BSD_WARN, BSD_ALLOW } = require('./browserschemedirectoryguard.js')

test('BSD block classification', () => {
  for (const v of BSD_BLOCK) assert.equal(BSDClassify(v), BSD_CLASS.BLOCK, v)
})

test('BSD warn classification', () => {
  for (const v of BSD_WARN) assert.equal(BSDClassify(v), BSD_CLASS.WARN, v)
})

test('BSD allow classification', () => {
  for (const v of BSD_ALLOW) assert.equal(BSDClassify(v), BSD_CLASS.ALLOW, v)
})

test('BSD unknown classification', () => {
  assert.equal(BSDClassify('zzz-not-in-catalog-7'), BSD_CLASS.UNKNOWN)
})
