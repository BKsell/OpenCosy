'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BATClassify, BAT_CLASS, BAT_BLOCK, BAT_WARN, BAT_ALLOW } = require('./batteryfingerprintcatalogguard.js')

test('BAT block classification', () => {
  for (const v of BAT_BLOCK) assert.equal(BATClassify(v), BAT_CLASS.BLOCK, v)
})

test('BAT warn classification', () => {
  for (const v of BAT_WARN) assert.equal(BATClassify(v), BAT_CLASS.WARN, v)
})

test('BAT allow classification', () => {
  for (const v of BAT_ALLOW) assert.equal(BATClassify(v), BAT_CLASS.ALLOW, v)
})

test('BAT unknown classification', () => {
  assert.equal(BATClassify('zzz-not-in-catalog-7'), BAT_CLASS.UNKNOWN)
})
