'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PPKClassify, PPK_CLASS, PPK_BLOCK, PPK_WARN, PPK_ALLOW } = require('./prototypepollutionkeydirectoryguard.js')

test('PPK block classification', () => {
  for (const v of PPK_BLOCK) assert.equal(PPKClassify(v), PPK_CLASS.BLOCK, v)
})

test('PPK warn classification', () => {
  for (const v of PPK_WARN) assert.equal(PPKClassify(v), PPK_CLASS.WARN, v)
})

test('PPK allow classification', () => {
  for (const v of PPK_ALLOW) assert.equal(PPKClassify(v), PPK_CLASS.ALLOW, v)
})

test('PPK unknown classification', () => {
  assert.equal(PPKClassify('zzz-not-in-catalog-7'), PPK_CLASS.UNKNOWN)
})
