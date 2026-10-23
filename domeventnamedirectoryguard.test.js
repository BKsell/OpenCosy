'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DENClassify, DEN_CLASS, DEN_BLOCK, DEN_WARN, DEN_ALLOW } = require('./domeventnamedirectoryguard.js')

test('DEN block classification', () => {
  for (const v of DEN_BLOCK) assert.equal(DENClassify(v), DEN_CLASS.BLOCK, v)
})

test('DEN warn classification', () => {
  for (const v of DEN_WARN) assert.equal(DENClassify(v), DEN_CLASS.WARN, v)
})

test('DEN allow classification', () => {
  for (const v of DEN_ALLOW) assert.equal(DENClassify(v), DEN_CLASS.ALLOW, v)
})

test('DEN unknown classification', () => {
  assert.equal(DENClassify('zzz-not-in-catalog-7'), DEN_CLASS.UNKNOWN)
})
