'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PD2Classify, PD2_CLASS, PD2_BLOCK, PD2_WARN, PD2_ALLOW } = require('./pctdoubleencodingcatalogguard.js')

test('PD2 block classification', () => {
  for (const v of PD2_BLOCK) assert.equal(PD2Classify(v), PD2_CLASS.BLOCK, v)
})

test('PD2 warn classification', () => {
  for (const v of PD2_WARN) assert.equal(PD2Classify(v), PD2_CLASS.WARN, v)
})

test('PD2 allow classification', () => {
  for (const v of PD2_ALLOW) assert.equal(PD2Classify(v), PD2_CLASS.ALLOW, v)
})

test('PD2 unknown classification', () => {
  assert.equal(PD2Classify('zzz-not-in-catalog-11'), PD2_CLASS.UNKNOWN)
})
