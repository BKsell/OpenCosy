'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LPCClassify, LPC_CLASS, LPC_BLOCK, LPC_WARN, LPC_ALLOW } = require('./preconnectthirdpartycatalogguard.js')

test('LPC block classification', () => {
  for (const v of LPC_BLOCK) assert.equal(LPCClassify(v), LPC_CLASS.BLOCK, v)
})

test('LPC warn classification', () => {
  for (const v of LPC_WARN) assert.equal(LPCClassify(v), LPC_CLASS.WARN, v)
})

test('LPC allow classification', () => {
  for (const v of LPC_ALLOW) assert.equal(LPCClassify(v), LPC_CLASS.ALLOW, v)
})

test('LPC unknown classification', () => {
  assert.equal(LPCClassify('zzz-not-in-catalog-7'), LPC_CLASS.UNKNOWN)
})
