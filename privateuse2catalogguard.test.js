'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { P22Classify, P22_CLASS, P22_BLOCK, P22_WARN, P22_ALLOW } = require('./privateuse2catalogguard.js')

test('P22 block classification', () => {
  for (const v of P22_BLOCK) assert.equal(P22Classify(v), P22_CLASS.BLOCK, v)
})

test('P22 warn classification', () => {
  for (const v of P22_WARN) assert.equal(P22Classify(v), P22_CLASS.WARN, v)
})

test('P22 allow classification', () => {
  for (const v of P22_ALLOW) assert.equal(P22Classify(v), P22_CLASS.ALLOW, v)
})

test('P22 unknown classification', () => {
  assert.equal(P22Classify('zzz-not-in-catalog-11'), P22_CLASS.UNKNOWN)
})
