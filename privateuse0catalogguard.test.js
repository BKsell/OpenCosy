'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { P02Classify, P02_CLASS, P02_BLOCK, P02_WARN, P02_ALLOW } = require('./privateuse0catalogguard.js')

test('P02 block classification', () => {
  for (const v of P02_BLOCK) assert.equal(P02Classify(v), P02_CLASS.BLOCK, v)
})

test('P02 warn classification', () => {
  for (const v of P02_WARN) assert.equal(P02Classify(v), P02_CLASS.WARN, v)
})

test('P02 allow classification', () => {
  for (const v of P02_ALLOW) assert.equal(P02Classify(v), P02_CLASS.ALLOW, v)
})

test('P02 unknown classification', () => {
  assert.equal(P02Classify('zzz-not-in-catalog-11'), P02_CLASS.UNKNOWN)
})
