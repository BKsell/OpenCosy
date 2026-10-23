'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TMGClassify, TMG_CLASS, TMG_BLOCK, TMG_WARN, TMG_ALLOW } = require('./hightresstimingcatalogguard.js')

test('TMG block classification', () => {
  for (const v of TMG_BLOCK) assert.equal(TMGClassify(v), TMG_CLASS.BLOCK, v)
})

test('TMG warn classification', () => {
  for (const v of TMG_WARN) assert.equal(TMGClassify(v), TMG_CLASS.WARN, v)
})

test('TMG allow classification', () => {
  for (const v of TMG_ALLOW) assert.equal(TMGClassify(v), TMG_CLASS.ALLOW, v)
})

test('TMG unknown classification', () => {
  assert.equal(TMGClassify('zzz-not-in-catalog-7'), TMG_CLASS.UNKNOWN)
})
