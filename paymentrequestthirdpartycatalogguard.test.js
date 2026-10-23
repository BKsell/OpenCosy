'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PAYClassify, PAY_CLASS, PAY_BLOCK, PAY_WARN, PAY_ALLOW } = require('./paymentrequestthirdpartycatalogguard.js')

test('PAY block classification', () => {
  for (const v of PAY_BLOCK) assert.equal(PAYClassify(v), PAY_CLASS.BLOCK, v)
})

test('PAY warn classification', () => {
  for (const v of PAY_WARN) assert.equal(PAYClassify(v), PAY_CLASS.WARN, v)
})

test('PAY allow classification', () => {
  for (const v of PAY_ALLOW) assert.equal(PAYClassify(v), PAY_CLASS.ALLOW, v)
})

test('PAY unknown classification', () => {
  assert.equal(PAYClassify('zzz-not-in-catalog-7'), PAY_CLASS.UNKNOWN)
})
