'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { JU2Classify, JU2_CLASS, JU2_BLOCK, JU2_WARN, JU2_ALLOW } = require('./jsuesccontrolcatalogguard.js')

test('JU2 block classification', () => {
  for (const v of JU2_BLOCK) assert.equal(JU2Classify(v), JU2_CLASS.BLOCK, v)
})

test('JU2 warn classification', () => {
  for (const v of JU2_WARN) assert.equal(JU2Classify(v), JU2_CLASS.WARN, v)
})

test('JU2 allow classification', () => {
  for (const v of JU2_ALLOW) assert.equal(JU2Classify(v), JU2_CLASS.ALLOW, v)
})

test('JU2 unknown classification', () => {
  assert.equal(JU2Classify('zzz-not-in-catalog-11'), JU2_CLASS.UNKNOWN)
})
