'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CM2Classify, CM2_CLASS, CM2_BLOCK, CM2_WARN, CM2_ALLOW } = require('./combiningmarkcodepointcatalogguard.js')

test('CM2 block classification', () => {
  for (const v of CM2_BLOCK) assert.equal(CM2Classify(v), CM2_CLASS.BLOCK, v)
})

test('CM2 warn classification', () => {
  for (const v of CM2_WARN) assert.equal(CM2Classify(v), CM2_CLASS.WARN, v)
})

test('CM2 allow classification', () => {
  for (const v of CM2_ALLOW) assert.equal(CM2Classify(v), CM2_CLASS.ALLOW, v)
})

test('CM2 unknown classification', () => {
  assert.equal(CM2Classify('zzz-not-in-catalog-11'), CM2_CLASS.UNKNOWN)
})
