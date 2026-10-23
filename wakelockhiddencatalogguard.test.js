'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WKLClassify, WKL_CLASS, WKL_BLOCK, WKL_WARN, WKL_ALLOW } = require('./wakelockhiddencatalogguard.js')

test('WKL block classification', () => {
  for (const v of WKL_BLOCK) assert.equal(WKLClassify(v), WKL_CLASS.BLOCK, v)
})

test('WKL warn classification', () => {
  for (const v of WKL_WARN) assert.equal(WKLClassify(v), WKL_CLASS.WARN, v)
})

test('WKL allow classification', () => {
  for (const v of WKL_ALLOW) assert.equal(WKLClassify(v), WKL_CLASS.ALLOW, v)
})

test('WKL unknown classification', () => {
  assert.equal(WKLClassify('zzz-not-in-catalog-7'), WKL_CLASS.UNKNOWN)
})
