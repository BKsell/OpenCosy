'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PRESClassify, PRES_CLASS, PRES_BLOCK, PRES_WARN, PRES_ALLOW } = require('./presentationcasturlcatalogguard.js')

test('PRES block classification', () => {
  for (const v of PRES_BLOCK) assert.equal(PRESClassify(v), PRES_CLASS.BLOCK, v)
})

test('PRES warn classification', () => {
  for (const v of PRES_WARN) assert.equal(PRESClassify(v), PRES_CLASS.WARN, v)
})

test('PRES allow classification', () => {
  for (const v of PRES_ALLOW) assert.equal(PRESClassify(v), PRES_CLASS.ALLOW, v)
})

test('PRES unknown classification', () => {
  assert.equal(PRESClassify('zzz-not-in-catalog-7'), PRES_CLASS.UNKNOWN)
})
