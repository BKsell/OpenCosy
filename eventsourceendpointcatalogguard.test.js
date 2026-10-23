'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ESJClassify, ESJ_CLASS, ESJ_BLOCK, ESJ_WARN, ESJ_ALLOW } = require('./eventsourceendpointcatalogguard.js')

test('ESJ block classification', () => {
  for (const v of ESJ_BLOCK) assert.equal(ESJClassify(v), ESJ_CLASS.BLOCK, v)
})

test('ESJ warn classification', () => {
  for (const v of ESJ_WARN) assert.equal(ESJClassify(v), ESJ_CLASS.WARN, v)
})

test('ESJ allow classification', () => {
  for (const v of ESJ_ALLOW) assert.equal(ESJClassify(v), ESJ_CLASS.ALLOW, v)
})

test('ESJ unknown classification', () => {
  assert.equal(ESJClassify('zzz-not-in-catalog-7'), ESJ_CLASS.UNKNOWN)
})
