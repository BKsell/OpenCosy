'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LASClassify, LAS_CLASS, LAS_BLOCK, LAS_WARN, LAS_ALLOW } = require('./locationnavigationsinkcatalogguard.js')

test('LAS block classification', () => {
  for (const v of LAS_BLOCK) assert.equal(LASClassify(v), LAS_CLASS.BLOCK, v)
})

test('LAS warn classification', () => {
  for (const v of LAS_WARN) assert.equal(LASClassify(v), LAS_CLASS.WARN, v)
})

test('LAS allow classification', () => {
  for (const v of LAS_ALLOW) assert.equal(LASClassify(v), LAS_CLASS.ALLOW, v)
})

test('LAS unknown classification', () => {
  assert.equal(LASClassify('zzz-not-in-catalog-7'), LAS_CLASS.UNKNOWN)
})
