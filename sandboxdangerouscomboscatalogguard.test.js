'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SFFClassify, SFF_CLASS, SFF_BLOCK, SFF_WARN, SFF_ALLOW } = require('./sandboxdangerouscomboscatalogguard.js')

test('SFF block classification', () => {
  for (const v of SFF_BLOCK) assert.equal(SFFClassify(v), SFF_CLASS.BLOCK, v)
})

test('SFF warn classification', () => {
  for (const v of SFF_WARN) assert.equal(SFFClassify(v), SFF_CLASS.WARN, v)
})

test('SFF allow classification', () => {
  for (const v of SFF_ALLOW) assert.equal(SFFClassify(v), SFF_CLASS.ALLOW, v)
})

test('SFF unknown classification', () => {
  assert.equal(SFFClassify('zzz-not-in-catalog-7'), SFF_CLASS.UNKNOWN)
})
